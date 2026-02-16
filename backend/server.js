const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(cors({
    origin: [process.env.FRONTEND_URL, process.env.ADMIN_URL, 'http://localhost:3000', 'http://localhost:5000'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200
});
app.use('/api/', limiter);

// Cloudinary Configuration
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer Memory Storage (for handling multiple files)
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.log('❌ MongoDB Connection Error:', err));

// ==================== SCHEMAS ====================

// Admin Schema
const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: { type: String, default: 'Admin' },
    role: { type: String, default: 'super_admin' },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date }
});

// Product Schema
const productSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    cat: { type: String, required: true, enum: ['watch', 'earbud', 'power', 'speaker'] },
    name: { type: String, required: true },
    price: { type: Number, required: true },
    oldPrice: { type: Number, required: true },
    discount: { type: Number, required: true },
    desc: { type: String, required: true },
    images: [{ type: String, required: true }],
    stock: { type: Number, default: 10 },
    featured: { type: Boolean, default: false },
    specifications: { type: Map, of: String },
    tags: [String],
    views: { type: Number, default: 0 },
    sold: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Order Schema
const orderSchema = new mongoose.Schema({
    orderId: { type: String, unique: true },
    customerName: { type: String, required: true },
    customerPhone: { type: String, required: true },
    customerAddress: { type: String, required: true },
    customerEmail: String,
    items: [{
        productId: String,
        name: String,
        price: Number,
        quantity: Number,
        image: String
    }],
    totalAmount: { type: Number, required: true },
    deliveryCharge: { type: Number, default: 60 },
    grandTotal: { type: Number, required: true },
    status: { 
        type: String, 
        enum: ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'],
        default: 'pending'
    },
    paymentMethod: { type: String, default: 'cash_on_delivery' },
    paymentStatus: { type: String, default: 'pending' },
    orderSummary: String,
    notes: String,
    trackingCode: String,
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Review Schema
const reviewSchema = new mongoose.Schema({
    name: { type: String, required: true },
    address: String,
    text: { type: String, required: true },
    rating: { type: Number, min: 1, max: 5, default: 5 },
    productId: String,
    productName: String,
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    isFeatured: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

// Slide Schema
const slideSchema = new mongoose.Schema({
    title: { type: String, required: true },
    subtitle: String,
    badge: String,
    badgeIcon: String,
    image: { type: String, required: true },
    category: String,
    discount: String,
    buttonText: String,
    buttonLink: String,
    order: { type: Number, default: 0 },
    active: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

// Settings Schema
const settingsSchema = new mongoose.Schema({
    siteName: { type: String, default: 'Jahid Gadgets' },
    siteTitle: { type: String, default: 'আধুনিক প্রযুক্তির ঠিকানা' },
    siteDescription: { type: String, default: 'প্রিমিয়াম গ্যাজেটের সেরা সংগ্রহ' },
    phone: { type: String, default: '+8801709363983' },
    whatsapp: { type: String, default: '+8801709363983' },
    address: { type: String, default: 'রংপুর, বোদা, পঞ্চগড় সদর' },
    email: String,
    facebook: String,
    instagram: String,
    youtube: String,
    deliveryCharge: { type: Number, default: 60 },
    freeDeliveryAbove: { type: Number, default: 2000 },
    currency: { type: String, default: '৳' },
    themeColor: { type: String, default: '#00AEEF' },
    logo: String,
    favicon: String,
    updatedAt: { type: Date, default: Date.now }
});

const Admin = mongoose.model('Admin', adminSchema);
const Product = mongoose.model('Product', productSchema);
const Order = mongoose.model('Order', orderSchema);
const Review = mongoose.model('Review', reviewSchema);
const Slide = mongoose.model('Slide', slideSchema);
const Settings = mongoose.model('Settings', settingsSchema);

// ==================== MIDDLEWARE ====================

// Auth Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access denied' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Validation Middleware
const validate = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};

// ==================== INITIAL SETUP ====================

async function createInitialAdmin() {
    try {
        const adminExists = await Admin.findOne({ username: 'jahid' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('Jahid@2025', 10);
            await Admin.create({
                username: 'jahid',
                password: hashedPassword,
                name: 'Jahid Admin'
            });
            console.log('✅ Initial admin created');
        }
    } catch (error) {
        console.error('❌ Error creating admin:', error);
    }
}

async function initializeSettings() {
    try {
        const settings = await Settings.findOne();
        if (!settings) {
            await Settings.create({});
            console.log('✅ Default settings created');
        }
    } catch (error) {
        console.error('❌ Error creating settings:', error);
    }
}

createInitialAdmin();
initializeSettings();

// Helper function to upload to Cloudinary
async function uploadToCloudinary(file, folder = 'jahid-gadgets') {
    return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
            {
                folder: folder,
                allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'webp'],
                transformation: [{ width: 1200, height: 1200, crop: 'limit' }]
            },
            (error, result) => {
                if (error) reject(error);
                else resolve(result.secure_url);
            }
        );
        uploadStream.end(file.buffer);
    });
}

// ==================== AUTH ROUTES ====================

app.post('/api/admin/login', [
    body('username').notEmpty(),
    body('password').notEmpty()
], validate, async (req, res) => {
    try {
        const { username, password } = req.body;
        const admin = await Admin.findOne({ username });

        if (!admin) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, admin.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        admin.lastLogin = new Date();
        await admin.save();

        const token = jwt.sign(
            { id: admin._id, username: admin.username, name: admin.name },
            process.env.JWT_SECRET,
            { expiresIn: '30d' }
        );

        res.json({ 
            token, 
            username: admin.username,
            name: admin.name
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/verify', authenticateToken, async (req, res) => {
    try {
        const admin = await Admin.findById(req.user.id).select('-password');
        res.json(admin);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/admin/change-password', authenticateToken, [
    body('currentPassword').notEmpty(),
    body('newPassword').isLength({ min: 6 })
], validate, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const admin = await Admin.findById(req.user.id);

        const validPassword = await bcrypt.compare(currentPassword, admin.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        admin.password = hashedPassword;
        await admin.save();

        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== PRODUCT ROUTES ====================

// Get all products (public)
app.get('/api/products', async (req, res) => {
    try {
        const { category, search, sort, featured } = req.query;
        let filter = {};
        
        if (category && category !== 'all') filter.cat = category;
        if (featured === 'true') filter.featured = true;
        if (search) {
            filter.$or = [
                { name: { $regex: search, $options: 'i' } },
                { desc: { $regex: search, $options: 'i' } },
                { id: { $regex: search, $options: 'i' } }
            ];
        }

        let sortOption = { createdAt: -1 };
        if (sort === 'price_asc') sortOption = { price: 1 };
        if (sort === 'price_desc') sortOption = { price: -1 };
        if (sort === 'name') sortOption = { name: 1 };

        const products = await Product.find(filter).sort(sortOption);
        res.json(products);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
    try {
        const product = await Product.findOne({ id: req.params.id });
        if (!product) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        product.views += 1;
        await product.save();
        
        res.json(product);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create product (admin)
app.post('/api/admin/products', authenticateToken, upload.array('images', 10), async (req, res) => {
    try {
        const productData = JSON.parse(req.body.product);
        
        // Upload images to Cloudinary
        const imageUrls = [];
        if (req.files && req.files.length > 0) {
            for (const file of req.files) {
                try {
                    const url = await uploadToCloudinary(file, 'jahid-gadgets/products');
                    imageUrls.push(url);
                } catch (uploadError) {
                    console.error('Image upload error:', uploadError);
                }
            }
        }

        if (imageUrls.length === 0) {
            return res.status(400).json({ error: 'At least one image is required' });
        }

        // Calculate old price if not provided
        if (!productData.oldPrice && productData.discount) {
            productData.oldPrice = Math.round(productData.price * (100 / (100 - productData.discount)));
        }

        const product = await Product.create({
            ...productData,
            images: imageUrls
        });

        res.json(product);
    } catch (error) {
        console.error('Product creation error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update product (admin)
app.put('/api/admin/products/:id', authenticateToken, upload.array('images', 10), async (req, res) => {
    try {
        const productId = req.params.id;
        let updateData = req.body.product ? JSON.parse(req.body.product) : req.body;

        // Upload new images if any
        if (req.files && req.files.length > 0) {
            const imageUrls = [];
            for (const file of req.files) {
                try {
                    const url = await uploadToCloudinary(file, 'jahid-gadgets/products');
                    imageUrls.push(url);
                } catch (uploadError) {
                    console.error('Image upload error:', uploadError);
                }
            }
            updateData.images = [...(updateData.images || []), ...imageUrls];
        }

        updateData.updatedAt = Date.now();

        const product = await Product.findOneAndUpdate(
            { id: productId },
            updateData,
            { new: true }
        );

        if (!product) {
            return res.status(404).json({ error: 'Product not found' });
        }

        res.json(product);
    } catch (error) {
        console.error('Product update error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Delete product (admin)
app.delete('/api/admin/products/:id', authenticateToken, async (req, res) => {
    try {
        const product = await Product.findOneAndDelete({ id: req.params.id });
        if (!product) {
            return res.status(404).json({ error: 'Product not found' });
        }

        // Delete images from cloudinary (optional)
        for (const imageUrl of product.images) {
            try {
                const publicId = imageUrl.split('/').pop().split('.')[0];
                await cloudinary.uploader.destroy(`jahid-gadgets/products/${publicId}`);
            } catch (err) {
                console.error('Error deleting image from cloudinary:', err);
            }
        }

        res.json({ message: 'Product deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Bulk delete products
app.post('/api/admin/products/bulk-delete', authenticateToken, async (req, res) => {
    try {
        const { ids } = req.body;
        await Product.deleteMany({ id: { $in: ids } });
        res.json({ message: 'Products deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== ORDER ROUTES ====================

// Generate order ID
function generateOrderId() {
    return 'ORD' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).substring(2, 5).toUpperCase();
}

// Create order (public)
app.post('/api/orders', [
    body('customerName').notEmpty(),
    body('customerPhone').matches(/^01[3-9]\d{8}$/),
    body('customerAddress').notEmpty(),
    body('items').isArray().notEmpty()
], validate, async (req, res) => {
    try {
        const orderData = req.body;
        const subtotal = orderData.items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
        
        // Get delivery charge from settings
        const settings = await Settings.findOne() || { deliveryCharge: 60, freeDeliveryAbove: 2000 };
        const deliveryCharge = subtotal >= settings.freeDeliveryAbove ? 0 : settings.deliveryCharge;
        const grandTotal = subtotal + deliveryCharge;

        const order = await Order.create({
            ...orderData,
            orderId: generateOrderId(),
            totalAmount: subtotal,
            deliveryCharge,
            grandTotal,
            orderSummary: orderData.items.map(i => `${i.name} (${i.quantity}টি)`).join(', ')
        });

        // Update product sold count
        for (const item of orderData.items) {
            await Product.findOneAndUpdate(
                { id: item.productId },
                { $inc: { sold: item.quantity, stock: -item.quantity } }
            );
        }

        res.json({ success: true, orderId: order.orderId });
    } catch (error) {
        console.error('Order creation error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get all orders (admin)
app.get('/api/admin/orders', authenticateToken, async (req, res) => {
    try {
        const { status, page = 1, limit = 20, search } = req.query;
        let filter = {};
        
        if (status && status !== 'all') filter.status = status;
        if (search) {
            filter.$or = [
                { orderId: { $regex: search, $options: 'i' } },
                { customerName: { $regex: search, $options: 'i' } },
                { customerPhone: { $regex: search, $options: 'i' } }
            ];
        }
        
        const orders = await Order.find(filter)
            .sort({ createdAt: -1 })
            .limit(parseInt(limit))
            .skip((parseInt(page) - 1) * parseInt(limit));

        const total = await Order.countDocuments(filter);

        res.json({
            orders,
            totalPages: Math.ceil(total / limit),
            currentPage: parseInt(page),
            total
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get single order
app.get('/api/admin/orders/:id', authenticateToken, async (req, res) => {
    try {
        const order = await Order.findById(req.params.id);
        if (!order) {
            return res.status(404).json({ error: 'Order not found' });
        }
        res.json(order);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update order (admin)
app.put('/api/admin/orders/:id', authenticateToken, async (req, res) => {
    try {
        const { status, paymentStatus, notes, trackingCode } = req.body;
        const order = await Order.findByIdAndUpdate(
            req.params.id,
            { 
                status, 
                paymentStatus, 
                notes, 
                trackingCode,
                updatedAt: Date.now() 
            },
            { new: true }
        );
        res.json(order);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete order (admin)
app.delete('/api/admin/orders/:id', authenticateToken, async (req, res) => {
    try {
        await Order.findByIdAndDelete(req.params.id);
        res.json({ message: 'Order deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== REVIEW ROUTES ====================

// Get approved reviews (public)
app.get('/api/reviews', async (req, res) => {
    try {
        const { featured } = req.query;
        let filter = { status: 'approved' };
        if (featured === 'true') filter.isFeatured = true;
        
        const reviews = await Review.find(filter)
            .sort({ createdAt: -1 })
            .limit(20);
        res.json(reviews);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create review (public)
app.post('/api/reviews', [
    body('name').notEmpty(),
    body('text').notEmpty()
], validate, async (req, res) => {
    try {
        const review = await Review.create({
            ...req.body,
            status: 'pending'
        });
        res.json({ success: true, message: 'Review submitted for approval' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all reviews (admin)
app.get('/api/admin/reviews', authenticateToken, async (req, res) => {
    try {
        const { status, page = 1, limit = 20 } = req.query;
        const filter = status && status !== 'all' ? { status } : {};
        
        const reviews = await Review.find(filter)
            .sort({ createdAt: -1 })
            .limit(parseInt(limit))
            .skip((parseInt(page) - 1) * parseInt(limit));

        const total = await Review.countDocuments(filter);

        res.json({
            reviews,
            totalPages: Math.ceil(total / limit),
            currentPage: parseInt(page),
            total
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update review (admin)
app.put('/api/admin/reviews/:id', authenticateToken, async (req, res) => {
    try {
        const { status, isFeatured } = req.body;
        const review = await Review.findByIdAndUpdate(
            req.params.id,
            { status, isFeatured },
            { new: true }
        );
        res.json(review);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete review (admin)
app.delete('/api/admin/reviews/:id', authenticateToken, async (req, res) => {
    try {
        await Review.findByIdAndDelete(req.params.id);
        res.json({ message: 'Review deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== SLIDE ROUTES ====================

// Get active slides (public)
app.get('/api/slides', async (req, res) => {
    try {
        const slides = await Slide.find({ active: true }).sort({ order: 1 });
        res.json(slides);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all slides (admin)
app.get('/api/admin/slides', authenticateToken, async (req, res) => {
    try {
        const slides = await Slide.find().sort({ order: 1 });
        res.json(slides);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create slide (admin)
app.post('/api/admin/slides', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const slideData = JSON.parse(req.body.slide);
        
        if (!req.file) {
            return res.status(400).json({ error: 'Image is required' });
        }

        const imageUrl = await uploadToCloudinary(req.file, 'jahid-gadgets/slides');

        const slide = await Slide.create({
            ...slideData,
            image: imageUrl
        });

        res.json(slide);
    } catch (error) {
        console.error('Slide creation error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update slide (admin)
app.put('/api/admin/slides/:id', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const slideData = req.body.slide ? JSON.parse(req.body.slide) : req.body;
        
        if (req.file) {
            slideData.image = await uploadToCloudinary(req.file, 'jahid-gadgets/slides');
        }

        const slide = await Slide.findByIdAndUpdate(
            req.params.id,
            slideData,
            { new: true }
        );
        res.json(slide);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete slide (admin)
app.delete('/api/admin/slides/:id', authenticateToken, async (req, res) => {
    try {
        const slide = await Slide.findByIdAndDelete(req.params.id);
        if (slide && slide.image) {
            try {
                const publicId = slide.image.split('/').pop().split('.')[0];
                await cloudinary.uploader.destroy(`jahid-gadgets/slides/${publicId}`);
            } catch (err) {
                console.error('Error deleting image from cloudinary:', err);
            }
        }
        res.json({ message: 'Slide deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== SETTINGS ROUTES ====================

// Get settings (public)
app.get('/api/settings', async (req, res) => {
    try {
        let settings = await Settings.findOne();
        if (!settings) {
            settings = await Settings.create({});
        }
        res.json(settings);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update settings (admin)
app.put('/api/admin/settings', authenticateToken, async (req, res) => {
    try {
        let settings = await Settings.findOne();
        if (!settings) {
            settings = new Settings();
        }
        
        Object.assign(settings, req.body, { updatedAt: Date.now() });
        await settings.save();
        
        res.json(settings);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Upload logo
app.post('/api/admin/settings/logo', authenticateToken, upload.single('logo'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'Logo is required' });
        }

        const logoUrl = await uploadToCloudinary(req.file, 'jahid-gadgets/settings');
        
        let settings = await Settings.findOne();
        if (!settings) {
            settings = new Settings();
        }
        
        settings.logo = logoUrl;
        await settings.save();

        res.json({ logo: logoUrl });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== DASHBOARD STATS ====================

app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const thisWeek = new Date();
        thisWeek.setDate(thisWeek.getDate() - 7);

        const thisMonth = new Date();
        thisMonth.setMonth(thisMonth.getMonth() - 1);

        const [
            totalOrders,
            pendingOrders,
            totalProducts,
            totalRevenue,
            todayOrders,
            weekOrders,
            monthOrders,
            lowStock,
            recentOrders,
            ordersByStatus,
            topProducts
        ] = await Promise.all([
            Order.countDocuments(),
            Order.countDocuments({ status: 'pending' }),
            Product.countDocuments(),
            Order.aggregate([
                { $match: { status: { $in: ['delivered', 'shipped'] } } },
                { $group: { _id: null, total: { $sum: '$grandTotal' } } }
            ]),
            Order.countDocuments({ createdAt: { $gte: today } }),
            Order.countDocuments({ createdAt: { $gte: thisWeek } }),
            Order.countDocuments({ createdAt: { $gte: thisMonth } }),
            Product.countDocuments({ stock: { $lt: 5 } }),
            Order.find().sort({ createdAt: -1 }).limit(5),
            Order.aggregate([
                { $group: { _id: '$status', count: { $sum: 1 } } }
            ]),
            Product.find().sort({ sold: -1 }).limit(5)
        ]);

        res.json({
            totalOrders,
            pendingOrders,
            totalProducts,
            totalRevenue: totalRevenue[0]?.total || 0,
            todayOrders,
            weekOrders,
            monthOrders,
            lowStock,
            recentOrders,
            ordersByStatus,
            topProducts
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});