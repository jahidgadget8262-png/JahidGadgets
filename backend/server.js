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
require('dotenv').config();

const app = express();

// Middleware
app.use(helmet());
app.use(cors({
    origin: [process.env.FRONTEND_URL, process.env.ADMIN_URL],
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use('/api/', limiter);

// Cloudinary Configuration
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer Cloudinary Storage
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'jahid-gadgets',
        allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'webp'],
        transformation: [{ width: 800, height: 800, crop: 'limit' }]
    }
});
const upload = multer({ storage: storage });

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB Connected'))
  .catch(err => console.log('MongoDB Connection Error:', err));

// ==================== SCHEMAS ====================

// Admin Schema
const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
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
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Order Schema
const orderSchema = new mongoose.Schema({
    customerName: { type: String, required: true },
    customerPhone: { type: String, required: true },
    customerAddress: { type: String, required: true },
    items: [{
        productId: String,
        name: String,
        price: Number,
        quantity: Number,
        image: String
    }],
    totalAmount: { type: Number, required: true },
    status: { 
        type: String, 
        enum: ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'],
        default: 'pending'
    },
    paymentMethod: { type: String, default: 'cash_on_delivery' },
    paymentStatus: { type: String, default: 'pending' },
    orderSummary: String,
    notes: String,
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
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
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
    order: { type: Number, default: 0 },
    active: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

// Settings Schema
const settingsSchema = new mongoose.Schema({
    siteName: { type: String, default: 'Jahid Gadgets' },
    siteTitle: { type: String, default: 'আধুনিক প্রযুক্তির ঠিকানা' },
    phone: { type: String, default: '+8801709363983' },
    whatsapp: { type: String, default: '+8801709363983' },
    address: { type: String, default: 'রংপুর, বোদা, পঞ্চগড় সদর' },
    email: String,
    facebook: String,
    instagram: String,
    deliveryCharge: { type: Number, default: 60 },
    freeDeliveryAbove: { type: Number, default: 2000 },
    currency: { type: String, default: '৳' }
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
                password: hashedPassword
            });
            console.log('Initial admin created');
        }
    } catch (error) {
        console.error('Error creating admin:', error);
    }
}

async function initializeSettings() {
    try {
        const settings = await Settings.findOne();
        if (!settings) {
            await Settings.create({});
            console.log('Default settings created');
        }
    } catch (error) {
        console.error('Error creating settings:', error);
    }
}

createInitialAdmin();
initializeSettings();

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

        const token = jwt.sign(
            { id: admin._id, username: admin.username },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ token, username: admin.username });
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
        const { category } = req.query;
        const filter = category && category !== 'all' ? { cat: category } : {};
        const products = await Product.find(filter).sort({ createdAt: -1 });
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
        res.json(product);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create product (admin)
app.post('/api/admin/products', authenticateToken, upload.array('images', 5), [
    body('id').notEmpty(),
    body('name').notEmpty(),
    body('price').isNumeric(),
    body('cat').isIn(['watch', 'earbud', 'power', 'speaker'])
], validate, async (req, res) => {
    try {
        const productData = JSON.parse(req.body.product);
        const images = req.files.map(file => file.path);

        const product = await Product.create({
            ...productData,
            images,
            oldPrice: productData.oldPrice || Math.round(productData.price * (100 / (100 - (productData.discount || 0))))
        });

        res.json(product);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update product (admin)
app.put('/api/admin/products/:id', authenticateToken, upload.array('images', 5), async (req, res) => {
    try {
        const productId = req.params.id;
        let updateData = req.body.product ? JSON.parse(req.body.product) : req.body;

        if (req.files && req.files.length > 0) {
            updateData.images = req.files.map(file => file.path);
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

        // Delete images from cloudinary
        for (const imageUrl of product.images) {
            const publicId = imageUrl.split('/').pop().split('.')[0];
            await cloudinary.uploader.destroy(`jahid-gadgets/${publicId}`);
        }

        res.json({ message: 'Product deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== ORDER ROUTES ====================

// Create order (public)
app.post('/api/orders', [
    body('customerName').notEmpty(),
    body('customerPhone').matches(/^01[3-9]\d{8}$/),
    body('customerAddress').notEmpty(),
    body('items').isArray().notEmpty()
], validate, async (req, res) => {
    try {
        const orderData = req.body;
        const totalAmount = orderData.items.reduce((sum, item) => sum + (item.price * item.quantity), 0);

        const order = await Order.create({
            ...orderData,
            totalAmount,
            orderSummary: orderData.items.map(i => `${i.name} (${i.quantity}টি)`).join(', ')
        });

        res.json({ success: true, orderId: order._id });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all orders (admin)
app.get('/api/admin/orders', authenticateToken, async (req, res) => {
    try {
        const { status, page = 1, limit = 20 } = req.query;
        const filter = status && status !== 'all' ? { status } : {};
        
        const orders = await Order.find(filter)
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);

        const total = await Order.countDocuments(filter);

        res.json({
            orders,
            totalPages: Math.ceil(total / limit),
            currentPage: page
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update order status (admin)
app.put('/api/admin/orders/:id', authenticateToken, async (req, res) => {
    try {
        const { status, paymentStatus, notes } = req.body;
        const order = await Order.findByIdAndUpdate(
            req.params.id,
            { status, paymentStatus, notes, updatedAt: Date.now() },
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
        const reviews = await Review.find({ status: 'approved' })
            .sort({ createdAt: -1 })
            .limit(10);
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
        const { status } = req.query;
        const filter = status && status !== 'all' ? { status } : {};
        const reviews = await Review.find(filter).sort({ createdAt: -1 });
        res.json(reviews);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update review status (admin)
app.put('/api/admin/reviews/:id', authenticateToken, async (req, res) => {
    try {
        const { status } = req.body;
        const review = await Review.findByIdAndUpdate(
            req.params.id,
            { status },
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
app.post('/api/admin/slides', authenticateToken, upload.single('image'), [
    body('title').notEmpty()
], validate, async (req, res) => {
    try {
        const slideData = JSON.parse(req.body.slide);
        const slide = await Slide.create({
            ...slideData,
            image: req.file.path
        });
        res.json(slide);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update slide (admin)
app.put('/api/admin/slides/:id', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const slideData = req.body.slide ? JSON.parse(req.body.slide) : req.body;
        
        if (req.file) {
            slideData.image = req.file.path;
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
            const publicId = slide.image.split('/').pop().split('.')[0];
            await cloudinary.uploader.destroy(`jahid-gadgets/${publicId}`);
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
        
        Object.assign(settings, req.body);
        await settings.save();
        
        res.json(settings);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== DASHBOARD STATS ====================

app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const totalOrders = await Order.countDocuments();
        const pendingOrders = await Order.countDocuments({ status: 'pending' });
        const totalProducts = await Product.countDocuments();
        const totalRevenue = await Order.aggregate([
            { $match: { status: { $in: ['delivered', 'shipped'] } } },
            { $group: { _id: null, total: { $sum: '$totalAmount' } } }
        ]);

        const todayOrders = await Order.countDocuments({
            createdAt: { $gte: today }
        });

        const recentOrders = await Order.find()
            .sort({ createdAt: -1 })
            .limit(5);

        const lowStock = await Product.find({ stock: { $lt: 5 } }).countDocuments();

        res.json({
            totalOrders,
            pendingOrders,
            totalProducts,
            totalRevenue: totalRevenue[0]?.total || 0,
            todayOrders,
            lowStock,
            recentOrders
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});