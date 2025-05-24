require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const multer = require('multer');
const fs = require('fs');

const app = express();

// Middleware
app.use(express.json());
app.use(cors({ origin: process.env.CLIENT_URL || 'http://localhost:3000', credentials: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(passport.initialize());

// Multer Setup for File Uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'Uploads');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, `${uniqueSuffix}-${file.originalname}`);
    }
});

const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Only images are allowed'), false);
    }
};

const upload = multer({
    storage,
    fileFilter,
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        console.error('No token provided');
        return res.status(401).json({ message: 'Unauthorized' });
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT Verification Error:', err.message);
            return res.status(403).json({ message: 'Forbidden' });
        }
        req.user = user;
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        console.error('User is not admin:', req.user);
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

// Google OAuth Setup
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.CLIENT_URL || 'http://localhost:3000'}/api/auth/google/callback`
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let userResult = await pool.query('SELECT * FROM users WHERE google_id = $1', [profile.id]);
        if (userResult.rows.length > 0) {
            return done(null, userResult.rows[0]);
        }
        userResult = await pool.query('SELECT * FROM users WHERE email = $1', [profile.emails[0].value]);
        if (userResult.rows.length > 0) {
            const updatedUser = await pool.query(
                'UPDATE users SET google_id = $1 WHERE email = $2 RETURNING *',
                [profile.id, profile.emails[0].value]
            );
            return done(null, updatedUser.rows[0]);
        }
        const newUser = await pool.query(
            'INSERT INTO users (email, name, google_id, role, profile_image) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [profile.emails[0].value, profile.displayName, profile.id, 'user', null]
        );
        return done(null, newUser.rows[0]);
    } catch (error) {
        console.error('Google OAuth Error:', error.message);
        return done(error);
    }
}));

// Database Connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Test Database Connection
async function testDbConnection() {
    try {
        const client = await pool.connect();
        console.log('Database connected successfully');
        await client.query('SELECT NOW()');
        client.release();
    } catch (error) {
        console.error('Database connection error:', error.message, error.stack);
        throw error;
    }
}

// Check and Update Schema
async function checkAndUpdateSchema() {
    try {
        console.log('Checking database schema...');

        // Check for profile_image column in users table
        const profileImageCheck = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users' AND column_name = 'profile_image'
        `);
        if (profileImageCheck.rows.length === 0) {
            console.log('Adding profile_image column to users table...');
            await pool.query('ALTER TABLE users ADD COLUMN profile_image TEXT');
            console.log('profile_image column added successfully');
        } else {
            console.log('profile_image column already exists in users table');
        }

        // Check for customer_name column in orders table
        const customerNameCheck = await pool.query(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'orders' AND column_name = 'customer_name'
        `);
        if (customerNameCheck.rows.length === 0) {
            console.log('Adding customer_name column to orders table...');
            await pool.query('ALTER TABLE orders ADD COLUMN customer_name VARCHAR(255) NOT NULL DEFAULT \'Unknown\'');
            console.log('customer_name column added successfully');
        } else {
            console.log('customer_name column already exists in orders table');
        }
    } catch (error) {
        console.error('Error checking/updating schema:', error.message, error.stack);
        throw error;
    }
}

// Initialize Database
async function initializeDatabase() {
    try {
        console.log('Initializing database...');
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255),
                name VARCHAR(255),
                phone VARCHAR(20),
                role VARCHAR(20) DEFAULT 'user',
                google_id VARCHAR(255),
                profile_image TEXT
            );

            CREATE TABLE IF NOT EXISTS menu_items (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                price VARCHAR(20) NOT NULL,
                image TEXT
            );

            CREATE TABLE IF NOT EXISTS special_offers (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                price VARCHAR(20) NOT NULL,
                image TEXT
            );

            CREATE TABLE IF NOT EXISTS customers (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                phone VARCHAR(20)
            );

            CREATE TABLE IF NOT EXISTS orders (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                customer_name VARCHAR(255) NOT NULL,
                items JSONB NOT NULL,
                total_amount VARCHAR(20) NOT NULL,
                status VARCHAR(50) DEFAULT 'Pending',
                razorpay_order_id VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS otps (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                otp VARCHAR(6) NOT NULL,
                expires_at TIMESTAMP NOT NULL
            );
        `);
        console.log('Database tables created successfully');

        // Seed admin user
        const adminCount = await pool.query('SELECT COUNT(*) FROM users WHERE email = $1', ['admin@delicute.com']);
        if (parseInt(adminCount.rows[0].count) === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await pool.query(
                'INSERT INTO users (email, password, name, role, profile_image) VALUES ($1, $2, $3, $4, $5)',
                ['admin@delicute.com', hashedPassword, 'Admin User', 'admin', null]
            );
            console.log('Seeded admin user: admin@delicute.com');
        }

        // Seed menu items
        const menuCount = await pool.query('SELECT COUNT(*) FROM menu_items');
        if (parseInt(menuCount.rows[0].count) === 0) {
            const initialItems = [
                {
                    name: 'Fresh Garden Salad',
                    description: 'Crisp greens, cherry tomatoes, and a zesty dressing.',
                    price: '₹749',
                    image: '/Uploads/salad.jpg'
                },
                {
                    name: 'Margherita Pizza',
                    description: 'Classic pizza with fresh basil and mozzarella.',
                    price: '₹1099',
                    image: '/Uploads/pizza.jpg'
                }
            ];
            for (const item of initialItems) {
                await pool.query(
                    'INSERT INTO menu_items (name, description, price, image) VALUES ($1, $2, $3, $4)',
                    [item.name, item.description, item.price, item.image]
                );
            }
            console.log('Seeded menu items');
        }

        // Seed special offers
        const offerCount = await pool.query('SELECT COUNT(*) FROM special_offers');
        if (parseInt(offerCount.rows[0].count) === 0) {
            const initialOffers = [
                {
                    name: 'Family Combo',
                    description: 'Pizza, salad, and drinks for 4.',
                    price: '₹1999',
                    image: '/Uploads/combo.jpg'
                }
            ];
            for (const offer of initialOffers) {
                await pool.query(
                    'INSERT INTO special_offers (name, description, price, image) VALUES ($1, $2, $3, $4)',
                    [offer.name, offer.description, offer.price, offer.image]
                );
            }
            console.log('Seeded special offers');
        }

        // Seed customers
        const customerCount = await pool.query('SELECT COUNT(*) FROM customers');
        if (parseInt(customerCount.rows[0].count) === 0) {
            const initialCustomers = [
                { name: 'John Doe', email: 'john.doe@example.com', phone: '9876543210' },
                { name: 'Jane Smith', email: 'jane.smith@example.com', phone: '9123456789' }
            ];
            for (const customer of initialCustomers) {
                await pool.query(
                    'INSERT INTO customers (name, email, phone) VALUES ($1, $2, $3)',
                    [customer.name, customer.email, customer.phone]
                );
            }
            console.log('Seeded customers');
        }
    } catch (error) {
        console.error('Error initializing database:', error.message, error.stack);
        throw error;
    }
}

// Razorpay Instance
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Nodemailer Transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Health Check Endpoint
app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT NOW()');
        res.json({ status: 'ok', database: 'connected' });
    } catch (error) {
        console.error('Health check error:', error.message, error.stack);
        res.status(500).json({ message: 'Database connection failed' });
    }
});

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
    const { name, email, phone, password, role } = req.body;
    const userRole = role === 'admin' ? 'admin' : 'user';
    try {
        if (!email || !password || !name) {
            return res.status(400).json({ message: 'Name, email, and password are required' });
        }
        const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userExists.rows.length > 0) {
            return res.status(400).json({ message: 'User already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await pool.query(
            'INSERT INTO users (email, password, name, phone, role, profile_image) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, name, phone, role, profile_image',
            [email, hashedPassword, name, phone || null, userRole, null]
        );
        const token = jwt.sign({ id: newUser.rows[0].id, email: newUser.rows[0].email, role: newUser.rows[0].role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(201).json({ token, user: newUser.rows[0] });
    } catch (error) {
        console.error('Register Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }
        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userResult.rows.length === 0) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const user = userResult.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, user: { id: user.id, email: user.email, name: user.name, phone: user.phone, role: user.role, profile_image: user.profile_image } });
    } catch (error) {
        console.error('Login Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/api/auth/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
    const token = jwt.sign({ id: req.user.id, email: req.user.email, role: req.user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}/admindashboard.html?token=${token}`);
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const user = await pool.query('SELECT id, email, name, phone, role, profile_image FROM users WHERE id = $1', [req.user.id]);
        if (user.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user.rows[0]);
    } catch (error) {
        console.error('Get Profile Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.put('/api/auth/update', authenticateToken, upload.single('profileImage'), async (req, res) => {
    const { name, phone } = req.body;
    const profileImage = req.file ? `/uploads/${req.file.filename}` : null;
    try {
        if (!name || !phone) {
            return res.status(400).json({ message: 'Name and phone are required' });
        }
        const updateFields = [name.trim(), phone.trim()];
        let query = 'UPDATE users SET name = $1, phone = $2';
        let paramsIndex = 3;
        if (profileImage) {
            query += `, profile_image = $${paramsIndex++}`;
            updateFields.push(profileImage);
        }
        query += ` WHERE id = $${paramsIndex} RETURNING id, email, name, phone, role, profile_image`;
        updateFields.push(req.user.id);
        const updatedUser = await pool.query(query, updateFields);
        if (updatedUser.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(updatedUser.rows[0]);
    } catch (error) {
        console.error('Update Profile Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        if (!email) {
            return res.status(400).json({ message: 'Email is required' });
        }
        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userResult.rows.length === 0) {
            return res.status(400).json({ message: 'User not found' });
        }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
        await pool.query(
            'INSERT INTO otps (email, otp, expires_at) VALUES ($1, $2, $3)',
            [email, otp, expiresAt]
        );
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Delicute Password Reset OTP',
            text: `Your OTP for password reset is ${otp}. It is valid for 10 minutes.`
        });
        res.json({ message: 'OTP sent to email' });
    } catch (error) {
        console.error('Forgot Password Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    try {
        if (!email || !otp) {
            return res.status(400).json({ message: 'Email and OTP are required' });
        }
        const otpResult = await pool.query(
            'SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires_at > NOW()',
            [email, otp]
        );
        if (otpResult.rows.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired OTP' });
        }
        await pool.query('DELETE FROM otps WHERE email = $1', [email]);
        res.json({ message: 'OTP verified' });
    } catch (error) {
        console.error('Verify OTP Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'UPDATE users SET password = $1 WHERE email = $2 RETURNING id, email, name, phone, role, profile_image',
            [hashedPassword, email]
        );
        if (result.rows.length === 0) {
            return res.status(400).json({ message: 'User not found' });
        }
        res.json({ message: 'Password reset successful' });
    } catch (error) {
        console.error('Reset Password Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Menu Routes
app.get('/api/menu', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM menu_items ORDER BY id');
        res.json(result.rows);
    } catch (error) {
        console.error('Get Menu Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.post('/api/menu', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
    const { name, description, price } = req.body;
    const image = req.file ? `/uploads/${req.file.filename}` : null;
    try {
        if (!name || !price) {
            return res.status(400).json({ message: 'Name and price are required' });
        }
        if (typeof name !== 'string' || name.trim() === '') {
            return res.status(400).json({ message: 'Invalid name' });
        }
        if (typeof price !== 'string' || !price.startsWith('₹') || isNaN(parseFloat(price.slice(1)))) {
            return res.status(400).json({ message: 'Invalid price format' });
        }
        const newItem = await pool.query(
            'INSERT INTO menu_items (name, description, price, image) VALUES ($1, $2, $3, $4) RETURNING *',
            [name.trim(), description ? description.trim() : null, price.trim(), image]
        );
        res.status(201).json(newItem.rows[0]);
    } catch (error) {
        console.error('POST /api/menu Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.put('/api/menu/:id', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
    const { id } = req.params;
    const { name, description, price } = req.body;
    const image = req.file ? `/uploads/${req.file.filename}` : null;
    try {
        if (!name || !price) {
            return res.status(400).json({ message: 'Name and price are required' });
        }
        if (typeof name !== 'string' || name.trim() === '') {
            return res.status(400).json({ message: 'Invalid name' });
        }
        if (typeof price !== 'string' || !price.startsWith('₹') || isNaN(parseFloat(price.slice(1)))) {
            return res.status(400).json({ message: 'Invalid price format' });
        }
        const existingItem = await pool.query('SELECT * FROM menu_items WHERE id = $1', [id]);
        if (existingItem.rows.length === 0) {
            return res.status(404).json({ message: 'Menu item not found' });
        }
        const updateFields = [name.trim(), description ? description.trim() : null, price.trim()];
        let query = 'UPDATE menu_items SET name = $1, description = $2, price = $3';
        let paramsIndex = 4;
        if (image) {
            query += `, image = $${paramsIndex++}`;
            updateFields.push(image);
        }
        query += ` WHERE id = $${paramsIndex} RETURNING *`;
        updateFields.push(id);
        const updatedItem = await pool.query(query, updateFields);
        res.json(updatedItem.rows[0]);
    } catch (error) {
        console.error('PUT /api/menu/:id Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.delete('/api/menu/:id', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM menu_items WHERE id = $1 RETURNING *', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Menu item not found' });
        }
        if (result.rows[0].image) {
            const imagePath = path.join(__dirname, result.rows[0].image);
            if (fs.existsSync(imagePath)) {
                fs.unlinkSync(imagePath);
            }
        }
        res.json({ message: 'Menu item deleted' });
    } catch (error) {
        console.error('Delete Menu Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Special Offers Routes
app.get('/api/special-offers', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM special_offers ORDER BY id');
        res.json(result.rows);
    } catch (error) {
        console.error('Get Offers Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.post('/api/special-offers', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
    const { name, description, price } = req.body;
    const image = req.file ? `/uploads/${req.file.filename}` : null;
    try {
        if (!name || !price) {
            return res.status(400).json({ message: 'Name and price are required' });
        }
        if (typeof name !== 'string' || name.trim() === '') {
            return res.status(400).json({ message: 'Invalid name' });
        }
        if (typeof price !== 'string' || !price.startsWith('₹') || isNaN(parseFloat(price.slice(1)))) {
            return res.status(400).json({ message: 'Invalid price format' });
        }
        const newOffer = await pool.query(
            'INSERT INTO special_offers (name, description, price, image) VALUES ($1, $2, $3, $4) RETURNING *',
            [name.trim(), description ? description.trim() : null, price.trim(), image]
        );
        res.status(201).json(newOffer.rows[0]);
    } catch (error) {
        console.error('POST /api/special-offers Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.put('/api/special-offers/:id', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
    const { id } = req.params;
    const { name, description, price } = req.body;
    const image = req.file ? `/uploads/${req.file.filename}` : null;
    try {
        if (!name || !price) {
            return res.status(400).json({ message: 'Name and price are required' });
        }
        if (typeof name !== 'string' || name.trim() === '') {
            return res.status(400).json({ message: 'Invalid name' });
        }
        if (typeof price !== 'string' || !price.startsWith('₹') || isNaN(parseFloat(price.slice(1)))) {
            return res.status(400).json({ message: 'Invalid price format' });
        }
        const existingOffer = await pool.query('SELECT * FROM special_offers WHERE id = $1', [id]);
        if (existingOffer.rows.length === 0) {
            return res.status(404).json({ message: 'Offer not found' });
        }
        const updateFields = [name.trim(), description ? description.trim() : null, price.trim()];
        let query = 'UPDATE special_offers SET name = $1, description = $2, price = $3';
        let paramsIndex = 4;
        if (image) {
            query += `, image = $${paramsIndex++}`;
            updateFields.push(image);
            if (existingOffer.rows[0].image) {
                const imagePath = path.join(__dirname, existingOffer.rows[0].image);
                if (fs.existsSync(imagePath)) {
                    fs.unlinkSync(imagePath);
                }
            }
        }
        query += ` WHERE id = $${paramsIndex} RETURNING *`;
        updateFields.push(id);
        const updatedOffer = await pool.query(query, updateFields);
        res.json(updatedOffer.rows[0]);
    } catch (error) {
        console.error('PUT /api/special-offers/:id Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.delete('/api/special-offers/:id', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM special_offers WHERE id = $1 RETURNING *', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Offer not found' });
        }
        if (result.rows[0].image) {
            const imagePath = path.join(__dirname, result.rows[0].image);
            if (fs.existsSync(imagePath)) {
                fs.unlinkSync(imagePath);
            }
        }
        res.json({ message: 'Offer deleted' });
    } catch (error) {
        console.error('Delete Offer Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Customers Routes
app.get('/api/customers', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM customers ORDER BY id');
        res.json(result.rows);
    } catch (error) {
        console.error('Get Customers Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Orders Routes
app.get('/api/orders', authenticateToken, isAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, customer_name, total_amount, status, created_at FROM orders ORDER BY created_at DESC');
        res.json(result.rows.map(order => ({
            id: order.id,
            customerName: order.customer_name,
            total: parseFloat(order.total_amount.replace('₹', '')),
            status: order.status
        })));
    } catch (error) {
        console.error('Get Orders Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.put('/api/orders/:id', authenticateToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    try {
        if (!['Pending', 'Processing', 'Delivered', 'Cancelled'].includes(status)) {
            return res.status(400).json({ message: 'Invalid status' });
        }
        const updatedOrder = await pool.query(
            'UPDATE orders SET status = $1 WHERE id = $2 RETURNING id, customer_name, total_amount, status',
            [status, id]
        );
        if (updatedOrder.rows.length === 0) {
            return res.status(404).json({ message: 'Order not found' });
        }
        res.json({
            id: updatedOrder.rows[0].id,
            customerName: updatedOrder.rows[0].customer_name,
            total: parseFloat(updatedOrder.rows[0].total_amount.replace('₹', '')),
            status: updatedOrder.rows[0].status
        });
    } catch (error) {
        console.error('Update Order Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.post('/api/orders', authenticateToken, async (req, res) => {
    const { items, total_amount, customer_name } = req.body;
    try {
        if (!items || !total_amount || !customer_name || !Array.isArray(items)) {
            return res.status(400).json({ message: 'Items, total_amount, and customer_name are required' });
        }
        const newOrder = await pool.query(
            'INSERT INTO orders (user_id, customer_name, items, total_amount) VALUES ($1, $2, $3, $4) RETURNING *',
            [req.user.id, customer_name, JSON.stringify(items), total_amount]
        );
        res.status(201).json({
            id: newOrder.rows[0].id,
            customerName: newOrder.rows[0].customer_name,
            total: parseFloat(newOrder.rows[0].total_amount.replace('₹', '')),
            status: newOrder.rows[0].status
        });
    } catch (error) {
        console.error('Create Order Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Dashboard Stats
app.get('/api/dashboard/stats', authenticateToken, isAdmin, async (req, res) => {
    try {
        const totalOrders = await pool.query('SELECT COUNT(*) FROM orders');
        const totalCustomers = await pool.query('SELECT COUNT(*) FROM customers');
        const totalRevenue = await pool.query('SELECT SUM(CAST(REPLACE(total_amount, \'₹\', \'\') AS NUMERIC)) as total FROM orders WHERE status = $1', ['Delivered']);
        const recentOrders = await pool.query('SELECT id, customer_name, status FROM orders ORDER BY created_at DESC LIMIT 5');
        res.json({
            totalOrders: parseInt(totalOrders.rows[0].count),
            totalCustomers: parseInt(totalCustomers.rows[0].count),
            totalRevenue: parseFloat(totalRevenue.rows[0].total || 0),
            recentOrders: recentOrders.rows.map(order => ({
                id: order.id,
                customerName: order.customer_name,
                status: order.status
            }))
        });
    } catch (error) {
        console.error('Get Dashboard Stats Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Payment Routes
app.post('/api/payments/create-order', authenticateToken, async (req, res) => {
    const { amount } = req.body;
    try {
        if (!amount || isNaN(parseFloat(amount))) {
            return res.status(400).json({ message: 'Valid amount is required' });
        }
        const order = await razorpay.orders.create({
            amount: parseInt(amount * 100),
            currency: 'INR',
            receipt: `receipt_${Date.now()}`
        });
        await pool.query(
            'UPDATE orders SET razorpay_order_id = $1 WHERE id = (SELECT MAX(id) FROM orders WHERE user_id = $2)',
            [order.id, req.user.id]
        );
        res.json({ orderId: order.id, key: process.env.RAZORPAY_KEY_ID });
    } catch (error) {
        console.error('Create Payment Order Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

app.post('/api/payments/verify', authenticateToken, async (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    try {
        if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
            return res.status(400).json({ message: 'Missing payment details' });
        }
        const body = razorpay_order_id + '|' + razorpay_payment_id;
        const expectedSignature = crypto
            .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(body)
            .digest('hex');
        if (expectedSignature === razorpay_signature) {
            await pool.query(
                'UPDATE orders SET status = $1 WHERE razorpay_order_id = $2',
                ['Delivered', razorpay_order_id]
            );
            res.json({ message: 'Payment verified' });
        } else {
            return res.status(400).json({ message: 'Invalid signature' });
        }
    } catch (error) {
        console.error('Verify Payment Error:', error.message, error.stack);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Serve Frontend Pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admindashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admindashboard.html'));
});

app.get('/userdashboard.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'userdashboard.html'));
});

app.get('/forgot-password.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
const PORT = process.env.PORT || 3000;
async function startServer() {
    try {
        await testDbConnection();
        await checkAndUpdateSchema();
        await initializeDatabase();
        app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
    } catch (error) {
        console.error('Failed to start server:', error.message, error.stack);
        process.exit(1);
    }
}

startServer();