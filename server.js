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
app.use('/Uploads', express.static(path.join(__dirname, 'Uploads')));
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
    let user;
    if (userResult.rows.length > 0) {
      user = userResult.rows[0];
    } else {
      userResult = await pool.query('SELECT * FROM users WHERE email = $1', [profile.emails[0].value]);
      if (userResult.rows.length > 0) {
        user = await pool.query(
          'UPDATE users SET google_id = $1 WHERE email = $2 RETURNING *',
          [profile.id, profile.emails[0].value]
        ).then(res => res.rows[0]);
      } else {
        user = await pool.query(
          'INSERT INTO users (email, name, google_id, role, profile_image) VALUES ($1, $2, $3, $4, $5) RETURNING *',
          [profile.emails[0].value, profile.displayName, profile.id, 'user', null]
        ).then(res => res.rows[0]);
      }
    }
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    user.token = token;
    return done(null, user);
  } catch (error) {
    console.error('Google OAuth Error:', error.message);
    return done(error);
  }
}));

// Database Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 5000,
  max: 20
});

// Enhanced Error Logging for Pool
pool.on('error', (err) => {
  console.error('Unexpected error on idle client:', {
    message: err.message,
    code: err.code,
    stack: err.stack
  });
});
pool.on('connect', () => {
  console.log('Pool connected to database');
});

// Test Database Connection
async function testDbConnection() {
  let client;
  try {
    client = await pool.connect();
    console.log('Database connected successfully');
    const result = await client.query('SELECT NOW()');
    console.log('Database time:', result.rows[0].now);
  } catch (error) {
    console.error('Database connection error:', {
      message: error.message,
      code: error.code,
      detail: error.detail,
      connectionString: process.env.DATABASE_URL ? process.env.DATABASE_URL.replace(/:([^:@]+)@/, ':****@') : 'undefined',
      stack: error.stack
    });
    throw error;
  } finally {
    if (client) {
      client.release();
    }
  }
}

// Initialize and Update Database Schema
async function initializeAndUpdateDatabase() {
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

      CREATE TABLE IF NOT EXISTS menu_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL
      );

      CREATE TABLE IF NOT EXISTS menu_items (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        category_id INTEGER REFERENCES menu_categories(id),
        price VARCHAR(20) NOT NULL,
        image TEXT,
        image_url TEXT,
        is_available BOOLEAN DEFAULT TRUE
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
        delivery_address TEXT,
        payment_status VARCHAR(50) DEFAULT 'Pending',
        delivery_personnel_id INTEGER,
        cancel_reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        coupon_code VARCHAR(50),
        coupon_type VARCHAR(20),
        coupon_value NUMERIC,
        discount_amount VARCHAR(20)
      );

      CREATE TABLE IF NOT EXISTS otps (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        otp VARCHAR(6) NOT NULL,
        expires_at TIMESTAMP NOT NULL
      );

      CREATE TABLE IF NOT EXISTS customer_queries (
        id SERIAL PRIMARY KEY,
        customer_id INTEGER REFERENCES customers(id),
        name VARCHAR(255) NOT NULL,
        query_text TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'Open',
        response_text TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS refunds (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id),
        customer_name VARCHAR(255) NOT NULL,
        amount VARCHAR(20) NOT NULL,
        reason TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'Pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS business_settings (
        id SERIAL PRIMARY KEY,
        restaurant_name VARCHAR(255) NOT NULL,
        contact_email VARCHAR(255) NOT NULL,
        contact_phone VARCHAR(20) NOT NULL,
        opening_hours JSONB NOT NULL,
        logo TEXT
      );

      CREATE TABLE IF NOT EXISTS delivery_personnel (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        phone VARCHAR(20) NOT NULL
      );

      CREATE TABLE IF NOT EXISTS coupons (
        id SERIAL PRIMARY KEY,
        code VARCHAR(50) UNIQUE NOT NULL,
        type VARCHAR(20) NOT NULL,
        value NUMERIC NOT NULL,
        valid_from TIMESTAMP NOT NULL,
        valid_until TIMESTAMP NOT NULL,
        image TEXT
      );
    `);
    console.log('Database tables created successfully');

    // Check and update schema
    console.log('Checking and updating database schema...');

    const profileImageCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'users' AND column_name = 'profile_image'
    `);
    if (profileImageCheck.rows.length === 0) {
      console.log('Adding profile_image column to users table...');
      await pool.query('ALTER TABLE users ADD COLUMN profile_image TEXT');
    }

    const customerNameCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'orders' AND column_name = 'customer_name'
    `);
    if (customerNameCheck.rows.length === 0) {
      console.log('Adding customer_name column to orders table...');
      await pool.query('ALTER TABLE orders ADD COLUMN customer_name VARCHAR(255) NOT NULL DEFAULT \'Unknown\'');
    }

    const imageUrlCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'menu_items' AND column_name = 'image_url'
    `);
    if (imageUrlCheck.rows.length === 0) {
      console.log('Adding image_url column to menu_items table...');
      await pool.query('ALTER TABLE menu_items ADD COLUMN image_url TEXT');
    }

    const categoryIdCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'menu_items' AND column_name = 'category_id'
    `);
    if (categoryIdCheck.rows.length === 0) {
      console.log('Adding category_id column to menu_items table...');
      await pool.query('ALTER TABLE menu_items ADD COLUMN category_id INTEGER REFERENCES menu_categories(id)');
    }

    const isAvailableCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'menu_items' AND column_name = 'is_available'
    `);
    if (isAvailableCheck.rows.length === 0) {
      console.log('Adding is_available column to menu_items table...');
      await pool.query('ALTER TABLE menu_items ADD COLUMN is_available BOOLEAN DEFAULT TRUE');
    }

    const deliveryAddressCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'orders' AND column_name = 'delivery_address'
    `);
    if (deliveryAddressCheck.rows.length === 0) {
      console.log('Adding delivery_address column to orders table...');
      await pool.query('ALTER TABLE orders ADD COLUMN delivery_address TEXT');
    }

    const paymentStatusCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'orders' AND column_name = 'payment_status'
    `);
    if (paymentStatusCheck.rows.length === 0) {
      console.log('Adding payment_status column to orders table...');
      await pool.query('ALTER TABLE orders ADD COLUMN payment_status VARCHAR(50) DEFAULT \'Pending\'');
    }

    const deliveryPersonnelIdCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'orders' AND column_name = 'delivery_personnel_id'
    `);
    if (deliveryPersonnelIdCheck.rows.length === 0) {
      console.log('Adding delivery_personnel_id column to orders table...');
      await pool.query('ALTER TABLE orders ADD COLUMN delivery_personnel_id INTEGER REFERENCES delivery_personnel(id)');
    }

    const cancelReasonCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'orders' AND column_name = 'cancel_reason'
    `);
    if (cancelReasonCheck.rows.length === 0) {
      console.log('Adding cancel_reason column to orders table...');
      await pool.query('ALTER TABLE orders ADD COLUMN cancel_reason TEXT');
    }

    const couponCodeCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'orders' AND column_name = 'coupon_code'
    `);
    if (couponCodeCheck.rows.length === 0) {
      console.log('Adding coupon_code column to orders table...');
      await pool.query('ALTER TABLE orders ADD COLUMN coupon_code VARCHAR(50)');
    }

    const couponTypeCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'orders' AND column_name = 'coupon_type'
    `);
    if (couponTypeCheck.rows.length === 0) {
      console.log('Adding coupon_type column to orders table...');
      await pool.query('ALTER TABLE orders ADD COLUMN coupon_type VARCHAR(20)');
    }

    const couponValueCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'orders' AND column_name = 'coupon_value'
    `);
    if (couponValueCheck.rows.length === 0) {
      console.log('Adding coupon_value column to orders table...');
      await pool.query('ALTER TABLE orders ADD COLUMN coupon_value NUMERIC');
    }

    const discountAmountCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'orders' AND column_name = 'discount_amount'
    `);
    if (discountAmountCheck.rows.length === 0) {
      console.log('Adding discount_amount column to orders table...');
      await pool.query('ALTER TABLE orders ADD COLUMN discount_amount VARCHAR(20)');
    }

    const refundCustomerNameCheck = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'refunds' AND column_name = 'customer_name'
    `);
    if (refundCustomerNameCheck.rows.length === 0) {
      console.log('Adding customer_name column to refunds table...');
      await pool.query('ALTER TABLE refunds ADD COLUMN customer_name VARCHAR(255) NOT NULL DEFAULT \'Unknown\'');
    }

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

    // Seed menu categories
    const categoryCount = await pool.query('SELECT COUNT(*) FROM menu_categories');
    if (parseInt(categoryCount.rows[0].count) === 0) {
      const initialCategories = [
        { name: 'Salads' },
        { name: 'Pizzas' },
        { name: 'Desserts' }
      ];
      for (const category of initialCategories) {
        await pool.query(
          'INSERT INTO menu_categories (name) VALUES ($1)',
          [category.name]
        );
      }
      console.log('Seeded menu categories');
    }

    // Seed menu items
    const menuCount = await pool.query('SELECT COUNT(*) FROM menu_items');
    if (parseInt(menuCount.rows[0].count) === 0) {
      const initialItems = [
        {
          name: 'Fresh Garden Salad',
          description: 'Crisp greens, cherry tomatoes, and a zesty dressing.',
          category_id: 1,
          price: '₹749',
          image: '/Uploads/salad.jpg',
          is_available: true
        },
        {
          name: 'Margherita Pizza',
          description: 'Classic pizza with fresh basil and mozzarella.',
          category_id: 2,
          price: '₹1099',
          image_url: 'https://example.com/pizza.jpg',
          is_available: true
        }
      ];
      for (const item of initialItems) {
        await pool.query(
          'INSERT INTO menu_items (name, description, category_id, price, image, image_url, is_available) VALUES ($1, $2, $3, $4, $5, $6, $7)',
          [item.name, item.description, item.category_id, item.price, item.image || null, item.image_url || null, item.is_available]
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

    // Seed delivery personnel
    const deliveryPersonnelCount = await pool.query('SELECT COUNT(*) FROM delivery_personnel');
    if (parseInt(deliveryPersonnelCount.rows[0].count) === 0) {
      const initialPersonnel = [
        { name: 'Mike Johnson', phone: '9988776655' },
        { name: 'Sarah Lee', phone: '9876541234' }
      ];
      for (const personnel of initialPersonnel) {
        await pool.query(
          'INSERT INTO delivery_personnel (name, phone) VALUES ($1, $2)',
          [personnel.name, personnel.phone]
        );
      }
      console.log('Seeded delivery personnel');
    }

    // Seed business settings
    const settingsCount = await pool.query('SELECT COUNT(*) FROM business_settings');
    if (parseInt(settingsCount.rows[0].count) === 0) {
      await pool.query(
        'INSERT INTO business_settings (restaurant_name, contact_email, contact_phone, opening_hours, logo) VALUES ($1, $2, $3, $4, $5)',
        [
          'Delicute Restaurant',
          'contact@delicute.com',
          '9876543210',
          JSON.stringify({ mon_fri: '9:00 AM - 10:00 PM', sat_sun: '10:00 AM - 11:00 PM' }),
          null
        ]
      );
      console.log('Seeded business settings');
    }

    // Seed coupons
    const couponCount = await pool.query('SELECT COUNT(*) FROM coupons');
    if (parseInt(couponCount.rows[0].count) === 0) {
      const initialCoupons = [
        {
          code: 'SAVE10',
          type: 'percentage',
          value: 10,
          valid_from: '2025-01-01T00:00:00Z',
          valid_until: '2025-12-31T23:59:59Z',
          image: '/Uploads/coupon_save10.jpg'
        },
        {
          code: 'FLAT200',
          type: 'fixed',
          value: 200,
          valid_from: '2025-01-01T00:00:00Z',
          valid_until: '2025-06-30T23:59:59Z',
          image: null
        }
      ];
      for (const coupon of initialCoupons) {
        await pool.query(
          'INSERT INTO coupons (code, type, value, valid_from, valid_until, image) VALUES ($1, $2, $3, $4, $5, $6)',
          [coupon.code, coupon.type, coupon.value, coupon.valid_from, coupon.valid_until, coupon.image]
        );
      }
      console.log('Seeded coupons');
    }

    console.log('Database initialization and schema update completed successfully');
  } catch (error) {
    console.error('Error initializing and updating database:', error.message, error.stack);
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

// Utility Functions
const generateOtp = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

const sendOtpEmail = async (email, otp) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Delicute Password Reset OTP',
    text: `Your OTP for password reset is: ${otp}. It is valid for 10 minutes.`
  };
  try {
    await transporter.sendMail(mailOptions);
    console.log(`OTP sent to ${email}`);
  } catch (error) {
    console.error('Error sending OTP email:', error.message);
    throw new Error('Failed to send OTP email');
  }
};

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

// Google Auth Routes
app.get('/api/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/api/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: '/' }),
  (req, res) => {
    try {
      const token = req.user.token;
      res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}?token=${token}`);
    } catch (error) {
      console.error('Google callback error:', error.message);
      res.status(500).json({ message: 'Authentication failed' });
    }
  }
);

// Forgot Password Routes
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: 'Valid email is required' });
    }
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    const otp = generateOtp();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    await pool.query('DELETE FROM otps WHERE email = $1', [email]);
    await pool.query(
      'INSERT INTO otps (email, otp, expires_at) VALUES ($1, $2, $3)',
      [email, otp, expiresAt]
    );
    await sendOtpEmail(email, otp);
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Forgot Password Error:', error.message, error.stack);
    res.status(500).json({ message: error.message || 'Server error' });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  try {
    if (!email || !otp || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({ message: 'Valid email and 6-digit OTP are required' });
    }
    const otpResult = await pool.query(
      'SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires_at > NOW()',
      [email, otp]
    );
    if (otpResult.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }
    await pool.query('DELETE FROM otps WHERE email = $1', [email]);
    res.json({ message: 'OTP verified successfully' });
  } catch (error) {
    console.error('Verify OTP Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: 'Valid email is required' });
    }
    if (!password || password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'UPDATE users SET password = $1 WHERE email = $2',
      [hashedPassword, email]
    );
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset Password Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  const { name, email, phone, password, role } = req.body;
  const userRole = role === 'admin' ? 'admin' : 'user';
  try {
    if (!email || !password || !name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: 'Valid name, email, and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
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
    const token = jwt.sign(
      { id: newUser.rows[0].id, email: newUser.rows[0].email, role: newUser.rows[0].role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.status(201).json({ token, user: newUser.rows[0] });
  } catch (error) {
    console.error('Register Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: 'Valid email and password are required' });
    }
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const user = userResult.rows[0];
    if (!user.password) {
      return res.status(401).json({ message: 'Please use Google login or reset your password' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role, profile_image: user.profile_image } });
  } catch (error) {
    console.error('Login Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

// Menu Categories Routes
app.get('/api/menu-categories', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM menu_categories ORDER BY id');
    res.json(result.rows);
  } catch (error) {
    console.error('Get Menu Categories Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/menu-categories', authenticateToken, isAdmin, async (req, res) => {
  const { name } = req.body;
  try {
    if (!name || typeof name !== 'string' || name.trim() === '') {
      return res.status(400).json({ message: 'Valid category name is required' });
    }
    const newCategory = await pool.query(
      'INSERT INTO menu_categories (name) VALUES ($1) RETURNING *',
      [name.trim()]
    );
    res.status(201).json(newCategory.rows[0]);
  } catch (error) {
    console.error('Create Menu Category Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

// Menu Routes
app.get('/api/menu', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM menu_items ORDER BY id');
    res.json(result.rows);
  } catch (error) {
    console.error('Get Menu Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/menu', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
  const { name, description, category_id, price, image_url, is_available } = req.body;
  const image = req.file ? `/Uploads/${req.file.filename}` : null;
  try {
    if (!name || !price || !category_id) {
      return res.status(400).json({ message: 'Name, price, and category are required' });
    }
    if (typeof name !== 'string' || name.trim() === '') {
      return res.status(400).json({ message: 'Invalid name' });
    }
    if (typeof price !== 'string' || !price.startsWith('₹') || isNaN(parseFloat(price.slice(1)))) {
      return res.status(400).json({ message: 'Invalid price format' });
    }
    if (!image && !image_url) {
      return res.status(400).json({ message: 'Image file or URL is required' });
    }
    const newItem = await pool.query(
      'INSERT INTO menu_items (name, description, category_id, price, image, image_url, is_available) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [
        name.trim(),
        description ? description.trim() : null,
        parseInt(category_id),
        price.trim(),
        image,
        image_url ? image_url.trim() : null,
        is_available === 'true' || is_available === true
      ]
    );
    res.status(201).json(newItem.rows[0]);
  } catch (error) {
    console.error('POST /api/menu Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/menu/:id', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { name, description, category_id, price, image_url, is_available } = req.body;
  const image = req.file ? `/Uploads/${req.file.filename}` : null;
  try {
    if (!name || !price || !category_id) {
      return res.status(400).json({ message: 'Name, price, and category are required' });
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
    const updateFields = [
      name.trim(),
      description ? description.trim() : null,
      parseInt(category_id),
      price.trim(),
      is_available === 'true' || is_available === true
    ];
    let query = 'UPDATE menu_items SET name = $1, description = $2, category_id = $3, price = $4, is_available = $5';
    let paramsIndex = 6;
    if (image) {
      query += `, image = $${paramsIndex++}`;
      updateFields.push(image);
      if (existingItem.rows[0].image) {
        const imagePath = path.join(__dirname, existingItem.rows[0].image);
        if (fs.existsSync(imagePath)) {
          fs.unlinkSync(imagePath);
        }
      }
    }
    if (image_url) {
      query += `, image_url = $${paramsIndex++}`;
      updateFields.push(image_url.trim());
    }
    query += ` WHERE id = $${paramsIndex} RETURNING *`;
    updateFields.push(id);
    const updatedItem = await pool.query(query, updateFields);
    res.json(updatedItem.rows[0]);
  } catch (error) {
    console.error('PUT /api/menu/:id Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/menu/:id/availability', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { is_available } = req.body;
  try {
    if (typeof is_available !== 'boolean') {
      return res.status(400).json({ message: 'Valid is_available boolean is required' });
    }
    const updatedItem = await pool.query(
      'UPDATE menu_items SET is_available = $1 WHERE id = $2 RETURNING *',
      [is_available, id]
    );
    if (updatedItem.rows.length === 0) {
      return res.status(404).json({ message: 'Menu item not found' });
    }
    res.json(updatedItem.rows[0]);
  } catch (error) {
    console.error('Update Menu Availability Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
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
    res.status(500).json({ message: 'Server error' });
  }
});

// Special Offers Routes
app.get('/api/special-offers', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM special_offers ORDER BY id');
    res.json(result.rows);
  } catch (error) {
    console.error('Get Offers Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/special-offers', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
  const { name, description, price } = req.body;
  const image = req.file ? `/Uploads/${req.file.filename}` : null;
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
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/special-offers/:id', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { name, description, price } = req.body;
  const image = req.file ? `/Uploads/${req.file.filename}` : null;
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
    res.status(500).json({ message: 'Server error' });
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
    res.status(500).json({ message: 'Server error' });
  }
});

// Customers Routes
app.get('/api/customers', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM customers ORDER BY id');
    res.json(result.rows);
  } catch (error) {
    console.error('Get Customers Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/customers/:id', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const customer = await pool.query('SELECT * FROM customers WHERE id = $1', [id]);
    if (customer.rows.length === 0) {
      return res.status(404).json({ message: 'Customer not found' });
    }
    res.json(customer.rows[0]);
  } catch (error) {
    console.error('Get Customer Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

// Orders Routes
app.get('/api/orders', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status, date, customer } = req.query;
    let query = 'SELECT id, customer_name, total_amount, status, created_at, coupon_code, discount_amount FROM orders';
    const conditions = [];
    const params = [];
    let paramIndex = 1;
    if (status) {
      conditions.push(`status = $${paramIndex++}`);
      params.push(status);
    }
    if (date) {
      conditions.push(`DATE(created_at) = $${paramIndex++}`);
      params.push(date);
    }
    if (customer) {
      conditions.push(`customer_name ILIKE $${paramIndex++}`);
      params.push(`%${customer}%`);
    }
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    query += ' ORDER BY created_at DESC';
    const result = await pool.query(query, params);
    res.json(result.rows.map(order => ({
      id: order.id,
      customerName: order.customer_name,
      total: parseFloat(order.total_amount.replace('₹', '')),
      status: order.status,
      coupon_code: order.coupon_code,
      discount_amount: order.discount_amount
    })));
  } catch (error) {
    console.error('Get Orders Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/orders/:id', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const order = await pool.query(
      'SELECT id, customer_name, items, total_amount, status, delivery_address, payment_status, delivery_personnel_id, cancel_reason, coupon_code, coupon_type, coupon_value, discount_amount FROM orders WHERE id = $1',
      [id]
    );
    if (order.rows.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }
    res.json({
      id: order.rows[0].id,
      customer_name: order.rows[0].customer_name,
      items: order.rows[0].items,
      total_amount: order.rows[0].total_amount,
      status: order.rows[0].status,
      delivery_address: order.rows[0].delivery_address,
      payment_status: order.rows[0].payment_status,
      delivery_personnel_id: order.rows[0].delivery_personnel_id,
      cancel_reason: order.rows[0].cancel_reason,
      coupon_code: order.rows[0].coupon_code,
      coupon_type: order.rows[0].coupon_type,
      coupon_value: order.rows[0].coupon_value,
      discount_amount: order.rows[0].discount_amount
    });
  } catch (error) {
    console.error('Get Order Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/orders/:id', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  try {
    if (!['Pending', 'Accepted', 'In Progress', 'Out for Delivery', 'Completed', 'Cancelled'].includes(status)) {
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
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/orders/:id/assign-delivery', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { delivery_personnel_id } = req.body;
  try {
    if (!delivery_personnel_id) {
      return res.status(400).json({ message: 'Delivery personnel ID is required' });
    }
    const updatedOrder = await pool.query(
      'UPDATE orders SET delivery_personnel_id = $1 WHERE id = $2 RETURNING id, customer_name, total_amount, status, delivery_personnel_id',
      [parseInt(delivery_personnel_id), id]
    );
    if (updatedOrder.rows.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }
    res.json({
      id: updatedOrder.rows[0].id,
      customerName: updatedOrder.rows[0].customer_name,
      total: parseFloat(updatedOrder.rows[0].total_amount.replace('₹', '')),
      status: updatedOrder.rows[0].status,
      delivery_personnel_id: updatedOrder.rows[0].delivery_personnel_id
    });
  } catch (error) {
    console.error('Assign Delivery Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/orders/:id/cancel', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { cancel_reason } = req.body;
  try {
    if (!cancel_reason) {
      return res.status(400).json({ message: 'Cancel reason is required' });
    }
    const updatedOrder = await pool.query(
      'UPDATE orders SET status = $1, cancel_reason = $2 WHERE id = $3 RETURNING id, customer_name, total_amount, status, cancel_reason',
      ['Cancelled', cancel_reason.trim(), id]
    );
    if (updatedOrder.rows.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }
    res.json({
      id: updatedOrder.rows[0].id,
      customerName: updatedOrder.rows[0].customer_name,
      total: parseFloat(updatedOrder.rows[0].total_amount.replace('₹', '')),
      status: updatedOrder.rows[0].status,
      cancel_reason: updatedOrder.rows[0].cancel_reason
    });
  } catch (error) {
    console.error('Cancel Order Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/orders', authenticateToken, async (req, res) => {
  const { items, total_amount, customer_name, delivery_address } = req.body;
  try {
    if (!items || !total_amount || !customer_name || !Array.isArray(items)) {
      return res.status(400).json({ message: 'Items, total_amount, and customer_name are required' });
    }
    const newOrder = await pool.query(
      'INSERT INTO orders (user_id, customer_name, items, total_amount, delivery_address) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.id, customer_name, JSON.stringify(items), total_amount, delivery_address || null]
    );
    res.status(201).json({
      id: newOrder.rows[0].id,
      customerName: newOrder.rows[0].customer_name,
      total: parseFloat(newOrder.rows[0].total_amount.replace('₹', '')),
      status: newOrder.rows[0].status
    });
  } catch (error) {
    console.error('Create Order Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

// Customer Queries Routes
app.get('/api/customer-queries', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, customer_id, name, query_text, status, response_text, created_at FROM customer_queries ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (error) {
    console.error('Get Customer Queries Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/customer-queries/:id/respond', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { response_text } = req.body;
  try {
    if (!response_text || typeof response_text !== 'string' || response_text.trim() === '') {
      return res.status(400).json({ message: 'Valid response text is required' });
    }
    const updatedQuery = await pool.query(
      'UPDATE customer_queries SET status = $1, response_text = $2 WHERE id = $3 RETURNING *',
      ['Responded', response_text.trim(), id]
    );
    if (updatedQuery.rows.length === 0) {
      return res.status(404).json({ message: 'Query not found' });
    }
    res.json(updatedQuery.rows[0]);
  } catch (error) {
    console.error('Respond to Query Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

// Refunds Routes
app.get('/api/refunds', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, order_id, customer_name, amount, reason, status, created_at FROM refunds ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (error) {
    console.error('Get Refunds Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

// Revenue Reports Routes
app.get('/api/revenue-reports', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT DATE(created_at) as date, SUM(CAST(REPLACE(total_amount, '₹', '') AS NUMERIC)) as total
      FROM orders
      WHERE status = 'Completed'
      GROUP BY DATE(created_at)
      ORDER BY DATE(created_at)
    `);
    res.json(result.rows.map(row => ({
      date: row.date,
      total: parseFloat(row.total)
    })));
  } catch (error) {
    console.error('Get Revenue Reports Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

// Business Settings Routes
app.get('/api/business-settings', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM business_settings LIMIT 1');
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Business settings not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Get Business Settings Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/business-settings', authenticateToken, isAdmin, upload.single('logo'), async (req, res) => {
  const { restaurant_name, contact_email, contact_phone, opening_hours } = req.body;
  const logo = req.file ? `/Uploads/${req.file.filename}` : null;
  try {
    if (!restaurant_name || !contact_email || !contact_phone || !opening_hours) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    let parsedOpeningHours;
    try {
      parsedOpeningHours = JSON.parse(opening_hours);
    } catch (e) {
      return res.status(400).json({ message: 'Invalid opening_hours JSON' });
    }
    const updateFields = [restaurant_name.trim(), contact_email.trim(), contact_phone.trim(), JSON.stringify(parsedOpeningHours)];
    let query = 'UPDATE business_settings SET restaurant_name = $1, contact_email = $2, contact_phone = $3, opening_hours = $4';
    let paramsIndex = 5;
    if (logo) {
      query += `, logo = $${paramsIndex++}`;
      updateFields.push(logo);
    }
    query += ' WHERE id = 1 RETURNING *';
    const updatedSettings = await pool.query(query, updateFields);
    if (updatedSettings.rows.length === 0) {
      const newSettings = await pool.query(
        'INSERT INTO business_settings (restaurant_name, contact_email, contact_phone, opening_hours, logo) VALUES ($1, $2, $3, $4, $5) RETURNING *',
        [restaurant_name.trim(), contact_email.trim(), contact_phone.trim(), JSON.stringify(parsedOpeningHours), logo]
      );
      return res.json(newSettings.rows[0]);
    }
    res.json(updatedSettings.rows[0]);
  } catch (error) {
    console.error('Update Business Settings Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delivery Personnel Routes
app.get('/api/delivery-personnel', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, phone FROM delivery_personnel ORDER BY id');
    res.json(result.rows);
  } catch (error) {
    console.error('Get Delivery Personnel Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

// Dashboard Stats
app.get('/api/dashboard/stats', authenticateToken, isAdmin, async (req, res) => {
  try {
    const totalOrders = await pool.query('SELECT COUNT(*) FROM orders');
    const totalCustomers = await pool.query('SELECT COUNT(*) FROM customers');
    const totalRevenue = await pool.query('SELECT SUM(CAST(REPLACE(total_amount, \'₹\', \'\') AS NUMERIC)) as total FROM orders WHERE status = $1', ['Completed']);
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
    res.status(500).json({ message: 'Server error' });
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
    res.status(500).json({ message: 'Server error' });
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
        'UPDATE orders SET status = $1, payment_status = $2 WHERE razorpay_order_id = $3',
        ['Completed', 'Paid', razorpay_order_id]
      );
      res.json({ message: 'Payment verified' });
    } else {
      return res.status(400).json({ message: 'Invalid signature' });
    }
  } catch (error) {
    console.error('Verify Payment Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

// Coupon Routes
app.get('/api/coupons', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, code, type, value, valid_from, valid_until, image FROM coupons ORDER BY id');
    res.json(result.rows);
  } catch (error) {
    console.error('Get Coupons Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/coupons', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
  const { code, type, value, valid_from, valid_until } = req.body;
  const image = req.file ? `/Uploads/${req.file.filename}` : null;
  try {
    if (!code || !type || !value || !valid_from || !valid_until) {
      return res.status(400).json({ message: 'Code, type, value, valid_from, and valid_until are required' });
    }
    if (typeof code !== 'string' || code.trim() === '') {
      return res.status(400).json({ message: 'Invalid coupon code' });
    }
    if (!['percentage', 'fixed'].includes(type)) {
      return res.status(400).json({ message: 'Type must be percentage or fixed' });
    }
    if (isNaN(parseFloat(value)) || parseFloat(value) <= 0) {
      return res.status(400).json({ message: 'Value must be a positive number' });
    }
    const validFromDate = new Date(valid_from);
    const validUntilDate = new Date(valid_until);
    if (isNaN(validFromDate) || isNaN(validUntilDate) || validFromDate >= validUntilDate) {
      return res.status(400).json({ message: 'Invalid date range' });
    }
    const newCoupon = await pool.query(
      'INSERT INTO coupons (code, type, value, valid_from, valid_until, image) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [code.trim().toUpperCase(), type, parseFloat(value), valid_from, valid_until, image]
    );
    res.status(201).json(newCoupon.rows[0]);
  } catch (error) {
    console.error('POST /api/coupons Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/coupons/:id', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { code, type, value, valid_from, valid_until } = req.body;
  const image = req.file ? `/Uploads/${req.file.filename}` : null;
  try {
    if (!code || !type || !value || !valid_from || !valid_until) {
      return res.status(400).json({ message: 'Code, type, value, valid_from, and valid_until are required' });
    }
    if (typeof code !== 'string' || code.trim() === '') {
      return res.status(400).json({ message: 'Invalid coupon code' });
    }
    if (!['percentage', 'fixed'].includes(type)) {
      return res.status(400).json({ message: 'Type must be percentage or fixed' });
    }
    if (isNaN(parseFloat(value)) || parseFloat(value) <= 0) {
      return res.status(400).json({ message: 'Value must be a positive number' });
    }
    const validFromDate = new Date(valid_from);
    const validUntilDate = new Date(valid_until);
    if (isNaN(validFromDate) || isNaN(validUntilDate) || validFromDate >= validUntilDate) {
      return res.status(400).json({ message: 'Invalid date range' });
    }
    const existingCoupon = await pool.query('SELECT * FROM coupons WHERE id = $1', [id]);
    if (existingCoupon.rows.length === 0) {
      return res.status(404).json({ message: 'Coupon not found' });
    }
    const updateFields = [
      code.trim().toUpperCase(),
      type,
      parseFloat(value),
      valid_from,
      valid_until
    ];
    let query = 'UPDATE coupons SET code = $1, type = $2, value = $3, valid_from = $4, valid_until = $5';
    let paramsIndex = 6;
    if (image) {
      query += `, image = $${paramsIndex++}`;
      updateFields.push(image);
      if (existingCoupon.rows[0].image) {
        const imagePath = path.join(__dirname, existingCoupon.rows[0].image);
        if (fs.existsSync(imagePath)) {
          fs.unlinkSync(imagePath);
        }
      }
    }
    query += ` WHERE id = $${paramsIndex} RETURNING *`;
    updateFields.push(id);
    const updatedCoupon = await pool.query(query, updateFields);
    res.json(updatedCoupon.rows[0]);
  } catch (error) {
    console.error('PUT /api/coupons/:id Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/coupons/:id', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM coupons WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Coupon not found' });
    }
    if (result.rows[0].image) {
      const imagePath = path.join(__dirname, result.rows[0].image);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }
    res.json({ message: 'Coupon deleted' });
  } catch (error) {
    console.error('Delete Coupon Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/orders/:id/apply-coupon', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { coupon_id } = req.body;
  try {
    if (!coupon_id) {
      return res.status(400).json({ message: 'Coupon ID is required' });
    }
    const coupon = await pool.query('SELECT * FROM coupons WHERE id = $1', [coupon_id]);
    if (coupon.rows.length === 0) {
      return res.status(404).json({ message: 'Coupon not found' });
    }
    const order = await pool.query('SELECT * FROM orders WHERE id = $1', [id]);
    if (order.rows.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }
    const couponData = coupon.rows[0];
    const currentDate = new Date();
    if (currentDate < new Date(couponData.valid_from) || currentDate > new Date(couponData.valid_until)) {
      return res.status(400).json({ message: 'Coupon is not valid at this time' });
    }
    let totalAmount = parseFloat(order.rows[0].total_amount.replace('₹', ''));
    let discountAmount = 0;
    if (couponData.type === 'percentage') {
      discountAmount = (couponData.value / 100) * totalAmount;
    } else if (couponData.type === 'fixed') {
      discountAmount = couponData.value;
    }
    if (discountAmount > totalAmount) {
      discountAmount = totalAmount;
    }
    const newTotalAmount = totalAmount - discountAmount;
    const updatedOrder = await pool.query(
      'UPDATE orders SET coupon_code = $1, coupon_type = $2, coupon_value = $3, discount_amount = $4, total_amount = $5 WHERE id = $6 RETURNING *',
      [
        couponData.code,
        couponData.type,
        couponData.value,
        `₹${discountAmount.toFixed(2)}`,
        `₹${newTotalAmount.toFixed(2)}`,
        id
      ]
    );
    res.json({
      id: updatedOrder.rows[0].id,
      customer_name: updatedOrder.rows[0].customer_name,
      total_amount: updatedOrder.rows[0].total_amount,
      coupon_code: updatedOrder.rows[0].coupon_code,
      coupon_type: updatedOrder.rows[0].coupon_type,
      coupon_value: updatedOrder.rows[0].coupon_value,
      discount_amount: updatedOrder.rows[0].discount_amount,
      status: updatedOrder.rows[0].status
    });
  } catch (error) {
    console.error('Apply Coupon Error:', error.message, error.stack);
    res.status(500).json({ message: 'Server error' });
  }
});

// Serve Frontend Pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Start Server
async function startServer() {
  try {
    if (!process.env.JWT_SECRET || !process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      throw new Error('Missing required environment variables');
    }
    await testDbConnection();
    await initializeAndUpdateDatabase();
    const port = process.env.PORT || 3000;
    app.listen(port, () => {
      console.log(`🚀 Server running on http://localhost:${port}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error.message, error.stack);
    process.exit(1);
  }
}

startServer();