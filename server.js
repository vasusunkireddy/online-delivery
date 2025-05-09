const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');
const path = require('path');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Logger Setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console()
  ]
});

// Validate Environment Variables
const requiredEnv = ['DATABASE_URL', 'GOOGLE_CLIENT_ID', 'JWT_SECRET', 'EMAIL_USER', 'EMAIL_PASS'];
requiredEnv.forEach(key => {
  if (!process.env[key]) {
    logger.error(`Missing required env variable: ${key}`);
    process.exit(1);
  }
});

// Middleware
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

app.use(cors({
  origin: ['http://localhost:3000'],
  credentials: true
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/user.html', (req, res) => {
  const filePath = path.join(__dirname, 'public/user.html');
  logger.info(`Serving user.html from: ${filePath}`);
  res.sendFile(filePath, (err) => {
    if (err) {
      logger.error(`Error serving user.html: ${err.message}`);
      res.status(404).json({ message: 'user.html not found' });
    }
  });
});

// Rate Limiting for OTP Requests
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many OTP requests, please try again later.'
});
app.use('/api/users/request-otp', otpLimiter);

// PostgreSQL Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000
});

pool.on('error', (err) => {
  logger.error('Unexpected error on idle PostgreSQL client:', err);
  setTimeout(() => pool.connect(), 1000);
});

// Google OAuth Client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Nodemailer Setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  port: 587,
  secure: false,
  tls: {
    rejectUnauthorized: false
  }
});

// Initialize Database
async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255),
        email VARCHAR(255) UNIQUE,
        phone VARCHAR(20),
        password VARCHAR(255),
        address TEXT,
        role VARCHAR(50) DEFAULT 'user'
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS otps (
        email VARCHAR(255) PRIMARY KEY,
        otp VARCHAR(6),
        expires_at TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS menu_items (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255),
        description TEXT,
        price DECIMAL(10,2),
        image TEXT,
        category VARCHAR(100),
        is_popular BOOLEAN DEFAULT FALSE
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS carts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        item_id INTEGER REFERENCES menu_items(id),
        quantity INTEGER
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS promotions (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255),
        description TEXT,
        code VARCHAR(50),
        discount DECIMAL(10,2),
        image TEXT
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        order_id VARCHAR(50),
        date TIMESTAMP,
        total DECIMAL(10,2),
        status VARCHAR(50),
        address_id INTEGER,
        payment_method VARCHAR(50)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS order_items (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id),
        item_id INTEGER REFERENCES menu_items(id),
        quantity INTEGER,
        price DECIMAL(10,2)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS favourites (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        item_id INTEGER REFERENCES menu_items(id)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS addresses (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        name VARCHAR(255),
        street TEXT,
        city VARCHAR(100),
        state VARCHAR(100),
        zip VARCHAR(20),
        mobile VARCHAR(20),
        is_default BOOLEAN DEFAULT FALSE
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS loyalty (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        points INTEGER DEFAULT 0
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS loyalty_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        action VARCHAR(255),
        points INTEGER,
        date TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS referrals (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        code VARCHAR(50),
        link TEXT
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS support_tickets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        subject VARCHAR(255),
        description TEXT,
        status VARCHAR(50),
        date TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS support_chat (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        sender VARCHAR(255),
        message TEXT,
        timestamp TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS faqs (
        id SERIAL PRIMARY KEY,
        question TEXT,
        answer TEXT
      );
    `);

    // Seed admin user
    const adminEmail = 'svasudevareddy18604@gmail.com';
    const adminPassword = 'vasudev';
    const hashedPassword = await bcrypt.hash(adminPassword, 10);
    await pool.query(`
      INSERT INTO users (name, email, password, role)
      SELECT 'Admin', $1, $2, 'admin'
      WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = $1)
    `, [adminEmail, hashedPassword]);

    // Seed default menu items
    const menuCount = await pool.query('SELECT COUNT(*) FROM menu_items');
    if (menuCount.rows[0].count == 0) {
      const defaultMenu = [
        {
          name: 'Margherita Pizza',
          description: 'Classic pizza with tomato and mozzarella',
          price: 250,
          image: 'https://images.unsplash.com/photo-1595854341625-f33eece6d2d4?ixlib=rb-4.0.3&auto=format&fit=crop&w=300&h=200&q=80',
          category: 'Vegetarian',
          is_popular: true
        },
        {
          name: 'Butter Chicken',
          description: 'Creamy tomato-based chicken curry',
          price: 350,
          image: 'https://images.unsplash.com/photo-1603894584373-5ac82b2ae398?ixlib=rb-4.0.3&auto=format&fit=crop&w=300&h=200&q=80',
          category: 'Non-Veg',
          is_popular: true
        },
        {
          name: 'Chocolate Lava Cake',
          description: 'Warm cake with molten chocolate center',
          price: 150,
          image: 'https://images.unsplash.com/photo-1617634667039-44e6a1004b2d?ixlib=rb-4.0.3&auto=format&fit=crop&w=300&h=200&q=80',
          category: 'Desserts',
          is_popular: false
        },
        {
          name: 'Paneer Tikka',
          description: 'Grilled paneer with spices',
          price: 280,
          image: 'https://images.unsplash.com/photo-1596797038530-2c107229654b?ixlib=rb-4.0.3&auto=format&fit=crop&w=300&h=200&q=80',
          category: 'Vegetarian',
          is_popular: false
        }
      ];
      for (const item of defaultMenu) {
        await pool.query(`
          INSERT INTO menu_items (name, description, price, image, category, is_popular)
          VALUES ($1, $2, $3, $4, $5, $6)
        `, [item.name, item.description, item.price, item.image, item.category, item.is_popular]);
      }
    }

    // Seed default promotion
    const promoCount = await pool.query('SELECT COUNT(*) FROM promotions');
    if (promoCount.rows[0].count == 0) {
      await pool.query(`
        INSERT INTO promotions (title, description, code, discount, image)
        VALUES ($1, $2, $3, $4, $5)
      `, [
        '20% Off First Order',
        'Use code FIRST20 for 20% off',
        'FIRST20',
        20,
        'https://images.unsplash.com/photo-1546069901-ba9599a7e63c?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&h=300&q=80'
      ]);
    }

    // Seed default FAQs
    const faqCount = await pool.query('SELECT COUNT(*) FROM faqs');
    if (faqCount.rows[0].count == 0) {
      const defaultFaqs = [
        { question: 'What are your delivery hours?', answer: 'We deliver from 10 AM to 10 PM daily.' },
        { question: 'Can I cancel my order?', answer: 'Yes, within 10 minutes of placing the order.' }
      ];
      for (const faq of defaultFaqs) {
        await pool.query(`
          INSERT INTO faqs (question, answer)
          VALUES ($1, $2)
        `, [faq.question, faq.answer]);
      }
    }

    logger.info('Database initialized successfully');
  } catch (err) {
    logger.error('Error initializing database:', err);
  }
}

// OTP Generation and Email Sending
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOTP(email, otp) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'DELICUTE OTP Verification',
    text: `Your OTP for DELICUTE is ${otp}. It is valid for 5 minutes.`
  };
  try {
    await transporter.sendMail(mailOptions);
    logger.info(`OTP sent to ${email}: ${otp}`);
  } catch (err) {
    logger.error('Error sending OTP:', err);
    throw new Error('Failed to send OTP');
  }
}

// Middleware to Verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Routes
app.get('/api/test-email', async (req, res) => {
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: 'test@example.com',
      subject: 'Test Email',
      text: 'This is a test email from DELICUTE.'
    });
    res.json({ message: 'Test email sent' });
  } catch (err) {
    logger.error('Test email error:', err);
    res.status(500).json({ message: 'Failed to send test email', error: err.message });
  }
});

// Login
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role || 'user' }, process.env.JWT_SECRET, { expiresIn: '1h' });
    logger.info(`User logged in: ${email}, Role: ${user.role || 'user'}`);
    res.json({ token });
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Signup
app.post('/api/users/signup', async (req, res) => {
  const { name, email, phone, password, address, otp } = req.body;
  if (!name || !email || !phone || !password || !address || !otp) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  try {
    // Validate OTP
    const otpResult = await pool.query(
      'SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires_at > NOW()',
      [email, otp]
    );
    if (otpResult.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    // Check if email exists
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    // Validate inputs
    if (name.length < 3) {
      return res.status(400).json({ message: 'Name must be at least 3 characters long' });
    }
    if (!/^\d{10}$/.test(phone)) {
      return res.status(400).json({ message: 'Phone number must be 10 digits' });
    }
    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters long' });
    }
    if (address.trim().length === 0) {
      return res.status(400).json({ message: 'Address cannot be empty' });
    }

    // Create user
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(`
      INSERT INTO users (name, email, phone, password, address, role)
      VALUES ($1, $2, $3, $4, $5, 'user') RETURNING id, email, role
    `, [name, email, phone, hashedPassword, address]);

    const user = result.rows[0];

    // Initialize loyalty points
    await pool.query('INSERT INTO loyalty (user_id, points) VALUES ($1, 0)', [user.id]);

    // Initialize referral
    const referralCode = `DEL${Math.floor(100 + Math.random() * 900)}`;
    const referralLink = `https://delicute.com/refer/${referralCode}`;
    await pool.query('INSERT INTO referrals (user_id, code, link) VALUES ($1, $2, $3)', [user.id, referralCode, referralLink]);

    // Delete OTP
    await pool.query('DELETE FROM otps WHERE email = $1', [email]);

    // Generate token
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    logger.info(`User signed up: ${email}`);
    res.json({ token });
  } catch (err) {
    logger.error('Signup error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Google Sign-In
app.post('/api/users/google', async (req, res) => {
  const { id_token } = req.body;
  if (!id_token) {
    return res.status(400).json({ message: 'ID token is required' });
  }
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: id_token,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const { email, name } = ticket.getPayload();
    let result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    let user = result.rows[0];
    if (!user) {
      const role = email === 'svasudevareddy18604@gmail.com' ? 'admin' : 'user';
      result = await pool.query(`
        INSERT INTO users (name, email, role) VALUES ($1, $2, $3) RETURNING id, email, role
      `, [name, email, role]);
      user = result.rows[0];
      await pool.query('INSERT INTO loyalty (user_id, points) VALUES ($1, 0)', [user.id]);
      const referralCode = `DEL${Math.floor(100 + Math.random() * 900)}`;
      const referralLink = `https://delicute.com/refer/${referralCode}`;
      await pool.query('INSERT INTO referrals (user_id, code, link) VALUES ($1, $2, $3)', [user.id, referralCode, referralLink]);
    }
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    logger.info(`Google Sign-In: ${email}, Role: ${user.role}`);
    res.json({ token });
  } catch (err) {
    logger.error('Google Sign-In error:', err);
    res.status(400).json({ message: `Google login failed: ${err.message}` });
  }
});

// Request OTP
app.post('/api/users/request-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }
  try {
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    await pool.query(`
      INSERT INTO otps (email, otp, expires_at)
      VALUES ($1, $2, $3)
      ON CONFLICT (email)
      DO UPDATE SET otp = $2, expires_at = $3
    `, [email, otp, expiresAt]);
    await sendOTP(email, otp);
    res.json({ message: 'OTP sent' });
  } catch (err) {
    logger.error('Request OTP error:', err);
    res.status(500).json({ message: 'Failed to send OTP' });
  }
});

// Reset Password
app.post('/api/users/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  try {
    const otpResult = await pool.query(
      'SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires_at > NOW()',
      [email, otp]
    );
    if (otpResult.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);
    await pool.query('DELETE FROM otps WHERE email = $1', [email]);
    res.json({ message: 'Password reset successful' });
  } catch (err) {
    logger.error('Reset password error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, phone, address FROM users WHERE id = $1', [req.user.id]);
    res.json(result.rows[0]);
  } catch (err) {
    logger.error('Get profile error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Profile
app.post('/api/profile', authenticateToken, async (req, res) => {
  const { name, phone, address } = req.body;
  try {
    await pool.query('UPDATE users SET name = $1, phone = $2, address = $3 WHERE id = $4', [name, phone, address, req.user.id]);
    res.json({ message: 'Profile updated' });
  } catch (err) {
    logger.error('Update profile error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Menu
app.get('/api/menu', async (req, res) => {
  const { search, category, price, query } = req.query;
  try {
    let sql = 'SELECT * FROM menu_items WHERE 1=1';
    const params = [];
    if (search || query) {
      sql += ' AND name ILIKE $' + (params.length + 1);
      params.push(`%${search || query}%`);
    }
    if (category && category !== 'all') {
      sql += ' AND category = $' + (params.length + 1);
      params.push(category);
    }
    if (price && price !== 'all') {
      const [min, max] = price.split('-').map(Number);
      sql += ` AND price >= $${params.length + 1}`;
      params.push(min);
      if (max) {
        sql += ` AND price <= $${params.length + 1}`;
        params.push(max);
      }
    }
    const result = await pool.query(sql, params);
    res.json(result.rows);
  } catch (err) {
    logger.error('Get menu error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add to Cart
app.post('/api/cart/add', authenticateToken, async (req, res) => {
  const { item } = req.body;
  const userId = req.user.id;
  if (!item || !item.id || !item.quantity) {
    return res.status(400).json({ message: 'Item ID and quantity are required' });
  }
  try {
    await pool.query(`
      INSERT INTO carts (user_id, item_id, quantity)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id, item_id)
      DO UPDATE SET quantity = carts.quantity + $3
    `, [userId, item.id, item.quantity]);
    res.json({ success: true });
  } catch (err) {
    logger.error('Add to cart error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Cart
app.post('/api/cart/update', authenticateToken, async (req, res) => {
  const { itemId, action } = req.body;
  const userId = req.user.id;
  if (!itemId || !action) {
    return res.status(400).json({ message: 'Item ID and action are required' });
  }
  try {
    const result = await pool.query('SELECT quantity FROM carts WHERE user_id = $1 AND item_id = $2', [userId, itemId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Item not found in cart' });
    }
    let quantity = result.rows[0].quantity;
    if (action === 'increase') quantity += 1;
    if (action === 'decrease' && quantity > 1) quantity -= 1;
    await pool.query('UPDATE carts SET quantity = $1 WHERE user_id = $2 AND item_id = $3', [quantity, userId, itemId]);
    res.json({ success: true });
  } catch (err) {
    logger.error('Update cart error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Remove from Cart
app.post('/api/cart/remove', authenticateToken, async (req, res) => {
  const { itemId } = req.body;
  const userId = req.user.id;
  if (!itemId) {
    return res.status(400).json({ message: 'Item ID is required' });
  }
  try {
    await pool.query('DELETE FROM carts WHERE user_id = $1 AND item_id = $2', [userId, itemId]);
    res.json({ success: true });
  } catch (err) {
    logger.error('Remove from cart error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Cart
app.get('/api/cart', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.item_id AS id, m.name, m.price, c.quantity
      FROM carts c
      JOIN menu_items m ON c.item_id = m.id
      WHERE c.user_id = $1
    `, [req.user.id]);
    res.json({ items: result.rows });
  } catch (err) {
    logger.error('Get cart error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Apply Coupon
app.post('/api/cart/apply-coupon', authenticateToken, async (req, res) => {
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ message: 'Coupon code is required' });
  }
  try {
    const result = await pool.query('SELECT * FROM promotions WHERE code = $1', [code]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid coupon' });
    }
    const promotion = result.rows[0];
    res.json({ success: true, discount: promotion.discount });
  } catch (err) {
    logger.error('Apply coupon error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Checkout
app.post('/api/cart/checkout', authenticateToken, async (req, res) => {
  const { addressId, paymentMethod } = req.body;
  const userId = req.user.id;
  if (!addressId || !paymentMethod) {
    return res.status(400).json({ message: 'Address ID and payment method are required' });
  }
  try {
    const cartResult = await pool.query(`
      SELECT c.item_id AS id, m.name, m.price, c.quantity
      FROM carts c
      JOIN menu_items m ON c.item_id = m.id
      WHERE c.user_id = $1
    `, [userId]);
    const items = cartResult.rows;
    if (!items.length) {
      return res.status(400).json({ message: 'Cart is empty' });
    }
    const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    const orderId = `ORD${Math.floor(Math.random() * 1000).toString().padStart(3, '0')}`;
    const orderResult = await pool.query(`
      INSERT INTO orders (user_id, order_id, date, total, status, address_id, payment_method)
      VALUES ($1, $2, NOW(), $3, 'Placed', $4, $5) RETURNING id
    `, [userId, orderId, total, addressId, paymentMethod]);
    const order = orderResult.rows[0];
    for (const item of items) {
      await pool.query(`
        INSERT INTO order_items (order_id, item_id, quantity, price)
        VALUES ($1, $2, $3, $4)
      `, [order.id, item.id, item.quantity, item.price]);
    }
    await pool.query('DELETE FROM carts WHERE user_id = $1', [userId]);
    await pool.query('UPDATE loyalty SET points = points + $1 WHERE user_id = $2', [Math.floor(total / 10), userId]);
    await pool.query(`
      INSERT INTO loyalty_history (user_id, action, points, date)
      VALUES ($1, 'Order placed', $2, NOW())
    `, [userId, Math.floor(total / 10)]);
    res.json({ success: true, order: { id: orderId, date: new Date(), total, status: 'Placed', items } });
  } catch (err) {
    logger.error('Checkout error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Orders
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const ordersResult = await pool.query('SELECT * FROM orders WHERE user_id = $1 ORDER BY date DESC', [req.user.id]);
    const orders = [];
    for (const order of ordersResult.rows) {
      const itemsResult = await pool.query(`
        SELECT oi.item_id AS id, m.name, oi.quantity, oi.price
        FROM order_items oi
        JOIN menu_items m ON oi.item_id = m.id
        WHERE oi.order_id = $1
      `, [order.id]);
      orders.push({ ...order, items: itemsResult.rows });
    }
    res.json(orders);
  } catch (err) {
    logger.error('Get orders error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Track Order
app.get('/api/orders/:orderId/track', authenticateToken, async (req, res) => {
  const { orderId } = req.params;
  try {
    const result = await pool.query('SELECT status FROM orders WHERE order_id = $1 AND user_id = $2', [orderId, req.user.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }
    res.json({ status: result.rows[0].status, deliveryPartner: { name: 'John Smith', contact: '+91 9876543210' } });
  } catch (err) {
    logger.error('Track order error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Reorder
app.post('/api/orders/:orderId/reorder', authenticateToken, async (req, res) => {
  const { orderId } = req.params;
  const userId = req.user.id;
  try {
    const orderResult = await pool.query('SELECT id FROM orders WHERE order_id = $1 AND user_id = $2', [orderId, userId]);
    if (orderResult.rows.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }
    const order = orderResult.rows[0];
    const itemsResult = await pool.query(`
      SELECT item_id, quantity
      FROM order_items
      WHERE order_id = $1
    `, [order.id]);
    for (const item of itemsResult.rows) {
      await pool.query(`
        INSERT INTO carts (user_id, item_id, quantity)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, item_id)
        DO UPDATE SET quantity = carts.quantity + $3
      `, [userId, item.item_id, item.quantity]);
    }
    res.json({ success: true });
  } catch (err) {
    logger.error('Reorder error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Rate Order
app.post('/api/orders/:orderId/rate', authenticateToken, async (req, res) => {
  const { orderId } = req.params;
  const { rating, comment } = req.body;
  if (!rating || !comment) {
    return res.status(400).json({ message: 'Rating and comment are required' });
  }
  try {
    const result = await pool.query('SELECT id FROM orders WHERE order_id = $1 AND user_id = $2', [orderId, req.user.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }
    // Note: You may want to add a ratings table to store rating and comment
    res.json({ success: true });
  } catch (err) {
    logger.error('Rate order error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Favourites
app.get('/api/favourites', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT m.*
      FROM favourites f
      JOIN menu_items m ON f.item_id = m.id
      WHERE f.user_id = $1
    `, [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    logger.error('Get favourites error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add to Favourites
app.post('/api/favourites/add', authenticateToken, async (req, res) => {
  const { itemId } = req.body;
  const userId = req.user.id;
  if (!itemId) {
    return res.status(400).json({ message: 'Item ID is required' });
  }
  try {
    await pool.query('INSERT INTO favourites (user_id, item_id) VALUES ($1, $2)', [userId, itemId]);
    res.json({ success: true });
  } catch (err) {
    logger.error('Add to favourites error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Remove from Favourites
app.post('/api/favourites/remove', authenticateToken, async (req, res) => {
  const { itemId } = req.body;
  const userId = req.user.id;
  if (!itemId) {
    return res.status(400).json({ message: 'Item ID is required' });
  }
  try {
    await pool.query('DELETE FROM favourites WHERE user_id = $1 AND item_id = $2', [userId, itemId]);
    res.json({ success: true });
  } catch (err) {
    logger.error('Remove from favourites error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Addresses
app.get('/api/addresses', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM addresses WHERE user_id = $1', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    logger.error('Get addresses error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add Address
app.post('/api/addresses/add', authenticateToken, async (req, res) => {
  const { name, street, city, state, zip, mobile, isDefault } = req.body;
  const userId = req.user.id;
  if (!name || !street || !city || !state || !zip || !mobile) {
    return res.status(400).json({ message: 'All address fields are required' });
  }
  try {
    if (isDefault) {
      await pool.query('UPDATE addresses SET is_default = FALSE WHERE user_id = $1', [userId]);
    }
    await pool.query(`
      INSERT INTO addresses (user_id, name, street, city, state, zip, mobile, is_default)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `, [userId, name, street, city, state, zip, mobile, isDefault || false]);
    res.json({ success: true });
  } catch (err) {
    logger.error('Add address error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Address
app.post('/api/addresses/update', authenticateToken, async (req, res) => {
  const { id, name, street, city, state, zip, mobile, isDefault } = req.body;
  const userId = req.user.id;
  if (!id || !name || !street || !city || !state || !zip || !mobile) {
    return res.status(400).json({ message: 'All address fields are required' });
  }
  try {
    if (isDefault) {
      await pool.query('UPDATE addresses SET is_default = FALSE WHERE user_id = $1', [userId]);
    }
    await pool.query(`
      UPDATE addresses
      SET name = $1, street = $2, city = $3, state = $4, zip = $5, mobile = $6, is_default = $7
      WHERE id = $8 AND user_id = $9
    `, [name, street, city, state, zip, mobile, isDefault || false, id, userId]);
    res.json({ success: true });
  } catch (err) {
    logger.error('Update address error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete Address
app.post('/api/addresses/delete', authenticateToken, async (req, res) => {
  const { id } = req.body;
  const userId = req.user.id;
  if (!id) {
    return res.status(400).json({ message: 'Address ID is required' });
  }
  try {
    await pool.query('DELETE FROM addresses WHERE id = $1 AND user_id = $2', [id, userId]);
    res.json({ success: true });
  } catch (err) {
    logger.error('Delete address error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Set Default Address
app.post('/api/addresses/set-default', authenticateToken, async (req, res) => {
  const { id } = req.body;
  const userId = req.user.id;
  if (!id) {
    return res.status(400).json({ message: 'Address ID is required' });
  }
  try {
    await pool.query('UPDATE addresses SET is_default = FALSE WHERE user_id = $1', [userId]);
    await pool.query('UPDATE addresses SET is_default = TRUE WHERE id = $1 AND user_id = $2', [id, userId]);
    res.json({ success: true });
  } catch (err) {
    logger.error('Set default address error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Loyalty
app.get('/api/loyalty', authenticateToken, async (req, res) => {
  try {
    const pointsResult = await pool.query('SELECT points FROM loyalty WHERE user_id = $1', [req.user.id]);
    const historyResult = await pool.query('SELECT action, points, date FROM loyalty_history WHERE user_id = $1 ORDER BY date DESC', [req.user.id]);
    res.json({
      points: pointsResult.rows[0]?.points || 0,
      history: historyResult.rows
    });
  } catch (err) {
    logger.error('Get loyalty error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Referral
app.get('/api/referral', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT code, link FROM referrals WHERE user_id = $1', [req.user.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Referral not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    logger.error('Get referral error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Support Tickets
app.get('/api/support/tickets', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, subject, status, date FROM support_tickets WHERE user_id = $1 ORDER BY date DESC', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    logger.error('Get support tickets error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create Support Ticket
app.post('/api/support/tickets', authenticateToken, async (req, res) => {
  const { subject, description } = req.body;
  const userId = req.user.id;
  if (!subject || !description) {
    return res.status(400).json({ message: 'Subject and description are required' });
  }
  try {
    await pool.query(`
      INSERT INTO support_tickets (user_id, subject, description, status, date)
      VALUES ($1, $2, $3, 'Open', NOW())
    `, [userId, subject, description]);
    res.json({ success: true });
  } catch (err) {
    logger.error('Create support ticket error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Support Chat
app.get('/api/support/chat', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT sender, message, timestamp
      FROM support_chat
      WHERE user_id = $1
      ORDER BY timestamp
    `, [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    logger.error('Get support chat error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Send Support Chat Message
app.post('/api/support/chat', authenticateToken, async (req, res) => {
  const { message } = req.body;
  const userId = req.user.id;
  if (!message) {
    return res.status(400).json({ message: 'Message is required' });
  }
  try {
    await pool.query(`
      INSERT INTO support_chat (user_id, sender, message, timestamp)
      VALUES ($1, $2, $3, NOW())
    `, [userId, req.user.email, message]);
    res.json({ success: true });
  } catch (err) {
    logger.error('Send support chat error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get FAQs
app.get('/api/faq', async (req, res) => {
  try {
    const result = await pool.query('SELECT question, answer FROM faqs');
    res.json(result.rows);
  } catch (err) {
    logger.error('Get FAQs error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Promotions
app.get('/api/offers', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, title, description, code, discount, image FROM promotions');
    res.json(result.rows);
  } catch (err) {
    logger.error('Get promotions error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Status
app.get('/api/status', async (req, res) => {
  res.json({ isOpen: true, prepTime: 30 });
});

// Get Cancellation Policy
app.get('/api/cancellation-policy', async (req, res) => {
  res.json({ text: 'Cancel within 10 mins for full refund' });
});

// Admin Routes
app.post('/api/admin/menu', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  const { name, description, price, image, category, is_popular } = req.body;
  if (!name || !price || !category) {
    return res.status(400).json({ message: 'Name, price, and category are required' });
  }
  try {
    await pool.query(`
      INSERT INTO menu_items (name, description, price, image, category, is_popular)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [name, description, price, image, category, is_popular || false]);
    res.json({ message: 'Menu item added' });
  } catch (err) {
    logger.error('Add menu item error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/admin/promotion', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  const { title, description, code, discount, image } = req.body;
  if (!title || !code || !discount) {
    return res.status(400).json({ message: 'Title, code, and discount are required' });
  }
  try {
    await pool.query(`
      INSERT INTO promotions (title, description, code, discount, image)
      VALUES ($1, $2, $3, $4, $5)
    `, [title, description, code, discount, image]);
    res.json({ message: 'Promotion added' });
  } catch (err) {
    logger.error('Add promotion error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Logout
app.post('/api/logout', authenticateToken, (req, res) => {
  // Client-side token removal is sufficient with JWT
  res.json({ success: true });
});

// Start Server
async function startServer() {
  try {
    await initDb();
    app.listen(port, () => {
      logger.info(`Server running at http://localhost:${port}`);
    });
  } catch (err) {
    logger.error('Failed to start server:', err);
    process.exit(1);
  }
}

startServer();
