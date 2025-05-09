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
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:8080', 'https://online-food-deliveryyy.onrender.com'],
  credentials: true
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Rate Limiting for OTP Requests
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 OTP requests per window
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

pool.on('error', (err, client) => {
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
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255),
        email VARCHAR(255) UNIQUE,
        phone VARCHAR(20),
        password VARCHAR(255),
        address TEXT,
        role VARCHAR(50) DEFAULT 'user' CHECK (role IN ('user', 'admin')),
        google_id VARCHAR(255) UNIQUE
      );
    `);

    // Create otps table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS otps (
        email VARCHAR(255) PRIMARY KEY,
        otp VARCHAR(6),
        expires_at TIMESTAMP
      );
    `);

    // Create other tables
    await pool.query(`
      CREATE TABLE IF NOT EXISTS menu_items (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255),
        description TEXT,
        price DECIMAL(10,2),
        image TEXT,
        category VARCHAR(100)
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
        discount DECIMAL(10,2)
      );
    `);

    // Seed default admin user
    const adminEmail = 'svasudevareddy18604@gmail.com';
    const adminPasswordHash = '$2b$10$GPO8fPVfncXr0SB.vF9vcuKOo4RKm3bzrXcm1dN2dzFWQSPz6Fony';
    await pool.query(`
      INSERT INTO users (name, email, password, role)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (email) DO UPDATE SET
        name = EXCLUDED.name,
        password = EXCLUDED.password,
        role = EXCLUDED.role
    `, ['Admin', adminEmail, adminPasswordHash, 'admin']);

    // Seed default menu items
    const menuCount = await pool.query('SELECT COUNT(*) FROM menu_items');
    if (menuCount.rows[0].count == 0) {
      const defaultMenu = [
        {
          name: 'Butter Chicken',
          description: 'Creamy tomato-based chicken curry',
          price: 12.99,
          image: 'https://images.unsplash.com/photo-1603894584373-5ac82b2ae398?q=80&w=200&auto=format&fit=crop',
          category: 'Non-Veg'
        },
        {
          name: 'Paneer Tikka',
          description: 'Grilled cottage cheese with spices',
          price: 10.99,
          image: 'https://images.unsplash.com/photo-1626500118719-b88a8f844e01?q=80&w=200&auto=format&fit=crop',
          category: 'Vegetarian'
        },
        {
          name: 'Gulab Jamun',
          description: 'Sweet milk-based dessert',
          price: 5.99,
          image: 'https://images.unsplash.com/photo-1622898791919-94e9210ed5e9?q=80&w=200&auto=format&fit=crop',
          category: 'Desserts'
        }
      ];
      for (const item of defaultMenu) {
        await pool.query(`
          INSERT INTO menu_items (name, description, price, image, category)
          VALUES ($1, $2, $3, $4, $5)
        `, [item.name, item.description, item.price, item.image, item.category]);
      }
    }

    // Seed default promotion
    const promoCount = await pool.query('SELECT COUNT(*) FROM promotions');
    if (promoCount.rows[0].count == 0) {
      await pool.query(`
        INSERT INTO promotions (title, description, code, discount)
        VALUES ('First Order Discount', 'Get ₹100 off your first order!', 'DELICUTE100', 100.00)
      `);
    }

    logger.info('Database initialized successfully');
  } catch (err) {
    logger.error('Error initializing database:', err);
    throw err;
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
// Test Email Route
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
      VALUES ($1, $2, $3, $4, $5, 'user')
      RETURNING id, email, role
    `, [name, email, phone, hashedPassword, address]);
    const user = result.rows[0];

    // Delete OTP
    await pool.query('DELETE FROM otps WHERE email = $1', [email]);

    // Generate token
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
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
    const { email, name, sub } = ticket.getPayload();
    let result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    let user = result.rows[0];
    if (!user) {
      const role = email === 'svasudevareddy18604@gmail.com' ? 'admin' : 'user';
      result = await pool.query(`
        INSERT INTO users (name, email, role, google_id)
        VALUES ($1, $2, $3, $4)
        RETURNING id, email, role
      `, [name, email, role, sub]);
      user = result.rows[0];
    } else if (!user.google_id) {
      await pool.query('UPDATE users SET google_id = $1 WHERE email = $2', [sub, email]);
      user.google_id = sub;
    }
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
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
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
    await pool.query(`
      INSERT INTO otps (email, otp, expires_at)
      VALUES ($1, $2, $3)
      ON CONFLICT (email)
      DO UPDATE SET otp = EXCLUDED.otp, expires_at = EXCLUDED.expires_at
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

// Get Menu
app.get('/api/menu', async (req, res) => {
  const { search, category } = req.query;
  try {
    let query = 'SELECT * FROM menu_items WHERE 1=1';
    const params = [];
    if (search) {
      query += ' AND name ILIKE $1';
      params.push(`%${search}%`);
    }
    if (category) {
      query += ` AND category = $${params.length + 1}`;
      params.push(category);
    }
    const result = await pool.query(query, params);
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
  if (!item || !item.id) {
    return res.status(400).json({ message: 'Item ID is required' });
  }
  try {
    await pool.query(`
      INSERT INTO carts (user_id, item_id, quantity)
      VALUES ($1, $2, 1)
      ON CONFLICT (user_id, item_id)
      DO UPDATE SET quantity = carts.quantity + 1
    `, [userId, item.id]);
    res.json({ message: 'Item added to cart' });
  } catch (err) {
    logger.error('Add to cart error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get Promotions
app.get('/api/promotions', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM promotions');
    res.json(result.rows);
  } catch (err) {
    logger.error('Get promotions error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin Routes
app.post('/api/admin/menu', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  const { name, description, price, image, category } = req.body;
  if (!name || !price || !category) {
    return res.status(400).json({ message: 'Name, price, and category are required' });
  }
  try {
    await pool.query(`
      INSERT INTO menu_items (name, description, price, image, category)
      VALUES ($1, $2, $3, $4, $5)
    `, [name, description, price, image, category]);
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
  const { title, description, code, discount } = req.body;
  if (!title || !code || !discount) {
    return res.status(400).json({ message: 'Title, code, and discount are required' });
  }
  try {
    await pool.query(`
      INSERT INTO promotions (title, description, code, discount)
      VALUES ($1, $2, $3, $4)
    `, [title, description, code, discount]);
    res.json({ message: 'Promotion added' });
  } catch (err) {
    logger.error('Add promotion error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Start Server
app.listen(port, async () => {
  try {
    await initDb();
    logger.info(`Server running at http://localhost:${port}`);
  } catch (err) {
    logger.error('Failed to start server:', err);
    process.exit(1);
  }
});