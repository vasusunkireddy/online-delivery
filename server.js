const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const cors = require('cors');
const http = require('http');
const { OAuth2Client } = require('google-auth-library');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();

// Google OAuth2 Client
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
if (!GOOGLE_CLIENT_ID) {
  console.error('GOOGLE_CLIENT_ID is not set in .env');
  process.exit(1);
}
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// PostgreSQL Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Required for Render PostgreSQL
});

// Middleware
const corsOptions = {
  origin: ['https://delicute.onrender.com', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());
app.use(express.static('public'));

// Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} ${JSON.stringify(req.body)}`);
  next();
});

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Authentication middleware
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ message: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Token verification failed:', err.message);
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// Generate OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Initialize database (seed admin user)
async function initializeDatabase() {
  try {
    const adminEmail = 'svasudevareddy18604@gmail.com';
    const adminPassword = 'vasudev';
    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    const client = await pool.connect();
    const userExists = await client.query('SELECT * FROM users WHERE email = $1', [adminEmail]);
    if (userExists.rows.length === 0) {
      await client.query(
        'INSERT INTO users (name, email, phone, password, address, role) VALUES ($1, $2, $3, $4, $5, $6)',
        ['Admin', adminEmail, '1234567890', hashedPassword, 'Admin Address', 'admin']
      );
      console.log('Admin user seeded');
    }
    client.release();
  } catch (err) {
    console.error('Database initialization error:', err.message);
    throw err;
  }
}

// Routes

// Request OTP
app.post('/api/users/request-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    console.log('No email provided');
    return res.status(400).json({ message: 'Email required' });
  }

  const otp = generateOTP();
  const expires = new Date(Date.now() + 5 * 60 * 1000); // 5-minute expiry

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'DELICUTE OTP Verification',
    text: `Your OTP is ${otp}. Valid for 5 minutes.`,
  };

  try {
    const client = await pool.connect();
    await client.query(
      'INSERT INTO otps (email, otp, expires) VALUES ($1, $2, $3) ON CONFLICT (email) DO UPDATE SET otp = $2, expires = $3',
      [email, otp, expires]
    );
    client.release();

    await transporter.sendMail(mailOptions);
    console.log(`OTP sent to ${email}`);
    res.json({ message: 'OTP sent' });
  } catch (err) {
    console.error('Email or database error:', err.message);
    res.status(500).json({ message: 'Failed to send OTP' });
  }
});

// Signup
app.post('/api/users/signup', async (req, res) => {
  const { name, email, phone, password, address, otp } = req.body;
  console.log(`Signup attempt: ${email}, OTP: ${otp}`);

  try {
    const client = await pool.connect();
    const otpRecord = await client.query('SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires > NOW()', [email, otp]);
    if (otpRecord.rows.length === 0) {
      client.release();
      console.log(`Invalid or expired OTP for ${email}`);
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const userExists = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      client.release();
      console.log(`User already exists: ${email}`);
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await client.query(
      'INSERT INTO users (name, email, phone, password, address, role) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, role',
      [name, email, phone, hashedPassword, address, 'user']
    );
    const user = result.rows[0];

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    await client.query('DELETE FROM otps WHERE email = $1', [email]);
    client.release();

    console.log(`Signup successful: ${email}`);
    res.status(201).json({ token });
  } catch (err) {
    console.error('Signup error:', err.message);
    res.status(500).json({ message: 'Signup failed' });
  }
});

// Login
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  console.log(`Login attempt: ${email}`);

  try {
    const client = await pool.connect();
    const result = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    client.release();

    if (!user || !(await bcrypt.compare(password, user.password))) {
      console.log(`Invalid credentials for ${email}`);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    console.log(`Login successful: ${email}`);
    res.json({ token });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ message: 'Login failed' });
  }
});

// Google Login
app.post('/api/users/google', async (req, res) => {
  const { id_token } = req.body;
  console.log('Google login attempt');

  if (!id_token) {
    console.log('No id_token provided');
    return res.status(400).json({ message: 'id_token required' });
  }

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: id_token,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { email, name, sub: google_id } = payload;

    const client = await pool.connect();
    let user = (await client.query('SELECT * FROM users WHERE email = $1', [email])).rows[0];

    if (!user) {
      const hashedPassword = await bcrypt.hash('google_dummy_' + Math.random(), 10);
      const result = await client.query(
        'INSERT INTO users (name, email, phone, password, address, role, google_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, email, role',
        [name || 'Google User', email, '1234567890', hashedPassword, 'Google Address', 'user', google_id]
      );
      user = result.rows[0];
      console.log(`New Google user created: ${email}`);
    } else if (!user.google_id) {
      await client.query('UPDATE users SET google_id = $1 WHERE email = $2', [google_id, email]);
      console.log(`Linked Google ID to existing user: ${email}`);
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    client.release();

    console.log(`Google login successful: ${email}`);
    res.json({ token });
  } catch (err) {
    console.error('Google login error:', err.message, err.stack);
    res.status(500).json({ message: 'Google login failed', error: err.message });
  }
});

// Reset Password
app.post('/api/users/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  console.log(`Password reset attempt: ${email}`);

  try {
    const client = await pool.connect();
    const otpRecord = await client.query('SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires > NOW()', [email, otp]);
    if (otpRecord.rows.length === 0) {
      client.release();
      console.log(`Invalid or expired OTP for ${email}`);
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const user = (await client.query('SELECT * FROM users WHERE email = $1', [email])).rows[0];
    if (!user) {
      client.release();
      console.log(`User not found: ${email}`);
      return res.status(404).json({ message: 'User not found' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await client.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);
    await client.query('DELETE FROM otps WHERE email = $1', [email]);
    client.release();

    console.log(`Password reset successful: ${email}`);
    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({ message: 'Reset password failed' });
  }
});

// Menu
app.get('/api/users/menu', authenticateToken, async (req, res) => {
  const { search, category } = req.query;

  try {
    let query = 'SELECT * FROM menu_items';
    const params = [];
    let conditions = [];

    if (search) {
      conditions.push('LOWER(name) LIKE LOWER($' + (params.length + 1) + ')');
      params.push(`%${search}%`);
    }
    if (category) {
      conditions.push('category = $' + (params.length + 1));
      params.push(category);
    }
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    const client = await pool.connect();
    const result = await client.query(query, params);
    client.release();

    console.log(`Menu fetched for user ${req.user.email}`);
    res.json(result.rows);
  } catch (err) {
    console.error('Menu fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch menu' });
  }
});

// Add to Cart
app.post('/api/users/cart/add', authenticateToken, async (req, res) => {
  const { item } = req.body;
  console.log(`Add to cart attempt for user ${req.user.email}`);

  if (!item || !item.id) {
    console.log('Invalid item data');
    return res.status(400).json({ message: 'Invalid item data' });
  }

  try {
    const client = await pool.connect();
    await client.query(
      'INSERT INTO cart (user_id, item_id, quantity) VALUES ($1, $2, $3)',
      [req.user.id, item.id, 1]
    );
    client.release();

    console.log(`Item ${item.id} added to cart for user ${req.user.email}`);
    res.json({ message: 'Item added to cart' });
  } catch (err) {
    console.error('Cart error:', err.message);
    res.status(500).json({ message: 'Failed to add to cart' });
  }
});

// Admin Route
app.get('/api/users/admin', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    console.log(`Admin access denied for ${req.user.email}`);
    return res.status(403).json({ message: 'Admin access required' });
  }
  console.log(`Admin accessed by ${req.user.email}`);
  res.json({ message: 'Admin dashboard' });
});

// Razorpay Placeholder (for future integration)
app.get('/api/payment/config', authenticateToken, (req, res) => {
  res.json({
    key_id: process.env.RAZORPAY_KEY_ID,
  });
});

// Test Endpoint
app.get('/api/users/test', (req, res) => {
  console.log('Test endpoint accessed');
  res.json({ message: 'Server is running' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err.message, err.stack);
  res.status(500).json({ message: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 3000;
const server = http.createServer(app);
server.keepAliveTimeout = 120000; // 120 seconds
server.headersTimeout = 120000; // 120 seconds

server.listen(PORT, async () => {
  try {
    await initializeDatabase();
    console.log(`HTTP Server running on http://localhost:${PORT}`);
  } catch (err) {
    console.error('Startup error:', err.message);
    process.exit(1);
  }
});