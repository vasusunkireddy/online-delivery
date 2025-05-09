const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');
const { Pool } = require('pg');
const path = require('path');
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
  ssl: { rejectUnauthorized: false },
});

// Middleware
const corsOptions = {
  origin: ['http://localhost:3000', 'https://delicute.onrender.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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

// Initialize database
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
  const expires = new Date(Date.now() + 10 * 60 * 1000); // 10-minute expiry

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'DELICUTE OTP Verification',
    text: `Your OTP is ${otp}. Valid for 10 minutes. Check your spam folder if not received.`,
  };

  let client;
  try {
    client = await pool.connect();
    // Ensure otps table exists
    await client.query(`
      CREATE TABLE IF NOT EXISTS otps (
        email VARCHAR(255) PRIMARY KEY,
        otp VARCHAR(6) NOT NULL,
        expires TIMESTAMP NOT NULL
      )
    `);
    // Delete existing OTP
    await client.query('DELETE FROM otps WHERE email = $1', [email]);
    // Insert new OTP
    await client.query(
      'INSERT INTO otps (email, otp, expires) VALUES ($1, $2, $3)',
      [email, otp, expires]
    );
  } catch (err) {
    console.error('Database error in OTP request:', err.message);
    if (client) client.release();
    return res.status(500).json({ message: 'Failed to store OTP: Database error' });
  } finally {
    if (client) client.release();
  }

  try {
    await transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Email sending error:', error.message);
        return res.status(500).json({ message: 'Failed to send OTP: Email error' });
      }
      console.log(`OTP sent to ${email}: ${info.response}`);
    });
    res.json({ message: 'OTP sent' });
  } catch (err) {
    console.error('Email error in OTP request:', err.message);
    return res.status(500).json({ message: 'Failed to send OTP: Email error' });
  }
});

// Signup
app.post('/api/users/signup', async (req, res) => {
  const { name, email, phone, password, address, otp } = req.body;
  console.log(`Signup attempt: ${email}, OTP: ${otp}`);

  // Server-side validation
  if (!name || name.length < 3) {
    return res.status(400).json({ message: 'Name must be at least 3 characters' });
  }
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ message: 'Invalid email format' });
  }
  if (!phone || !/^\d{10}$/.test(phone)) {
    return res.status(400).json({ message: 'Phone must be 10 digits' });
  }
  if (!password || password.length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters' });
  }
  if (!address) {
    return res.status(400).json({ message: 'Address is required' });
  }
  if (!otp || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({ message: 'OTP must be 6 digits' });
  }

  let client;
  try {
    client = await pool.connect();
    const otpRecord = await client.query('SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires > NOW()', [email, otp]);
    if (otpRecord.rows.length === 0) {
      console.log(`Invalid or expired OTP for ${email}`);
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const userExists = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      console.log(`User already exists: ${email}`);
      return res.status(400).json({ message: 'User already exists' });
    }

    const phoneExists = await client.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if (phoneExists.rows.length > 0) {
      console.log(`Phone number already in use: ${phone}`);
      return res.status(400).json({ message: 'Phone number already in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await client.query(
      'INSERT INTO users (name, email, phone, password, address, role) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, role',
      [name, email, phone, hashedPassword, address, 'user']
    );
    const user = result.rows[0];

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    await client.query('DELETE FROM otps WHERE email = $1', [email]);
    res.status(201).json({ token });
    console.log(`Signup successful: ${email}`);
  } catch (err) {
    console.error('Signup error:', err.message);
    res.status(500).json({ message: 'Signup failed: ' + err.message });
  } finally {
    if (client) client.release();
  }
});

// Login
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  console.log(`Login attempt: ${email}`);

  let client;
  try {
    client = await pool.connect();
    const result = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

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
  } finally {
    if (client) client.release();
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
        [name || 'Google User', email, null, hashedPassword, 'Google Address', 'user', google_id]
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
    res.status(500).json({ message: 'Google login failed: ' + err.message });
  }
});

// Reset Password
app.post('/api/users/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  console.log(`Password reset attempt: ${email}`);

  let client;
  try {
    client = await pool.connect();
    const otpRecord = await client.query('SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires > NOW()', [email, otp]);
    if (otpRecord.rows.length === 0) {
      console.log(`Invalid or expired OTP for ${email}`);
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const user = (await client.query('SELECT * FROM users WHERE email = $1', [email])).rows[0];
    if (!user) {
      console.log(`User not found: ${email}`);
      return res.status(404).json({ message: 'User not found' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await client.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);
    await client.query('DELETE FROM otps WHERE email = $1', [email]);
    console.log(`Password reset successful: ${email}`);
    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({ message: 'Reset password failed' });
  } finally {
    if (client) client.release();
  }
});

// Menu
app.get('/api/users/menu', authenticateToken, async (req, res) => {
  const { search, category } = req.query;

  let client;
  try {
    client = await pool.connect();
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

    const result = await client.query(query, params);
    console.log(`Menu fetched for user ${req.user.email}`);
    res.json(result.rows);
  } catch (err) {
    console.error('Menu fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch menu' });
  } finally {
    if (client) client.release();
  }
});

// Add to Cart
app.post('/api/users/cart/add', authenticateToken, async (req, res) => {
  const { item } = req.body;
  const userId = req.user.id;

  if (!item || !item.id) {
    console.log('Invalid item data');
    return res.status(400).json({ message: 'Invalid item data' });
  }

  let client;
  try {
    client = await pool.connect();
    const itemExists = await client.query('SELECT * FROM menu_items WHERE id = $1', [item.id]);
    if (itemExists.rows.length === 0) {
      console.log(`Item not found: ${item.id}`);
      return res.status(404).json({ message: 'Item not found' });
    }

    const existingCartItem = await client.query(
      'SELECT * FROM cart WHERE user_id = $1 AND item_id = $2',
      [userId, item.id]
    );
    if (existingCartItem.rows.length > 0) {
      await client.query(
        'UPDATE cart SET quantity = quantity + 1 WHERE user_id = $1 AND item_id = $2',
        [userId, item.id]
      );
    } else {
      await client.query(
        'INSERT INTO cart (user_id, item_id, quantity) VALUES ($1, $2, $3)',
        [userId, item.id, 1]
      );
    }
    console.log(`Item added to cart for user ${req.user.email}: ${item.id}`);
    res.json({ message: 'Item added to cart' });
  } catch (err) {
    console.error('Add to cart error:', err.message);
    res.status(500).json({ message: 'Failed to add to cart' });
  } finally {
    if (client) client.release();
  }
});

// Start server
const PORT = 3000;
initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize database:', err.message);
    process.exit(1);
  });