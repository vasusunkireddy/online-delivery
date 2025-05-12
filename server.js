const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');
const { Pool } = require('pg');
const path = require('path');
const { Server } = require('socket.io');
const http = require('http');
const multer = require('multer');
const fs = require('fs');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: [process.env.CLIENT_URL, 'https://delicute.onrender.com'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
  },
});

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
  connectionTimeoutMillis: 5000,
  max: 20,
  idleTimeoutMillis: 30000,
});
// Log pool errors
pool.on('error', (err) => {
  console.error('PostgreSQL pool error:', err.message, err.stack);
});

// Multer for file uploads
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  fs.chmodSync(uploadDir, 0o755);
}
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    if (!file || !file.originalname) {
      return cb(new Error('No file or invalid file name provided'), null);
    }
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (!file) {
      return cb(new Error('No file uploaded'), false);
    }
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Only image files are allowed'), false);
    }
    cb(null, true);
  },
}).single('image');

// Middleware
const corsOptions = {
  origin: [process.env.CLIENT_URL || 'http://localhost:3000', 'http://localhost:3000', process.env.RENDER_URL].filter(Boolean),
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());
app.use('/uploads', express.static(uploadDir));
app.use(express.static(path.join(__dirname, 'public')));

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
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// Admin middleware
function authenticateAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
}

// Generate OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Initialize database with retries
async function initializeDatabase() {
  let retries = 15;
  while (retries > 0) {
    try {
      console.log('Attempting database connection with DATABASE_URL:', process.env.DATABASE_URL.replace(/:\/\//, '://<user>:<pass>@'));
      const client = await pool.connect();
      console.log('Database connected successfully');

      const adminEmail = 'svasudevareddy18604@gmail.com';
      const adminPassword = 'vasudev';
      const hashedPassword = await bcrypt.hash(adminPassword, 10);

      // Create tables
      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          email VARCHAR(255) UNIQUE NOT NULL,
          phone VARCHAR(20),
          password VARCHAR(255),
          address TEXT,
          role VARCHAR(50) DEFAULT 'user',
          google_id VARCHAR(255),
          image TEXT,
          loyalty_points INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS addresses (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          address_line TEXT NOT NULL,
          city VARCHAR(100),
          state VARCHAR(100),
          postal_code VARCHAR(20),
          country VARCHAR(100),
          is_default BOOLEAN DEFAULT FALSE
        );

        CREATE TABLE IF NOT EXISTS admin (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          permissions JSONB
        );

        CREATE TABLE IF NOT EXISTS otps (
          email VARCHAR(255) PRIMARY KEY,
          otp VARCHAR(6) NOT NULL,
          expires TIMESTAMP NOT NULL
        );

        CREATE TABLE IF NOT EXISTS menu (
          id SERIAL PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          price NUMERIC(10,2) NOT NULL,
          category VARCHAR(100) NOT NULL,
          description TEXT,
          image TEXT,
          available BOOLEAN DEFAULT TRUE
        );

        CREATE TABLE IF NOT EXISTS cart (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          item_id INTEGER REFERENCES menu(id) ON DELETE CASCADE,
          quantity INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS orders (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          items JSONB NOT NULL,
          total NUMERIC(10,2) NOT NULL,
          status VARCHAR(50) NOT NULL,
          payment_method VARCHAR(50),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS order_items (
          id SERIAL PRIMARY KEY,
          order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
          item_id INTEGER REFERENCES menu(id) ON DELETE CASCADE,
          quantity INTEGER NOT NULL,
          price NUMERIC(10,2) NOT NULL
        );

        CREATE TABLE IF NOT EXISTS offers (
          id SERIAL PRIMARY KEY,
          title VARCHAR(255) NOT NULL,
          code VARCHAR(50) UNIQUE,
          discount INTEGER NOT NULL,
          description TEXT,
          start_date DATE NOT NULL,
          end_date DATE NOT NULL,
          image TEXT
        );

        CREATE TABLE IF NOT EXISTS testimonials (
          id SERIAL PRIMARY KEY,
          text TEXT NOT NULL,
          author VARCHAR(255) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS feedback (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          rating INTEGER NOT NULL,
          comment TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS support_chat (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          sender VARCHAR(50) NOT NULL,
          content TEXT NOT NULL,
          timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS support_tickets (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          subject VARCHAR(255) NOT NULL,
          description TEXT NOT NULL,
          status VARCHAR(50) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS restaurant_status (
          id SERIAL PRIMARY KEY,
          status VARCHAR(50) NOT NULL,
          open_time TIME,
          close_time TIME
        );

        CREATE TABLE IF NOT EXISTS favourites (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          item_id INTEGER REFERENCES menu(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS loyalty (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          points INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS loyalty_history (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          points INTEGER NOT NULL,
          action VARCHAR(50) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS referrals (
          id SERIAL PRIMARY KEY,
          referrer_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          referred_email VARCHAR(255) NOT NULL,
          status VARCHAR(50) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);

      // Fix restaurant_status schema
      await client.query(`
        ALTER TABLE restaurant_status ALTER COLUMN status TYPE VARCHAR(50);
      `);

      // Drop conflicting tables
      await client.query('DROP TABLE IF EXISTS menu_items CASCADE;');
      await client.query('DROP TABLE IF EXISTS promotions CASCADE;');

      // Remove CHECK constraint on menu.category
      await client.query(`
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conname = 'menu_category_check'
            AND conrelid = 'menu'::regclass
          ) THEN
            ALTER TABLE menu DROP CONSTRAINT menu_category_check;
          END IF;
        END $$;
      `);

      // Add missing columns
      await client.query(`
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'image') THEN
            ALTER TABLE users ADD COLUMN image TEXT;
          END IF;
          IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'loyalty_points') THEN
            ALTER TABLE users ADD COLUMN loyalty_points INTEGER DEFAULT 0;
          END IF;
          IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'menu' AND column_name = 'description') THEN
            ALTER TABLE menu ADD COLUMN description TEXT;
          END IF;
          IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'menu' AND column_name = 'image') THEN
            ALTER TABLE menu ADD COLUMN image TEXT;
          END IF;
          IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'menu' AND column_name = 'available') THEN
            ALTER TABLE menu ADD COLUMN available BOOLEAN DEFAULT TRUE;
          END IF;
          IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'orders' AND column_name = 'items') THEN
            ALTER TABLE orders ADD COLUMN items JSONB NOT NULL DEFAULT '[]'::jsonb;
          END IF;
          IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'orders' AND column_name = 'created_at') THEN
            ALTER TABLE orders ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
          END IF;
          IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'offers' AND column_name = 'start_date') THEN
            ALTER TABLE offers ADD COLUMN start_date DATE NOT NULL DEFAULT CURRENT_DATE;
          END IF;
          IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'offers' AND column_name = 'end_date') THEN
            ALTER TABLE offers ADD COLUMN end_date DATE NOT NULL DEFAULT CURRENT_DATE + INTERVAL '30 days';
          END IF;
          IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'offers' AND column_name = 'image') THEN
            ALTER TABLE offers ADD COLUMN image TEXT;
          END IF;
          IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'offers' AND column_name = 'description') THEN
            ALTER TABLE offers ADD COLUMN description TEXT;
          END IF;
        END $$;
      `);

      // Seed admin user
      const userExists = await client.query('SELECT * FROM users WHERE email = $1', [adminEmail]);
      if (userExists.rows.length === 0) {
        const userResult = await client.query(
          'INSERT INTO users (name, email, phone, password, address, role, image) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
          ['Admin', adminEmail, '1234567890', hashedPassword, 'Admin Address', 'admin', '/assets/fallback-profile.png']
        );
        const adminUserId = userResult.rows[0].id;
        await client.query(
          'INSERT INTO admin (user_id, permissions) VALUES ($1, $2)',
          [adminUserId, JSON.stringify(['all'])]
        );
      }

      // Seed restaurant status
      const statusExists = await client.query('SELECT * FROM restaurant_status WHERE id = 1');
      if (statusExists.rows.length === 0) {
        await client.query(
          'INSERT INTO restaurant_status (id, status, open_time, close_time) VALUES ($1, $2, $3, $4)',
          [1, 'closed', '09:00:00', '21:00:00']
        );
      }

      client.release();
      console.log('Database initialized successfully');
      return true;
    } catch (err) {
      console.error(`Database connection attempt failed (${retries} retries left):`, err.message, err.stack);
      retries -= 1;
      if (retries === 0) {
        console.error('All database connection attempts failed. Retrying in 30 seconds...');
        await new Promise(resolve => setTimeout(resolve, 30000));
        retries = 15; // Reset retries for continuous attempts
      } else {
        await new Promise(resolve => setTimeout(resolve, 15000));
      }
    }
  }
}

// Socket.IO Events
io.on('connection', (socket) => {
  console.log('Socket.IO client connected');
  socket.on('chatMessage', async (data) => {
    try {
      const client = await pool.connect();
      const result = await client.query(
        'INSERT INTO support_chat (user_id, sender, content) VALUES ($1, $2, $3) RETURNING *',
        [data.userId, data.sender, data.content]
      );
      client.release();
      io.emit('chatMessage', result.rows[0]);
    } catch (err) {
      console.error('Socket.IO chat message error:', err.message);
    }
  });

  socket.on('newOrder', (order) => {
    io.emit('newOrder', order);
  });

  socket.on('orderStatus', (data) => {
    io.emit('orderStatus', data);
  });

  socket.on('disconnect', () => {
    console.log('Socket.IO client disconnected');
  });
});

// Routes

// Request OTP
app.post('/api/users/request-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: 'Email required' });
  }

  const otp = generateOTP();
  const expires = new Date(Date.now() + 10 * 60 * 1000);

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'DELICUTE OTP Verification',
    text: `Your OTP is ${otp}. Valid for 10 minutes. Check your spam folder if not received.`,
  };

  try {
    const client = await pool.connect();
    await client.query('DELETE FROM otps WHERE email = $1', [email]);
    await client.query(
      'INSERT INTO otps (email, otp, expires) VALUES ($1, $2, $3)',
      [email, otp, expires]
    );
    client.release();

    await transporter.sendMail(mailOptions);
    res.json({ message: 'OTP sent' });
  } catch (err) {
    console.error('OTP request error:', err.message);
    res.status(500).json({ message: 'Failed to send OTP' });
  }
});

// Signup
app.post('/api/users/signup', async (req, res) => {
  const { name, email, phone, password, address, otp } = req.body;

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

  try {
    const client = await pool.connect();
    const otpRecord = await client.query('SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires > NOW()', [email, otp]);
    if (otpRecord.rows.length === 0) {
      client.release();
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const userExists = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      client.release();
      return res.status(400).json({ message: 'User already exists' });
    }

    const phoneExists = await client.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if (phoneExists.rows.length > 0) {
      client.release();
      return res.status(400).json({ message: 'Phone number already in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await client.query(
      'INSERT INTO users (name, email, phone, password, address, role, image) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, email, role',
      [name, email, phone, hashedPassword, address, 'user', '/assets/fallback-profile.png']
    );
    const user = result.rows[0];

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    await client.query('DELETE FROM otps WHERE email = $1', [email]);
    client.release();

    res.status(201).json({ token });
  } catch (err) {
    console.error('Signup error:', err.message);
    res.status(500).json({ message: 'Signup failed' });
  }
});

// Login
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const client = await pool.connect();
    const result = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    client.release();

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ message: 'Login failed due to server error' });
  }
});

// Google Login
app.post('/api/users/google', async (req, res) => {
  const { id_token } = req.body;

  if (!id_token) {
    return res.status(400).json({ message: 'id_token required' });
  }

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (!payload) {
      return res.status(400).json({ message: 'Invalid Google token' });
    }

    const { email, name, sub: google_id } = payload;

    const client = await pool.connect();
    let user = (await client.query('SELECT * FROM users WHERE email = $1', [email])).rows[0];

    if (!user) {
      const hashedPassword = await bcrypt.hash('google_dummy_' + Math.random(), 10);
      const result = await client.query(
        'INSERT INTO users (name, email, phone, password, address, role, google_id, image) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, email, role',
        [name || 'Google User', email, null, hashedPassword, 'Google Address', 'user', google_id, '/assets/fallback-profile.png']
      );
      user = result.rows[0];
    } else if (!user.google_id) {
      await client.query('UPDATE users SET google_id = $1 WHERE email = $2', [google_id, email]);
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    client.release();

    res.json({ token });
  } catch (err) {
    console.error('Google login error:', err.message);
    res.status(500).json({ message: 'Google login failed' });
  }
});

// Reset Password
app.post('/api/users/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    const client = await pool.connect();
    const otpRecord = await client.query('SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires > NOW()', [email, otp]);
    if (otpRecord.rows.length === 0) {
      client.release();
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const user = (await client.query('SELECT * FROM users WHERE email = $1', [email])).rows[0];
    if (!user) {
      client.release();
      return res.status(404).json({ message: 'User not found' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await client.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);
    await client.query('DELETE FROM otps WHERE email = $1', [email]);
    client.release();

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({ message: 'Reset password failed' });
  }
});

// Admin Profile
app.get('/api/admin/profile', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT id, name, email, image FROM users WHERE id = $1', [req.user.id]);
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Admin profile fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch profile' });
  }
});

app.put('/api/admin/profile', authenticateToken, authenticateAdmin, async (req, res) => {
  const { name, email, image } = req.body;

  try {
    const client = await pool.connect();
    await client.query(
      'UPDATE users SET name = $1, email = $2, image = COALESCE($3, image) WHERE id = $4',
      [name, email, image, req.user.id]
    );
    client.release();
    res.json({ message: 'Profile updated' });
  } catch (err) {
    console.error('Admin profile update error:', err.message);
    res.status(500).json({ message: 'Failed to update profile' });
  }
});

// Image Upload
app.post('/api/upload/:type', authenticateToken, (req, res) => {
  const type = req.params.type;
  if (!['profile', 'menu', 'offer'].includes(type)) {
    return res.status(400).json({ message: 'Invalid upload type' });
  }

  upload(req, res, (err) => {
    if (err) {
      console.error('Image upload error:', err.message);
      return res.status(400).json({ message: err.message || 'File upload failed' });
    }
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }
    const url = `/uploads/${req.file.filename}`;
    res.json({ url });
  });
});

// Menu
app.get('/api/menu', authenticateToken, async (req, res) => {
  const { category, search } = req.query;
  try {
    const client = await pool.connect();
    let query = 'SELECT id, name, price, category, description, image FROM menu WHERE available = TRUE';
    const params = [];

    if (category) {
      query += ' AND category = $1';
      params.push(category);
    }
    if (search) {
      query += params.length ? ' AND' : ' WHERE';
      query += ' name ILIKE $' + (params.length + 1);
      params.push(`%${search}%`);
    }
    query += ' LIMIT 100';

    const result = await client.query(query, params);
    client.release();
    res.json(result.rows);
  } catch (err) {
    console.error('Menu fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch menu due to server error' });
  }
});

app.get('/api/menu/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid menu item ID is required' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query('SELECT * FROM menu WHERE id = $1', [id]);
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Menu item not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Menu item fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch menu item' });
  }
});

app.post('/api/menu', authenticateToken, authenticateAdmin, async (req, res) => {
  const { name, category, price, description, available, image } = req.body;

  if (!name || typeof name !== 'string' || name.trim() === '') {
    return res.status(400).json({ message: 'Name is required and must be a non-empty string' });
  }
  if (!category || typeof category !== 'string' || category.trim() === '') {
    return res.status(400).json({ message: 'Category is required and must be a non-empty string' });
  }
  if (!price || isNaN(price) || price <= 0) {
    return res.status(400).json({ message: 'Price must be a positive number' });
  }
  if (available !== undefined && typeof available !== 'boolean') {
    return res.status(400).json({ message: 'Available must be a boolean' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(
      'INSERT INTO menu (name, category, price, description, available, image) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [name.trim(), category.trim(), price, description, available ?? true, image]
    );
    client.release();
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Menu item create error:', err.message);
    res.status(500).json({ message: 'Failed to create menu item' });
  }
});

app.put('/api/menu/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, category, price, description, available, image } = req.body;

  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid menu item ID is required' });
  }
  if (!name || typeof name !== 'string' || name.trim() === '') {
    return res.status(400).json({ message: 'Name is required and must be a non-empty string' });
  }
  if (!category || typeof category !== 'string' || category.trim() === '') {
    return res.status(400).json({ message: 'Category is required and must be a non-empty string' });
  }
  if (!price || isNaN(price) || price <= 0) {
    return res.status(400).json({ message: 'Price must be a positive number' });
  }
  if (available !== undefined && typeof available !== 'boolean') {
    return res.status(400).json({ message: 'Available must be a boolean' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(
      'UPDATE menu SET name = $1, category = $2, price = $3, description = $4, available = $5, image = COALESCE($6, image) WHERE id = $7 RETURNING *',
      [name.trim(), category.trim(), price, description, available ?? true, image, id]
    );
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Menu item not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Menu item update error:', err.message);
    res.status(500).json({ message: 'Failed to update menu item' });
  }
});

app.delete('/api/menu/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;

  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid menu item ID is required' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query('DELETE FROM menu WHERE id = $1 RETURNING *', [id]);
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Menu item not found' });
    }
    res.json({ message: 'Menu item deleted' });
  } catch (err) {
    console.error('Menu item delete error:', err.message);
    res.status(500).json({ message: 'Failed to delete menu item' });
  }
});

// Cart
app.post('/api/cart/add', authenticateToken, async (req, res) => {
  const { item } = req.body;
  if (!item || !item.id) {
    return res.status(400).json({ message: 'Item ID is required' });
  }

  try {
    const client = await pool.connect();
    const menuItem = await client.query('SELECT * FROM menu WHERE id = $1 AND available = TRUE', [item.id]);
    if (menuItem.rows.length === 0) {
      client.release();
      return res.status(404).json({ message: 'Menu item not found or unavailable' });
    }

    const existingCartItem = await client.query('SELECT * FROM cart WHERE user_id = $1 AND item_id = $2', [req.user.id, item.id]);
    if (existingCartItem.rows.length > 0) {
      await client.query('UPDATE cart SET quantity = quantity + 1 WHERE user_id = $1 AND item_id = $2', [req.user.id, item.id]);
    } else {
      await client.query('INSERT INTO cart (user_id, item_id, quantity) VALUES ($1, $2, $3)', [req.user.id, item.id, 1]);
    }
    client.release();
    res.json({ message: 'Item added to cart' });
  } catch (err) {
    console.error('Add to cart error:', err.message);
    res.status(500).json({ message: 'Failed to add item to cart' });
  }
});

// Orders
app.get('/api/orders', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query(`
      SELECT o.id, o.user_id, o.items, o.total, o.status, o.payment_method, o.created_at,
             u.name as customer_name
      FROM orders o
      JOIN users u ON o.user_id = u.id
      ORDER BY o.created_at DESC
    `);
    client.release();
    res.json(result.rows.map(row => ({
      _id: row.id,
      userId: row.user_id,
      customer: { name: row.customer_name },
      items: row.items,
      total: row.total,
      status: row.status,
      paymentMethod: row.payment_method,
      createdAt: row.created_at
    })));
  } catch (err) {
    console.error('Orders fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch orders' });
  }
});

app.get('/api/orders/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid order ID is required' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(`
      SELECT o.id, o.user_id, o.items, o.total, o.status, o.payment_method, o.created_at,
             u.name as customer_name
      FROM orders o
      JOIN users u ON o.user_id = u.id
      WHERE o.id = $1
    `, [id]);
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }
    const row = result.rows[0];
    res.json({
      _id: row.id,
      userId: row.user_id,
      customer: { name: row.customer_name },
      items: row.items,
      total: row.total,
      status: row.status,
      paymentMethod: row.payment_method,
      createdAt: row.created_at
    });
  } catch (err) {
    console.error('Order fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch order' });
  }
});

app.post('/api/orders', authenticateToken, async (req, res) => {
  const { items, total, paymentMethod } = req.body;

  if (!items || !total || !paymentMethod) {
    return res.status(400).json({ message: 'Items, total, and payment method required' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(
      'INSERT INTO orders (user_id, items, total, status, payment_method) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.id, JSON.stringify(items), total, 'pending', paymentMethod]
    );
    await client.query('DELETE FROM cart WHERE user_id = $1', [req.user.id]);
    client.release();

    const order = result.rows[0];
    io.emit('newOrder', order);
    res.status(201).json(order);
  } catch (err) {
    console.error('Order create error:', err.message);
    res.status(500).json({ message: 'Failed to create order' });
  }
});

app.post('/api/orders/:id/refund', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;

  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid order ID is required' });
  }

  try {
    const client = await pool.connect();
    const order = await client.query('SELECT * FROM orders WHERE id = $1', [id]);
    if (order.rows.length === 0) {
      client.release();
      return res.status(404).json({ message: 'Order not found' });
    }
    if (order.rows[0].status !== 'completed' || order.rows[0].payment_method === 'cash') {
      client.release();
      return res.status(400).json({ message: 'Cannot refund this order' });
    }

    await client.query('UPDATE orders SET status = $1 WHERE id = $2', ['refunded', id]);
    client.release();

    io.emit('orderStatus', { orderId: id, status: 'refunded' });
    res.json({ message: 'Refund processed' });
  } catch (err) {
    console.error('Refund process error:', err.message);
    res.status(500).json({ message: 'Failed to process refund' });
  }
});

// Offers
app.get('/api/offers', async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query(`
      SELECT id, title, code, discount, description, start_date, end_date, image
      FROM offers
      WHERE start_date <= CURRENT_DATE AND end_date >= CURRENT_DATE
    `);
    client.release();
    res.json(result.rows.map(p => ({
      _id: p.id,
      title: p.title,
      code: p.code,
      discount: p.discount,
      description: p.description,
      startDate: p.start_date,
      endDate: p.end_date,
      image: p.image
    })));
  } catch (err) {
    console.error('Offers fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch offers' });
  }
});

app.get('/api/offers/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid offer ID is required' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query('SELECT * FROM offers WHERE id = $1', [id]);
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Offer not found' });
    }
    const p = result.rows[0];
    res.json({
      _id: p.id,
      title: p.title,
      code: p.code,
      discount: p.discount,
      description: p.description,
      startDate: p.start_date,
      endDate: p.end_date,
      image: p.image
    });
  } catch (err) {
    console.error('Offer fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch offer' });
  }
});

app.post('/api/offers', authenticateToken, authenticateAdmin, async (req, res) => {
  const { title, code, discount, description, startDate, endDate, image } = req.body;

  if (!title || typeof title !== 'string' || title.trim() === '') {
    return res.status(400).json({ message: 'Title is required and must be a non-empty string' });
  }
  if (!code || typeof code !== 'string' || code.trim() === '') {
    return res.status(400).json({ message: 'Code is required and must be a non-empty string' });
  }
  if (!discount || isNaN(discount) || discount <= 0) {
    return res.status(400).json({ message: 'Discount must be a positive number' });
  }
  if (!startDate || isNaN(Date.parse(startDate))) {
    return res.status(400).json({ message: 'Start date is required and must be a valid date' });
  }
  if (!endDate || isNaN(Date.parse(endDate))) {
    return res.status(400).json({ message: 'End date is required and must be a valid date' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(
      'INSERT INTO offers (title, code, discount, description, start_date, end_date, image) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [title.trim(), code.trim(), discount, description, startDate, endDate, image]
    );
    client.release();
    res.status(201).json({
      _id: result.rows[0].id,
      title: result.rows[0].title,
      code: result.rows[0].code,
      discount: result.rows[0].discount,
      description: result.rows[0].description,
      startDate: result.rows[0].start_date,
      endDate: result.rows[0].end_date,
      image: result.rows[0].image
    });
  } catch (err) {
    console.error('Offer create error:', err.message);
    res.status(500).json({ message: 'Failed to create offer' });
  }
});

app.put('/api/offers/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { title, code, discount, description, startDate, endDate, image } = req.body;

  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid offer ID is required' });
  }
  if (!title || typeof title !== 'string' || title.trim() === '') {
    return res.status(400).json({ message: 'Title is required and must be a non-empty string' });
  }
  if (!code || typeof code !== 'string' || code.trim() === '') {
    return res.status(400).json({ message: 'Code is required and must be a non-empty string' });
  }
  if (!discount || isNaN(discount) || discount <= 0) {
    return res.status(400).json({ message: 'Discount must be a positive number' });
  }
  if (!startDate || isNaN(Date.parse(startDate))) {
    return res.status(400).json({ message: 'Start date is required and must be a valid date' });
  }
  if (!endDate || isNaN(Date.parse(endDate))) {
    return res.status(400).json({ message: 'End date is required and must be a valid date' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(
      'UPDATE offers SET title = $1, code = $2, discount = $3, description = $4, start_date = $5, end_date = $6, image = COALESCE($7, image) WHERE id = $8 RETURNING *',
      [title.trim(), code.trim(), discount, description, startDate, endDate, image, id]
    );
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Offer not found' });
    }
    res.json({
      _id: result.rows[0].id,
      title: result.rows[0].title,
      code: result.rows[0].code,
      discount: result.rows[0].discount,
      description: result.rows[0].description,
      startDate: result.rows[0].start_date,
      endDate: result.rows[0].end_date,
      image: result.rows[0].image
    });
  } catch (err) {
    console.error('Offer update error:', err.message);
    res.status(500).json({ message: 'Failed to update offer' });
  }
});

app.delete('/api/offers/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;

  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid offer ID is required' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query('DELETE FROM offers WHERE id = $1 RETURNING *', [id]);
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Offer not found' });
    }
    res.json({ message: 'Offer deleted' });
  } catch (err) {
    console.error('Offer delete error:', err.message);
    res.status(500).json({ message: 'Failed to delete offer' });
  }
});

// Testimonials
app.get('/api/content/testimonials', async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT text, author FROM testimonials');
    client.release();
    res.json(result.rows);
  } catch (err) {
    console.error('Testimonials fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch testimonials' });
  }
});

// Users
app.get('/api/users', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT id, name, email, phone, loyalty_points FROM users WHERE role = $1', ['user']);
    const orders = await client.query('SELECT user_id, COUNT(*) as order_count FROM orders GROUP BY user_id');
    client.release();

    const users = result.rows.map(user => ({
      _id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      loyaltyPoints: user.loyalty_points,
      orders: orders.rows.find(o => o.user_id == user.id)?.order_count || 0
    }));
    res.json(users);
  } catch (err) {
    console.error('Users fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

app.get('/api/users/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid user ID is required' });
  }

  try {
    const client = await pool.connect();
    const userResult = await client.query('SELECT id, name, email, phone, loyalty_points FROM users WHERE id = $1 AND role = $2', [id, 'user']);
    const ordersResult = await client.query('SELECT COUNT(*) as order_count FROM orders WHERE user_id = $1', [id]);
    client.release();

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    const user = userResult.rows[0];
    res.json({
      _id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      loyaltyPoints: user.loyalty_points,
      orders: parseInt(ordersResult.rows[0].order_count)
    });
  } catch (err) {
    console.error('User fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch user' });
  }
});

app.put('/api/users/:id/loyalty', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { points } = req.body;

  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid user ID is required' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(
      'UPDATE users SET loyalty_points = loyalty_points + $1 WHERE id = $2 AND role = $3 RETURNING *',
      [points, id, 'user']
    );
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'Loyalty points updated' });
  } catch (err) {
    console.error('Loyalty points update error:', err.message);
    res.status(500).json({ message: 'Failed to update loyalty points' });
  }
});

// Support Chat
app.get('/api/support/chat/:userId', authenticateToken, authenticateAdmin, async (req, res) => {
  const { userId } = req.params;
  if (!userId || isNaN(userId)) {
    return res.status(400).json({ message: 'Valid user ID is required' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(
      'SELECT id, user_id, sender, content, timestamp FROM support_chat WHERE user_id = $1 ORDER BY timestamp',
      [userId]
    );
    client.release();
    res.json(result.rows.map(msg => ({
      _id: msg.id,
      userId: msg.user_id,
      sender: msg.sender,
      content: msg.content,
      timestamp: msg.timestamp
    })));
  } catch (err) {
    console.error('Support chat fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch chat messages' });
  }
});

app.post('/api/support/chat/:userId', authenticateToken, authenticateAdmin, async (req, res) => {
  const { userId } = req.params;
  const { content } = req.body;

  if (!userId || isNaN(userId)) {
    return res.status(400).json({ message: 'Valid user ID is required' });
  }
  if (!content || typeof content !== 'string' || content.trim() === '') {
    return res.status(400).json({ message: 'Content is required and must be a non-empty string' });
  }

  try {
    const client = await pool.connect();
    const userExists = await client.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userExists.rows.length === 0) {
      client.release();
      return res.status(404).json({ message: 'User not found' });
    }

    const result = await client.query(
      'INSERT INTO support_chat (user_id, sender, content) VALUES ($1, $2, $3) RETURNING *',
      [userId, 'admin', content.trim()]
    );
    client.release();

    io.emit('chatMessage', result.rows[0]);
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Support chat send error:', err.message);
    res.status(500).json({ message: 'Failed to send message' });
  }
});

// Support Tickets
app.get('/api/support/tickets', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query(`
      SELECT t.id, t.user_id, t.subject, t.description, t.status, t.created_at,
             u.name as customer_name
      FROM support_tickets t
      JOIN users u ON t.user_id = u.id
      ORDER BY t.created_at DESC
    `);
    client.release();
    res.json(result.rows.map(t => ({
      _id: t.id,
      userId: t.user_id,
      customer: { name: t.customer_name },
      subject: t.subject,
      description: t.description,
      status: t.status,
      createdAt: t.created_at
    })));
  } catch (err) {
    console.error('Support tickets fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch support tickets' });
  }
});

app.post('/api/support/tickets', authenticateToken, async (req, res) => {
  const { subject, description } = req.body;

  if (!subject || typeof subject !== 'string' || subject.trim() === '') {
    return res.status(400).json({ message: 'Subject is required and must be a non-empty string' });
  }
  if (!description || typeof description !== 'string' || description.trim() === '') {
    return res.status(400).json({ message: 'Description is required and must be a non-empty string' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(
      'INSERT INTO support_tickets (user_id, subject, description, status) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.user.id, subject.trim(), description.trim(), 'open']
    );
    client.release();
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Support ticket create error:', err.message);
    res.status(500).json({ message: 'Failed to create support ticket' });
  }
});

// Feedback
app.get('/api/feedback', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query(`
      SELECT f.id, f.user_id, f.rating, f.comment, f.created_at,
             u.name as customer_name
      FROM feedback f
      JOIN users u ON f.user_id = u.id
      ORDER BY f.created_at DESC
    `);
    client.release();
    res.json(result.rows.map(f => ({
      _id: f.id,
      userId: f.user_id,
      customer: { name: f.customer_name },
      rating: f.rating,
      comment: f.comment,
      createdAt: f.created_at
    })));
  } catch (err) {
    console.error('Feedback fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch feedback' });
  }
});

app.get('/api/feedback/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid feedback ID is required' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(`
      SELECT f.id, f.user_id, f.rating, f.comment, f.created_at,
             u.name as customer_name
      FROM feedback f
      JOIN users u ON f.user_id = u.id
      WHERE f.id = $1
    `, [id]);
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Feedback not found' });
    }
    const f = result.rows[0];
    res.json({
      _id: f.id,
      userId: f.user_id,
      customer: { name: f.customer_name },
      rating: f.rating,
      comment: f.comment,
      createdAt: f.created_at
    });
  } catch (err) {
    console.error('Feedback fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch feedback' });
  }
});

app.post('/api/feedback', authenticateToken, async (req, res) => {
  const { rating, comment } = req.body;

  if (!rating || isNaN(rating) || rating < 1 || rating > 5) {
    return res.status(400).json({ message: 'Rating must be a number between 1 and 5' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(
      'INSERT INTO feedback (user_id, rating, comment) VALUES ($1, $2, $3) RETURNING *',
      [req.user.id, rating, comment]
    );
    client.release();
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Feedback create error:', err.message);
    res.status(500).json({ message: 'Failed to create feedback' });
  }
});

// Restaurant Status
app.get('/api/restaurant/status', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT status, open_time, close_time FROM restaurant_status WHERE id = 1');
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Restaurant status not found' });
    }
    res.json({
      status: result.rows[0].status,
      openTime: result.rows[0].open_time,
      closeTime: result.rows[0].close_time
    });
  } catch (err) {
    console.error('Restaurant status fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch restaurant status' });
  }
});

app.put('/api/restaurant/status', authenticateToken, authenticateAdmin, async (req, res) => {
  const { status, openTime, closeTime } = req.body;

  if (!status || !['open', 'closed'].includes(status)) {
    return res.status(400).json({ message: 'Status must be "open" or "closed"' });
  }
  if (!openTime || !/^\d{2}:\d{2}(:\d{2})?$/.test(openTime)) {
    return res.status(400).json({ message: 'openTime must be in HH:MM or HH:MM:SS format' });
  }
  if (!closeTime || !/^\d{2}:\d{2}(:\d{2})?$/.test(closeTime)) {
    return res.status(400).json({ message: 'closeTime must be in HH:MM or HH:MM:SS format' });
  }

  const normalizedOpenTime = openTime.length === 5 ? `${openTime}:00` : openTime;
  const normalizedCloseTime = closeTime.length === 5 ? `${closeTime}:00` : closeTime;

  try {
    const client = await pool.connect();
    const result = await client.query(
      'UPDATE restaurant_status SET status = $1, open_time = $2, close_time = $3 WHERE id = 1 RETURNING *',
      [status, normalizedOpenTime, normalizedCloseTime]
    );
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Restaurant status not found' });
    }
    res.json({
      message: 'Restaurant status updated',
      data: {
        status: result.rows[0].status,
        openTime: result.rows[0].open_time,
        closeTime: result.rows[0].close_time
      }
    });
  } catch (err) {
    console.error('Restaurant status update error:', err.message);
    res.status(500).json({ message: 'Failed to update restaurant status' });
  }
});

// Favourites
app.post('/api/favourites', authenticateToken, async (req, res) => {
  const { itemId } = req.body;

  if (!itemId || isNaN(itemId)) {
    return res.status(400).json({ message: 'Valid item ID is required' });
  }

  try {
    const client = await pool.connect();
    const menuItem = await client.query('SELECT * FROM menu WHERE id = $1', [itemId]);
    if (menuItem.rows.length === 0) {
      client.release();
      return res.status(404).json({ message: 'Menu item not found' });
    }

    const existingFavourite = await client.query('SELECT * FROM favourites WHERE user_id = $1 AND item_id = $2', [req.user.id, itemId]);
    if (existingFavourite.rows.length > 0) {
      client.release();
      return res.status(400).json({ message: 'Item already in favourites' });
    }

    await client.query('INSERT INTO favourites (user_id, item_id) VALUES ($1, $2)', [req.user.id, itemId]);
    client.release();
    res.json({ message: 'Item added to favourites' });
  } catch (err) {
    console.error('Add to favourites error:', err.message);
    res.status(500).json({ message: 'Failed to add item to favourites' });
  }
});

// Loyalty
app.get('/api/loyalty', authenticateToken, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT points FROM loyalty WHERE user_id = $1', [req.user.id]);
    client.release();
    if (result.rows.length === 0) {
      return res.json({ points: 0 });
    }
    res.json({ points: result.rows[0].points });
  } catch (err) {
    console.error('Loyalty fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch loyalty points' });
  }
});

// Referrals
app.post('/api/referrals', authenticateToken, async (req, res) => {
  const { referredEmail } = req.body;

  if (!referredEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(referredEmail)) {
    return res.status(400).json({ message: 'Valid email is required' });
  }

  try {
    const client = await pool.connect();
    const userExists = await client.query('SELECT * FROM users WHERE email = $1', [referredEmail]);
    if (userExists.rows.length > 0) {
      client.release();
      return res.status(400).json({ message: 'Referred email already registered' });
    }

    await client.query(
      'INSERT INTO referrals (referrer_id, referred_email, status) VALUES ($1, $2, $3)',
      [req.user.id, referredEmail, 'pending']
    );
    client.release();
    res.json({ message: 'Referral sent' });
  } catch (err) {
    console.error('Referral create error:', err.message);
    res.status(500).json({ message: 'Failed to create referral' });
  }
});

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin.html', authenticateToken, authenticateAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  res.status(500).json({ message: 'Internal server error' });
});

// Start server with retry
async function startServer() {
  while (true) {
    try {
      const initialized = await initializeDatabase();
      if (initialized) {
        const PORT = process.env.PORT || 3000;
        server.listen(PORT, () => {
          console.log(`Server running on http://localhost:${PORT}`);
        });
        break; // Exit loop on successful start
      }
    } catch (err) {
      console.error('Server start failed:', err.message);
      console.log('Retrying server start in 30 seconds...');
      await new Promise(resolve => setTimeout(resolve, 30000));
    }
  }
}

startServer();