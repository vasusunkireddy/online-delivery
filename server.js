const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');
const { Pool } = require('pg');
const path = require('path');
const multer = require('multer'); // For handling file uploads
require('dotenv').config();

const app = express();

// Google OAuth2 Client
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '1019406651586-rgl91utq3nn9ohudbrt15o74el8eq75j.apps.googleusercontent.com';
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

// Multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (['image/jpeg', 'image/png', 'image/gif'].includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'), false);
    }
  },
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
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>
  if (!token) {
    console.log('No token provided in request');
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
        profile_image TEXT
      );

      CREATE TABLE IF NOT EXISTS otps (
        email VARCHAR(255) PRIMARY KEY,
        otp VARCHAR(6) NOT NULL,
        expires TIMESTAMP NOT NULL
      );

      CREATE TABLE IF NOT EXISTS menu_items (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        price NUMERIC(10,2) NOT NULL,
        category VARCHAR(15) NOT NULL,
        image VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT menu_items_category_check CHECK (category IN ('Non-Veg', 'Vegetarian', 'Desserts'))
      );

      CREATE TABLE IF NOT EXISTS cart (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        item_id INTEGER REFERENCES menu_items(id),
        quantity INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total DECIMAL(10,2) NOT NULL,
        status VARCHAR(50) DEFAULT 'Confirmed',
        address_id INTEGER,
        payment_method VARCHAR(50)
      );

      CREATE TABLE IF NOT EXISTS order_items (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id),
        item_id INTEGER REFERENCES menu_items(id),
        name VARCHAR(255),
        price DECIMAL(10,2),
        quantity INTEGER
      );

      CREATE TABLE IF NOT EXISTS favourites (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        item_id INTEGER REFERENCES menu_items(id)
      );

      CREATE TABLE IF NOT EXISTS addresses (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        name VARCHAR(255) NOT NULL,
        street TEXT NOT NULL,
        city VARCHAR(100) NOT NULL,
        state VARCHAR(100) NOT NULL,
        zip VARCHAR(20) NOT NULL,
        mobile VARCHAR(20) NOT NULL,
        is_default BOOLEAN DEFAULT FALSE
      );

      CREATE TABLE IF NOT EXISTS loyalty (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        points INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS loyalty_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        description VARCHAR(255),
        points INTEGER,
        date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS referrals (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        code VARCHAR(50) UNIQUE,
        link TEXT
      );

      CREATE TABLE IF NOT EXISTS support_tickets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        subject VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        status VARCHAR(50) DEFAULT 'Open',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS support_chat (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        sender VARCHAR(50),
        content TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS offers (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        code VARCHAR(50) UNIQUE,
        discount INTEGER,
        image TEXT
      );

      CREATE TABLE IF NOT EXISTS testimonials (
        id SERIAL PRIMARY KEY,
        text TEXT NOT NULL,
        author VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Seed admin user
    const userExists = await client.query('SELECT * FROM users WHERE email = $1', [adminEmail]);
    if (userExists.rows.length === 0) {
      await client.query(
        'INSERT INTO users (name, email, phone, password, address, role) VALUES ($1, $2, $3, $4, $5, $6)',
        ['Admin', adminEmail, '1234567890', hashedPassword, 'Admin Address', 'admin']
      );
      console.log('Admin user seeded');
    }

    // Seed sample menu items
    const menuExists = await client.query('SELECT COUNT(*) FROM menu_items');
    if (menuExists.rows[0].count == 0) {
      await client.query(`
        INSERT INTO menu_items (name, price, category, image) VALUES
        ('Margherita Pizza', 250.00, 'Vegetarian', 'https://images.unsplash.com/photo-1513106580091-1d82408b8cd6'),
        ('Butter Chicken', 350.00, 'Non-Veg', 'https://images.unsplash.com/photo-1603894584373-5ac82b2ae398'),
        ('Chocolate Lava Cake', 150.00, 'Desserts', 'https://images.unsplash.com/photo-1617303421954-0db7df940ce3');
      `);
      console.log('Sample menu items seeded');
    }

    // Seed sample offers
    const offersExist = await client.query('SELECT COUNT(*) FROM offers');
    if (offersExist.rows[0].count == 0) {
      await client.query(`
        INSERT INTO offers (title, description, code, discount, image) VALUES
        ('20% Off First Order', 'Use code FIRST20 to get 20% off your first order!', 'FIRST20', 20, 'https://images.unsplash.com/photo-1513106580091-1d82408b8cd6'),
        ('Free Delivery', 'On orders above ₹500', 'FREEDEL', 10, 'https://images.unsplash.com/photo-1565299624946-b28f40a0ae38');
      `);
      console.log('Sample offers seeded');
    }

    // Seed sample testimonials
    const testimonialsExist = await client.query('SELECT COUNT(*) FROM testimonials');
    if (testimonialsExist.rows[0].count == 0) {
      await client.query(`
        INSERT INTO testimonials (text, author) VALUES
        ('The Butter Chicken was absolutely delicious!', 'Priya S.'),
        ('Fast delivery and great packaging!', 'Rahul M.'),
        ('Loved the Margherita Pizza, will order again!', 'Anita K.');
      `);
      console.log('Sample testimonials seeded');
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

  try {
    const client = await pool.connect();
    await client.query('DELETE FROM otps WHERE email = $1', [email]);
    await client.query(
      'INSERT INTO otps (email, otp, expires) VALUES ($1, $2, $3)',
      [email, otp, expires]
    );
    client.release();

    await transporter.sendMail(mailOptions);
    console.log(`OTP sent to ${email}`);
    res.json({ message: 'OTP sent' });
  } catch (err) {
    console.error('OTP request error:', err.message);
    res.status(500).json({ message: 'Failed to send OTP' });
  }
});

// Signup
app.post('/api/users/signup', async (req, res) => {
  const { name, email, phone, password, address, otp } = req.body;
  console.log(`Signup attempt: ${email}, OTP: ${otp}`);

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
      console.log(`Invalid or expired OTP for ${email}`);
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const userExists = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      client.release();
      console.log(`User already exists: ${email}`);
      return res.status(400).json({ message: 'User already exists' });
    }

    const phoneExists = await client.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if (phoneExists.rows.length > 0) {
      client.release();
      console.log(`Phone number already in use: ${phone}`);
      return res.status(400).json({ message: 'Phone number already in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await client.query(
      'INSERT INTO users (name, email, phone, password, address, role) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, role',
      [name, email, phone, hashedPassword, address, 'user']
    );
    const user = result.rows[0];

    // Initialize referral code and link
    const referralCode = `DEL${Math.floor(100 + Math.random() * 900)}`;
    const referralLink = `https://delicute.onrender.com/refer/${referralCode}`;
    await client.query(
      'INSERT INTO referrals (user_id, code, link) VALUES ($1, $2, $3)',
      [user.id, referralCode, referralLink]
    );

    // Initialize loyalty points
    await client.query(
      'INSERT INTO loyalty (user_id, points) VALUES ($1, $2)',
      [user.id, 0]
    );

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    await client.query('DELETE FROM otps WHERE email = $1', [email]);
    client.release();

    console.log(`Signup successful: ${email}`);
    res.status(201).json({ token });
  } catch (err) {
    console.error('Signup error:', err.message);
    res.status(500).json({ message: 'Signup failed: ' + err.message });
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
    if (!payload) {
      console.log('Invalid Google token: No payload');
      return res.status(400).json({ message: 'Invalid Google token' });
    }

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

      // Initialize referral code and link
      const referralCode = `DEL${Math.floor(100 + Math.random() * 900)}`;
      const referralLink = `https://delicute.onrender.com/refer/${referralCode}`;
      await client.query(
        'INSERT INTO referrals (user_id, code, link) VALUES ($1, $2, $3)',
        [user.id, referralCode, referralLink]
      );

      // Initialize loyalty points
      await client.query(
        'INSERT INTO loyalty (user_id, points) VALUES ($1, $2)',
        [user.id, 0]
      );

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

// Dynamic Content Endpoints for index.html
app.get('/api/content/offers', async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT description FROM offers WHERE code = $1', ['FIRST20']);
    client.release();
    if (result.rows.length === 0) {
      return res.json({ offerText: 'Check back soon for exciting offers!' });
    }
    res.json({ offerText: result.rows[0].description });
  } catch (err) {
    console.error('Offers content fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch offers content' });
  }
});

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

app.get('/api/content/terms', async (req, res) => {
  try {
    res.json({
      content: `
        <p class="text-gray-700 mb-4">Welcome to DELICUTE. By using our services, you agree to the following terms and conditions:</p>
        <ul class="list-disc pl-6 text-gray-700">
          <li class="mb-2">You must provide accurate information during signup.</li>
          <li class="mb-2">Orders are subject to availability and confirmation.</li>
          <li class="mb-2">DELICUTE reserves the right to cancel orders due to unforeseen circumstances.</li>
          <li class="mb-2">All payments are processed securely through our payment gateway.</li>
          <li class="mb-2">We comply with the Information Technology Act, 2000 for data protection.</li>
        </ul>
        <p class="text-gray-700 mt-4">For any questions, contact us at <a href="mailto:support@delicute.com" class="text-orange-600 hover:underline">support@delicute.com</a>.</p>
      `
    });
  } catch (err) {
    console.error('Terms fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch terms' });
  }
});

app.get('/api/content/privacy', async (req, res) => {
  try {
    res.json({
      content: `
        <p class="text-gray-700 mb-4">At DELICUTE, we value your privacy. This policy outlines how we handle your data:</p>
        <ul class="list-disc pl-6 text-gray-700">
          <li class="mb-2">We collect personal information (name, email, phone, address) to process orders.</li>
          <li class="mb-2">Your data is stored securely and not shared with third parties, except for payment processing.</li>
          <li class="mb-2">We use cookies to enhance your browsing experience.</li>
          <li class="mb-2">You can request deletion of your data by contacting us.</li>
          <li class="mb-2">We comply with the Information Technology Act, 2000.</li>
        </ul>
        <p class="text-gray-700 mt-4">For more details, email us at <a href="mailto:support@delicute.com" class="text-orange-600 hover:underline">support@delicute.com</a>.</p>
      `
    });
  } catch (err) {
    console.error('Privacy fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch privacy policy' });
  }
});

// Status
app.get('/api/status', authenticateToken, async (req, res) => {
  try {
    res.json({ isOpen: true, prepTime: 30 });
  } catch (err) {
    console.error('Status fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch status' });
  }
});

// Offers
app.get('/api/offers', authenticateToken, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT id, title, description, code, discount, image FROM offers');
    client.release();
    res.json(result.rows);
  } catch (err) {
    console.error('Offers fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch offers' });
  }
});

// Menu
app.get('/api/menu', authenticateToken, async (req, res) => {
  const { category, price, search } = req.query;

  try {
    let sql = 'SELECT id, name, price, category, image FROM menu_items';
    const params = [];
    let conditions = [];

    if (search) {
      conditions.push('LOWER(name) LIKE LOWER($' + (params.length + 1) + ')');
      params.push(`%${search}%`);
    }
    if (category && category !== 'all') {
      conditions.push('category = $' + (params.length + 1));
      params.push(category);
    }
    if (price && price !== 'all') {
      const [min, max] = price.split('-').map(Number);
      conditions.push('price >= $' + (params.length + 1));
      params.push(min);
      if (max) {
        conditions.push('price <= $' + (params.length + 1));
        params.push(max);
      }
    }
    if (conditions.length > 0) {
      sql += ' WHERE ' + conditions.join(' AND ');
    }

    const client = await pool.connect();
    const result = await client.query(sql, params);
    client.release();

    console.log(`Menu fetched for user ${req.user.email}`);
    res.json(result.rows);
  } catch (err) {
    console.error('Menu fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch menu' });
  }
});

// Cart
app.get('/api/cart', authenticateToken, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query(`
      SELECT c.id, c.quantity, m.id AS item_id, m.name, m.price
      FROM cart c
      JOIN menu_items m ON c.item_id = m.id
      WHERE c.user_id = $1
    `, [req.user.id]);
    client.release();
    res.json({ items: result.rows });
  } catch (err) {
    console.error('Cart fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch cart' });
  }
});

app.post('/api/cart/add', authenticateToken, async (req, res) => {
  const { item } = req.body;
  if (!item || !item.id) {
    console.log('Invalid item data');
    return res.status(400).json({ message: 'Invalid item data' });
  }

  try {
    const client = await pool.connect();
    const itemExists = await client.query('SELECT * FROM menu_items WHERE id = $1', [item.id]);
    if (itemExists.rows.length === 0) {
      client.release();
      console.log(`Item not found: ${item.id}`);
      return res.status(404).json({ message: 'Item not found' });
    }

    const existingCartItem = await client.query(
      'SELECT * FROM cart WHERE user_id = $1 AND item_id = $2',
      [req.user.id, item.id]
    );
    if (existingCartItem.rows.length > 0) {
      await client.query(
        'UPDATE cart SET quantity = quantity + 1 WHERE user_id = $1 AND item_id = $2',
        [req.user.id, item.id]
      );
    } else {
      await client.query(
        'INSERT INTO cart (user_id, item_id, quantity) VALUES ($1, $2, $3)',
        [req.user.id, item.id, 1]
      );
    }
    client.release();

    console.log(`Item added to cart for user ${req.user.email}: ${item.id}`);
    res.json({ success: true });
  } catch (err) {
    console.error('Add to cart error:', err.message);
    res.status(500).json({ message: 'Failed to add to cart' });
  }
});

app.post('/api/cart/update', authenticateToken, async (req, res) => {
  const { itemId, action } = req.body;
  if (!itemId || !['increase', 'decrease'].includes(action)) {
    return res.status(400).json({ message: 'Invalid request' });
  }

  try {
    const client = await pool.connect();
    const cartItem = await client.query(
      'SELECT * FROM cart WHERE user_id = $1 AND item_id = $2',
      [req.user.id, itemId]
    );
    if (cartItem.rows.length === 0) {
      client.release();
      return res.status(404).json({ message: 'Item not in cart' });
    }

    if (action === 'increase') {
      await client.query(
        'UPDATE cart SET quantity = quantity + 1 WHERE user_id = $1 AND item_id = $2',
        [req.user.id, itemId]
      );
    } else if (action === 'decrease') {
      if (cartItem.rows[0].quantity > 1) {
        await client.query(
          'UPDATE cart SET quantity = quantity - 1 WHERE user_id = $1 AND item_id = $2',
          [req.user.id, itemId]
        );
      } else {
        await client.query(
          'DELETE FROM cart WHERE user_id = $1 AND item_id = $2',
          [req.user.id, itemId]
        );
      }
    }
    client.release();
    res.json({ success: true });
  } catch (err) {
    console.error('Cart update error:', err.message);
    res.status(500).json({ message: 'Failed to update cart' });
  }
});

app.post('/api/cart/remove', authenticateToken, async (req, res) => {
  const { itemId } = req.body;
  if (!itemId) {
    return res.status(400).json({ message: 'Item ID required' });
  }

  try {
    const client = await pool.connect();
    await client.query(
      'DELETE FROM cart WHERE user_id = $1 AND item_id = $2',
      [req.user.id, itemId]
    );
    client.release();
    res.json({ success: true });
  } catch (err) {
    console.error('Cart remove error:', err.message);
    res.status(500).json({ message: 'Failed to remove item' });
  }
});

app.post('/api/cart/apply-coupon', authenticateToken, async (req, res) => {
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ message: 'Coupon code required' });
  }

  try {
    const client = await pool.connect();
    const offer = await client.query('SELECT * FROM offers WHERE code = $1', [code]);
    client.release();
    if (offer.rows.length === 0) {
      return res.status(404).json({ message: 'Invalid coupon code' });
    }
    res.json({ success: true, discount: offer.rows[0].discount });
  } catch (err) {
    console.error('Coupon apply error:', err.message);
    res.status(500).json({ message: 'Failed to apply coupon' });
  }
});

// Orders
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const client = await pool.connect();
    const orders = await client.query(`
      SELECT o.id, o.date, o.total, o.status,
             json_agg(json_build_object('name', oi.name)) AS items
      FROM orders o
      LEFT JOIN order_items oi ON o.id = oi.order_id
      WHERE o.user_id = $1
      GROUP BY o.id, o.date, o.total, o.status
    `, [req.user.id]);
    client.release();
    res.json(orders.rows.map(o => ({
      id: o.id,
      date: o.date,
      items: o.items,
      total: o.total,
      status: o.status
    })));
  } catch (err) {
    console.error('Orders fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch orders' });
  }
});

app.get('/api/cancellation-policy', authenticateToken, async (req, res) => {
  try {
    res.json({ text: 'Cancel within 10 mins for full refund' });
  } catch (err) {
    console.error('Cancellation policy fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch cancellation policy' });
  }
});

app.get('/api/orders/:orderId/track', authenticateToken, async (req, res) => {
  const { orderId } = req.params;
  try {
    const client = await pool.connect();
    const order = await client.query('SELECT * FROM orders WHERE id = $1 AND user_id = $2', [orderId, req.user.id]);
    client.release();
    if (order.rows.length === 0) {
      return res.status(404).json({ message: 'Order not found' });
    }
    res.json({
      status: order.rows[0].status,
      deliveryPartner: { name: 'Jane Doe', contact: '9876543212' }
    });
  } catch (err) {
    console.error('Order track error:', err.message);
    res.status(500).json({ message: 'Failed to track order' });
  }
});

app.post('/api/orders/:orderId/reorder', authenticateToken, async (req, res) => {
  const { orderId } = req.params;
  try {
    const client = await pool.connect();
    const orderItems = await client.query('SELECT item_id, quantity FROM order_items WHERE order_id = $1', [orderId]);
    for (const item of orderItems.rows) {
      const existingCartItem = await client.query(
        'SELECT * FROM cart WHERE user_id = $1 AND item_id = $2',
        [req.user.id, item.item_id]
      );
      if (existingCartItem.rows.length > 0) {
        await client.query(
          'UPDATE cart SET quantity = quantity + $1 WHERE user_id = $2 AND item_id = $3',
          [item.quantity, req.user.id, item.item_id]
        );
      } else {
        await client.query(
          'INSERT INTO cart (user_id, item_id, quantity) VALUES ($1, $2, $3)',
          [req.user.id, item.item_id, item.quantity]
        );
      }
    }
    client.release();
    res.json({ success: true });
  } catch (err) {
    console.error('Reorder error:', err.message);
    res.status(500).json({ message: 'Failed to reorder' });
  }
});

app.post('/api/orders/:orderId/rate', authenticateToken, async (req, res) => {
  const { orderId } = req.params;
  const { rating, comment } = req.body;
  try {
    // Assuming a ratings table could be added in the future
    res.json({ success: true });
  } catch (err) {
    console.error('Order rate error:', err.message);
    res.status(500).json({ message: 'Failed to rate order' });
  }
});

// Favourites
app.get('/api/favourites', authenticateToken, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query(`
      SELECT m.id, m.name, m.price, m.image
      FROM favourites f
      JOIN menu_items m ON f.item_id = m.id
      WHERE f.user_id = $1
    `, [req.user.id]);
    client.release();
    res.json(result.rows);
  } catch (err) {
    console.error('Favourites fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch favourites' });
  }
});

app.post('/api/favourites/add', authenticateToken, async (req, res) => {
  const { itemId } = req.body;
  try {
    const client = await pool.connect();
    const itemExists = await client.query('SELECT * FROM menu_items WHERE id = $1', [itemId]);
    if (itemExists.rows.length === 0) {
      client.release();
      return res.status(404).json({ message: 'Item not found' });
    }
    await client.query(
      'INSERT INTO favourites (user_id, item_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.user.id, itemId]
    );
    client.release();
    res.json({ success: true });
  } catch (err) {
    console.error('Add favourite error:', err.message);
    res.status(500).json({ message: 'Failed to add favourite' });
  }
});

app.post('/api/favourites/remove', authenticateToken, async (req, res) => {
  const { itemId } = req.body;
  try {
    const client = await pool.connect();
    await client.query(
      'DELETE FROM favourites WHERE user_id = $1 AND item_id = $2',
      [req.user.id, itemId]
    );
    client.release();
    res.json({ success: true });
  } catch (err) {
    console.error('Remove favourite error:', err.message);
    res.status(500).json({ message: 'Failed to remove favourite' });
  }
});

// Addresses
app.get('/api/addresses', authenticateToken, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT * FROM addresses WHERE user_id = $1', [req.user.id]);
    client.release();
    res.json(result.rows);
  } catch (err) {
    console.error('Addresses fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch addresses' });
  }
});

app.post('/api/addresses/add', authenticateToken, async (req, res) => {
  const { name, street, city, state, zip, mobile } = req.body;
  try {
    const client = await pool.connect();
    const result = await client.query(
      'INSERT INTO addresses (user_id, name, street, city, state, zip, mobile) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [req.user.id, name, street, city, state, zip, mobile]
    );
    client.release();
    res.json({ success: true });
  } catch (err) {
    console.error('Add address error:', err.message);
    res.status(500).json({ message: 'Failed to add address' });
  }
});

app.post('/api/addresses/update', authenticateToken, async (req, res) => {
  const { id, name, street, city, state, zip, mobile } = req.body;
  try {
    const client = await pool.connect();
    const result = await client.query(
      'UPDATE addresses SET name = $1, street = $2, city = $3, state = $4, zip = $5, mobile = $6 WHERE id = $7 AND user_id = $8 RETURNING *',
      [name, street, city, state, zip, mobile, id, req.user.id]
    );
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Address not found' });
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Update address error:', err.message);
    res.status(500).json({ message: 'Failed to update address' });
  }
});

app.post('/api/addresses/delete', authenticateToken, async (req, res) => {
  const { id } = req.body;
  try {
    const client = await pool.connect();
    await client.query('DELETE FROM addresses WHERE id = $1 AND user_id = $2', [id, req.user.id]);
    client.release();
    res.json({ success: true });
  } catch (err) {
    console.error('Delete address error:', err.message);
    res.status(500).json({ message: 'Failed to delete address' });
  }
});

app.post('/api/addresses/set-default', authenticateToken, async (req, res) => {
  const { id } = req.body;
  try {
    const client = await pool.connect();
    await client.query('UPDATE addresses SET is_default = FALSE WHERE user_id = $1', [req.user.id]);
    await client.query('UPDATE addresses SET is_default = TRUE WHERE id = $1 AND user_id = $2', [id, req.user.id]);
    client.release();
    res.json({ success: true });
  } catch (err) {
    console.error('Set default address error:', err.message);
    res.status(500).json({ message: 'Failed to set default address' });
  }
});

// Checkout
app.post('/api/checkout', authenticateToken, async (req, res) => {
  const { addressId, paymentMethod } = req.body;
  if (!addressId || !paymentMethod) {
    return res.status(400).json({ message: 'Address and payment method required' });
  }

  try {
    const client = await pool.connect();
    const cart = await client.query(`
      SELECT c.quantity, m.id, m.name, m.price
      FROM cart c
      JOIN menu_items m ON c.item_id = m.id
      WHERE c.user_id = $1
    `, [req.user.id]);

    if (cart.rows.length === 0) {
      client.release();
      return res.status(400).json({ message: 'Cart is empty' });
    }

    const total = cart.rows.reduce((sum, item) => sum + item.price * item.quantity, 0);
    const orderResult = await client.query(
      'INSERT INTO orders (user_id, total, address_id, payment_method) VALUES ($1, $2, $3, $4) RETURNING id',
      [req.user.id, total, addressId, paymentMethod]
    );
    const orderId = orderResult.rows[0].id;

    for (const item of cart.rows) {
      await client.query(
        'INSERT INTO order_items (order_id, item_id, name, price, quantity) VALUES ($1, $2, $3, $4, $5)',
        [orderId, item.id, item.name, item.price, item.quantity]
      );
    }

    await client.query('DELETE FROM cart WHERE user_id = $1', [req.user.id]);

    // Award loyalty points (e.g., 1 point per ₹100 spent)
    const points = Math.floor(total / 100);
    await client.query(
      'UPDATE loyalty SET points = points + $1 WHERE user_id = $2',
      [points, req.user.id]
    );
    await client.query(
      'INSERT INTO loyalty_history (user_id, description, points) VALUES ($1, $2, $3)',
      [req.user.id, `Order #${orderId}`, points]
    );

    client.release();
    res.json({ success: true });
  } catch (err) {
    console.error('Checkout error:', err.message);
    res.status(500).json({ message: 'Failed to checkout' });
  }
});

// Loyalty
app.get('/api/loyalty', authenticateToken, async (req, res) => {
  try {
    const client = await pool.connect();
    const loyalty = await client.query('SELECT points FROM loyalty WHERE user_id = $1', [req.user.id]);
    const history = await client.query('SELECT description, points, date FROM loyalty_history WHERE user_id = $1', [req.user.id]);
    client.release();
    res.json({
      points: loyalty.rows[0]?.points || 0,
      history: history.rows
    });
  } catch (err) {
    console.error('Loyalty fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch loyalty' });
  }
});

// Referrals
app.get('/api/referrals', authenticateToken, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT code, link FROM referrals WHERE user_id = $1', [req.user.id]);
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Referral not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Referrals fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch referrals' });
  }
});

// Support
app.get('/api/support/tickets', authenticateToken, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT id, subject, status, created_at FROM support_tickets WHERE user_id = $1', [req.user.id]);
    client.release();
    res.json(result.rows);
  } catch (err) {
    console.error('Support tickets fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch tickets' });
  }
});

app.post('/api/support/tickets/create', authenticateToken, async (req, res) => {
  const { subject, description } = req.body;
  if (!subject || !description) {
    return res.status(400).json({ message: 'Subject and description required' });
  }

  try {
    const client = await pool.connect();
    await client.query(
      'INSERT INTO support_tickets (user_id, subject, description) VALUES ($1, $2, $3)',
      [req.user.id, subject, description]
    );
    client.release();
    res.json({ success: true });
  } catch (err) {
    console.error('Create ticket error:', err.message);
    res.status(500).json({ message: 'Failed to create ticket' });
  }
});

app.get('/api/support/chat', authenticateToken, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT sender, content, timestamp FROM support_chat WHERE user_id = $1', [req.user.id]);
    client.release();
    res.json(result.rows);
  } catch (err) {
    console.error('Support chat fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch chat' });
  }
});

app.post('/api/support/chat/send', authenticateToken, async (req, res) => {
  const { message } = req.body;
  if (!message) {
    return res.status(400).json({ message: 'Message required' });
  }

  try {
    const client = await pool.connect();
    await client.query(
      'INSERT INTO support_chat (user_id, sender, content) VALUES ($1, $2, $3)',
      [req.user.id, 'user', message]
    );
    // Simulate admin response
    setTimeout(async () => {
      await client.query(
        'INSERT INTO support_chat (user_id, sender, content) VALUES ($1, $2, $3)',
        [req.user.id, 'admin', 'Thank you for your message. How can we assist you further?']
      );
    }, 2000);
    client.release();
    res.json({ success: true });
  } catch (err) {
    console.error('Send chat error:', err.message);
    res.status(500).json({ message: 'Failed to send message' });
  }
});

// Profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query(
      'SELECT id, name, email, phone, profile_image FROM users WHERE id = $1',
      [req.user.id]
    );
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Profile fetch error:', err.message);
    res.status(500).json({ message: 'Failed to fetch profile' });
  }
});

app.post('/api/profile/update', authenticateToken, async (req, res) => {
  const { name, email, phone } = req.body;
  try {
    const client = await pool.connect();
    const result = await client.query(
      'UPDATE users SET name = $1, email = $2, phone = $3 WHERE id = $4 RETURNING id, name, email, phone, profile_image',
      [name, email, phone, req.user.id]
    );
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Profile update error:', err.message);
    res.status(500).json({ message: 'Failed to update profile' });
  }
});

app.post('/api/profile/upload-image', upload.single('image'), authenticateToken, async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No image uploaded' });
  }

  try {
    // In a real app, you'd upload to a cloud storage like AWS S3
    // For simplicity, store as base64 in DB
    const imageUrl = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
    const client = await pool.connect();
    await client.query(
      'UPDATE users SET profile_image = $1 WHERE id = $2',
      [imageUrl, req.user.id]
    );
    client.release();
    res.json({ success: true, imageUrl });
  } catch (err) {
    console.error('Profile image upload error:', err.message);
    res.status(500).json({ message: 'Failed to upload image' });
  }
});

// Logout
app.post('/api/logout', authenticateToken, async (req, res) => {
  // JWT is stateless; client should remove token
  res.json({ success: true });
});

// Start server
const PORT = process.env.PORT || 3000;
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