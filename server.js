const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const Razorpay = require('razorpay');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
  origin: ['https://delicute.onrender.com', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

// File Upload Setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});
const upload = multer({ storage });

// Environment Variables
const {
  DATABASE_URL,
  JWT_SECRET,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  EMAIL_USER,
  EMAIL_PASS,
  RAZORPAY_KEY_ID,
  RAZORPAY_KEY_SECRET,
  PORT = 3000,
  CLIENT_URL = 'http://localhost:3000',
  NODE_ENV = 'development'
} = process.env;

// Database Connection
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 5000,
  max: 10
});

// Initialize Database
async function initializeDatabase() {
  try {
    console.log('Attempting to connect to PostgreSQL...');
    const client = await pool.connect();
    console.log('✅ Connected to PostgreSQL database');

    // Check if tables exist
    const tableCheck = await client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      AND table_name IN ('users', 'menu_items', 'offers', 'orders', 'restaurant_status', 'coupons', 'contact_messages')
    `);
    const existingTables = tableCheck.rows.map(row => row.table_name);

    // Create tables only if they don't exist
    if (!existingTables.includes('users')) {
      await client.query(`
        CREATE TABLE users (
          id SERIAL PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          email VARCHAR(255) UNIQUE NOT NULL,
          phone VARCHAR(20),
          password VARCHAR(255),
          is_admin BOOLEAN DEFAULT FALSE,
          is_blocked BOOLEAN DEFAULT FALSE,
          profile_image VARCHAR(255),
          reset_otp VARCHAR(6),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      console.log('✅ Created users table');
    }

    if (!existingTables.includes('menu_items')) {
      await client.query(`
        CREATE TABLE menu_items (
          id SERIAL PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          category VARCHAR(100) NOT NULL,
          price INTEGER NOT NULL,
          description TEXT,
          image VARCHAR(255),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      console.log('✅ Created menu_items table');
    }

    if (!existingTables.includes('offers')) {
      await client.query(`
        CREATE TABLE offers (
          id SERIAL PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          description TEXT,
          price INTEGER NOT NULL,
          image VARCHAR(255),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      console.log('✅ Created offers table');
    }

    if (!existingTables.includes('orders')) {
      await client.query(`
        CREATE TABLE orders (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id),
          items JSONB NOT NULL,
          total INTEGER NOT NULL,
          status VARCHAR(50) DEFAULT 'Pending',
          payment_status VARCHAR(50) DEFAULT 'Pending',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      console.log('✅ Created orders table');
    }

    if (!existingTables.includes('restaurant_status')) {
      await client.query(`
        CREATE TABLE restaurant_status (
          id SERIAL PRIMARY KEY,
          status VARCHAR(50) DEFAULT 'Closed',
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO restaurant_status (status) 
        VALUES ('Closed') 
        ON CONFLICT DO NOTHING;
      `);
      console.log('✅ Created restaurant_status table and initialized status');
    }

    if (!existingTables.includes('coupons')) {
      await client.query(`
        CREATE TABLE coupons (
          id SERIAL PRIMARY KEY,
          code VARCHAR(50) UNIQUE NOT NULL,
          discount INTEGER NOT NULL,
          description TEXT,
          image VARCHAR(255),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      console.log('✅ Created coupons table');
    }

    if (!existingTables.includes('contact_messages')) {
      await client.query(`
        CREATE TABLE contact_messages (
          id SERIAL PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          email VARCHAR(255) NOT NULL,
          subject VARCHAR(255) NOT NULL,
          message TEXT NOT NULL,
          status VARCHAR(50) DEFAULT 'Pending',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      console.log('✅ Created contact_messages table');
    }

    // Ensure at least one admin user exists
    const adminCheck = await client.query('SELECT * FROM users WHERE is_admin = TRUE LIMIT 1');
    if (adminCheck.rows.length === 0) {
      const defaultAdminEmail = 'admin@delicute.com';
      const defaultAdminPassword = await bcrypt.hash('Admin123!', 10);
      await client.query(
        `INSERT INTO users (name, email, phone, password, is_admin) 
         VALUES ($1, $2, $3, $4, $5) 
         ON CONFLICT (email) DO NOTHING`,
        ['Default Admin', defaultAdminEmail, '1234567890', defaultAdminPassword, true]
      );
      console.log('✅ Created default admin user');
    }

    console.log('✅ Database initialization completed');
    const tables = await client.query("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'");
    console.log('📋 Public tables:', tables.rows.map(row => row.table_name));

    client.release();
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    throw error;
  }
}

// Email Transporter Setup
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS
  }
});

// Google OAuth Setup
const oauth2Client = new google.auth.OAuth2(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  `${CLIENT_URL}/api/auth/google/callback`
);

// Razorpay Setup
const razorpay = new Razorpay({
  key_id: RAZORPAY_KEY_ID,
  key_secret: RAZORPAY_KEY_SECRET
});

// Middleware to Verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied, no token provided' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// Middleware to Check Admin Privileges
async function authenticateAdmin(req, res, next) {
  try {
    const result = await pool.query('SELECT is_admin, is_blocked FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];
    if (!user || !user.is_admin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    if (user.is_blocked) {
      return res.status(403).json({ error: 'Account is blocked' });
    }
    next();
  } catch (error) {
    console.error('Admin authentication error:', error);
    res.status(500).json({ error: 'Invalid token or user not found' });
  }
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admindashboard.html', authenticateToken, authenticateAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/userdashboard.html', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'userdashboard.html'));
});

app.post('/api/files/upload', authenticateToken, authenticateAdmin, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  res.json({ fileUrl });
});

app.get('/api/auth/admin/me', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email, name, phone, profile_image, is_admin FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      _id: user.id,
      email: user.email,
      name: user.name,
      phone: user.phone,
      profileImage: user.profile_image,
      isAdmin: user.is_admin
    });
  } catch (error) {
    console.error('Error fetching admin details:', error);
    res.status(500).json({ error: 'Failed to fetch admin details' });
  }
});

app.put('/api/auth/admin/profile', authenticateToken, authenticateAdmin, async (req, res) => {
  const { profileImage } = req.body;
  if (!profileImage) {
    return res.status(400).json({ error: 'Profile image URL required' });
  }
  try {
    const result = await pool.query(
      'UPDATE users SET profile_image = $1 WHERE id = $2 RETURNING id, email, name, phone, profile_image, is_admin',
      [profileImage, req.user.id]
    );
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      _id: user.id,
      email: user.email,
      name: user.name,
      phone: user.phone,
      profileImage: user.profile_image,
      isAdmin: user.is_admin
    });
  } catch (error) {
    console.error('Error updating profile image:', error);
    res.status(500).json({ error: 'Failed to update profile image' });
  }
});

app.get('/api/menu', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM menu_items ORDER BY created_at DESC');
    const items = result.rows.map(item => ({
      _id: item.id,
      name: item.name,
      category: item.category,
      price: item.price,
      description: item.description,
      image: item.image,
      created_at: item.created_at
    }));
    res.json(items);
  } catch (error) {
    console.error('Error fetching menu items:', error);
    res.status(500).json({ error: 'Failed to fetch menu items' });
  }
});

app.get('/api/menu/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM menu_items WHERE id = $1', [id]);
    const item = result.rows[0];
    if (!item) return res.status(404).json({ error: 'Menu item not found' });
    res.json({
      _id: item.id,
      name: item.name,
      category: item.category,
      price: item.price,
      description: item.description,
      image: item.image
    });
  } catch (error) {
    console.error('Error fetching menu item:', error);
    res.status(500).json({ error: 'Failed to fetch menu item' });
  }
});

app.post('/api/menu', authenticateToken, authenticateAdmin, async (req, res) => {
  const { name, category, price, image, description } = req.body;
  if (!name || !category || !price) {
    return res.status(400).json({ error: 'Name, category, and price are required' });
  }
  if (typeof price !== 'number' || price <= 0) {
    return res.status(400).json({ error: 'Price must be a positive number' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO menu_items (name, category, price, image, description) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, category, price, image, description]
    );
    const item = result.rows[0];
    res.status(201).json({
      _id: item.id,
      name: item.name,
      category: item.category,
      price: item.price,
      description: item.description,
      image: item.image
    });
  } catch (error) {
    console.error('Error adding menu item:', error);
    res.status(500).json({ error: 'Failed to add menu item' });
  }
});

app.put('/api/menu/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, category, price, image, description } = req.body;
  if (!name || !category || !price) {
    return res.status(400).json({ error: 'Name, category, and price are required' });
  }
  if (typeof price !== 'number' || price <= 0) {
    return res.status(400).json({ error: 'Price must be a positive number' });
  }
  try {
    const result = await pool.query(
      'UPDATE menu_items SET name = $1, category = $2, price = $3, image = $4, description = $5 WHERE id = $6 RETURNING *',
      [name, category, price, image, description, id]
    );
    const item = result.rows[0];
    if (!item) return res.status(404).json({ error: 'Menu item not found' });
    res.json({
      _id: item.id,
      name: item.name,
      category: item.category,
      price: item.price,
      description: item.description,
      image: item.image
    });
  } catch (error) {
    console.error('Error updating menu item:', error);
    res.status(500).json({ error: 'Failed to update menu item' });
  }
});

app.delete('/api/menu/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM menu_items WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    res.json({ message: 'Menu item deleted successfully' });
  } catch (error) {
    console.error('Error deleting menu item:', error);
    res.status(500).json({ error: 'Failed to delete menu item' });
  }
});

app.get('/api/offers', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM offers ORDER BY created_at DESC');
    const offers = result.rows.map(offer => ({
      _id: offer.id,
      name: offer.name,
      price: offer.price,
      description: offer.description,
      image: offer.image,
      created_at: offer.created_at
    }));
    res.json(offers);
  } catch (error) {
    console.error('Error fetching offers:', error);
    res.status(500).json({ error: 'Failed to fetch offers' });
  }
});

app.get('/api/offers/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM offers WHERE id = $1', [id]);
    const offer = result.rows[0];
    if (!offer) return res.status(404).json({ error: 'Offer not found' });
    res.json({
      _id: offer.id,
      name: offer.name,
      price: offer.price,
      description: offer.description,
      image: offer.image
    });
  } catch (error) {
    console.error('Error fetching offer:', error);
    res.status(500).json({ error: 'Failed to fetch offer' });
  }
});

app.post('/api/offers', authenticateToken, authenticateAdmin, async (req, res) => {
  const { name, price, image, description } = req.body;
  if (!name || !price) {
    return res.status(400).json({ error: 'Name and price required' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO offers (name, price, image, description) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, price, image, description]
    );
    const offer = result.rows[0];
    res.status(201).json({
      _id: offer.id,
      name: offer.name,
      price: offer.price,
      description: offer.description,
      image: offer.image
    });
  } catch (error) {
    console.error('Error adding offer:', error);
    res.status(500).json({ error: 'Failed to add offer' });
  }
});

app.put('/api/offers/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, price, image, description } = req.body;
  if (!name || !price) {
    return res.status(400).json({ error: 'Name and price required' });
  }
  try {
    const result = await pool.query(
      'UPDATE offers SET name = $1, price = $2, image = $3, description = $4 WHERE id = $5 RETURNING *',
      [name, price, image, description, id]
    );
    const offer = result.rows[0];
    if (!offer) return res.status(404).json({ error: 'Offer not found' });
    res.json({
      _id: offer.id,
      name: offer.name,
      price: offer.price,
      description: offer.description,
      image: offer.image
    });
  } catch (error) {
    console.error('Error updating offer:', error);
    res.status(500).json({ error: 'Failed to update offer' });
  }
});

app.delete('/api/offers/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM offers WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Offer not found' });
    }
    res.json({ message: 'Offer deleted successfully' });
  } catch (error) {
    console.error('Error deleting offer:', error);
    res.status(500).json({ error: 'Failed to delete offer' });
  }
});

app.get('/api/coupons', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM coupons ORDER BY created_at DESC');
    const coupons = result.rows.map(coupon => ({
      _id: coupon.id,
      code: coupon.code,
      discount: coupon.discount,
      description: coupon.description,
      image: coupon.image,
      created_at: coupon.created_at
    }));
    res.json(coupons);
  } catch (error) {
    console.error('Error fetching coupons:', error);
    res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

app.get('/api/coupons/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM coupons WHERE id = $1', [id]);
    const coupon = result.rows[0];
    if (!coupon) return res.status(404).json({ error: 'Coupon not found' });
    res.json({
      _id: coupon.id,
      code: coupon.code,
      discount: coupon.discount,
      description: coupon.description,
      image: coupon.image
    });
  } catch (error) {
    console.error('Error fetching coupon:', error);
    res.status(500).json({ error: 'Failed to fetch coupon' });
  }
});

app.post('/api/coupons', authenticateToken, authenticateAdmin, async (req, res) => {
  const { code, discount, image, description } = req.body;
  if (!code || !discount) {
    return res.status(400).json({ error: 'Code and discount are required' });
  }
  if (typeof discount !== 'number' || discount < 1 || discount > 100) {
    return res.status(400).json({ error: 'Discount must be a number between 1 and 100' });
  }
  try {
    const codeCheck = await pool.query('SELECT * FROM coupons WHERE code = $1', [code]);
    if (codeCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Coupon code already exists' });
    }
    const result = await pool.query(
      'INSERT INTO coupons (code, discount, image, description) VALUES ($1, $2, $3, $4) RETURNING *',
      [code, discount, image, description]
    );
    const coupon = result.rows[0];
    res.status(201).json({
      _id: coupon.id,
      code: coupon.code,
      discount: coupon.discount,
      description: coupon.description,
      image: coupon.image,
      created_at: coupon.created_at
    });
  } catch (error) {
    console.error('Error adding coupon:', error);
    if (error.code === '23505') {
      return res.status(400).json({ error: 'Coupon code already exists' });
    }
    res.status(500).json({ error: 'Failed to add coupon' });
  }
});

app.put('/api/coupons/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { code, discount, image, description } = req.body;
  if (!code || !discount) {
    return res.status(400).json({ error: 'Code and discount are required' });
  }
  if (typeof discount !== 'number' || discount < 1 || discount > 100) {
    return res.status(400).json({ error: 'Discount must be a number between 1 and 100' });
  }
  try {
    const codeCheck = await pool.query('SELECT * FROM coupons WHERE code = $1 AND id != $2', [code, id]);
    if (codeCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Coupon code already exists' });
    }
    const result = await pool.query(
      'UPDATE coupons SET code = $1, discount = $2, image = $3, description = $4 WHERE id = $5 RETURNING *',
      [code, discount, image, description, id]
    );
    const coupon = result.rows[0];
    if (!coupon) return res.status(404).json({ error: 'Coupon not found' });
    res.json({
      _id: coupon.id,
      code: coupon.code,
      discount: coupon.discount,
      description: coupon.description,
      image: coupon.image
    });
  } catch (error) {
    console.error('Error updating coupon:', error);
    if (error.code === '23505') {
      return res.status(400).json({ error: 'Coupon code already exists' });
    }
    res.status(500).json({ error: 'Failed to update coupon' });
  }
});

app.delete('/api/coupons/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM coupons WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Coupon not found' });
    }
    res.json({ message: 'Coupon deleted successfully' });
  } catch (error) {
    console.error('Error deleting coupon:', error);
    res.status(500).json({ error: 'Failed to delete coupon' });
  }
});

app.get('/api/contact', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM contact_messages ORDER BY created_at DESC');
    const messages = result.rows.map(message => ({
      _id: message.id,
      name: message.name,
      email: message.email,
      subject: message.subject,
      message: message.message,
      status: message.status,
      created_at: message.created_at
    }));
    res.json(messages);
  } catch (error) {
    console.error('Error fetching contact messages:', error);
    res.status(500).json({ error: 'Failed to fetch contact messages' });
  }
});

app.get('/api/contact/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM contact_messages WHERE id = $1', [id]);
    const message = result.rows[0];
    if (!message) return res.status(404).json({ error: 'Message not found' });
    res.json({
      _id: message.id,
      name: message.name,
      email: message.email,
      subject: message.subject,
      message: message.message,
      status: message.status,
      created_at: message.created_at
    });
  } catch (error) {
    console.error('Error fetching contact message:', error);
    res.status(500).json({ error: 'Failed to fetch message' });
  }
});

app.post('/api/contact', async (req, res) => {
  const { name, email, subject, message } = req.body;
  if (!name || !email || !subject || !message) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO contact_messages (name, email, subject, message) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, email, subject, message]
    );
    const newMessage = result.rows[0];
    res.status(201).json({
      _id: newMessage.id,
      name: newMessage.name,
      email: newMessage.email,
      subject: newMessage.subject,
      message: newMessage.message,
      status: newMessage.status,
      created_at: newMessage.created_at
    });
  } catch (error) {
    console.error('Error adding contact message:', error);
    res.status(500).json({ error: 'Failed to add contact message' });
  }
});

app.post('/api/contact/:id/reply', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { subject, message: reply } = req.body;
  if (!subject || !reply) {
    return res.status(400).json({ error: 'Subject and reply are required' });
  }
  try {
    const messageResult = await pool.query('SELECT email, name FROM contact_messages WHERE id = $1', [id]);
    const message = messageResult.rows[0];
    if (!message) return res.status(404).json({ error: 'Message not found' });

    await transporter.sendMail({
      from: `"Delicute" <${EMAIL_USER}>`,
      to: message.email,
      subject: subject,
      text: reply,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #f59e0b;">Delicute</h2>
          <p>Dear ${message.name},</p>
          <p>${reply}</p>
          <p>Best regards,<br>Delicute Team</p>
        </div>
      `
    });

    await pool.query('UPDATE contact_messages SET status = $1 WHERE id = $2', ['Replied', id]);
    res.json({ message: 'Reply sent successfully' });
  } catch (error) {
    console.error('Error sending reply:', error);
    res.status(500).json({ error: 'Failed to send reply' });
  }
});

app.delete('/api/contact/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM contact_messages WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Message not found' });
    }
    res.json({ message: 'Message deleted successfully' });
  } catch (error) {
    console.error('Error deleting contact message:', error);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

app.get('/api/orders', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT orders.*, users.email, users.name as customer_name 
      FROM orders 
      JOIN users ON orders.user_id = users.id 
      ORDER BY orders.created_at DESC
    `);
    const orders = result.rows.map(order => ({
      _id: order.id,
      customerName: order.customer_name,
      email: order.email,
      total: order.total,
      status: order.status,
      paymentStatus: order.payment_status,
      items: order.items,
      created_at: order.created_at
    }));
    res.json(orders);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

app.put('/api/orders/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!['Pending', 'Confirmed', 'Delivered', 'Cancelled'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  try {
    const result = await pool.query(
      'UPDATE orders SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    const order = result.rows[0];
    res.json({
      _id: order.id,
      status: order.status
    });
  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

app.post('/api/orders/:id/refund', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'UPDATE orders SET status = $1, payment_status = $2 WHERE id = $3 RETURNING *',
      ['Cancelled', 'Refunded', id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json({ message: 'Order refunded successfully' });
  } catch (error) {
    console.error('Error processing refund:', error);
    res.status(500).json({ error: 'Failed to process refund' });
  }
});

app.get('/api/orders/customer/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC', [id]);
    const orders = result.rows.map(order => ({
      _id: order.id,
      total: order.total,
      status: order.status,
      paymentStatus: order.payment_status,
      items: order.items,
      created_at: order.created_at
    }));
    res.json(orders);
  } catch (error) {
    console.error('Error fetching customer orders:', error);
    res.status(500).json({ error: 'Failed to fetch customer orders' });
  }
});

app.get('/api/users', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, phone, is_blocked FROM users WHERE is_admin = FALSE ORDER BY created_at DESC');
    const customers = result.rows.map(user => ({
      _id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      status: user.is_blocked ? 'Blocked' : 'Active'
    }));
    res.json(customers);
  } catch (error) {
    console.error('Error fetching customers:', error);
    res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

app.get('/api/users/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const userResult = await pool.query('SELECT id, name, email, phone, is_blocked FROM users WHERE id = $1 AND is_admin = FALSE', [id]);
    const user = userResult.rows[0];
    if (!user) return res.status(404).json({ error: 'Customer not found' });

    const ordersResult = await pool.query('SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC', [id]);
    const orders = ordersResult.rows.map(order => ({
      _id: order.id,
      total: order.total,
      status: order.status,
      createdAt: order.created_at
    }));

    res.json({
      _id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      status: user.is_blocked ? 'Blocked' : 'Active',
      orders
    });
  } catch (error) {
    console.error('Error fetching customer:', error);
    res.status(500).json({ error: 'Failed to fetch customer' });
  }
});

app.put('/api/users/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const isBlocked = status === 'Blocked';
  try {
    const result = await pool.query(
      'UPDATE users SET is_blocked = $1 WHERE id = $2 AND is_admin = FALSE RETURNING id, name, email, phone, is_blocked',
      [isBlocked, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }
    const user = result.rows[0];
    res.json({
      _id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      status: user.is_blocked ? 'Blocked' : 'Active'
    });
  } catch (error) {
    console.error('Error updating customer status:', error);
    res.status(500).json({ error: 'Failed to update customer status' });
  }
});

app.get('/api/restaurant/status', async (req, res) => {
  try {
    const result = await pool.query('SELECT status FROM restaurant_status LIMIT 1');
    const status = result.rows[0]?.status || 'Closed';
    res.json({ status });
  } catch (error) {
    console.error('Error fetching restaurant status:', error);
    res.status(500).json({ error: 'Failed to fetch restaurant status' });
  }
});

app.put('/api/restaurant/status', authenticateToken, authenticateAdmin, async (req, res) => {
  let { status } = req.body;
  status = status.charAt(0).toUpperCase() + status.slice(1).toLowerCase();
  if (!['Open', 'Closed'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  try {
    const result = await pool.query(
      'UPDATE restaurant_status SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = 1 RETURNING *',
      [status]
    );
    if (result.rows.length === 0) {
      await pool.query(
        'INSERT INTO restaurant_status (id, status, updated_at) VALUES (1, $1, CURRENT_TIMESTAMP) RETURNING *',
        [status]
      );
    }
    res.json({ status });
  } catch (error) {
    console.error('Error updating restaurant status:', error);
    res.status(500).json({ error: 'Failed to update restaurant status' });
  }
});

app.post('/api/auth/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  try {
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, phone, password, is_admin) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, is_admin',
      [name, email, phone, hashedPassword, false]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Failed to sign up' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (user.is_blocked) {
      return res.status(403).json({ error: 'Account is blocked' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Failed to log in' });
  }
});

app.post('/api/auth/admin/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  try {
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, phone, password, is_admin) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, is_admin',
      [name, email, phone, hashedPassword, true]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token });
  } catch (error) {
    console.error('Admin signup error:', error);
    res.status(500).json({ error: 'Failed to sign up admin' });
  }
});

app.post('/api/auth/admin/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 AND is_admin = $2', [email, true]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials or not an admin' });
    }
    if (user.is_blocked) {
      return res.status(403).json({ error: 'Account is blocked' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Failed to log in admin' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await pool.query('UPDATE users SET reset_otp = $1 WHERE email = $2', [otp, email]);
    await transporter.sendMail({
      from: `"Delicute" <${EMAIL_USER}>`,
      to: email,
      subject: 'Delicute - Password Reset OTP',
      text: `Your OTP: ${otp}`,
      html: `<p>Your OTP: <strong>${otp}</strong></p>`
    });
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 AND reset_otp = $2', [email, otp]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: 'Invalid OTP' });
    if (newPassword) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await pool.query('UPDATE users SET password = $1, reset_otp = NULL WHERE email = $2', [hashedPassword, email]);
      res.json({ message: 'Password reset successfully' });
    } else {
      res.json({ message: 'OTP verified successfully' });
    }
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

app.post('/api/auth/admin/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 AND is_admin = $2', [email, true]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'Admin not found' });
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await pool.query('UPDATE users SET reset_otp = $1 WHERE email = $2', [otp, email]);
    await transporter.sendMail({
      from: `"Delicute" <${EMAIL_USER}>`,
      to: email,
      subject: 'Delicute - Admin Password Reset OTP',
      text: `Your OTP: ${otp}`,
      html: `<p>Your OTP: <strong>${otp}</strong></p>`
    });
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Error sending admin OTP:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

app.post('/api/auth/reset-password/admin', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 AND reset_otp = $2 AND is_admin = $3', [email, otp, true]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: 'Invalid OTP or not an admin' });
    if (newPassword) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await pool.query('UPDATE users SET password = $1, reset_otp = NULL WHERE email = $2', [hashedPassword, email]);
      res.json({ message: 'Password reset successfully' });
    } else {
      res.json({ message: 'OTP verified successfully' });
    }
  } catch (error) {
    console.error('Admin reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Google OAuth Routes
app.get('/api/auth/google', (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    scope: ['profile', 'email'],
    redirect_uri: `${CLIENT_URL}/api/auth/google/callback`
  });
  res.redirect(url);
});

app.get('/api/auth/google/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) {
    console.error('Google OAuth callback error:', error);
    return res.redirect(`${CLIENT_URL}/?error=${encodeURIComponent('Google authentication failed')}`);
  }
  try {
    // Exchange authorization code for tokens
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // Fetch user info
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data } = await oauth2.userinfo.get();
    const { email, name } = data;

    // Check if user exists or create new user
    let result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    let user = result.rows[0];
    if (!user) {
      result = await pool.query(
        'INSERT INTO users (name, email, is_admin) VALUES ($1, $2, $3) RETURNING id, email, is_admin',
        [name || 'Google User', email, false]
      );
      user = result.rows[0];
    }

    // Check if user is blocked
    if (user.is_blocked) {
      return res.redirect(`${CLIENT_URL}/?error=${encodeURIComponent('Account is blocked')}`);
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, isAdmin: user.is_admin },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Redirect to frontend with token
    res.redirect(`${CLIENT_URL}/?token=${encodeURIComponent(token)}`);
  } catch (error) {
    console.error('Google OAuth error:', error);
    res.redirect(`${CLIENT_URL}/?error=${encodeURIComponent('Google authentication error')}`);
  }
});

app.post('/api/orders', authenticateToken, async (req, res) => {
  const { items, total } = req.body;
  const userId = req.user.id;
  if (!items || !total) {
    return res.status(400).json({ error: 'Items and total are required' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO orders (user_id, items, total) VALUES ($1, $2, $3) RETURNING id',
      [userId, JSON.stringify(items), total]
    );
    const orderId = result.rows[0].id;
    const options = {
      amount: total * 100,
      currency: 'INR',
      receipt: `order_${orderId}`
    };
    const razorpayOrder = await razorpay.orders.create(options);
    res.json({ orderId: razorpayOrder.id, amount: total * 100, currency: 'INR' });
  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

app.post('/api/payment/verify', async (req, res) => {
  const { orderId, paymentId, signature } = req.body;
  try {
    const generatedSignature = crypto
      .createHmac('sha256', RAZORPAY_KEY_SECRET)
      .update(`${orderId}|${paymentId}`)
      .digest('hex');
    if (generatedSignature === signature) {
      const orderNum = orderId.split('_')[1];
      await pool.query(
        'UPDATE orders SET status=$1, payment_status=$2 WHERE id=$3',
        ['Confirmed', 'Paid', orderNum]
      );
      res.json({ message: 'Payment verified successfully' });
    } else {
      res.status(400).json({ error: 'Payment verification failed' });
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Failed to verify payment' });
  }
});

app.use((err, req, res, next) => {
  console.error('Unexpected error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

async function startServer() {
  try {
    await initializeDatabase();
    app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();