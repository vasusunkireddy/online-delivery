const express = require('express');
const path = require('path');
const dotenv = require('dotenv');
const mysql = require('mysql2/promise');
const cors = require('cors');
<<<<<<< HEAD
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const fs = require('fs');

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Create uploads directory
const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Database initialization
async function initializeDatabase() {
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'your_db_name',
    });
    console.log('Database connected successfully');

    // Users table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(15),
        password VARCHAR(255),
        role ENUM('user', 'admin') DEFAULT 'user',
=======
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// Environment Variables
const requiredEnvVars = ['DB_NAME', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_PORT', 'JWT_SECRET', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'EMAIL_USER', 'EMAIL_PASS'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Missing environment variable: ${envVar}`);
    process.exit(1);
  }
}

const {
  DB_NAME,
  DB_HOST,
  DB_USER,
  DB_PASSWORD,
  DB_PORT,
  JWT_SECRET,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  EMAIL_USER,
  EMAIL_PASS,
  PORT = 3000,
  CLIENT_URL = 'http://localhost:3000',
  BASE_URL = process.env.NODE_ENV === 'production' ? 'https://delicute.onrender.com' : 'http://localhost:3000',
  PHONEPE_MERCHANT_ID = process.env.PHONEPE_MERCHANT_ID,
  PHONEPE_SALT_KEY = process.env.PHONEPE_SALT_KEY,
  PHONEPE_SALT_INDEX = process.env.PHONEPE_SALT_INDEX,
  GOOGLE_PAY_MERCHANT_ID = process.env.GOOGLE_PAY_MERCHANT_ID
} = process.env;

// Middleware
app.use(cors({
  origin: ['https://delicute.onrender.com', 'http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-VERIFY']
}));
app.use(express.json());

// Serve static files
const publicPath = path.join(__dirname, 'public');
const uploadDir = path.join(publicPath, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}
app.use('/uploads', express.static(uploadDir, {
  setHeaders: (res) => {
    res.set('Cache-Control', 'public, max-age=31557600');
    res.set('Access-Control-Allow-Origin', '*');
  }
}));
app.use(express.static(publicPath));

// File Upload Setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname.replace(/\s+/g, '-')}`)
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Only image files allowed'), false);
  },
  limits: { fileSize: 5 * 1024 * 1024 }
});

// Database Connection
const pool = mysql.createPool({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  port: DB_PORT,
  connectionLimit: 10
});

// Initialize Database
async function initializeDatabase() {
  try {
    const connection = await pool.getConnection();
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255),
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(20),
        password VARCHAR(255),
        is_admin BOOLEAN DEFAULT FALSE,
        is_blocked BOOLEAN DEFAULT FALSE,
        reset_otp VARCHAR(6),
>>>>>>> cb012eab1291e632c5fb7e02506a098c75266316
        profile_image VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
<<<<<<< HEAD

    // Menu items table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS menu_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        price DECIMAL(10,2) NOT NULL,
        category VARCHAR(100),
        image VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Orders table (aligned with your schema)
    await connection.execute(`
=======
    await connection.query(`
      CREATE TABLE IF NOT EXISTS menu_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        category VARCHAR(100) NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        description TEXT,
        image VARCHAR(255),
        rating INT DEFAULT 0,
        rating_count INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await connection.query(`
      CREATE TABLE IF NOT EXISTS offers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        price DECIMAL(10,2) NOT NULL,
        image VARCHAR(255),
        is_special BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await connection.query(`
      CREATE TABLE IF NOT EXISTS coupons (
        id INT AUTO_INCREMENT PRIMARY KEY,
        code VARCHAR(50) UNIQUE NOT NULL,
        discount INT NOT NULL,
        description TEXT,
        image VARCHAR(255),
        is_special BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await connection.query(`
      CREATE TABLE IF NOT EXISTS contact_messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        subject VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        status VARCHAR(50) DEFAULT 'Pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    await connection.query(`
>>>>>>> cb012eab1291e632c5fb7e02506a098c75266316
      CREATE TABLE IF NOT EXISTS orders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        address_id INT,
        items JSON NOT NULL,
        total DECIMAL(10,2) NOT NULL,
        status VARCHAR(50) DEFAULT 'Pending',
        payment_status VARCHAR(50) DEFAULT 'Pending',
        payment_method VARCHAR(50),
        coupon VARCHAR(50),
<<<<<<< HEAD
        discount DECIMAL(10,2) DEFAULT 0.00,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        order_id VARCHAR(50),
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    // Admin cart table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS admin_cart (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        items JSON NOT NULL,
=======
        discount DECIMAL(10,2) DEFAULT 0,
>>>>>>> cb012eab1291e632c5fb7e02506a098c75266316
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
<<<<<<< HEAD

    // Contacts table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS contacts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        subject VARCHAR(255),
        message TEXT NOT NULL,
=======
    await connection.query(`
      CREATE TABLE IF NOT EXISTS addresses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        address_line1 VARCHAR(255) NOT NULL,
        address_line2 VARCHAR(255),
        city VARCHAR(100) NOT NULL,
        state VARCHAR(100) NOT NULL,
        zip_code VARCHAR(20) NOT NULL,
>>>>>>> cb012eab1291e632c5fb7e02506a098c75266316
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
<<<<<<< HEAD

    // Password resets table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS password_resets (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        otp VARCHAR(6) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Favorites table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS favorites (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        menu_item_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (menu_item_id) REFERENCES menu_items(id),
        UNIQUE (user_id, menu_item_id)
      )
    `);

    // Ratings table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS ratings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        menu_item_id INT NOT NULL,
        rating INT NOT NULL CHECK (rating >= 1 AND rating <= 5),
        review TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (menu_item_id) REFERENCES menu_items(id),
        UNIQUE (user_id, menu_item_id)
      )
    `);

    // Coupons table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS coupons (
        id INT AUTO_INCREMENT PRIMARY KEY,
        code VARCHAR(50) UNIQUE NOT NULL,
        description TEXT,
        discount DECIMAL(5,2) NOT NULL,
        min_quantity INT NOT NULL,
        item_category VARCHAR(100),
        image VARCHAR(255),
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Addresses table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS addresses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        mobile_number VARCHAR(15) NOT NULL,
        house_flat_no VARCHAR(50) NOT NULL,
        floor_no VARCHAR(50) NOT NULL,
        address TEXT NOT NULL,
        landmark VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    return connection;
  } catch (error) {
    console.error('Database connection failed:', error.message);
=======
    await connection.query(`
      CREATE TABLE IF NOT EXISTS ratings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        menu_item_id INT,
        rating INT NOT NULL,
        review TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (menu_item_id) REFERENCES menu_items(id)
      )
    `);
    console.log('✅ Database initialized');
    connection.release();
  } catch (error) {
    console.error('❌ Database initialization failed:', error.stack);
>>>>>>> cb012eab1291e632c5fb7e02506a098c75266316
    throw error;
  }
}

<<<<<<< HEAD
// Routes
const indexRoutes = require('./routes/index');
const adminRoutes = require('./routes/admin');
const userDashboardRoutes = require('./routes/userdashboard');
const adminDashboardRoutes = require('./routes/admindashboard');
=======
// Email Transporter
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: { user: EMAIL_USER, pass: EMAIL_PASS }
});

// Google OAuth
const oauth2Client = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, `${BASE_URL}/api/auth/google/callback`);

// JWT Middleware
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    console.error('Invalid token:', error.message);
    res.status(403).json({ error: 'Invalid token' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
  next();
}

// Helper Functions
function getImageUrl(imagePath) {
  if (!imagePath || typeof imagePath !== 'string') return null;
  return imagePath.startsWith('http') ? imagePath : `${BASE_URL}${imagePath}`;
}

function validateInput(data, requiredFields) {
  for (const field of requiredFields) {
    if (!data[field] || (typeof data[field] === 'string' && !data[field].trim())) {
      return { valid: false, error: `${field} is required` };
    }
  }
  return { valid: true };
}

// Routes
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(publicPath, 'admin.html')));

// File Upload Endpoint
app.post('/api/files/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) {
    console.error('File upload failed: No file or invalid type');
    return res.status(400).json({ error: 'No file uploaded or invalid file type' });
  }
  const fileUrl = getImageUrl(`/uploads/${req.file.filename}`);
  console.log(`File uploaded: ${fileUrl}`);
  res.json({ fileUrl });
});

// Auth Routes
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT id, email, name, phone, is_admin, profile_image FROM users WHERE id = ?', [req.user.id]);
    if (!result[0]) return res.status(404).json({ error: 'User not found' });
    res.json({
      _id: result[0].id,
      email: result[0].email,
      name: result[0].name,
      phone: result[0].phone,
      isAdmin: result[0].is_admin,
      profileImage: getImageUrl(result[0].profile_image)
    });
  } catch (error) {
    console.error('Error fetching user:', error.stack);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

app.put('/api/auth/update', authenticateToken, upload.single('profileImage'), async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });
  try {
    let imageUrl = req.body.profileImage;
    if (req.file) imageUrl = `/uploads/${req.file.filename}`;
    imageUrl = getImageUrl(imageUrl);
    await pool.query('UPDATE users SET name = ?, profile_image = ? WHERE id = ?', [name, imageUrl, req.user.id]);
    res.json({
      message: 'Profile updated',
      name,
      profileImage: imageUrl
    });
  } catch (error) {
    console.error('Error updating profile:', error.stack);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

app.get('/api/auth/admin/me', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT id, email, name, phone, is_admin, profile_image FROM users WHERE id = ?', [req.user.id]);
    if (!result[0]) return res.status(404).json({ error: 'Admin not found' });
    res.json({
      _id: result[0].id,
      email: result[0].email,
      name: result[0].name,
      phone: result[0].phone,
      isAdmin: result[0].is_admin,
      profileImage: getImageUrl(result[0].profile_image)
    });
  } catch (error) {
    console.error('Error fetching admin:', error.stack);
    res.status(500).json({ error: 'Failed to fetch admin' });
  }
});

// Menu Routes
app.get('/api/menu', async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM menu_items ORDER BY created_at DESC');
    res.json(result.map(item => ({
      _id: item.id,
      name: item.name,
      category: item.category,
      price: parseFloat(item.price),
      description: item.description,
      image: getImageUrl(item.image),
      rating: item.rating,
      created_at: item.created_at
    })));
  } catch (error) {
    console.error('Error fetching menu:', error.stack);
    res.status(500).json({ error: 'Failed to fetch menu' });
  }
});

app.get('/api/menu/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM menu_items WHERE id = ?', [req.params.id]);
    if (!result[0]) return res.status(404).json({ error: 'Menu item not found' });
    res.json({
      _id: result[0].id,
      name: result[0].name,
      category: result[0].category,
      price: parseFloat(result[0].price),
      description: result[0].description,
      image: getImageUrl(result[0].image),
      rating: result[0].rating
    });
  } catch (error) {
    console.error('Error fetching menu item:', error.stack);
    res.status(500).json({ error: 'Failed to fetch menu item' });
  }
});

app.post('/api/menu', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
  const { name, category, price, description, image } = req.body;
  const validation = validateInput({ name, category, price }, ['name', 'category', 'price']);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  try {
    let imageUrl = image;
    if (req.file) imageUrl = `/uploads/${req.file.filename}`;
    imageUrl = getImageUrl(imageUrl);
    const [result] = await pool.query('INSERT INTO menu_items (name, category, price, description, image) VALUES (?, ?, ?, ?, ?)', [name, category, parseFloat(price), description, imageUrl]);
    const [newItem] = await pool.query('SELECT * FROM menu_items WHERE id = ?', [result.insertId]);
    res.status(201).json({
      _id: newItem[0].id,
      name: newItem[0].name,
      category: newItem[0].category,
      price: parseFloat(newItem[0].price),
      description: newItem[0].description,
      image: getImageUrl(newItem[0].image)
    });
  } catch (error) {
    console.error('Error adding menu item:', error.stack);
    res.status(500).json({ error: 'Failed to add menu item' });
  }
});

app.put('/api/menu/:id', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
  const { name, category, price, description, image } = req.body;
  const validation = validateInput({ name, category, price }, ['name', 'category', 'price']);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  try {
    let imageUrl = image;
    if (req.file) imageUrl = `/uploads/${req.file.filename}`;
    imageUrl = getImageUrl(imageUrl);
    await pool.query('UPDATE menu_items SET name = ?, category = ?, price = ?, description = ?, image = ? WHERE id = ?', [name, category, parseFloat(price), description, imageUrl, req.params.id]);
    const [updatedItem] = await pool.query('SELECT * FROM menu_items WHERE id = ?', [req.params.id]);
    if (!updatedItem[0]) return res.status(404).json({ error: 'Menu item not found' });
    res.json({
      _id: updatedItem[0].id,
      name: updatedItem[0].name,
      category: updatedItem[0].category,
      price: parseFloat(updatedItem[0].price),
      description: updatedItem[0].description,
      image: getImageUrl(updatedItem[0].image)
    });
  } catch (error) {
    console.error('Error updating menu item:', error.stack);
    res.status(500).json({ error: 'Failed to update menu item' });
  }
});

app.delete('/api/menu/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM menu_items WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Menu item not found' });
    res.json({ message: 'Menu item deleted' });
  } catch (error) {
    console.error('Error deleting menu item:', error.stack);
    res.status(500).json({ error: 'Failed to delete menu item' });
  }
});

app.post('/api/menu/:id/rate', authenticateToken, async (req, res) => {
  const { rating, review } = req.body;
  if (!rating || rating < 1 || rating > 5) return res.status(400).json({ error: 'Valid rating (1-5) required' });
  try {
    const [item] = await pool.query('SELECT id FROM menu_items WHERE id = ?', [req.params.id]);
    if (!item[0]) return res.status(404).json({ error: 'Menu item not found' });
    await pool.query('INSERT INTO ratings (user_id, menu_item_id, rating, review) VALUES (?, ?, ?, ?)', [req.user.id, req.params.id, rating, review || null]);
    const [ratings] = await pool.query('SELECT AVG(rating) as avg_rating, COUNT(*) as count FROM ratings WHERE menu_item_id = ?', [req.params.id]);
    const avgRating = Math.round(ratings[0].avg_rating);
    await pool.query('UPDATE menu_items SET rating = ?, rating_count = ? WHERE id = ?', [avgRating, ratings[0].count, req.params.id]);
    res.json({ message: 'Rating submitted' });
  } catch (error) {
    console.error('Error submitting rating:', error.stack);
    res.status(500).json({ error: 'Failed to submit rating' });
  }
});

// Offer Routes
app.get('/api/offers', async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM offers WHERE is_special = ? ORDER BY created_at DESC', [true]);
    res.json(result.map(offer => ({
      _id: offer.id,
      name: offer.name,
      price: parseFloat(offer.price),
      description: offer.description,
      image: getImageUrl(offer.image),
      isSpecial: offer.is_special,
      created_at: offer.created_at
    })));
  } catch (error) {
    console.error('Error fetching offers:', error.stack);
    res.status(500).json({ error: 'Failed to fetch offers' });
  }
});

app.get('/api/offers/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM offers WHERE id = ?', [req.params.id]);
    if (!result[0]) return res.status(404).json({ error: 'Offer not found' });
    res.json({
      _id: result[0].id,
      name: result[0].name,
      price: parseFloat(result[0].price),
      description: result[0].description,
      image: getImageUrl(result[0].image),
      isSpecial: result[0].is_special
    });
  } catch (error) {
    console.error('Error fetching offer:', error.stack);
    res.status(500).json({ error: 'Failed to fetch offer' });
  }
});

app.post('/api/offers', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
  const { name, price, description, image, isSpecial } = req.body;
  const validation = validateInput({ name, price }, ['name', 'price']);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  try {
    let imageUrl = image;
    if (req.file) imageUrl = `/uploads/${req.file.filename}`;
    imageUrl = getImageUrl(imageUrl);
    const [result] = await pool.query('INSERT INTO offers (name, price, description, image, is_special) VALUES (?, ?, ?, ?, ?)', [name, parseFloat(price), description, imageUrl, isSpecial === 'true']);
    const [newOffer] = await pool.query('SELECT * FROM offers WHERE id = ?', [result.insertId]);
    res.status(201).json({
      _id: newOffer[0].id,
      name: newOffer[0].name,
      price: parseFloat(newOffer[0].price),
      description: newOffer[0].description,
      image: getImageUrl(newOffer[0].image),
      isSpecial: newOffer[0].is_special
    });
  } catch (error) {
    console.error('Error adding offer:', error.stack);
    res.status(500).json({ error: 'Failed to add offer' });
  }
});

app.put('/api/offers/:id', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
  const { name, price, description, image, isSpecial } = req.body;
  const validation = validateInput({ name, price }, ['name', 'price']);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  try {
    let imageUrl = image;
    if (req.file) imageUrl = `/uploads/${req.file.filename}`;
    imageUrl = getImageUrl(imageUrl);
    await pool.query('UPDATE offers SET name = ?, price = ?, description = ?, image = ?, is_special = ? WHERE id = ?', [name, parseFloat(price), description, imageUrl, isSpecial === 'true', req.params.id]);
    const [updatedOffer] = await pool.query('SELECT * FROM offers WHERE id = ?', [req.params.id]);
    if (!updatedOffer[0]) return res.status(404).json({ error: 'Offer not found' });
    res.json({
      _id: updatedOffer[0].id,
      name: updatedOffer[0].name,
      price: parseFloat(updatedOffer[0].price),
      description: updatedOffer[0].description,
      image: getImageUrl(updatedOffer[0].image),
      isSpecial: updatedOffer[0].is_special
    });
  } catch (error) {
    console.error('Error updating offer:', error.stack);
    res.status(500).json({ error: 'Failed to update offer' });
  }
});

app.delete('/api/offers/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM offers WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Offer not found' });
    res.json({ message: 'Offer deleted' });
  } catch (error) {
    console.error('Error deleting offer:', error.stack);
    res.status(500).json({ error: 'Failed to delete offer' });
  }
});

// Coupon Routes
app.get('/api/coupons', async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM coupons ORDER BY created_at DESC');
    res.json(result.map(coupon => ({
      _id: coupon.id,
      code: coupon.code,
      discount: coupon.discount,
      description: coupon.description,
      image: getImageUrl(coupon.image),
      isSpecial: coupon.is_special,
      created_at: coupon.created_at
    })));
  } catch (error) {
    console.error('Error fetching coupons:', error.stack);
    res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

app.get('/api/coupons/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM coupons WHERE id = ?', [req.params.id]);
    if (!result[0]) return res.status(404).json({ error: 'Coupon not found' });
    res.json({
      _id: result[0].id,
      code: result[0].code,
      discount: result[0].discount,
      description: result[0].description,
      image: getImageUrl(result[0].image),
      isSpecial: result[0].is_special
    });
  } catch (error) {
    console.error('Error fetching coupon:', error.stack);
    res.status(500).json({ error: 'Failed to fetch coupon' });
  }
});

app.post('/api/coupons', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
  const { code, discount, description, image, isSpecial } = req.body;
  const validation = validateInput({ code, discount }, ['code', 'discount']);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  try {
    let imageUrl = image;
    if (req.file) imageUrl = `/uploads/${req.file.filename}`;
    imageUrl = getImageUrl(imageUrl);
    const [result] = await pool.query('INSERT INTO coupons (code, discount, description, image, is_special) VALUES (?, ?, ?, ?, ?)', [code, parseInt(discount), description, imageUrl, isSpecial === 'true']);
    const [newCoupon] = await pool.query('SELECT * FROM coupons WHERE id = ?', [result.insertId]);
    res.status(201).json({
      _id: newCoupon[0].id,
      code: newCoupon[0].code,
      discount: newCoupon[0].discount,
      description: newCoupon[0].description,
      image: getImageUrl(newCoupon[0].image),
      isSpecial: newCoupon[0].is_special
    });
  } catch (error) {
    console.error('Error adding coupon:', error.stack);
    res.status(500).json({ error: 'Failed to add coupon' });
  }
});

app.put('/api/coupons/:id', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
  const { code, discount, description, image, isSpecial } = req.body;
  const validation = validateInput({ code, discount }, ['code', 'discount']);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  try {
    let imageUrl = image;
    if (req.file) imageUrl = `/uploads/${req.file.filename}`;
    imageUrl = getImageUrl(imageUrl);
    await pool.query('UPDATE coupons SET code = ?, discount = ?, description = ?, image = ?, is_special = ? WHERE id = ?', [code, parseInt(discount), description, imageUrl, isSpecial === 'true', req.params.id]);
    const [updatedCoupon] = await pool.query('SELECT * FROM coupons WHERE id = ?', [req.params.id]);
    if (!updatedCoupon[0]) return res.status(404).json({ error: 'Coupon not found' });
    res.json({
      _id: updatedCoupon[0].id,
      code: updatedCoupon[0].code,
      discount: updatedCoupon[0].discount,
      description: updatedCoupon[0].description,
      image: getImageUrl(updatedCoupon[0].image),
      isSpecial: updatedCoupon[0].is_special
    });
  } catch (error) {
    console.error('Error updating coupon:', error.stack);
    res.status(500).json({ error: 'Failed to update coupon' });
  }
});

app.delete('/api/coupons/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM coupons WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Coupon not found' });
    res.json({ message: 'Coupon deleted' });
  } catch (error) {
    console.error('Error deleting coupon:', error.stack);
    res.status(500).json({ error: 'Failed to delete coupon' });
  }
});

app.post('/api/coupons/validate', authenticateToken, async (req, res) => {
  const { couponCode } = req.body;
  if (!couponCode) return res.status(400).json({ error: 'Coupon code required' });
  try {
    const [result] = await pool.query('SELECT * FROM coupons WHERE code = ?', [couponCode]);
    if (!result[0]) return res.status(404).json({ error: 'Invalid coupon' });
    res.json({
      _id: result[0].id,
      code: result[0].code,
      discount: result[0].discount,
      description: result[0].description,
      image: getImageUrl(result[0].image),
      isSpecial: result[0].is_special
    });
  } catch (error) {
    console.error('Error validating coupon:', error.stack);
    res.status(500).json({ error: 'Failed to validate coupon' });
  }
});

// Contact Routes
app.post('/api/contact', authenticateToken, async (req, res) => {
  const { subject, message } = req.body;
  if (!subject || !message) return res.status(400).json({ error: 'Subject and message required' });
  try {
    const [user] = await pool.query('SELECT name, email FROM users WHERE id = ?', [req.user.id]);
    if (!user[0]) return res.status(404).json({ error: 'User not found' });
    const [result] = await pool.query('INSERT INTO contact_messages (user_id, name, email, subject, message) VALUES (?, ?, ?, ?, ?)', [req.user.id, user[0].name, user[0].email, subject, message]);
    const [newMessage] = await pool.query('SELECT * FROM contact_messages WHERE id = ?', [result.insertId]);
    await transporter.sendMail({
      from: `"Delicute" <${EMAIL_USER}>`,
      to: user[0].email,
      subject: 'Delicute - Message Received',
      text: `Thank you for your message: ${message}`,
      html: `<p>Thank you for your message: <strong>${message}</strong></p>`
    });
    res.status(201).json({
      _id: newMessage[0].id,
      userId: newMessage[0].user_id,
      name: newMessage[0].name,
      email: newMessage[0].email,
      subject: newMessage[0].subject,
      message: newMessage[0].message,
      status: newMessage[0].status,
      created_at: newMessage[0].created_at
    });
  } catch (error) {
    console.error('Error adding message:', error.stack);
    res.status(500).json({ error: 'Failed to add message' });
  }
});

app.get('/api/contact', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM contact_messages ORDER BY created_at DESC');
    res.json(result.map(msg => ({
      _id: msg.id,
      userId: msg.user_id,
      name: msg.name,
      email: msg.email,
      subject: msg.subject,
      message: msg.message,
      status: msg.status,
      created_at: msg.created_at
    })));
  } catch (error) {
    console.error('Error fetching messages:', error.stack);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.get('/api/contact/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM contact_messages WHERE id = ?', [req.params.id]);
    if (!result[0]) return res.status(404).json({ error: 'Message not found' });
    res.json({
      _id: result[0].id,
      userId: result[0].user_id,
      name: result[0].name,
      email: result[0].email,
      subject: result[0].subject,
      message: result[0].message,
      status: result[0].status,
      created_at: result[0].created_at
    });
  } catch (error) {
    console.error('Error fetching message:', error.stack);
    res.status(500).json({ error: 'Failed to fetch message' });
  }
});

app.post('/api/contact/:id/reply', authenticateToken, requireAdmin, async (req, res) => {
  const { reply } = req.body;
  if (!reply) return res.status(400).json({ error: 'Reply required' });
  try {
    const [message] = await pool.query('SELECT email FROM contact_messages WHERE id = ?', [req.params.id]);
    if (!message[0]) return res.status(404).json({ error: 'Message not found' });
    await transporter.sendMail({
      from: `"Delicute reply" <${EMAIL_USER}>`,
      to: message[0].email,
      subject: 'Delicute - Response to Your Message',
      text: reply,
      html: `<p>${reply}</p>`
    });
    await pool.query('UPDATE contact_messages SET status = ? WHERE id = ?', ['Replied', req.params.id]);
    res.json({ message: 'Reply sent' });
  } catch (error) {
    console.error('Error sending reply:', error.stack);
    res.status(500).json({ error: 'Failed to send reply' });
  }
});

app.delete('/api/contact/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM contact_messages WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Message not found' });
    res.json({ message: 'Message deleted' });
  } catch (error) {
    console.error('Error deleting message:', error.stack);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

// Address Routes
app.get('/api/addresses', authenticateToken, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM addresses WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
    res.json(result.map(address => ({
      id: address.id,
      addressLine1: address.address_line1,
      addressLine2: address.address_line2,
      city: address.city,
      state: address.state,
      zipCode: address.zip_code,
      created_at: address.created_at
    })));
  } catch (error) {
    console.error('Error fetching addresses:', error.stack);
    res.status(500).json({ error: 'Failed to fetch addresses' });
  }
});

app.post('/api/addresses', authenticateToken, async (req, res) => {
  const { addressLine1, addressLine2, city, state, zipCode } = req.body;
  const validation = validateInput({ addressLine1, city, state, zipCode }, ['addressLine1', 'city', 'state', 'zipCode']);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  try {
    const [result] = await pool.query('INSERT INTO addresses (user_id, address_line1, address_line2, city, state, zip_code) VALUES (?, ?, ?, ?, ?, ?)', [req.user.id, addressLine1, addressLine2 || null, city, state, zipCode]);
    const [newAddress] = await pool.query('SELECT * FROM addresses WHERE id = ?', [result.insertId]);
    res.status(201).json({
      id: newAddress[0].id,
      addressLine1: newAddress[0].address_line1,
      addressLine2: newAddress[0].address_line2,
      city: newAddress[0].city,
      state: newAddress[0].state,
      zipCode: newAddress[0].zip_code,
      created_at: newAddress[0].created_at
    });
  } catch (error) {
    console.error('Error adding address:', error.stack);
    res.status(500).json({ error: 'Failed to add address' });
  }
});

app.put('/api/addresses/:id', authenticateToken, async (req, res) => {
  const { addressLine1, addressLine2, city, state, zipCode } = req.body;
  const validation = validateInput({ addressLine1, city, state, zipCode }, ['addressLine1', 'city', 'state', 'zipCode']);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  try {
    const [result] = await pool.query('UPDATE addresses SET address_line1 = ?, address_line2 = ?, city = ?, state = ?, zip_code = ? WHERE id = ? AND user_id = ?', [addressLine1, addressLine2 || null, city, state, zipCode, req.params.id, req.user.id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Address not found or unauthorized' });
    const [updatedAddress] = await pool.query('SELECT * FROM addresses WHERE id = ?', [req.params.id]);
    res.json({
      id: updatedAddress[0].id,
      addressLine1: updatedAddress[0].address_line1,
      addressLine2: updatedAddress[0].address_line2,
      city: updatedAddress[0].city,
      state: updatedAddress[0].state,
      zipCode: updatedAddress[0].zip_code,
      created_at: updatedAddress[0].created_at
    });
  } catch (error) {
    console.error('Error updating address:', error.stack);
    res.status(500).json({ error: 'Failed to update address' });
  }
});

app.delete('/api/addresses/:id', authenticateToken, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM addresses WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Address not found or unauthorized' });
    res.json({ message: 'Address deleted' });
  } catch (error) {
    console.error('Error deleting address:', error.stack);
    res.status(500).json({ error: 'Failed to delete address' });
  }
});

// Order Routes
app.post('/api/orders', authenticateToken, async (req, res) => {
  const { items, addressId, coupon, paymentMethod } = req.body;
  const validation = validateInput({ items, addressId, paymentMethod }, ['items', 'addressId', 'paymentMethod']);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  if (!['cod', 'phonepe', 'gpay'].includes(paymentMethod)) return res.status(400).json({ error: 'Invalid payment method' });
  try {
    const [address] = await pool.query('SELECT * FROM addresses WHERE id = ? AND user_id = ?', [addressId, req.user.id]);
    if (!address[0]) return res.status(404).json({ error: 'Address not found' });
    let discount = 0;
    let couponCode = null;
    if (coupon) {
      const [couponResult] = await pool.query('SELECT * FROM coupons WHERE code = ?', [coupon]);
      if (!couponResult[0]) return res.status(400).json({ error: 'Invalid coupon' });
      couponCode = couponResult[0].code;
      const subtotal = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
      discount = (subtotal * couponResult[0].discount) / 100;
    }
    const total = items.reduce((sum, item) => sum + item.price * item.quantity, 0) - discount;
    const [result] = await pool.query(
      'INSERT INTO orders (user_id, address_id, items, total, payment_method, coupon, discount) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [req.user.id, addressId, JSON.stringify(items), total, paymentMethod, couponCode, discount]
    );
    const [newOrder] = await pool.query('SELECT * FROM orders WHERE id = ?', [result.insertId]);
    const orderResponse = {
      _id: newOrder[0].id,
      userId: newOrder[0].user_id,
      addressId: newOrder[0].address_id,
      address: {
        addressLine1: address[0].address_line1,
        addressLine2: address[0].address_line2,
        city: address[0].city,
        state: address[0].state,
        zipCode: address[0].zip_code
      },
      items: JSON.parse(newOrder[0].items),
      total: parseFloat(newOrder[0].total),
      status: newOrder[0].status,
      paymentStatus: newOrder[0].payment_status,
      paymentMethod: newOrder[0].payment_method,
      coupon: newOrder[0].coupon,
      discount: parseFloat(newOrder[0].discount),
      created_at: newOrder[0].created_at
    };
    if (paymentMethod === 'cod') {
      await pool.query('UPDATE orders SET status = ?, payment_status = ? WHERE id = ?', ['Confirmed', 'Pending', result.insertId]);
      orderResponse.status = 'Confirmed';
      orderResponse.paymentStatus = 'Pending';
      res.json(orderResponse);
    } else {
      res.json(orderResponse);
    }
  } catch (error) {
    console.error('Error creating order:', error.stack);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

app.get('/api/orders/active', authenticateToken, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM orders WHERE user_id = ? AND status NOT IN (?, ?) ORDER BY created_at DESC', [req.user.id, 'Delivered', 'Cancelled']);
    res.json(result.map(order => ({
      _id: order.id,
      addressId: order.address_id,
      items: JSON.parse(order.items),
      total: parseFloat(order.total),
      status: order.status,
      paymentStatus: order.payment_status,
      paymentMethod: order.payment_method,
      coupon: order.coupon,
      discount: parseFloat(order.discount),
      created_at: order.created_at
    })));
  } catch (error) {
    console.error('Error fetching active orders:', error.stack);
    res.status(500).json({ error: 'Failed to fetch active orders' });
  }
});

app.get('/api/orders/history', authenticateToken, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
    res.json(result.map(order => ({
      _id: order.id,
      addressId: order.address_id,
      items: JSON.parse(order.items),
      total: parseFloat(order.total),
      status: order.status,
      paymentStatus: order.payment_status,
      paymentMethod: order.payment_method,
      coupon: order.coupon,
      discount: parseFloat(order.discount),
      created_at: order.created_at
    })));
  } catch (error) {
    console.error('Error fetching order history:', error.stack);
    res.status(500).json({ error: 'Failed to fetch order history' });
  }
});

app.delete('/api/orders/history', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM orders WHERE user_id = ?', [req.user.id]);
    res.json({ message: 'Order history cleared' });
  } catch (error) {
    console.error('Error clearing order history:', error.stack);
    res.status(500).json({ error: 'Failed to clear order history' });
  }
});

app.post('/api/orders/:id/cancel', authenticateToken, async (req, res) => {
  const { reason } = req.body;
  if (!reason) return res.status(400).json({ error: 'Reason required' });
  try {
    const [order] = await pool.query('SELECT * FROM orders WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!order[0]) return res.status(404).json({ error: 'Order not found or unauthorized' });
    if (order[0].status !== 'Pending') return res.status(400).json({ error: 'Cannot cancel non-pending order' });
    await pool.query('UPDATE orders SET status = ? WHERE id = ?', ['Cancelled', req.params.id]);
    await transporter.sendMail({
      from: `"Delicute" <${EMAIL_USER}>`,
      to: req.user.email,
      subject: 'Delicute - Order Cancellation',
      text: `Your order #${req.params.id} has been cancelled. Reason: ${reason}`,
      html: `<p>Your order #${req.params.id} has been cancelled. Reason: <strong>${reason}</strong></p>`
    });
    res.json({ message: 'Order cancelled' });
  } catch (error) {
    console.error('Error cancelling order:', error.stack);
    res.status(500).json({ error: 'Failed to cancel order' });
  }
});

app.get('/api/orders', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM orders ORDER BY created_at DESC');
    res.json(result.map(order => ({
      _id: order.id,
      userId: order.user_id,
      addressId: order.address_id,
      items: JSON.parse(order.items),
      total: parseFloat(order.total),
      status: order.status,
      paymentStatus: order.payment_status,
      paymentMethod: order.payment_method,
      coupon: order.coupon,
      discount: parseFloat(order.discount),
      created_at: order.created_at
    })));
  } catch (error) {
    console.error('Error fetching orders:', error.stack);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

app.get('/api/orders/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT * FROM orders WHERE id = ?', [req.params.id]);
    if (!result[0]) return res.status(404).json({ error: 'Order not found' });
    res.json({
      _id: result[0].id,
      userId: result[0].user_id,
      addressId: result[0].address_id,
      items: JSON.parse(result[0].items),
      total: parseFloat(result[0].total),
      status: result[0].status,
      paymentStatus: result[0].payment_status,
      paymentMethod: result[0].payment_method,
      coupon: result[0].coupon,
      discount: parseFloat(result[0].discount),
      created_at: result[0].created_at
    });
  } catch (error) {
    console.error('Error fetching order:', error.stack);
    res.status(500).json({ error: 'Failed to fetch order' });
  }
});

app.put('/api/orders/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { status } = req.body;
  if (!status) return res.status(400).json({ error: 'Status required' });
  try {
    await pool.query('UPDATE orders SET status = ? WHERE id = ?', [status, req.params.id]);
    const [updatedOrder] = await pool.query('SELECT * FROM orders WHERE id = ?', [req.params.id]);
    if (!updatedOrder[0]) return res.status(404).json({ error: 'Order not found' });
    res.json({
      _id: updatedOrder[0].id,
      userId: updatedOrder[0].user_id,
      addressId: updatedOrder[0].address_id,
      items: JSON.parse(updatedOrder[0].items),
      total: parseFloat(updatedOrder[0].total),
      status: updatedOrder[0].status,
      paymentStatus: updatedOrder[0].payment_status,
      paymentMethod: updatedOrder[0].payment_method,
      coupon: updatedOrder[0].coupon,
      discount: parseFloat(updatedOrder[0].discount)
    });
  } catch (error) {
    console.error('Error updating order:', error.stack);
    res.status(500).json({ error: 'Failed to update order' });
  }
});

app.delete('/api/orders/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM orders WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Order not found' });
    res.json({ message: 'Order deleted' });
  } catch (error) {
    console.error('Error deleting order:', error.stack);
    res.status(500).json({ error: 'Failed to delete order' });
  }
});

// Payment Routes
app.post('/api/payment/phonepe', authenticateToken, async (req, res) => {
  const { data } = req.body;
  if (!data) return res.status(400).json({ error: 'Payment data required' });
  try {
    const decodedData = JSON.parse(Buffer.from(data, 'base64').toString('utf8'));
    const { merchantTransactionId, amount, redirectUrl, orderId } = decodedData;
    const payload = {
      merchantId: PHONEPE_MERCHANT_ID,
      merchantTransactionId,
      amount,
      redirectUrl,
      callbackUrl: `${BASE_URL}/api/payment/callback`,
      orderId
    };
    const payloadString = JSON.stringify(payload);
    const payloadBase64 = Buffer.from(payloadString).toString('base64');
    const checksum = crypto.createHash('sha256').update(payloadBase64 + '/pg/v1/pay' + PHONEPE_SALT_KEY).digest('hex') + '###' + PHONEPE_SALT_INDEX;
    if (checksum !== req.headers['x-verify']) return res.status(400).json({ error: 'Invalid checksum' });
    const paymentUrl = `https://api.phonepe.com/pg/v1/pay?data=${encodeURIComponent(payloadBase64)}&checksum=${encodeURIComponent(checksum)}`;
    res.json({ redirectUrl: paymentUrl });
  } catch (error) {
    console.error('Error initiating PhonePe payment:', error.stack);
    res.status(500).json({ error: 'Failed to initiate payment' });
  }
});

app.post('/api/payment/googlepay', authenticateToken, async (req, res) => {
  const { token, orderId } = req.body;
  if (!token || !orderId) return res.status(400).json({ error: 'Token and orderId required' });
  try {
    const [order] = await pool.query('SELECT * FROM orders WHERE id = ? AND user_id = ?', [orderId, req.user.id]);
    if (!order[0]) return res.status(404).json({ error: 'Order not found' });
    await pool.query('UPDATE orders SET status = ?, payment_status = ? WHERE id = ?', ['Confirmed', 'Completed', orderId]);
    res.json({ message: 'Google Pay payment successful' });
  } catch (error) {
    console.error('Error processing Google Pay payment:', error.stack);
    res.status(500).json({ error: 'Failed to process payment' });
  }
});

app.post('/api/payment/callback', async (req, res) => {
  try {
    const { transactionId, status } = req.body;
    const [order] = await pool.query('SELECT * FROM orders WHERE id = ?', [transactionId]);
    if (!order[0]) return res.status(404).json({ error: 'Order not found' });
    const paymentStatus = status === 'SUCCESS' ? 'Completed' : 'Failed';
    await pool.query('UPDATE orders SET payment_status = ? WHERE id = ?', [paymentStatus, transactionId]);
    res.json({ message: 'Payment callback processed' });
  } catch (error) {
    console.error('Error processing payment callback:', error.stack);
    res.status(500).json({ error: 'Failed to process callback' });
  }
});

// User Routes
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [result] = await pool.query('SELECT id, name, email, phone, is_blocked, profile_image FROM users WHERE is_admin = ?', [false]);
    res.json(result.map(user => ({
      _id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      status: user.is_blocked ? 'Blocked' : 'Active',
      profileImage: getImageUrl(user.profile_image)
    })));
  } catch (error) {
    console.error('Error fetching users:', error.stack);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/api/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [userResult] = await pool.query('SELECT id, name, email, phone, is_blocked, profile_image FROM users WHERE id = ? AND is_admin = ?', [req.params.id, false]);
    if (!userResult[0]) return res.status(404).json({ error: 'User not found' });
    const [orderResult] = await pool.query('SELECT id, total, status, created_at FROM orders WHERE user_id = ?', [req.params.id]);
    res.json({
      id: userResult[0].id,
      userName: userResult[0].name,
      email: userResult[0].email,
      phone: userResult[0].phone,
      status: userResult[0].is_blocked ? 'Blocked' : 'Active',
      profileImage: getImageUrl(userResult[0].profile_image),
      orders: orderResult.map(order => ({
        orderid: order.id,
        total: parseFloat(order.total),
        status: order.status,
        createdAt: order.created_at
      }))
    });
  } catch (error) {
    console.error('Error fetching user:', error.stack);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

app.put('/api/users/:id/status', authenticateToken, requireAdmin, async (req, res) => {
  const { status } = req.body;
  if (!status || !['Active', 'Blocked'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
  try {
    const isBlocked = status === 'Blocked';
    await pool.query('UPDATE users SET is_blocked = ? WHERE id = ?', [isBlocked, req.params.id]);
    res.json({ message: `User ${status.toLowerCase()} successfully` });
  } catch (error) {
    console.error('Error updating user status:', error.stack);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

// Restaurant Status Routes
app.get('/api/restaurant/status', async (req, res) => {
  try {
    res.json({ isOpen: true });
  } catch (error) {
    console.error('Error fetching restaurant status:', error.stack);
    res.status(500).json({ error: 'Failed to fetch restaurant status' });
  }
});

app.put('/api/restaurant/status/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const currentStatus = true;
    const newStatus = !currentStatus;
    res.json({ isOpen: newStatus });
  } catch (error) {
    console.error('Error toggling restaurant status:', error.stack);
    res.status(500).json({ error: 'Failed to toggle restaurant status' });
  }
});

// Auth Routes
app.post('/api/auth/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  const validation = validateInput({ name, email, phone, password }, ['name', 'email', 'phone', 'password']);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  try {
    const [userCheck] = await pool.query('SELECT email FROM users WHERE email = ?', [email]);
    if (userCheck[0]) return res.status(400).json({ error: 'Email exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query('INSERT INTO users (name, email, phone, password, is_admin) VALUES (?, ?, ?, ?, ?)', [name, email, phone, hashedPassword, false]);
    const token = jwt.sign({ id: result.insertId, email, isAdmin: false }, JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token });
  } catch (error) {
    console.error('Error signing up:', error.stack);
    res.status(500).json({ error: 'Failed to sign up' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const validation = validateInput({ email, password }, ['email', 'password']);
  if (!validation.valid) return res.status(400).json({ error: 'Email or password required' });
  try {
    const [result] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = result[0];
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.is_blocked) return res.status(403).json({ error: 'Account blocked' });
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Error logging in:', error.stack);
    res.status(500).json({ error: 'Failed to log in' });
  }
});

app.post('/api/auth/admin/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  const validation = validateInput({ name, email, phone, password }, ['name', 'email', 'phone', 'password']);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  try {
    const [userCheck] = await pool.query('SELECT email FROM users WHERE email = ?', [email]);
    if (userCheck[0]) return res.status(400).json({ error: 'Email exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query('INSERT INTO users (name, email, phone, password, is_admin) VALUES (?, ?, ?, ?, ?)', [name, email, phone, hashedPassword, true]);
    const token = jwt.sign({ id: result.insertId, email, isAdmin: true }, JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token });
  } catch (error) {
    console.error('Error signing up admin:', error.stack);
    res.status(500).json({ error: 'Failed to sign up admin' });
  }
});

app.post('/api/auth/admin/login', async (req, res) => {
  const { email, password } = req.body;
  const validation = validateInput({ email, password }, ['email', 'password']);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  try {
    const [result] = await pool.query('SELECT * FROM users WHERE email = ? AND is_admin = ?', [email, true]);
    const user = result[0];
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.is_blocked) return res.status(403).json({ error: 'Account blocked' });
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Error logging in admin:', error.stack);
    res.status(500).json({ error: 'Failed to log in admin' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  try {
    const [result] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (!result[0]) return res.status(404).json({ error: 'User not found' });
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await pool.query('UPDATE users SET reset_otp = ? WHERE email = ?', [otp, email]);
    await transporter.sendMail({
      from: `"Delicute" <${EMAIL_USER}>`,
      to: email,
      subject: 'Delicute - Password Reset OTP',
      text: `Your OTP: ${otp}`,
      html: `<p>Your OTP: <strong>${otp}</strong></p>`
    });
    res.json({ message: 'OTP sent' });
  } catch (error) {
    console.error('Error sending OTP:', error.stack);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  const validation = validateInput({ email, otp, newPassword }, ['email', 'otp', 'newPassword']);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  try {
    const [result] = await pool.query('SELECT * FROM users WHERE email = ? AND reset_otp = ?', [email, otp]);
    if (!result[0]) return res.status(400).json({ error: 'Invalid OTP' });
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = ?, reset_otp = NULL WHERE id = ?', [hashedPassword, result[0].id]);
    res.json({ message: 'Password reset' });
  } catch (error) {
    console.error('Error resetting password:', error.stack);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

app.post('/api/auth/admin/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  try {
    const [result] = await pool.query('SELECT * FROM users WHERE email = ? AND is_admin = ?', [email, true]);
    if (!result[0]) return res.status(404).json({ error: 'Admin not found' });
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await pool.query('UPDATE users SET reset_otp = ? WHERE id = ?', [otp, result[0].id]);
    await transporter.sendMail({
      from: `"Delicute" <${EMAIL_USER}>`,
      to: email,
      subject: 'Delicute - Admin Password Reset OTP',
      text: `Your OTP: ${otp}`,
      html: `<p>Your OTP: <strong>${otp}</strong></p>`
    });
    res.json({ message: 'OTP sent' });
  } catch (error) {
    console.error('Error sending OTP:', error.stack);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

app.post('/api/auth/admin/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  const validation = validateInput({ email, otp, newPassword }, ['email', 'otp', 'newPassword']);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  try {
    const [result] = await pool.query('SELECT * FROM users WHERE email = ? AND reset_otp = ? AND is_admin = ?', [email, otp, true]);
    if (!result[0]) return res.status(400).json({ error: 'Invalid OTP' });
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = ?, reset_otp = NULL WHERE id = ?', [hashedPassword, result[0].id]);
    res.json({ message: 'Password reset' });
  } catch (error) {
    console.error('Error resetting admin password:', error.stack);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

app.get('/api/auth/google', (req, res) => {
  const authUrl = oauth2Client.generateAuthUrl({
    scope: ['profile', 'email'],
    redirect_uri: `${BASE_URL}/api/auth/google/callback`
  });
  res.redirect(302, authUrl);
});

app.get('/api/auth/google/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.redirect(`${CLIENT_URL}/?error=${encodeURIComponent('Google auth failed')}`);
  try {
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data } = await oauth2.userinfo.get();
    const { email, name } = data;
    let [result] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    let user = result[0];
    if (!user) {
      const [insertResult] = await pool.query('INSERT INTO users (name, email, is_admin) VALUES (?, ?, ?)', [name || 'Google User', email, false]);
      [result] = await pool.query('SELECT * FROM users WHERE id = ?', [insertResult.insertId]);
      user = result[0];
    }
    if (user.is_blocked) return res.redirect(`${CLIENT_URL}/?error=${encodeURIComponent('Account blocked')}`);
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '1h' });
    res.redirect(`${CLIENT_URL}/dashboard?token=${encodeURIComponent(token)}`);
  } catch (error) {
    console.error('Error in Google auth:', error.stack);
    res.redirect(`${CLIENT_URL}/?error=${encodeURIComponent('Google auth failed')}`);
  }
});

// Error Handler
app.use((err, req, res, next) => {
  console.error('Error:', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});
>>>>>>> cb012eab1291e632c5fb7e02506a098c75266316

// Start Server
async function startServer() {
  try {
<<<<<<< HEAD
    const connection = await initializeDatabase();
    adminRoutes.setDatabaseConnection(connection);
    userDashboardRoutes.setDatabaseConnection(connection);
    app.use('/', indexRoutes);
    app.use('/api/auth/admin', adminRoutes.router);
    app.use('/api', userDashboardRoutes.router);
    app.use('/admindashboard', adminDashboardRoutes);

    // Serve frontend
    app.get('/userdashboard', (req, res) => {
      res.sendFile(path.join(__dirname, 'public', 'userdashboard.html'));
    });

    // Error handling middleware
    app.use((err, req, res, next) => {
      console.error('Server error:', err.stack);
      if (err instanceof multer.MulterError) {
        return res.status(400).json({ error: 'File upload error: ' + err.message });
      }
      res.status(500).json({ error: 'Something went wrong!', details: err.message });
    });

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
  } catch (error) {
    console.error('Failed to start server:', error.message);
=======
    await initializeDatabase();
    app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
  } catch (error) {
    console.error('Failed to start server:', error.stack);
>>>>>>> cb012eab1291e632c5fb7e02506a098c75266316
    process.exit(1);
  }
}

startServer();
