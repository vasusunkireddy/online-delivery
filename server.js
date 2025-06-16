const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const session = require('express-session');
const fileUpload = require('express-fileupload');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();
const app = express();

// Database connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Middleware
app.use(fileUpload());
app.use(express.json());
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 1 day
  }
}));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/Uploads', express.static(path.join(__dirname, 'Uploads')));

const formatDateForMySQL = (date) => {
  if (!date) return new Date().toISOString().slice(0, 19).replace('T', ' ');
  const d = new Date(date);
  if (isNaN(d.getTime())) throw new Error('Invalid date format');
  return d.toISOString().slice(0, 19).replace('T', ' ');
};

async function initializeDatabase() {
  const connection = await pool.getConnection();
  try {
    console.log('Connected to database');

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(15) UNIQUE,
        password VARCHAR(255),
        image VARCHAR(255),
        isAdmin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS menu_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        price DECIMAL(10,2) NOT NULL,
        image VARCHAR(255),
        category VARCHAR(100),
        stock INT DEFAULT 100,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS cart (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        item_id INT,
        name VARCHAR(255) NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        image VARCHAR(255),
        quantity INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (item_id) REFERENCES menu_items(id) ON DELETE CASCADE
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS addresses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        full_name VARCHAR(255) NOT NULL,
        mobile VARCHAR(15) NOT NULL,
        house_no VARCHAR(100) NOT NULL,
        location VARCHAR(255) NOT NULL,
        landmark VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS coupons (
        id INT AUTO_INCREMENT PRIMARY KEY,
        code VARCHAR(50) UNIQUE NOT NULL,
        discount DECIMAL(5,2) NOT NULL,
        image VARCHAR(255),
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS orders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        address_id INT,
        coupon_code VARCHAR(50),
        payment_method ENUM('cod', 'upi') DEFAULT 'cod',
        delivery_cost DECIMAL(10,2) DEFAULT 0,
        total DECIMAL(10,2) NOT NULL,
        status ENUM('pending', 'confirmed', 'shipped', 'delivered', 'cancelled') DEFAULT 'pending',
        date DATETIME NOT NULL,
        cancellation_reason TEXT,
        payment_status ENUM('pending', 'paid') DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (address_id) REFERENCES addresses(id) ON DELETE SET NULL,
        FOREIGN KEY (coupon_code) REFERENCES coupons(code) ON DELETE CASCADE
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS order_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        order_id INT,
        item_id INT,
        name VARCHAR(255) NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        quantity INT NOT NULL,
        image VARCHAR(255),
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
        FOREIGN KEY (item_id) REFERENCES menu_items(id) ON DELETE SET NULL
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        token VARCHAR(255) NOT NULL,
        expires_at VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS restaurant_status (
        id INT PRIMARY KEY,
        status ENUM('open', 'closed') DEFAULT 'closed',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS favorites (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        item_id INT,
        name VARCHAR(255) NOT NULL,
        image VARCHAR(255),
        price DECIMAL(10,2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (item_id) REFERENCES menu_items(id) ON DELETE CASCADE
      )
    `);

    await connection.query(`
      INSERT IGNORE INTO restaurant_status (id, status) VALUES (1, 'closed')
    `);

    await connection.query(`
      INSERT IGNORE INTO coupons (code, discount, image, expires_at) VALUES
      ('WELCOME10', 10.00, NULL, DATE_ADD(NOW(), INTERVAL 30 DAY)),
      ('SAVE20', 20.00, NULL, DATE_ADD(NOW(), INTERVAL 30 DAY))
    `);

    const [adminUsers] = await connection.query('SELECT id FROM users WHERE isAdmin = TRUE');
    if (!adminUsers.length) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await connection.query(
        `INSERT INTO users (name, email, phone, password, isAdmin) VALUES (?, ?, ?, ?, TRUE)`,
        ['Admin', 'admin@delicute.com', '9999999999', hashedPassword]
      );
    }

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error.message, error.stack);
    throw error;
  } finally {
    connection.release();
  }
}

// Routes
app.use('/api', require('./routes/index'));
app.use('/api', require('./routes/userdashboard'));
app.use('/api', require('./routes/admin'));
app.use('/api', require('./routes/admindashboard'));

app.all('/api/*', (req, res) => {
  console.warn(`API route not found: ${req.originalUrl}`);
  res.status(404).json({ error: `API endpoint ${req.originalUrl} not found` });
});

app.use((err, req, res, next) => {
  console.error('Error:', err.message, err.stack);
  res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
async function startServer() {
  try {
    await initializeDatabase();
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  } catch (error) {
    console.error('Failed to start server:', error.message);
    process.exit(1);
  }
}

startServer();