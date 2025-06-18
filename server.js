require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const session = require('express-session');
const cloudinary = require('cloudinary').v2;
const path = require('path');
const fs = require('fs').promises;
const twilio = require('twilio');
const morgan = require('morgan'); // For request logging
const indexRoutes = require('./routes/index');
const adminRoutes = require('./routes/admin');
const adminDashboardRoutes = require('./routes/admindashboard');
const userDashboardRoutes = require('./routes/userdashboard');

const app = express();

// Validate critical environment variables
const requiredEnvVars = [
  'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME',
  'CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET',
  'SESSION_SECRET', 'JWT_SECRET',
];
const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingEnvVars.length) {
  console.error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
  process.exit(1);
}

// Middleware
app.use(morgan('dev')); // Request logging for debugging
app.use(cors({
  origin: [
    process.env.CLIENT_URL || 'http://localhost:3000',
    'https://delicute.onrender.com',
  ].filter(Boolean),
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
}));
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0,
}));

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Twilio configuration
let twilioClient;
try {
  if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_PHONE_NUMBER) {
    twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
    console.log('Twilio client initialized successfully');
  } else {
    console.warn('Twilio credentials missing; SMS notifications will be disabled');
  }
} catch (error) {
  console.error('Twilio initialization error:', error.message);
  console.warn('Twilio client not initialized; SMS notifications will be disabled');
}
app.set('twilioClient', twilioClient);

// Database connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Make pool available to routes
app.set('dbPool', pool);

// Initialize database and verify schema
async function initializeDatabase() {
  try {
    const connection = await pool.getConnection();
    console.log('Connected to MySQL database');

    // Verify required tables
    const requiredTables = ['orders', 'order_items', 'menu_items', 'users', 'addresses', 'coupons', 'restaurant_status'];
    const [tables] = await connection.query(`SHOW TABLES LIKE ?`, ['%']);
    const existingTables = tables.map(row => Object.values(row)[0]);
    const missingTables = requiredTables.filter(table => !existingTables.includes(table));
    if (missingTables.length) {
      console.warn(`Missing database tables: ${missingTables.join(', ')}`);
      // Optionally, create missing tables or throw an error
      // throw new Error(`Missing required tables: ${missingTables.join(', ')}`);
    } else {
      console.log('All required database tables exist');
    }

    connection.release();
  } catch (error) {
    console.error('Database connection error:', error.message);
    throw error;
  }
}

// Routes
app.use('/api', indexRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/admin/dashboard', adminDashboardRoutes);
app.use('/api/user', userDashboardRoutes);

// Authentication middleware for protected static files
const jwt = require('jsonwebtoken');
const authenticateAdminToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized: No token provided' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Access denied: Admin role required' });
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Specific route for admin.html (protected)
app.get('/admin.html', authenticateAdminToken, async (req, res) => {
  const filePath = path.join(__dirname, 'public', 'admin.html');
  console.log(`Request for /admin.html, attempting to serve: ${filePath}`);
  try {
    await fs.access(filePath);
    res.sendFile(filePath, (err) => {
      if (err) {
        console.error(`Error serving admin.html: ${err.message}`);
        res.status(404).json({ error: 'Page not found', message: 'Admin page does not exist' });
      }
    });
  } catch (error) {
    console.error(`admin.html not found at ${filePath}: ${error.message}`);
    res.status(404).json({ error: 'Page not found', message: 'Admin page does not exist' });
  }
});

// Specific route for admindashboard.html (protected)
app.get('/admindashboard.html', authenticateAdminToken, async (req, res) => {
  const filePath = path.join(__dirname, 'public', 'admindashboard.html');
  console.log(`Request for /admindashboard.html, attempting to serve: ${filePath}`);
  try {
    await fs.access(filePath);
    res.sendFile(filePath, (err) => {
      if (err) {
        console.error(`Error serving admindashboard.html: ${err.message}`);
        res.status(404).json({ error: 'Page not found', message: 'Admin dashboard page does not exist' });
      }
    });
  } catch (error) {
    console.error(`admindashboard.html not found at ${filePath}: ${error.message}`);
    res.status(404).json({ error: 'Page not found', message: 'Admin dashboard page does not exist' });
  }
});

// Specific route for userdashboard.html
app.get('/userdashboard.html', async (req, res) => {
  const filePath = path.join(__dirname, 'public', 'userdashboard.html');
  console.log(`Request for /userdashboard.html, attempting to serve: ${filePath}`);
  try {
    await fs.access(filePath);
    res.sendFile(filePath, (err) => {
      if (err) {
        console.error(`Error serving userdashboard.html: ${err.message}`);
        res.status(404).json({ error: 'Page not found', message: 'User dashboard page does not exist' });
      }
    });
  } catch (error) {
    console.error(`userdashboard.html not found at ${filePath}: ${error.message}`);
    res.status(404).json({ error: 'Page not found', message: 'User dashboard page does not exist' });
  }
});

// Fallback route for client-side routing
app.get('*', async (req, res) => {
  if (req.url.startsWith('/api')) {
    console.warn(`API endpoint not found: ${req.method} ${req.url}`);
    return res.status(404).json({ error: 'API endpoint not found', message: 'The requested API route does not exist' });
  }
  const filePath = path.join(__dirname, 'public', 'index.html');
  console.log(`Fallback request for ${req.url}, attempting to serve: ${filePath}`);
  try {
    await fs.access(filePath);
    res.sendFile(filePath, (err) => {
      if (err) {
        console.error(`Error serving fallback index.html: ${err.message}`);
        res.status(404).json({ error: 'Resource not found', message: 'The requested page does not exist' });
      }
    });
  } catch (error) {
    console.error(`index.html not found at ${filePath}: ${error.message}`);
    res.status(404).json({ error: 'Resource not found', message: 'The requested page does not exist' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(`Server error: ${err.stack}`);
  const isDev = process.env.NODE_ENV === 'development';
  const errorResponse = {
    error: 'Internal server error',
    message: isDev ? err.message : 'Something went wrong',
  };

  switch (true) {
    case err.message.includes('Only JPEG, PNG, WebP, GIF, BMP, TIFF, or SVG images are allowed'):
      return res.status(400).json({ error: err.message });
    case err.code === 'LIMIT_FILE_SIZE':
      return res.status(413).json({ error: 'File too large', message: 'Please upload an image under 2MB' });
    case err.name === 'JsonWebTokenError':
      return res.status(401).json({ error: 'Invalid token', message: 'Authentication token is invalid' });
    case err.name === 'TokenExpiredError':
      return res.status(401).json({ error: 'Token expired', message: 'Authentication token has expired' });
    case err.code === 'ER_ACCESS_DENIED_ERROR':
      errorResponse.error = 'Database access denied';
      errorResponse.message = isDev ? err.message : 'Unable to connect to the database';
      return res.status(500).json(errorResponse);
    case err.code === 'ER_NO_SUCH_TABLE':
      errorResponse.error = 'Database table not found';
      errorResponse.message = isDev ? err.message : 'Database configuration error';
      return res.status(500).json(errorResponse);
    case err.message.includes('Twilio'):
      errorResponse.error = 'Twilio service error';
      errorResponse.message = isDev ? err.message : 'Unable to process Twilio request';
      return res.status(500).json(errorResponse);
    case err.code === 'ER_DUP_ENTRY':
      errorResponse.error = 'Duplicate entry';
      errorResponse.message = isDev ? err.message : 'A record with this value already exists';
      return res.status(409).json(errorResponse);
    case err.code === 'ER_BAD_FIELD_ERROR':
      errorResponse.error = 'Invalid database field';
      errorResponse.message = isDev ? err.message : 'Database query error';
      return res.status(500).json(errorResponse);
    default:
      return res.status(500).json(errorResponse);
  }
});

// Start server
const PORT = process.env.PORT || 3000;
async function startServer() {
  try {
    await initializeDatabase();
    app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
  } catch (error) {
    console.error(`Failed to start server: ${error.message}`);
    process.exit(1);
  }
}

startServer();