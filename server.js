require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const session = require('express-session');
const cloudinary = require('cloudinary').v2;
const path = require('path');
const indexRoutes = require('./routes/index');
const adminRoutes = require('./routes/admin');
const adminDashboardRoutes = require('./routes/admindashboard');
const userDashboardRoutes = require('./routes/userdashboard');

const app = express();

// Middleware
app.use(cors({
  origin: [process.env.CLIENT_URL || 'http://localhost:3000', 'http://localhost:3000'],
  credentials: true,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'default_session_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' },
}));
app.use(express.static(path.join(__dirname, 'public')));

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Database connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
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

// Initialize database
async function initializeDatabase() {
  try {
    const connection = await pool.getConnection();
    console.log('Connected to MySQL database');
    connection.release();
  } catch (error) {
    console.error('Database connection error:', error.message);
    process.exit(1);
  }
}

// Routes
app.use('/api', indexRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/admin', adminDashboardRoutes);
app.use('/api/user', userDashboardRoutes);

// Fallback route for userdashboard.html
app.get('/userdashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'userdashboard.html'), (err) => {
    if (err) {
      console.error('Error serving userdashboard.html:', err);
      res.status(404).json({ error: 'Page not found' });
    }
  });
});

// Fallback for client-side routing (e.g., refresh on userdashboard.html)
app.get('*', (req, res) => {
  if (req.url.startsWith('/api')) {
    res.status(404).json({ error: 'API endpoint not found' });
  } else {
    res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
      if (err) {
        console.error('Error serving fallback index.html:', err);
        res.status(404).json({ error: 'Resource not found' });
      }
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  if (err.message === 'Only JPEG or PNG images are allowed') {
    return res.status(400).json({ error: err.message });
  }
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'File too large. Please upload an image under 2MB.' });
  }
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({ error: 'Token expired' });
  }
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong',
  });
});

// Start server
const PORT = process.env.PORT || 3000;
async function startServer() {
  try {
    await initializeDatabase();
    app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();