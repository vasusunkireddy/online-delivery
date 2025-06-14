const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);

dotenv.config();

const app = express();

// Middleware
app.use(cors({
  origin: process.env.CLIENT_URL ? process.env.CLIENT_URL.split(',') : ['http://localhost:3000', 'https://delicute.onrender.com'],
  credentials: true,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true}));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret',
  resave: false,
  saveUninitialized: false,
  store: new MySQLStore({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  }),
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 },
}));

// Database pool
async function initializeDatabase() {
  try {
    const pool = await mysql.createPool({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });
    const connection = await pool.getConnection();
    console.log('✅ Database connected successfully');
    connection.release();
    return pool;
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    throw error;
  }
}

// Routes
let adminDashboardRoutes;
try {
  adminDashboardRoutes = require('./routes/admindashboard');
  console.log('✅ Loaded routes/admindashboard.js');
} catch (error) {
  console.error('❌ Failed to load routes/admindashboard.js:', error.message);
}

// Mount routes
if (adminDashboardRoutes) {
  app.use('/api/admin/dashboard', (req, res, next) => {
    console.log(`Received request for ${req.originalUrl}`);
    next();
  }, adminDashboardRoutes);
} else {
  console.warn('⚠️ /api/admin/dashboard routes not mounted due to load failure');
}

// Serve frontend
app.get('/admin/dashboard', (req, res) => {
  console.log('Serving admindashboard.html');
  res.sendFile(path.join(__dirname, 'public', 'admindashboard.html'));
});

// Catch-all for unmatched API routes
app.use('/api/*', (req, res) => {
  console.warn(`❌ 404: API route not found: ${req.originalUrl}`);
  res.status(404).json({ error: `API endpoint not found: ${req.originalUrl}` });
});

// Catch-all for frontend
app.get('*', (req, res) => {
  console.log(`Serving frontend file for ${req.path}`);
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling
app.use((err, req, res, next) => {
  console.error('❌ Server error:', err.stack);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

// Start server
const PORT = process.env.PORT || 3000;
async function startServer() {
  try {
    const pool = await initializeDatabase();
    app.set('dbPool', pool);
    app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
