const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const fileupload = require('express-fileupload');

dotenv.config({ path: path.resolve(__dirname, '.env') });

const app = express();

// Validate environment variables
const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'SESSION_SECRET'];
const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingEnvVars.length > 0) {
  console.error(`❌ Missing environment variables: ${missingEnvVars.join(', ')}`);
  process.exit(1);
}

// Middleware
app.use(cors({
  origin: process.env.CLIENT_URL ? process.env.CLIENT_URL.split(',').map(url => url.trim()) : ['http://localhost:3000', 'https://delicute.onrender.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(fileupload({
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  abortOnLimit: true,
  createParentPath: true,
}));

app.use(express.static(path.join(__dirname, 'public')));

// 🔁 Fix casing: /Uploads → /uploads
app.use((req, res, next) => {
  if (req.url.startsWith('/Uploads/')) {
    return res.redirect(301, req.url.replace('/Uploads/', '/uploads/'));
  }
  next();
});

// 🔁 Fix trailing slashes: /uploads/file.png/ → /uploads/file.png
app.use((req, res, next) => {
  if (req.path.startsWith('/uploads/') && req.path.endsWith('/')) {
    return res.redirect(301, req.path.replace(/\/+$/, ''));
  }
  next();
});

// Static upload serving
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  setHeaders: (res) => {
    res.set('Cache-Control', 'public, max-age=31536000');
  },
  index: false,
}));

// 404 handler for missing upload files
app.use('/uploads/*', (req, res) => {
  console.warn(`❌ 404: File not found: ${req.originalUrl}`);
  res.status(404).json({ error: 'File not found' });
});

// Trust proxy for production
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// Session store
const sessionStore = new MySQLStore({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  createDatabaseTable: true,
  clearExpired: true,
  checkExpirationInterval: 15 * 60 * 1000,
  expiration: 24 * 60 * 60 * 1000,
  schema: {
    tableName: 'sessions',
    columnNames: {
      session_id: 'session_id',
      expires: 'expires',
      data: 'data',
    },
  },
}, null, (error) => {
  if (error) {
    console.error('❌ Failed to initialize session store:', error.message);
    process.exit(1);
  }
  console.log('✅ Session store initialized');
});

sessionStore.on('error', (error) => {
  console.error('❌ Session store runtime error:', error.message);
});

// Session middleware
app.use((req, res, next) => {
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    },
  })(req, res, (err) => {
    if (err) {
      console.error(`❌ Session middleware error for ${req.method} ${req.originalUrl}:`, err.message);
      return res.status(500).json({ error: 'Session initialization failed' });
    }
    if (!req.session) {
      req.session = {};
      console.warn(`⚠️ Session not initialized for ${req.method} ${req.originalUrl}, using fallback`);
    }
    next();
  });
});

// Middleware to attach user to request
const setUserMiddleware = (req, res, next) => {
  if (req.session.user) {
    req.user = req.session.user;
    console.log(`Set req.user: ${req.user.email} (${req.user.role})`);
  } else {
    req.user = null;
  }
  next();
};

// Auth check
const isAuthenticated = (req, res, next) => {
  if (!req.session.user) {
    console.log(`Unauthorized access to ${req.originalUrl}`);
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
};

// Session debug logger
app.use((req, res, next) => {
  const userInfo = req.session.user
    ? `${req.session.user.email} (${req.session.user.role})`
    : 'None';
  console.log(`Request: ${req.method} ${req.originalUrl}, SessionID: ${req.sessionID || 'None'}, User: ${userInfo}, req.user: ${req.user ? req.user.email : 'None'}`);
  next();
});

// DB pool
async function initializeDatabase() {
  try {
    const pool = await mysql.createPool({
      host: process.env.DB_HOST,
      port: parseInt(process.env.DB_PORT) || 3306,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      charset: 'utf8mb4',
    });
    await pool.getConnection();
    console.log('✅ Database connected successfully');
    pool.on('error', (error) => {
      console.error('❌ Database pool error:', error.message);
    });
    return pool;
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    throw error;
  }
}

// Routes
function loadRoutes(routePath) {
  try {
    const routes = require(routePath);
    console.log(`✅ Loaded ${path.basename(routePath)} routes`);
    return routes;
  } catch (error) {
    console.error(`❌ Failed to load ${path.basename(routePath)} routes:`, error.message);
    throw error;
  }
}

async function setupRoutes(pool) {
  app.set('dbPool', pool);
  app.use(setUserMiddleware);
  app.use('/api/admin', isAuthenticated, loadRoutes('./routes/admin'));
  app.use('/api/admin/dashboard', isAuthenticated, loadRoutes('./routes/admindashboard'));
  app.use('/api/user', isAuthenticated, loadRoutes('./routes/userdashboard'));
  app.use('/api', loadRoutes('./routes/index'));

  // Frontend serving
  app.get('/', (req, res) => {
    console.log('Serving index.html');
    res.sendFile(path.join(__dirname, 'public', 'index.html'), err => {
      if (err) handleFileError(err, res);
    });
  });

  app.get('/admin', (req, res) => {
    console.log('Serving admin.html');
    res.sendFile(path.join(__dirname, 'public', 'admin.html'), err => {
      if (err) handleFileError(err, res);
    });
  });

  app.get('/admin/dashboard', isAuthenticated, (req, res) => {
    console.log('Serving admindashboard.html');
    if (!req.session.user || req.session.user.role !== 'admin') {
      console.log('No admin role, redirecting to /admin');
      return res.redirect('/admin');
    }
    res.sendFile(path.join(__dirname, 'public', 'admindashboard.html'), err => {
      if (err) handleFileError(err, res);
    });
  });

  app.get('/userdashboard', isAuthenticated, (req, res) => {
    console.log('Serving userdashboard.html');
    res.sendFile(path.join(__dirname, 'public', 'userdashboard.html'), err => {
      if (err) handleFileError(err, res);
    });
  });

  app.get('/favicon.ico', (req, res) => {
    const faviconPath = path.join(__dirname, 'public', 'favicon.ico');
    res.sendFile(faviconPath, err => {
      if (err) {
        console.warn(`⚠️ Favicon not found: ${err.message}`);
        res.status(404).send('Favicon not found');
      }
    });
  });

  // Unmatched API routes
  app.use('/api/*', (req, res) => {
    console.warn(`❌ 404: API route not found: ${req.originalUrl}`);
    res.status(404).json({ error: `API endpoint not found: ${req.originalUrl}` });
  });

  // Catch-all (SPA fallback)
  app.get('*', (req, res) => {
    if (req.path.startsWith('/.well-known/') || req.path.match(/\.(js|css|jpg|png|ico)$/)) {
      return res.status(404).json({ error: 'Asset not found' });
    }
    console.log(`Serving index.html for ${req.path}`);
    res.sendFile(path.join(__dirname, 'public', 'index.html'), err => {
      if (err) handleFileError(err, res);
    });
  });
}

// Handle file serving errors
function handleFileError(err, res) {
  console.error('❌ File serving error:', err.message);
  res.status(404).json({ error: 'Resource not found' });
}

// Global error handler
app.use((err, req, res, next) => {
  const sessionInfo = req.session ? `SessionID: ${req.sessionID || 'None'}` : 'Session: Missing';
  const userInfo = req.session && req.session.user
    ? `${req.session.user.email} (${req.session.user.role})`
    : 'None';
  const errorDetails = {
    message: err.message,
    stack: err.stack,
    request: `${req.method} ${req.originalUrl}`,
    session: sessionInfo,
    user: userInfo,
    reqUser: req.user ? req.user.email : 'None',
  };
  console.error('❌ Error:', JSON.stringify(errorDetails, null, 2));
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
const PORT = parseInt(process.env.PORT) || 3000;
async function startServer() {
  try {
    const pool = await initializeDatabase();
    await setupRoutes(pool);
    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`CORS origins: ${process.env.CLIENT_URL || 'http://localhost:3000,https://delicute.onrender.com'}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  }
}

startServer();
