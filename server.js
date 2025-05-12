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
const winston = require('winston');
require('dotenv').config();
const net = require('net');

// Initialize Express app and HTTP server
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
<<<<<<< HEAD
    origin: [
      process.env.CLIENT_URL,
      'https://delicute.onrender.com',
      'http://localhost:3000',
    ].filter(Boolean),
=======
    origin: [process.env.CLIENT_URL, 'https://delicute.onrender.com'],
>>>>>>> c920dafbda6f22b5b932d813c7068eb9ecf29ef1
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
  },
});

// Logger setup
const logger = winston.createLogger({
  level: 'error',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.Console({ format: winston.format.simple() }),
  ],
});

// Validate environment variables
const requiredEnv = [
  'DATABASE_URL',
  'JWT_SECRET',
  'EMAIL_USER',
  'EMAIL_PASS',
  'GOOGLE_CLIENT_ID',
];
const missingEnv = requiredEnv.filter(env => !process.env[env]);
if (missingEnv.length > 0) {
  const errorMsg = `Missing required environment variables: ${missingEnv.join(', ')}`;
  logger.error(errorMsg);
  console.error(errorMsg);
  process.exit(1);
}

// Set default environment variables
process.env.PORT = process.env.PORT || '3000';
process.env.CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:3000';

// Google OAuth2 Client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// PostgreSQL Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 20000,
  max: 20,
  idleTimeoutMillis: 60000,
});
pool.on('error', (err) => {
  logger.error('PostgreSQL pool error', { message: err.message, stack: err.stack });
});

// Multer for file uploads
const uploadDir = path.join(__dirname, 'Uploads');
if (!fs.existsSync(uploadDir)) {
  try {
    fs.mkdirSync(uploadDir, { recursive: true });
    fs.chmodSync(uploadDir, 0o755);
  } catch (err) {
    logger.error('Failed to create Uploads directory', { message: err.message, stack: err.stack });
    console.error('Failed to create Uploads directory:', err.message);
    process.exit(1);
  }
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
  limits: { fileSize: 5 * 1024 * 1024 },
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
  origin: [
    process.env.CLIENT_URL,
    'http://localhost:3000',
    'https://delicute.onrender.com',
  ].filter(Boolean),
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());
app.use('/Uploads', express.static(uploadDir));
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

// Check if port is in use
function checkPort(port) {
  return new Promise((resolve, reject) => {
    const tester = net.createServer()
      .once('error', (err) => {
        if (err.code === 'EADDRINUSE') {
          reject(new Error(`Port ${port} is already in use`));
        } else {
          reject(err);
        }
      })
      .once('listening', () => {
        tester.once('close', () => resolve(true)).close();
      })
      .listen(port);
  });
}

// Initialize database with retries
async function initializeDatabase() {
  let retries = 5;
  while (retries > 0) {
    try {
      console.log(`Attempting database connection (${retries} retries left)...`);
      logger.info(`Attempting database connection (${retries} retries left)`);
      const client = await pool.connect();
      console.log('Database connected successfully');
      logger.info('Database connected successfully');

      // Create essential tables
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
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          refund_reason TEXT
        );

        CREATE TABLE IF NOT EXISTS order_items (
          id SERIAL PRIMARY KEY,
          order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
          item_id INTEGER REFERENCES menu(id) ON DELETE CASCADE,
          quantity INTEGER NOT NULL,
          price NUMERIC(10,2) NOT NULL
        );

        CREATE TABLE IF NOT EXISTS promotions (
          id SERIAL PRIMARY KEY,
          title VARCHAR(255) NOT NULL,
          description TEXT,
          code VARCHAR(50) UNIQUE,
          discount INTEGER NOT NULL,
          image TEXT,
          start_date DATE,
          end_date DATE,
          image_data BYTEA
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
          status VARCHAR(10) NOT NULL,
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

      // Ensure refund_reason exists
      await client.query(`
        DO $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_name = 'orders' AND column_name = 'refund_reason'
          ) THEN
            ALTER TABLE orders ADD COLUMN refund_reason TEXT;
          END IF;
        END $$;
      `);

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
      logger.info('Database initialized successfully');
      return true;
    } catch (err) {
      retries -= 1;
      const errorMsg = `Database connection attempt failed (${retries} retries left): ${err.message}`;
      console.error(errorMsg);
      logger.error(errorMsg, { stack: err.stack });
      if (retries === 0) {
        throw new Error('Failed to initialize database after all retries');
      }
      await new Promise(resolve => setTimeout(resolve, 10000));
    }
  }
  return false;
}

// Socket.IO Events
io.on('connection', (socket) => {
  logger.info('Socket.IO client connected', { socketId: socket.id });

  socket.on('chatMessage', async (data) => {
    try {
      const { userId, sender, content } = data;
      if (!userId || !sender || !content || !['admin', 'user'].includes(sender)) {
        logger.error('Invalid chat message data', { data });
        socket.emit('error', { message: 'Invalid message data' });
        return;
      }

      const client = await pool.connect();
      const userExists = await client.query('SELECT id FROM users WHERE id = $1', [userId]);
      if (userExists.rows.length === 0) {
        client.release();
        logger.error('User not found for chat message', { userId });
        socket.emit('error', { message: 'User not found' });
        return;
      }

      const result = await client.query(
        'INSERT INTO support_chat (user_id, sender, content) VALUES ($1, $2, $3) RETURNING *',
        [userId, sender, content]
      );
      client.release();

      const message = {
        _id: result.rows[0].id,
        userId: result.rows[0].user_id,
        sender: result.rows[0].sender,
        content: result.rows[0].content,
        timestamp: result.rows[0].timestamp,
      };
      io.emit('chatMessage', message);
      logger.info('Chat message sent', { message });
    } catch (err) {
      logger.error('Socket.IO chat message error', { message: err.message, stack: err.stack });
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  socket.on('newOrder', (order) => {
    io.emit('newOrder', order);
  });

  socket.on('orderStatus', (data) => {
    io.emit('orderStatus', data);
  });

  socket.on('disconnect', () => {
    logger.info('Socket.IO client disconnected', { socketId: socket.id });
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
    logger.error('OTP request error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to send OTP', error: err.message });
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

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
    await client.query('DELETE FROM otps WHERE email = $1', [email]);
    client.release();

    res.status(201).json({ token, user: { id: user.id, email: user.email, role: user.role } });
  } catch (err) {
    logger.error('Signup error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Signup failed', error: err.message });
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

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, image: user.image, role: user.role },
    });
  } catch (err) {
    logger.error('Login error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Login failed due to server error', error: err.message });
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
        'INSERT INTO users (name, email, phone, password, address, role, google_id, image) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, email, role, name, image',
        [name || 'Google User', email, null, hashedPassword, 'Google Address', 'user', google_id, '/assets/fallback-profile.png']
      );
      user = result.rows[0];
    } else if (!user.google_id) {
      await client.query('UPDATE users SET google_id = $1 WHERE email = $2', [google_id, email]);
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
    client.release();

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, image: user.image, role: user.role },
    });
  } catch (err) {
    logger.error('Google login error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Google login failed', error: err.message });
  }
});

// Reset Password
app.post('/api/users/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ message: 'New password must be at least 8 characters' });
  }

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
    logger.error('Reset password error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Reset password failed', error: err.message });
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
    logger.error('Admin profile fetch error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to fetch profile', error: err.message });
  }
});

app.put('/api/admin/profile', authenticateToken, authenticateAdmin, async (req, res) => {
  const { name, email, image } = req.body;

  if (!name || !email) {
    return res.status(400).json({ message: 'Name and email are required' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(
      'UPDATE users SET name = $1, email = $2, image = COALESCE($3, image) WHERE id = $4 RETURNING id, name, email, image',
      [name, email, image, req.user.id]
    );
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    logger.error('Admin profile update error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to update profile', error: err.message });
  }
});

// Image Upload
app.post('/api/upload/:type', authenticateToken, (req, res) => {
  const type = req.params.type;
  if (!['profile', 'menu', 'promotion'].includes(type)) {
    return res.status(400).json({ message: 'Invalid upload type' });
  }

  upload(req, res, async (err) => {
    if (err) {
      logger.error('Image upload error', { message: err.message, stack: err.stack });
      return res.status(400).json({ message: err.message || 'File upload failed' });
    }
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }
    const url = `/Uploads/${req.file.filename}`;
    if (type === 'promotion') {
      try {
        const imageData = fs.readFileSync(path.join(uploadDir, req.file.filename));
        return res.json({ url, imageData: imageData.toString('base64') });
      } catch (err) {
        logger.error('Image data read error', { message: err.message, stack: err.stack });
        return res.status(500).json({ message: 'Failed to read image data', error: err.message });
      }
    }
    res.json({ url });
  });
});

// Menu
app.get('/api/menu', async (req, res) => {
  const { category, search } = req.query;
  try {
    const client = await pool.connect();
    let query = 'SELECT id, name, price, category, description, image, available FROM menu WHERE available = TRUE';
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
    logger.error('Menu fetch error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to fetch menu', error: err.message });
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
    logger.error('Menu item fetch error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to fetch menu item', error: err.message });
  }
});

app.post('/api/menu', authenticateToken, authenticateAdmin, async (req, res) => {
  const { name, category, price, description, available, image } = req.body;

  if (!name || !category || !price) {
    return res.status(400).json({ message: 'Name, category, and price are required' });
  }
  if (isNaN(price) || price <= 0) {
    return res.status(400).json({ message: 'Price must be a positive number' });
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
    logger.error('Menu item create error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to create menu item', error: err.message });
  }
});

app.put('/api/menu/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, category, price, description, available, image } = req.body;

  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid menu item ID is required' });
  }
  if (!name || !category || !price) {
    return res.status(400).json({ message: 'Name, category, and price are required' });
  }
  if (isNaN(price) || price <= 0) {
    return res.status(400).json({ message: 'Price must be a positive number' });
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
    logger.error('Menu item update error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to update menu item', error: err.message });
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
    res.json({ message: 'Menu item deleted', id });
  } catch (err) {
    logger.error('Menu item delete error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to delete menu item', error: err.message });
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
    logger.error('Add to cart error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to add item to cart', error: err.message });
  }
});

// Orders
app.get('/api/orders', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const client = await pool.connect();
    const columnCheck = await client.query(`
      SELECT 1
      FROM information_schema.columns
      WHERE table_name = 'orders' AND column_name = 'refund_reason'
    `);
    const hasRefundReason = columnCheck.rows.length > 0;

    const query = `
      SELECT o.id, o.user_id, o.items, o.total, o.status, o.payment_method, o.created_at
        ${hasRefundReason ? ', o.refund_reason' : ''}
        , u.name as customer_name
      FROM orders o
      JOIN users u ON o.user_id = u.id
      ORDER BY o.created_at DESC
    `;
    const result = await client.query(query);
    client.release();
    res.json(
      result.rows.map((row) => ({
        _id: row.id,
        userId: row.user_id,
        customer: { name: row.customer_name },
        items: row.items,
        total: row.total,
        status: row.status,
        paymentMethod: row.payment_method,
        createdAt: row.created_at,
        refundReason: row.refund_reason || null,
      }))
    );
  } catch (err) {
    logger.error('Orders fetch error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to fetch orders', error: err.message });
  }
});

app.get('/api/orders/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid order ID is required' });
  }

  try {
    const client = await pool.connect();
    const columnCheck = await client.query(`
      SELECT 1
      FROM information_schema.columns
      WHERE table_name = 'orders' AND column_name = 'refund_reason'
    `);
    const hasRefundReason = columnCheck.rows.length > 0;

    const query = `
      SELECT o.id, o.user_id, o.items, o.total, o.status, o.payment_method, o.created_at
        ${hasRefundReason ? ', o.refund_reason' : ''}
        , u.name as customer_name
      FROM orders o
      JOIN users u ON o.user_id = u.id
      WHERE o.id = $1
    `;
    const result = await client.query(query, [id]);
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
      createdAt: row.created_at,
      refundReason: row.refund_reason || null,
    });
  } catch (err) {
    logger.error('Order fetch error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to fetch order', error: err.message });
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
    logger.error('Order create error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to create order', error: err.message });
  }
});

app.post('/api/orders/:id/refund', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;

  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid order ID is required' });
  }
  if (!reason) {
    return res.status(400).json({ message: 'Refund reason is required' });
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

    const columnCheck = await client.query(`
      SELECT 1
      FROM information_schema.columns
      WHERE table_name = 'orders' AND column_name = 'refund_reason'
    `);
    const hasRefundReason = columnCheck.rows.length > 0;

    const query = hasRefundReason
      ? 'UPDATE orders SET status = $1, refund_reason = $2 WHERE id = $3 RETURNING *'
      : 'UPDATE orders SET status = $1 WHERE id = $2 RETURNING *';
    const params = hasRefundReason ? ['refunded', reason, id] : ['refunded', id];

    const result = await client.query(query, params);
    client.release();

    io.emit('orderStatus', { orderId: id, status: 'refunded', refundReason: reason });
    res.json(result.rows[0]);
  } catch (err) {
    logger.error('Refund process error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to process refund', error: err.message });
  }
});

// Promotions
app.get('/api/promotions', async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query(`
      SELECT id, title, code, discount, description, start_date, end_date, image
      FROM promotions
      WHERE start_date <= CURRENT_DATE AND end_date >= CURRENT_DATE
    `);
    client.release();
    res.json(
      result.rows.map((p) => ({
        _id: p.id,
        title: p.title,
        code: p.code,
        discount: p.discount,
        description: p.description,
        startDate: p.start_date,
        endDate: p.end_date,
        image: p.image || '/assets/fallback-promotion.png',
      }))
    );
  } catch (err) {
    logger.error('Promotions fetch error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to fetch promotions', error: err.message });
  }
});

app.get('/api/promotions/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid promotion ID is required' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(
      'SELECT id, title, code, discount, description, start_date, end_date, image FROM promotions WHERE id = $1',
      [id]
    );
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Promotion not found' });
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
      image: p.image || '/assets/fallback-promotion.png',
    });
  } catch (err) {
    logger.error('Promotion fetch error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to fetch promotion', error: err.message });
  }
});

app.post('/api/promotions', authenticateToken, authenticateAdmin, async (req, res) => {
  const { title, code, discount, description, startDate, endDate, image, imageData } = req.body;

  if (!title || !code || !discount || !startDate || !endDate) {
    return res.status(400).json({ message: 'Title, code, discount, startDate, and endDate are required' });
  }
  if (isNaN(discount) || discount <= 0) {
    return res.status(400).json({ message: 'Discount must be a positive number' });
  }
  if (isNaN(Date.parse(startDate)) || isNaN(Date.parse(endDate))) {
    return res.status(400).json({ message: 'Invalid date format for startDate or endDate' });
  }

  try {
    const client = await pool.connect();
    const codeExists = await client.query('SELECT id FROM promotions WHERE code = $1', [code.trim()]);
    if (codeExists.rows.length > 0) {
      client.release();
      return res.status(400).json({ message: 'Promotion code already exists' });
    }

    const imageDataBuffer = imageData ? Buffer.from(imageData, 'base64') : null;
    const result = await client.query(
      'INSERT INTO promotions (title, code, discount, description, start_date, end_date, image, image_data) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [title.trim(), code.trim(), discount, description || null, startDate, endDate, image || null, imageDataBuffer]
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
      image: result.rows[0].image || '/assets/fallback-promotion.png',
    });
  } catch (err) {
    logger.error('Promotion create error', { message: err.message, stack: err.stack });
    if (err.code === '23505') {
      res.status(400).json({ message: 'Promotion code already exists' });
    } else {
      res.status(500).json({ message: 'Failed to create promotion', error: err.message });
    }
  }
});

app.put('/api/promotions/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { title, code, discount, description, startDate, endDate, image, imageData } = req.body;

  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid promotion ID is required' });
  }
  if (!title && !code && !discount && !startDate && !endDate && !image && description === undefined && !imageData) {
    return res.status(400).json({ message: 'At least one field is required for update' });
  }
  if (discount && (isNaN(discount) || discount <= 0)) {
    return res.status(400).json({ message: 'Discount must be a positive number' });
  }
  if ((startDate && isNaN(Date.parse(startDate))) || (endDate && isNaN(Date.parse(endDate)))) {
    return res.status(400).json({ message: 'Invalid date format for startDate or endDate' });
  }

  try {
    const client = await pool.connect();
    const existingPromotion = await client.query('SELECT * FROM promotions WHERE id = $1', [id]);
    if (existingPromotion.rows.length === 0) {
      client.release();
      return res.status(404).json({ message: 'Promotion not found' });
    }

    if (code && code.trim() !== existingPromotion.rows[0].code) {
      const codeExists = await client.query('SELECT id FROM promotions WHERE code = $1 AND id != $2', [code.trim(), id]);
      if (codeExists.rows.length > 0) {
        client.release();
        return res.status(400).json({ message: 'Promotion code already exists' });
      }
    }

    const fields = [];
    const values = [];
    let index = 1;

    if (title) {
      fields.push(`title = $${index++}`);
      values.push(title.trim());
    }
    if (code) {
      fields.push(`code = $${index++}`);
      values.push(code.trim());
    }
    if (discount) {
      fields.push(`discount = $${index++}`);
      values.push(discount);
    }
    if (description !== undefined) {
      fields.push(`description = $${index++}`);
      values.push(description || null);
    }
    if (startDate) {
      fields.push(`start_date = $${index++}`);
      values.push(startDate);
    }
    if (endDate) {
      fields.push(`end_date = $${index++}`);
      values.push(endDate);
    }
    if (image) {
      fields.push(`image = $${index++}`);
      values.push(image);
    }
    if (imageData) {
      fields.push(`image_data = $${index++}`);
      values.push(Buffer.from(imageData, 'base64'));
    }

    if (fields.length === 0) {
      client.release();
      return res.status(400).json({ message: 'No valid fields provided for update' });
    }

    values.push(id);
    const query = `UPDATE promotions SET ${fields.join(', ')} WHERE id = $${index} RETURNING *`;
    const result = await client.query(query, values);
    client.release();

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Promotion not found' });
    }

    res.json({
      _id: result.rows[0].id,
      title: result.rows[0].title,
      code: result.rows[0].code,
      discount: result.rows[0].discount,
      description: result.rows[0].description,
      startDate: result.rows[0].start_date,
      endDate: result.rows[0].end_date,
      image: result.rows[0].image || '/assets/fallback-promotion.png',
    });
  } catch (err) {
    logger.error('Promotion update error', { message: err.message, stack: err.stack });
    if (err.code === '23505') {
      res.status(400).json({ message: 'Promotion code already exists' });
    } else {
      res.status(500).json({ message: 'Failed to update promotion', error: err.message });
    }
  }
});

app.delete('/api/promotions/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;

  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid promotion ID is required' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query('DELETE FROM promotions WHERE id = $1 RETURNING id', [id]);
    client.release();
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Promotion not found' });
    }
    res.json({ message: 'Promotion deleted', id: result.rows[0].id });
  } catch (err) {
    logger.error('Promotion delete error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to delete promotion', error: err.message });
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
    logger.error('Testimonials fetch error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to fetch testimonials', error: err.message });
  }
});

// Users
app.get('/api/users', authenticateToken, authenticateAdmin, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT id, name, email, phone, loyalty_points FROM users WHERE role = $1', ['user']);
    const orders = await client.query('SELECT user_id, COUNT(*) as order_count FROM orders GROUP BY user_id');
    client.release();

    const users = result.rows.map((user) => ({
      _id: user.id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      loyaltyPoints: user.loyalty_points,
      orders: orders.rows.find((o) => o.user_id == user.id)?.order_count || 0,
    }));
    res.json(users);
  } catch (err) {
    logger.error('Users fetch error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to fetch users', error: err.message });
  }
});

app.get('/api/users/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid user ID is required' });
  }

  try {
    const client = await pool.connect();
    const userResult = await client.query('SELECT id, name, email, phone, loyalty_points FROM users WHERE id = $1 AND role = $2', [
      id,
      'user',
    ]);
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
      orders: parseInt(ordersResult.rows[0].order_count),
    });
  } catch (err) {
    logger.error('User fetch error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to fetch user', error: err.message });
  }
});

app.put('/api/users/:id/loyalty', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { points } = req.body;

  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid user ID is required' });
  }
  if (!Number.isInteger(points)) {
    return res.status(400).json({ message: 'Points must be an integer' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(
      'UPDATE users SET loyalty_points = loyalty_points + $1 WHERE id = $2 AND role = $3 RETURNING *',
      [points, id, 'user']
    );
    if (result.rows.length === 0) {
      client.release();
      return res.status(404).json({ message: 'User not found' });
    }

    const columnCheck = await client.query(`
      SELECT 1
      FROM information_schema.columns
      WHERE table_name = 'loyalty_history' AND column_name = 'action'
    `);
    if (columnCheck.rows.length > 0) {
      await client.query(
        'INSERT INTO loyalty_history (user_id, points, action) VALUES ($1, $2, $3)',
        [id, points, points >= 0 ? 'added' : 'deducted']
      );
    }
    client.release();
    res.json({ message: 'Loyalty points updated', loyaltyPoints: result.rows[0].loyalty_points });
  } catch (err) {
    logger.error('Loyalty points update error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to update loyalty points', error: err.message });
  }
});

// Support Chat
app.get('/api/support/chat/:userId', authenticateToken, authenticateAdmin, async (req, res) => {
  const { userId } = req.params;
  if (!userId || isNaN(userId)) {
    logger.error('Invalid user ID for support chat fetch', { userId });
    return res.status(400).json({ message: 'Valid user ID is required' });
  }

  try {
    const client = await pool.connect();
    const userExists = await client.query('SELECT id FROM users WHERE id = $1', [userId]);
    if (userExists.rows.length === 0) {
      client.release();
      logger.error('User not found for support chat', { userId });
      return res.status(404).json({ message: 'User not found' });
    }

    const result = await client.query(
      'SELECT id, user_id, sender, content, timestamp FROM support_chat WHERE user_id = $1 ORDER BY timestamp',
      [userId]
    );
    client.release();
    res.json(
      result.rows.map((msg) => ({
        _id: msg.id,
        userId: msg.user_id,
        sender: msg.sender,
        content: msg.content,
        timestamp: msg.timestamp,
      }))
    );
  } catch (err) {
    logger.error('Support chat fetch error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to fetch chat messages', error: err.message });
  }
});

app.post('/api/support/chat/:userId', authenticateToken, authenticateAdmin, async (req, res) => {
  const { userId } = req.params;
  const { content } = req.body;

  if (!userId || isNaN(userId)) {
    logger.error('Invalid user ID for support chat send', { userId });
    return res.status(400).json({ message: 'Valid user ID is required' });
  }
  if (!content || typeof content !== 'string' || content.trim() === '') {
    logger.error('Invalid content for support chat', { content });
    return res.status(400).json({ message: 'Content is required and must be a non-empty string' });
  }

  try {
    const client = await pool.connect();
    const userExists = await client.query('SELECT id FROM users WHERE id = $1', [userId]);
    if (userExists.rows.length === 0) {
      client.release();
      logger.error('User not found for support chat', { userId });
      return res.status(404).json({ message: 'User not found' });
    }

    const result = await client.query(
      'INSERT INTO support_chat (user_id, sender, content) VALUES ($1, $2, $3) RETURNING *',
      [userId, 'admin', content.trim()]
    );
    client.release();

    const message = {
      _id: result.rows[0].id,
      userId: result.rows[0].user_id,
      sender: result.rows[0].sender,
      content: result.rows[0].content,
      timestamp: result.rows[0].timestamp,
    };
    io.emit('chatMessage', message);
    logger.info('Support chat message sent', { message });
    res.json(message);
  } catch (err) {
    logger.error('Support chat send error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to send message', error: err.message });
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
    res.json(
      result.rows.map((t) => ({
        _id: t.id,
        userId: t.user_id,
        customer: { name: t.customer_name },
        subject: t.subject,
        description: t.description,
        status: t.status,
        createdAt: t.created_at,
      }))
    );
  } catch (err) {
    logger.error('Support tickets fetch error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to fetch support tickets', error: err.message });
  }
});

app.post('/api/support/tickets', authenticateToken, async (req, res) => {
  const { subject, description } = req.body;

  if (!subject || !description) {
    return res.status(400).json({ message: 'Subject and description are required' });
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
    logger.error('Support ticket create error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to create support ticket', error: err.message });
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
    res.json(
      result.rows.map((f) => ({
        _id: f.id,
        userId: f.user_id,
        customer: { name: f.customer_name },
        rating: f.rating,
        comment: f.comment,
        createdAt: f.created_at,
      }))
    );
  } catch (err) {
    logger.error('Feedback fetch error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to fetch feedback', error: err.message });
  }
});

app.get('/api/feedback/:id', authenticateToken, authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  if (!id || isNaN(id)) {
    return res.status(400).json({ message: 'Valid feedback ID is required' });
  }

  try {
    const client = await pool.connect();
    const result = await client.query(
      `
      SELECT f.id, f.user_id, f.rating, f.comment, f.created_at,
             u.name as customer_name
      FROM feedback f
      JOIN users u ON f.user_id = u.id
      WHERE f.id = $1
    `,
      [id]
    );
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
      createdAt: f.created_at,
    });
  } catch (err) {
    logger.error('Feedback fetch error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to fetch feedback', error: err.message });
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
    logger.error('Feedback create error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to create feedback', error: err.message });
  }
});

// Restaurant Status
app.get('/api/restaurant/status', async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT status, open_time, close_time FROM restaurant_status WHERE id = 1');
    client.release();
    if (result.rows.length === 0) {
      logger.error('Restaurant status not found');
      return res.status(404).json({ message: 'Restaurant status not found' });
    }
    res.json({
      status: result.rows[0].status,
      openTime: result.rows[0].open_time,
      closeTime: result.rows[0].close_time,
    });
  } catch (err) {
    logger.error('Restaurant status fetch error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to fetch restaurant status', error: err.message });
  }
});

app.put('/api/restaurant/status', authenticateToken, authenticateAdmin, async (req, res) => {
  const { status, openTime, closeTime } = req.body;

  if (!status || !['open', 'closed'].includes(status)) {
    logger.error('Invalid restaurant status', { status });
    return res.status(400).json({ message: 'Status must be "open" or "closed"' });
  }
  if (!openTime || !/^\d{2}:\d{2}(:\d{2})?$/.test(openTime)) {
    logger.error('Invalid openTime format', { openTime });
    return res.status(400).json({ message: 'openTime must be in HH:MM or HH:MM:SS format' });
  }
  if (!closeTime || !/^\d{2}:\d{2}(:\d{2})?$/.test(closeTime)) {
    logger.error('Invalid closeTime format', { closeTime });
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
      logger.error('Restaurant status not found for update');
      return res.status(404).json({ message: 'Restaurant status not found' });
    }
    res.json({
      message: 'Restaurant status updated',
      data: {
        status: result.rows[0].status,
        openTime: result.rows[0].open_time,
        closeTime: result.rows[0].close_time,
      },
    });
  } catch (err) {
    logger.error('Restaurant status update error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to update restaurant status', error: err.message });
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
    logger.error('Add to favourites error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to add to favourites', error: err.message });
  }
});

// Loyalty
app.get('/api/loyalty', authenticateToken, async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT loyalty_points FROM users WHERE id = $1', [req.user.id]);
    client.release();
    if (result.rows.length === 0) {
      return res.json({ points: 0 });
    }
    res.json({ points: result.rows[0].loyalty_points });
  } catch (err) {
    logger.error('Loyalty fetch error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to fetch loyalty points', error: err.message });
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
    logger.error('Referral create error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Failed to create referral', error: err.message });
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
  logger.error('Server error', { message: err.message, stack: err.stack });
  res.status(500).json({ message: 'Internal server error', error: err.message });
});

// Start server with retry
async function startServer() {
  try {
    await checkPort(process.env.PORT);
    console.log(`Port ${process.env.PORT} is available`);

    const initialized = await initializeDatabase();
    if (initialized) {
      server.listen(process.env.PORT, () => {
        console.log(`Server running on http://localhost:${process.env.PORT}`);
        logger.info(`Server running on http://localhost:${process.env.PORT}`);
      });
    } else {
      throw new Error('Failed to initialize database');
    }
  } catch (err) {
    const errorMsg = `Server start failed: ${err.message}`;
    console.error(errorMsg);
    logger.error(errorMsg, { stack: err.stack });
    console.log('Retrying in 10 seconds...');
    await new Promise((resolve) => setTimeout(resolve, 10000));
    startServer();
  }
}

startServer();