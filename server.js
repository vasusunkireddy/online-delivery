const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const https = require('https');
const http = require('http');

require('dotenv').config({ path: process.env.NODE_ENV === 'development' ? '.env.local' : '.env' });

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET;

// Database connection with pooling
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'Uploads')));

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'Uploads');
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Images only (PNG, JPEG, GIF)'));
  }
});

// Middleware to verify JWT
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access denied' });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const result = await pool.query('SELECT * FROM users WHERE email = $1 AND role = $2', [decoded.email, 'admin']);
    if (result.rows.length === 0) {
      return res.status(403).json({ message: 'Unauthorized' });
    }
    req.user = decoded;
    next();
  } catch (err) {
    console.error('JWT verification error:', err);
    res.status(403).json({ message: 'Invalid token' });
  }
};

// Initialize database schema with retry
async function initDb(retries = 3, delay = 5000) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(`
          CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255),
            phone VARCHAR(20),
            role VARCHAR(50) DEFAULT 'customer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );

          CREATE TABLE IF NOT EXISTS orders (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            total DECIMAL(10, 2) NOT NULL,
            status VARCHAR(50) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );

          CREATE TABLE IF NOT EXISTS menu (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            category VARCHAR(100) NOT NULL,
            price DECIMAL(10, 2) NOT NULL,
            image VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );

          CREATE TABLE IF NOT EXISTS promotions (
            id SERIAL PRIMARY KEY,
            code VARCHAR(50) UNIQUE NOT NULL,
            discount INTEGER NOT NULL,
            valid_from DATE NOT NULL,
            valid_until DATE NOT NULL,
            image VARCHAR(255),
            usage_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );

          CREATE TABLE IF NOT EXISTS feedback (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            order_id INTEGER REFERENCES orders(id) ON DELETE SET NULL,
            rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
            comment TEXT,
            response TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );

          CREATE TABLE IF NOT EXISTS chat_messages (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            text TEXT NOT NULL,
            is_admin BOOLEAN NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );

          CREATE TABLE IF NOT EXISTS profiles (
            id SERIAL PRIMARY KEY,
            user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            image VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );
        `);
        await client.query('COMMIT');
        console.log('Database schema initialized successfully');
        return;
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      } finally {
        client.release();
      }
    } catch (err) {
      console.error(`Database initialization attempt ${attempt} failed:`, err.message, err.stack);
      if (attempt === retries) {
        throw new Error('Failed to initialize database after multiple attempts');
      }
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// Signup Route
app.post('/api/signup', async (req, res) => {
  const { name, email, password, phone } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Name, email, and password are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, password, phone, role) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, email, hashedPassword, phone, 'admin']
    );
    const user = result.rows[0];
    await pool.query(
      'INSERT INTO profiles (user_id, name, email) VALUES ($1, $2, $3)',
      [user.id, name, email]
    );
    const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });
    res.status(201).json({ token });
  } catch (err) {
    console.error('Signup error:', err);
    if (err.code === '23505') {
      res.status(409).json({ message: 'Email already exists' });
    } else {
      res.status(500).json({ message: 'Error creating user' });
    }
  }
});

// Login Route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 AND role = $2', [email, 'admin']);
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Error logging in' });
  }
});

// Order Routes
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM orders ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching orders:', err);
    res.status(500).json({ message: 'Error fetching orders' });
  }
});

// User Routes
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, phone, created_at FROM users WHERE role = $1 ORDER BY created_at DESC', ['customer']);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ message: 'Error fetching users' });
  }
});

// Menu Routes
app.get('/api/menu', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM menu ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching menu:', err);
    res.status(500).json({ message: 'Error fetching menu' });
  }
});

app.get('/api/menu/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM menu WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Menu item not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error fetching menu item:', err);
    res.status(500).json({ message: 'Error fetching menu item' });
  }
});

app.post('/api/menu', authenticateToken, upload.single('image'), async (req, res) => {
  const { name, category, price } = req.body;
  const image = req.file ? `${process.env.CLIENT_URL}/uploads/${req.file.filename}` : null;
  if (!name || !category || !price || !image) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO menu (name, category, price, image) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, category, parseFloat(price), image]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error adding menu item:', err);
    res.status(500).json({ message: 'Error adding menu item' });
  }
});

app.put('/api/menu/:id', authenticateToken, upload.single('image'), async (req, res) => {
  const { name, category, price } = req.body;
  const image = req.file ? `${process.env.CLIENT_URL}/uploads/${req.file.filename}` : req.body.image;
  try {
    const result = await pool.query(
      'UPDATE menu SET name = $1, category = $2, price = $3, image = $4 WHERE id = $5 RETURNING *',
      [name, category, parseFloat(price), image, req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Menu item not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating menu item:', err);
    res.status(500).json({ message: 'Error updating menu item' });
  }
});

app.delete('/api/menu/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM menu WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Menu item not found' });
    }
    res.json({ message: 'Menu item deleted' });
  } catch (err) {
    console.error('Error deleting menu item:', err);
    res.status(500).json({ message: 'Error deleting menu item' });
  }
});

// Promotion Routes
app.get('/api/promotions', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM promotions ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching promotions:', err);
    res.status(500).json({ message: 'Error fetching promotions' });
  }
});

app.post('/api/promotions', authenticateToken, upload.single('image'), async (req, res) => {
  const { code, discount, valid_from, valid_until } = req.body;
  const image = req.file ? `${process.env.CLIENT_URL}/uploads/${req.file.filename}` : null;
  if (!code || !discount || !valid_from || !valid_until || !image) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO promotions (code, discount, valid_from, valid_until, image) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [code, parseInt(discount), valid_from, valid_until, image]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error adding promotion:', err);
    if (err.code === '23505') {
      res.status(409).json({ message: 'Promo code already exists' });
    } else {
      res.status(500).json({ message: 'Error adding promotion' });
    }
  }
});

app.put('/api/promotions/:id', authenticateToken, upload.single('image'), async (req, res) => {
  const { code, discount, valid_from, valid_until } = req.body;
  const image = req.file ? `${process.env.CLIENT_URL}/uploads/${req.file.filename}` : req.body.image;
  try {
    const result = await pool.query(
      'UPDATE promotions SET code = $1, discount = $2, valid_from = $3, valid_until = $4, image = $5 WHERE id = $6 RETURNING *',
      [code, parseInt(discount), valid_from, valid_until, image, req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Promotion not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating promotion:', err);
    if (err.code === '23505') {
      res.status(409).json({ message: 'Promo code already exists' });
    } else {
      res.status(500).json({ message: 'Error updating promotion' });
    }
  }
});

app.delete('/api/promotions/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM promotions WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Promotion not found' });
    }
    res.json({ message: 'Promotion deleted' });
  } catch (err) {
    console.error('Error deleting promotion:', err);
    res.status(500).json({ message: 'Error deleting promotion' });
  }
});

// Feedback Routes
app.get('/api/feedback', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM feedback ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching feedback:', err);
    res.status(500).json({ message: 'Error fetching feedback' });
  }
});

app.post('/api/feedback/:id/respond', authenticateToken, async (req, res) => {
  const { response } = req.body;
  try {
    const result = await pool.query(
      'UPDATE feedback SET response = $1 WHERE id = $2 RETURNING *',
      [response, req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Feedback not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error responding to feedback:', err);
    res.status(500).json({ message: 'Error responding to feedback' });
  }
});

// Chat Message Routes
app.get('/api/chat-messages', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM chat_messages ORDER BY created_at ASC');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching chat messages:', err);
    res.status(500).json({ message: 'Error fetching chat messages' });
  }
});

app.post('/api/chat-messages', authenticateToken, async (req, res) => {
  const { user_id, text, is_admin } = req.body;
  if (!user_id || !text || is_admin === undefined) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO chat_messages (user_id, text, is_admin) VALUES ($1, $2, $3) RETURNING *',
      [user_id, text, is_admin]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error sending chat message:', err);
    res.status(500).json({ message: 'Error sending chat message' });
  }
});

// Profile Routes
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT name, email, image FROM profiles WHERE user_id = (SELECT id FROM users WHERE email = $1)', [req.user.email]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Profile not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error fetching profile:', err);
    res.status(500).json({ message: 'Error fetching profile' });
  }
});

app.put('/api/profile', authenticateToken, upload.single('image'), async (req, res) => {
  const { name, email } = req.body;
  const image = req.file ? `${process.env.CLIENT_URL}/uploads/${req.file.filename}` : req.body.image;
  try {
    const userResult = await pool.query('SELECT id FROM users WHERE email = $1', [req.user.email]);
    const userId = userResult.rows[0].id;
    const result = await pool.query(
      'UPDATE profiles SET name = $1, email = $2, image = $3 WHERE user_id = $4 RETURNING *',
      [name, email, image, userId]
    );
    if (result.rows.length === 0) {
      const insertResult = await pool.query(
        'INSERT INTO profiles (user_id, name, email, image) VALUES ($1, $2, $3, $4) RETURNING *',
        [userId, name, email, image]
      );
      return res.json(insertResult.rows[0]);
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating profile:', err);
    res.status(500).json({ message: 'Error updating profile' });
  }
});

// Report Routes
app.get('/api/reports/daily', authenticateToken, async (req, res) => {
  const { date } = req.query;
  if (!date) {
    return res.status(400).json({ message: 'Date is required' });
  }
  try {
    const result = await pool.query(
      'SELECT * FROM orders WHERE DATE(created_at) = $1',
      [date]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error generating report:', err);
    res.status(500).json({ message: 'Error generating report' });
  }
});

// CSV Export Route
app.get('/api/export/csv', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM orders');
    const orders = result.rows;
    let csv = 'ID,User ID,Total,Status,Created At\n';
    orders.forEach(order => {
      csv += `${order.id},${order.user_id},${order.total},${order.status},${order.created_at}\n`;
    });
    res.header('Content-Type', 'text/csv');
    res.attachment('orders.csv');
    res.send(csv);
  } catch (err) {
    console.error('Error exporting CSV:', err);
    res.status(500).json({ message: 'Error exporting CSV' });
  }
});

// Start server
if (process.env.NODE_ENV !== 'production') {
  // Local development: Try HTTPS, fall back to HTTP if certificates are missing
  const keyPath = path.join(__dirname, 'key.pem');
  const certPath = path.join(__dirname, 'cert.pem');
  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    const credentials = {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath)
    };
    https.createServer(credentials, app).listen(PORT, async () => {
      try {
        await initDb();
        console.log(`Server running on https://localhost:${PORT}`);
      } catch (err) {
        console.error('Failed to start server:', err);
        process.exit(1);
      }
    });
  } else {
    console.warn('SSL certificates missing, falling back to HTTP');
    http.createServer(app).listen(PORT, async () => {
      try {
        await initDb();
        console.log(`Server running on http://localhost:${PORT}`);
      } catch (err) {
        console.error('Failed to start server:', err);
        process.exit(1);
      }
    });
  }
} else {
  // Render.com: Use HTTP (Render handles HTTPS)
  http.createServer(app).listen(PORT, async () => {
    try {
      await initDb();
      console.log(`Server running on port ${PORT}`);
    } catch (err) {
      console.error('Failed to start server:', err);
      process.exit(1);
    }
  });
}