const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const cors = require('cors');
const helmet = require('helmet');
const { OAuth2Client } = require('google-auth-library');
const https = require('https');
const fs = require('fs');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000', 'https://your-frontend-domain.onrender.com'],
  credentials: true,
}));
app.use(express.json());

// PostgreSQL Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20, // Maximum number of clients in the pool
  idleTimeoutMillis: 30000, // Close idle clients after 30 seconds
  connectionTimeoutMillis: 5000, // Timeout after 5 seconds
});

// Google OAuth Client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Nodemailer Transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Generate JWT
const generateToken = (user) => {
  return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1d' });
};

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    console.error('No token provided');
    return res.status(401).json({ message: 'Unauthorized' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Invalid token:', err.message);
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Send OTP Email
const sendOtpEmail = async (email, otp) => {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'DELICUTE OTP Verification',
      text: `Your OTP for DELICUTE is ${otp}. It is valid for 5 minutes.`,
    };
    await transporter.sendMail(mailOptions);
    console.log(`OTP sent to ${email}`);
  } catch (error) {
    console.error('Error sending OTP email:', error);
    throw new Error('Failed to send OTP');
  }
};

// Routes
app.post('/api/users/signup', async (req, res) => {
  const { name, email, phone, password, address, otp } = req.body;

  try {
    const otpResult = await pool.query('SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires_at > NOW()', [email, otp]);
    if (otpResult.rows.length === 0) {
      console.error('Invalid or expired OTP for:', email);
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, phone, password, address) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, email, phone, hashedPassword, address]
    );

    await pool.query('DELETE FROM otps WHERE email = $1', [email]);

    const user = result.rows[0];
    const token = generateToken(user);
    res.status(201).json({ token });
  } catch (error) {
    console.error('Signup error:', error);
    if (error.code === '23505') {
      res.status(400).json({ message: 'Email or phone already exists' });
    } else {
      res.status(500).json({ message: 'Server error' });
    }
  }
});

app.post('/api/users/login', async (req, res) => {
  const { email, password, phone } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 AND phone = $2', [email, phone]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      console.error('Invalid credentials for:', email);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = generateToken(user);
    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/users/google', async (req, res) => {
  const { id_token } = req.body;

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { email, name, sub: googleId } = payload;

    let result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    let user = result.rows[0];

    if (!user) {
      result = await pool.query(
        'INSERT INTO users (name, email, google_id) VALUES ($1, $2, $3) RETURNING *',
        [name, email, googleId]
      );
      user = result.rows[0];
    }

    const token = generateToken(user);
    res.json({ token });
  } catch (error) {
    console.error('Google login error:', error);
    res.status(400).json({ message: 'Google authentication failed' });
  }
});

app.post('/api/users/request-otp', async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

  try {
    await pool.query('DELETE FROM otps WHERE email = $1', [email]);
    await pool.query('INSERT INTO otps (email, otp, expires_at) VALUES ($1, $2, $3)', [email, otp, expiresAt]);
    await sendOtpEmail(email, otp);
    res.json({ message: 'OTP sent' });
  } catch (error) {
    console.error('Request OTP error:', error);
    res.status(500).json({ message: 'Failed to send OTP' });
  }
});

app.post('/api/users/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    const otpResult = await pool.query('SELECT * FROM otps WHERE email = $1 AND otp = $2 AND expires_at > NOW()', [email, otp]);
    if (otpResult.rows.length === 0) {
      console.error('Invalid or expired OTP for reset:', email);
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);
    await pool.query('DELETE FROM otps WHERE email = $1', [email]);

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/users/menu', authenticateToken, async (req, res) => {
  const { category, search } = req.query;

  try {
    let query = 'SELECT * FROM menu';
    const params = [];
    const conditions = [];

    if (category) {
      conditions.push(`category = $${params.length + 1}`);
      params.push(category);
    }

    if (search) {
      conditions.push(`name ILIKE $${params.length + 1}`);
      params.push(`%${search}%`);
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Menu fetch error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/users/special-offers', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM special_offers');
    res.json(result.rows);
  } catch (error) {
    console.error('Special offers fetch error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Initialize Database
const initDb = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(15) UNIQUE,
        password VARCHAR(255),
        address TEXT,
        google_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS otps (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        otp VARCHAR(6) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS menu (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        category VARCHAR(50),
        image VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS special_offers (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        discount VARCHAR(50),
        image VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      INSERT INTO menu (name, price, category, image) VALUES
        ('Margherita Pizza', 299.00, 'Vegetarian', 'https://images.unsplash.com/photo-1513104890138-7c749659a680'),
        ('Chicken Biryani', 399.00, 'Non-Veg', 'https://images.unsplash.com/photo-1606842034046-28f80fdab9e5'),
        ('Chocolate Lava Cake', 199.00, 'Desserts', 'https://images.unsplash.com/photo-1611339555312-28f53176c99c')
      ON CONFLICT DO NOTHING;

      INSERT INTO special_offers (title, description, discount, image) VALUES
        ('Pizza Party', 'Get 20% off on all pizzas', '20% OFF', 'https://images.unsplash.com/photo-1513104890138-7c749659a680'),
        ('Weekend Feast', 'Free dessert with every main course', 'Free Dessert', 'https://images.unsplash.com/photo-1606842034046-28f80fdab9e5')
      ON CONFLICT DO NOTHING;
    `);
    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
    throw error;
  }
};

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unexpected error:', err.stack);
  res.status(500).json({ message: 'Internal server error' });
});

// Start Server
const startServer = async () => {
  try {
    const client = await pool.connect();
    console.log('Connected to PostgreSQL database');
    client.release();
    await initDb();

    if (process.env.NODE_ENV !== 'production') {
      try {
        const httpsOptions = {
          key: fs.readFileSync('localhost-key.pem'),
          cert: fs.readFileSync('localhost-cert.pem'),
        };
        https.createServer(httpsOptions, app).listen(port, () => {
          console.log(`Server running on https://localhost:${port}`);
        });
      } catch (error) {
        console.error('Failed to start HTTPS server:', error);
        console.log('Falling back to HTTP');
        app.listen(port, () => {
          console.log(`Server running on http://localhost:${port}`);
        });
      }
    } else {
      app.listen(port, () => {
        console.log(`Server running on http://localhost:${port}`);
      });
    }
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();