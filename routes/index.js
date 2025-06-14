const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: 'postmessage'
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// Restaurant status
router.get('/status', async (req, res) => {
  const hour = new Date().getHours();
  const isOpen = hour >= 10 && hour < 22; // 10 AM to 10 PM
  res.json({ status: isOpen ? 'open' : 'closed' });
});

// Menu items
router.get('/menu', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM menu_items');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch menu items' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ? OR phone = ?', [email, email]);
    if (users.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Signup
router.post('/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  try {
    const [existingUsers] = await pool.query('SELECT * FROM users WHERE email = ? OR phone = ?', [email, phone]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)',
      [name, email, phone, hashedPassword]
    );
    const token = jwt.sign({ id: result.insertId, email }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, user: { id: result.insertId, name, email } });
  } catch (error) {
    res.status(500).json({ error: 'Signup failed' });
  }
});

// Google login
router.post('/auth/google', async (req, res) => {
  const { credential } = req.body;
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    const { sub: googleId, name, email } = payload;

    let [users] = await pool.query('SELECT * FROM users WHERE google_id = ? OR email = ?', [googleId, email]);
    let user;
    if (users.length === 0) {
      const [result] = await pool.query(
        'INSERT INTO users (name, email, google_id) VALUES (?, ?, ?)',
        [name, email, googleId]
      );
      user = { id: result.insertId, name, email };
    } else {
      user = users[0];
    }
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (error) {
    console.error('Google login error:', error);
    res.status(500).json({ error: 'Google login failed' });
  }
});

// Forgot password
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await pool.query('UPDATE users SET reset_otp = ?, reset_otp_expiry = DATE_ADD(NOW(), INTERVAL 10 MINUTE) WHERE email = ?', [otp, email]);

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset OTP - Delicute',
      text: `Your OTP for password reset is ${otp}. It is valid for 10 minutes.`
    };
    await transporter.sendMail(mailOptions);
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Verify OTP
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ? AND reset_otp = ? AND reset_otp_expiry > NOW()', [email, otp]);
    if (users.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }
    res.json({ message: 'OTP verified successfully' });
  } catch (error) {
    res.status(500).json({ error: 'OTP verification failed' });
  }
});

// Reset password
router.post('/reset-password', async (req, res) => {
  const { email, newPassword, confirmPassword } = req.body;
  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = ?, reset_otp = NULL, reset_otp_expiry = NULL WHERE email = ?', [hashedPassword, email]);
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Password reset failed' });
  }
});

// Add to cart
router.post('/cart/add', authenticateToken, async (req, res) => {
  const { itemId, quantity } = req.body;
  const userId = req.user.id;
  try {
    const [items] = await pool.query('SELECT * FROM menu_items WHERE id = ?', [itemId]);
    if (items.length === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    await pool.query(
      'INSERT INTO cart (user_id, item_id, quantity) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE quantity = quantity + ?',
      [userId, itemId, quantity, quantity]
    );
    res.json({ message: 'Item added to cart' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add item to cart' });
  }
});

module.exports = router;