const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');
const sendgridTransport = require('nodemailer-sendgrid-transport');

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Email transporter setup
const transporter = nodemailer.createTransport(sendgridTransport({
  auth: {
    api_key: process.env.SENDGRID_API_KEY
  }
}));

// Middleware to verify user session
const verifyUser = (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized: Please log in' });
  }
  next();
};

// Get restaurant status
router.get('/status', async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [rows] = await pool.query('SELECT status FROM restaurant_status ORDER BY updated_at DESC LIMIT 1');
    res.json({ status: rows[0].status });
  } catch (error) {
    console.error('Error fetching status:', error.message);
    res.status(500).json({ error: 'Failed to fetch restaurant status' });
  }
});

// Get menu items
router.get('/menu', async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [rows] = await pool.query('SELECT id, name, description, price, image, category FROM menu_items');
    res.json(rows);
  } catch (error) {
    console.error('Error fetching menu:', error.message);
    res.status(500).json({ error: 'Failed to fetch menu' });
  }
});

// User login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  try {
    const pool = req.app.get('dbPool');
    const [users] = await pool.query('SELECT * FROM users WHERE email = ? OR phone = ?', [email, email]);
    if (users.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    req.session.user = { id: user.id, email: user.email, name: user.name, role: user.role };
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Failed to login' });
  }
});

// User signup
router.post('/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (!/^\d{10}$/.test(phone)) {
    return res.status(400).json({ error: 'Invalid phone number' });
  }
  try {
    const pool = req.app.get('dbPool');
    const [existingUsers] = await pool.query('SELECT * FROM users WHERE email = ? OR phone = ?', [email, phone]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Email or phone already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (name, email, phone, password, role) VALUES (?, ?, ?, ?, ?)',
      [name, email, phone, hashedPassword, 'user']
    );
    const user = { id: result.insertId, name, email, role: 'user' };
    req.session.user = user;
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user });
  } catch (error) {
    console.error('Signup error:', error.message);
    res.status(500).json({ error: 'Failed to signup' });
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
    const { sub: google_id, name, email } = payload;
    const pool = req.app.get('dbPool');
    let [users] = await pool.query('SELECT * FROM users WHERE google_id = ? OR email = ?', [google_id, email]);
    let user;
    if (users.length === 0) {
      const [result] = await pool.query(
        'INSERT INTO users (name, email, google_id, role) VALUES (?, ?, ?, ?)',
        [name, email, google_id, 'user']
      );
      user = { id: result.insertId, name, email, role: 'user' };
    } else {
      user = users[0];
    }
    req.session.user = { id: user.id, email: user.email, name: user.name, role: user.role };
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (error) {
    console.error('Google login error:', error.message);
    res.status(500).json({ error: 'Failed to login with Google' });
  }
});

// Add to cart
router.post('/cart/add', verifyUser, async (req, res) => {
  const { itemId, quantity } = req.body;
  if (!itemId || !quantity) {
    return res.status(400).json({ error: 'Item ID and quantity are required' });
  }
  try {
    const pool = req.app.get('dbPool');
    const userId = req.session.user.id;
    const [existing] = await pool.query('SELECT * FROM cart WHERE user_id = ? AND item_id = ?', [userId, itemId]);
    if (existing.length > 0) {
      await pool.query('UPDATE cart SET quantity = quantity + ? WHERE user_id = ? AND item_id = ?', [quantity, userId, itemId]);
    } else {
      await pool.query('INSERT INTO cart (user_id, item_id, quantity) VALUES (?, ?, ?)', [userId, itemId, quantity]);
    }
    res.json({ message: 'Item added to cart' });
  } catch (error) {
    console.error('Add to cart error:', error.message);
    res.status(500).json({ error: 'Failed to add item to cart' });
  }
});

// Forgot password - send OTP
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  try {
    const pool = req.app.get('dbPool');
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(400).json({ error: 'User not found' });
    }
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    await pool.query('INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)', [email, otp, expiresAt]);
    await transporter.sendMail({
      to: email,
      from: process.env.SENDGRID_FROM_EMAIL,
      subject: 'Password Reset OTP',
      text: `Your OTP for password reset is ${otp}. It is valid for 10 minutes.`
    });
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Forgot password error:', error.message);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Verify OTP
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ error: 'Email and OTP are required' });
  }
  try {
    const pool = req.app.get('dbPool');
    const [otps] = await pool.query('SELECT * FROM otps WHERE email = ? AND otp = ? AND expires_at > NOW()', [email, otp]);
    if (otps.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }
    await pool.query('DELETE FROM otps WHERE email = ?', [email]);
    res.json({ message: 'OTP verified successfully' });
  } catch (error) {
    console.error('Verify OTP error:', error.message);
    res.status(500).json({ error: 'Failed to verify OTP' });
  }
});

// Reset password
router.post('/reset-password', async (req, res) => {
  const { email, newPassword, confirmPassword } = req.body;
  if (!email || !newPassword || !confirmPassword) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }
  try {
    const pool = req.app.get('dbPool');
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error.message);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

module.exports = router;