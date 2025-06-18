const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail');
const { OAuth2Client } = require('google-auth-library');

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Database pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Middleware to verify JWT
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Get restaurant status
router.get('/status', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT status FROM restaurant_status ORDER BY updated_at DESC LIMIT 1');
    const status = rows.length > 0 ? rows[0].status : 'closed';
    res.json({ status });
  } catch (error) {
    console.error('Status fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch status' });
  }
});

// Get menu items
router.get('/menu', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM menu_items');
    res.json(rows);
  } catch (error) {
    console.error('Menu fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch menu' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
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
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: '1d',
    });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Failed to login' });
  }
});

// Signup
router.post('/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (!/^\d{10}$/.test(phone)) {
    return res.status(400).json({ error: 'Invalid mobile number' });
  }
  try {
    const [existingUsers] = await pool.query('SELECT * FROM users WHERE email = ? OR phone = ?', [email, phone]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Email or phone already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)',
      [name, email, phone, hashedPassword]
    );
    const token = jwt.sign({ id: result.insertId, email, role: 'user' }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, user: { id: result.insertId, name, email, role: 'user' } });
  } catch (error) {
    console.error('Signup error:', error.message);
    res.status(500).json({ error: 'Failed to signup' });
  }
});

// Google login
router.post('/auth/google', async (req, res) => {
  const { idToken } = req.body;
  if (!idToken) {
    return res.status(400).json({ error: 'ID token is required' });
  }
  if (!process.env.GOOGLE_CLIENT_ID) {
    console.error('Google Client ID is not configured');
    return res.status(500).json({ error: 'Server configuration error' });
  }
  try {
    const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
    const ticket = await client.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    // Check for existing user by googleId or email
    let [users] = await pool.query('SELECT * FROM users WHERE google_id = ? OR email = ?', [googleId, email]);
    let user;
    if (users.length === 0) {
      // Create new user
      const phone = `google_${Math.random().toString(36).substr(2, 10)}`; // Placeholder phone
      const password = await bcrypt.hash(Math.random().toString(36).slice(2), 10); // Random password
      const [result] = await pool.query(
        'INSERT INTO users (name, email, phone, password, google_id, picture) VALUES (?, ?, ?, ?, ?, ?)',
        [name, email, phone, password, googleId, picture || null]
      );
      user = { id: result.insertId, name, email, role: 'user', picture };
    } else {
      user = users[0];
      // Update google_id and picture if not set
      if (!user.google_id || user.google_id !== googleId) {
        await pool.query('UPDATE users SET google_id = ?, picture = ? WHERE id = ?', [googleId, picture || null, user.id]);
        user.google_id = googleId;
        user.picture = picture || null;
      }
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: '1d',
    });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, picture: user.picture } });
  } catch (error) {
    console.error('Google auth error:', error.message);
    res.status(401).json({ error: 'Failed to authenticate with Google' });
  }
});

// Logout
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    // Optionally invalidate the token on the server-side (e.g., add to a blacklist)
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error.message);
    res.status(500).json({ error: 'Failed to logout' });
  }
});

// Add to cart
router.post('/cart/add', authenticateToken, async (req, res) => {
  const { itemId, quantity } = req.body;
  if (!itemId || !quantity) {
    return res.status(400).json({ error: 'Item ID and quantity are required' });
  }
  try {
    const userId = req.user.id;
    const [existingCart] = await pool.query(
      'SELECT * FROM cart WHERE user_id = ? AND item_id = ?',
      [userId, itemId]
    );
    if (existingCart.length > 0) {
      await pool.query(
        'UPDATE cart SET quantity = quantity + ? WHERE user_id = ? AND item_id = ?',
        [quantity, userId, itemId]
      );
    } else {
      await pool.query(
        'INSERT INTO cart (user_id, item_id, quantity) VALUES (?, ?, ?)',
        [userId, itemId, quantity]
      );
    }
    res.json({ message: 'Item added to cart' });
  } catch (error) {
    console.error('Cart add error:', error.message);
    res.status(500).json({ error: 'Failed to add item to cart' });
  }
});

// Forgot password
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.status(400).json({ error: 'Email not found' });
    }
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    await pool.query('INSERT INTO otps (email, otp, expires_at) VALUES (?, ?, ?)', [email, otp, expiresAt]);
    const msg = {
      to: email,
      from: process.env.SENDGRID_FROM_EMAIL,
      subject: 'Password Reset OTP',
      text: `Your OTP for password reset is ${otp}. It is valid for 10 minutes.`,
    };
    await sgMail.send(msg);
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
    const [otps] = await pool.query(
      'SELECT * FROM otps WHERE email = ? AND otp = ? AND expires_at > NOW()',
      [email, otp]
    );
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
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error.message);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

module.exports = router;