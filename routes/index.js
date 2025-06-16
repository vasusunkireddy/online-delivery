const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Database connection
async function getConnection() {
  return await mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
  });
}

// Nodemailer transporter
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
  
  if (!token) return res.status(401).json({ error: 'Access denied' });
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Restaurant status
router.get('/status', async (req, res) => {
  try {
    const connection = await getConnection();
    const [rows] = await connection.execute('SELECT status FROM restaurant_status WHERE id = 1');
    await connection.end();
    res.json({ status: rows[0].status });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch restaurant status' });
  }
});

// Menu items
router.get('/menu', async (req, res) => {
  try {
    const connection = await getConnection();
    const [rows] = await connection.execute('SELECT * FROM menu_items');
    await connection.end();
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch menu items' });
  }
});

// Signup
router.post('/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  if (!/^\d{10}$/.test(phone)) {
    return res.status(400).json({ error: 'Invalid phone number' });
  }

  try {
    const connection = await getConnection();
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const [existingUser] = await connection.execute(
      'SELECT * FROM users WHERE email = ? OR phone = ?',
      [email, phone]
    );

    if (existingUser.length > 0) {
      await connection.end();
      return res.status(400).json({ error: 'Email or phone already exists' });
    }

    const [result] = await connection.execute(
      'INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)',
      [name, email, phone, hashedPassword]
    );

    const token = jwt.sign({ id: result.insertId, email }, process.env.JWT_SECRET, {
      expiresIn: '1d'
    });

    await connection.end();
    res.json({ 
      token, 
      user: { id: result.insertId, name, email, phone }
    });
  } catch (error) {
    res.status(500).json({ error: 'Signup failed' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const connection = await getConnection();
    const [rows] = await connection.execute(
      'SELECT * FROM users WHERE email = ? OR phone = ?',
      [email, email]
    );

    if (rows.length === 0) {
      await connection.end();
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      await connection.end();
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: '1d'
    });

    await connection.end();
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Google Login
router.post('/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const { name, email } = ticket.getPayload();
    const connection = await getConnection();
    
    let [user] = await connection.execute('SELECT * FROM users WHERE email = ?', [email]);
    
    if (user.length === 0) {
      const [result] = await connection.execute(
        'INSERT INTO users (name, email) VALUES (?, ?)',
        [name, email]
      );
      user = [{ id: result.insertId, name, email }];
    }

    const token = jwt.sign({ id: user[0].id, email }, process.env.JWT_SECRET, {
      expiresIn: '1d'
    });

    await connection.end();
    res.json({ token, user: { id: user[0].id, name, email } });
  } catch (error) {
    res.status(500).json({ error: 'Google authentication failed' });
  }
});

// Forgot Password
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const connection = await getConnection();
    const [user] = await connection.execute('SELECT * FROM users WHERE email = ?', [email]);

    if (user.length === 0) {
      await connection.end();
      return res.status(404).json({ error: 'User not found' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes expiry

    await connection.execute(
      'INSERT INTO password_reset_tokens (email, token, expires_at) VALUES (?, ?, ?)',
      [email, otp, expiresAt]
    );

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset OTP - Delicute',
      html: `<p>Your OTP for password reset is: <strong>${otp}</strong></p><p>This OTP is valid for 10 minutes.</p>`
    });

    await connection.end();
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
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
    const connection = await getConnection();
    const [tokens] = await connection.execute(
      'SELECT * FROM password_reset_tokens WHERE email = ? AND token = ? AND expires_at > NOW()',
      [email, otp]
    );

    if (tokens.length === 0) {
      await connection.end();
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    await connection.execute(
      'DELETE FROM password_reset_tokens WHERE email = ? AND token = ?',
      [email, otp]
    );

    await connection.end();
    res.json({ message: 'OTP verified successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to verify OTP' });
  }
});

// Reset Password
router.post('/reset-password', async (req, res) => {
  const { email, newPassword, confirmPassword } = req.body;

  if (!email || !newPassword || !confirmPassword) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }

  try {
    const connection = await getConnection();
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const [result] = await connection.execute(
      'UPDATE users SET password = ? WHERE email = ?',
      [hashedPassword, email]
    );

    if (result.affectedRows === 0) {
      await connection.end();
      return res.status(404).json({ error: 'User not found' });
    }

    await connection.end();
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Add to Cart
router.post('/cart/add', authenticateToken, async (req, res) => {
  const { itemId, quantity } = req.body;
  const userId = req.user.id;

  if (!itemId || !quantity) {
    return res.status(400).json({ error: 'Item ID and quantity are required' });
  }

  try {
    const connection = await getConnection();
    const [existingItem] = await connection.execute(
      'SELECT * FROM cart WHERE user_id = ? AND item_id = ?',
      [userId, itemId]
    );

    if (existingItem.length > 0) {
      await connection.execute(
        'UPDATE cart SET quantity = quantity + ? WHERE user_id = ? AND item_id = ?',
        [quantity, userId, itemId]
      );
    } else {
      await connection.execute(
        'INSERT INTO cart (user_id, item_id, quantity) VALUES (?, ?, ?)',
        [userId, itemId, quantity]
      );
    }

    await connection.end();
    res.json({ message: 'Item added to cart' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add item to cart' });
  }
});

module.exports = router;