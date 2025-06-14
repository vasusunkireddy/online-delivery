const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
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

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Admin Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ? AND is_admin = TRUE', [email]);
    if (users.length === 0) {
      return res.status(400).json({ error: 'Invalid admin credentials' });
    }
    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid admin credentials' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: true }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Admin login failed' });
  }
});

// Admin Signup
router.post('/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  try {
    const [existingUsers] = await pool.query('SELECT * FROM users WHERE email = ? OR phone = ?', [email, phone]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Admin already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (name, email, phone, password, is_admin) VALUES (?, ?, ?, ?, TRUE)',
      [name, email, phone, hashedPassword]
    );
    const token = jwt.sign({ id: result.insertId, email, isAdmin: true }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, user: { id: result.insertId, name, email } });
  } catch (error) {
    console.error('Admin signup error:', error);
    res.status(500).json({ error: 'Admin signup failed' });
  }
});

// Admin Forgot Password
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ? AND is_admin = TRUE', [email]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'Admin not found' });
    }
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await pool.query('UPDATE users SET reset_otp = ?, reset_otp_expiry = DATE_ADD(NOW(), INTERVAL 10 MINUTE) WHERE email = ?', [otp, email]);

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Admin Password Reset OTP - Delicute',
      text: `Your OTP for admin password reset is ${otp}. It is valid for 10 minutes.`
    };
    await transporter.sendMail(mailOptions);
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Admin forgot password error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Admin Verify OTP
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ? AND reset_otp = ? AND reset_otp_expiry > NOW() AND is_admin = TRUE', [email, otp]);
    if (users.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }
    res.json({ message: 'OTP verified successfully' });
  } catch (error) {
    console.error('Admin OTP verification error:', error);
    res.status(500).json({ error: 'OTP verification failed' });
  }
});

// Admin Reset Password
router.post('/reset-password', async (req, res) => {
  const { email, newPassword, confirmPassword } = req.body;
  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ? AND is_admin = TRUE', [email]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'Admin not found' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = ?, reset_otp = NULL, reset_otp_expiry = NULL WHERE email = ?', [hashedPassword, email]);
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Admin password reset error:', error);
    res.status(500).json({ error: 'Password reset failed' });
  }
});

module.exports = router;