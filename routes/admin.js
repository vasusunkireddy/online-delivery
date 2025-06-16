const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();

// Database connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Admin login
router.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT id, name, email, phone, password, isAdmin FROM users WHERE email = ? AND isAdmin = TRUE',
      [email]
    );
    connection.release();
    if (!rows.length) {
      return res.status(401).json({ error: 'Invalid email or not an admin' });
    }
    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: true }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, phone: user.phone } });
  } catch (error) {
    console.error('Admin login error:', error.message);
    res.status(500).json({ error: 'Failed to login' });
  }
});

// Admin signup
router.post('/admin/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (!/^\d{10}$/.test(phone)) {
    return res.status(400).json({ error: 'Mobile number must be 10 digits' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  try {
    const connection = await pool.getConnection();
    const [existing] = await connection.execute(
      'SELECT id FROM users WHERE email = ? OR phone = ?',
      [email, phone]
    );
    if (existing.length) {
      connection.release();
      return res.status(400).json({ error: 'Email or phone already registered' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await connection.execute(
      'INSERT INTO users (name, email, phone, password, isAdmin) VALUES (?, ?, ?, ?, TRUE)',
      [name, email, phone, hashedPassword]
    );
    connection.release();
    const token = jwt.sign({ id: result.insertId, email, isAdmin: true }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user: { id: result.insertId, name, email, phone } });
  } catch (error) {
    console.error('Admin signup error:', error.message);
    res.status(500).json({ error: 'Failed to signup' });
  }
});

// Forgot password - Send OTP
router.post('/admin/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT id FROM users WHERE email = ? AND isAdmin = TRUE',
      [email]
    );
    if (!rows.length) {
      connection.release();
      return res.status(404).json({ error: 'Admin not found' });
    }
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    await connection.execute(
      'INSERT INTO password_reset_tokens (email, token, expires_at) VALUES (?, ?, ?)',
      [email, otp, expiresAt]
    );
    connection.release();
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Delicute Admin Password Reset OTP',
      text: `Your OTP for password reset is ${otp}. It is valid for 10 minutes.`
    });
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Forgot password error:', error.message);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Verify OTP
router.post('/admin/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ error: 'Email and OTP are required' });
  }
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT token, expires_at FROM password_reset_tokens WHERE email = ? AND token = ?',
      [email, otp]
    );
    if (!rows.length || new Date(rows[0].expires_at) < new Date()) {
      connection.release();
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }
    await connection.execute(
      'DELETE FROM password_reset_tokens WHERE email = ? AND token = ?',
      [email, otp]
    );
    connection.release();
    res.json({ message: 'OTP verified successfully' });
  } catch (error) {
    console.error('OTP verification error:', error.message);
    res.status(500).json({ error: 'Failed to verify OTP' });
  }
});

// Reset password
router.post('/admin/reset-password', async (req, res) => {
  const { email, newPassword, confirmPassword } = req.body;
  if (!email || !newPassword || !confirmPassword) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT id FROM users WHERE email = ? AND isAdmin = TRUE',
      [email]
    );
    if (!rows.length) {
      connection.release();
      return res.status(404).json({ error: 'Admin not found' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await connection.execute(
      'UPDATE users SET password = ? WHERE email = ?',
      [hashedPassword, email]
    );
    connection.release();
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error.message);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

module.exports = router;