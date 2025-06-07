const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Nodemailer Transporter
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
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 AND role = $2', [email, 'admin']);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Admin Signup
router.post('/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, phone, password, role) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, email, phone, hashedPassword, 'admin']
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token });
  } catch (error) {
    console.error('Admin signup error:', error);
    res.status(400).json({ error: 'Email already exists or invalid data' });
  }
});

// Forgot Password (Send OTP)
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 AND role = $2', [email, 'admin']);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Admin user not found' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    await pool.query(
      'INSERT INTO password_resets (email, otp, expires_at) VALUES ($1, $2, $3)',
      [email, otp, expiresAt]
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Admin Password Reset OTP',
      text: `Your OTP for password reset is ${otp}. It is valid for 10 minutes.`
    };
    await transporter.sendMail(mailOptions);
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Reset Password
router.post('/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ error: 'Email and OTP are required' });
  }

  try {
    const result = await pool.query(
      'SELECT * FROM password_resets WHERE email = $1 AND otp = $2 AND expires_at > NOW()',
      [email, otp]
    );
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    if (newPassword) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await pool.query('UPDATE users SET password = $1 WHERE email = $2 AND role = $3', [hashedPassword, email, 'admin']);
      await pool.query('DELETE FROM password_resets WHERE email = $1', [email]);
      res.json({ message: 'Password reset successfully' });
    } else {
      res.json({ message: 'OTP verified' });
    }
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

module.exports = router;