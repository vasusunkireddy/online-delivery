const express = require('express');
const router = express.Router();
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { body, validationResult } = require('express-validator');
const mysql = require('mysql2/promise');

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const EMAIL_USER = process.env.EMAIL_USER || 'your_email@example.com';
const EMAIL_PASS = process.env.EMAIL_PASS || 'your_email_password';

// Database connection (assuming connection is passed from server.js)
let db;
async function setDatabaseConnection(connection) {
  db = connection;
}

// Serve admin.html
router.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public', 'admin.html'));
});

// Configure Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail', // Use your email service
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS,
  },
});

// Admin Signup Route
router.post(
  '/signup',
  [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Invalid email'),
    body('phone').notEmpty().withMessage('Phone number is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
      }

      const { name, email, phone, password } = req.body;

      // Check if admin already exists
      const [existingAdmin] = await db.execute('SELECT * FROM users WHERE email = ? AND role = "admin"', [email]);
      if (existingAdmin.length > 0) {
        return res.status(400).json({ error: 'Admin with this email already exists' });
      }

      // Hash password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Insert new admin
      await db.execute(
        'INSERT INTO users (name, email, phone, password, role) VALUES (?, ?, ?, ?, "admin")',
        [name, email, phone, hashedPassword]
      );

      // Fetch the newly created admin to get their ID
      const [newAdmin] = await db.execute('SELECT id FROM users WHERE email = ?', [email]);

      // Generate JWT
      const token = jwt.sign({ id: newAdmin[0].id, role: 'admin' }, JWT_SECRET, { expiresIn: '1h' });

      res.status(201).json({ token, message: 'Admin signup successful' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Server error during signup' });
    }
  }
);

// Admin Login Route
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Invalid email'),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
      }

      const { email, password } = req.body;

      // Find admin
      const [admin] = await db.execute('SELECT * FROM users WHERE email = ? AND role = "admin"', [email]);
      if (admin.length === 0) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Verify password
      const isMatch = await bcrypt.compare(password, admin[0].password);
      if (!isMatch) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Generate JWT
      const token = jwt.sign({ id: admin[0].id, role: 'admin' }, JWT_SECRET, { expiresIn: '1h' });

      res.json({ token, message: 'Admin login successful' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Server error during login' });
    }
  }
);

// Forgot Password - Send OTP
router.post(
  '/forgot-password',
  [body('email').isEmail().withMessage('Invalid email')],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
      }

      const { email } = req.body;

      // Find admin
      const [admin] = await db.execute('SELECT * FROM users WHERE email = ? AND role = "admin"', [email]);
      if (admin.length === 0) {
        return res.status(404).json({ error: 'Admin not found' });
      }

      // Generate OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // OTP valid for 10 minutes

      // Store OTP in password_resets table
      await db.execute(
        'INSERT INTO password_resets (email, otp, expires_at) VALUES (?, ?, ?)',
        [email, otp, expiresAt]
      );

      // Send OTP email
      const mailOptions = {
        from: EMAIL_USER,
        to: email,
        subject: 'Admin Password Reset OTP',
        text: `Your OTP for password reset is: ${otp}. It is valid for 10 minutes.`,
      };

      await transporter.sendMail(mailOptions);
      res.json({ message: 'OTP sent to your email' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Failed to send OTP' });
    }
  }
);

// Reset Password - Verify OTP and Update Password
router.post(
  '/reset-password',
  [
    body('email').isEmail().withMessage('Invalid email'),
    body('otp').notEmpty().withMessage('OTP is required'),
    body('newPassword')
      .if(body('newPassword').exists())
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array()[0].msg });
      }

      const { email, otp, newPassword } = req.body;

      // Verify OTP
      const [resetRecord] = await db.execute(
        'SELECT * FROM password_resets WHERE email = ? AND otp = ? AND expires_at > NOW()',
        [email, otp]
      );

      if (resetRecord.length === 0) {
        return res.status(400).json({ error: 'Invalid or expired OTP' });
      }

      // Find admin
      const [admin] = await db.execute('SELECT * FROM users WHERE email = ? AND role = "admin"', [email]);
      if (admin.length === 0) {
        return res.status(404).json({ error: 'Admin not found' });
      }

      if (!newPassword) {
        // OTP verification step
        res.json({ message: 'OTP verified successfully' });
      } else {
        // Reset password step
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update password
        await db.execute('UPDATE users SET password = ? WHERE email = ? AND role = "admin"', [
          hashedPassword,
          email,
        ]);

        // Delete used OTP
        await db.execute('DELETE FROM password_resets WHERE email = ? AND otp = ?', [email, otp]);

        res.json({ message: 'Password reset successful' });
      }
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Server error during password reset' });
    }
  }
);

// Export router and database connection setter
module.exports = {
  router,
  setDatabaseConnection,
};
