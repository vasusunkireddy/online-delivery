const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const cors = require('cors');
const http = require('http');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve static files (index.html)

// In-memory "database"
let users = [];
let cart = [];

// Seed Admin User
const initializeDatabase = async () => {
  try {
    const adminEmail = 'svasudevareddy18604@gmail.com';
    const adminPassword = 'vasudev';
    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    const adminExists = users.some(user => user.email === adminEmail);
    if (!adminExists) {
      users.push({
        id: 1,
        name: 'Admin',
        email: adminEmail,
        phone: '1234567890',
        password: hashedPassword,
        address: 'Admin Address',
        role: 'admin',
        created_at: new Date()
      });
      console.log('Admin user created');
    }
  } catch (err) {
    console.error('Initialization error:', err.message);
    throw err;
  }
};

// Email Transporter for OTP
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access denied' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Generate OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Store OTPs temporarily (in production, use Redis or similar)
const otpStore = {};

// Routes

// Request OTP
app.post('/api/users/request-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email required' });

  const otp = generateOTP();
  otpStore[email] = otp;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'DELICUTE OTP for Verification',
    text: `Your OTP is ${otp}. It is valid for 5 minutes.`
  };

  try {
    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'OTP sent' });
  } catch (err) {
    console.error('Email sending error:', err.message);
    res.status(500).json({ message: 'Failed to send OTP' });
  }
});

// Signup
app.post('/api/users/signup', async (req, res) => {
  const { name, email, phone, password, address, otp } = req.body;

  if (otp !== otpStore[email]) {
    return res.status(400).json({ message: 'Invalid OTP' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: users.length + 1,
      name,
      email,
      phone,
      password: hashedPassword,
      address,
      role: 'user',
      created_at: new Date()
    };
    users.push(newUser);
    const token = jwt.sign({ id: newUser.id, email: newUser.email, role: newUser.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    delete otpStore[email];
    res.status(201).json({ token });
  } catch (err) {
    console.error('Signup error:', err.message);
    res.status(500).json({ message: 'Signup failed' });
  }
});

// Login
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = users.find(u => u.email === email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ token });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ message: 'Login failed' });
  }
});

// Google Login (mocked for simplicity)
app.post('/api/users/google', async (req, res) => {
  const { id_token } = req.body;
  try {
    const email = `googleuser_${Date.now()}@example.com`;
    let user = users.find(u => u.email === email);

    if (!user) {
      const hashedPassword = await bcrypt.hash('google_dummy_password', 10);
      user = {
        id: users.length + 1,
        name: 'Google User',
        email,
        phone: '1234567890',
        password: hashedPassword,
        address: 'Google Address',
        role: 'user',
        created_at: new Date()
      };
      users.push(user);
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ token });
  } catch (err) {
    console.error('Google login error:', err.message);
    res.status(500).json({ message: 'Google login failed' });
  }
});

// Reset Password
app.post('/api/users/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (otp !== otpStore[email]) {
    return res.status(400).json({ message: 'Invalid OTP' });
  }

  try {
    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    user.password = await bcrypt.hash(newPassword, 10);
    delete otpStore[email];
    res.status(200).json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({ message: 'Reset password failed' });
  }
});

// Menu (mocked data)
app.get('/api/users/menu', authenticateToken, async (req, res) => {
  const menuItems = [
    { id: 1, name: 'Butter Chicken', price: 350, category: 'Non-Veg', image: 'https://images.unsplash.com/photo-1603894584373-5' },
    { id: 2, name: 'Paneer Tikka', price: 300, category: 'Vegetarian', image: 'https://images.unsplash.com/photo-1596797038530-2' },
    { id: 3, name: 'Gulab Jamun', price: 150, category: 'Desserts', image: 'https://images.unsplash.com/photo-1623855344311-9' }
  ];

  const { search, category } = req.query;
  let filteredItems = menuItems;

  if (search) {
    filteredItems = filteredItems.filter(item => item.name.toLowerCase().includes(search.toLowerCase()));
  }

  if (category) {
    filteredItems = filteredItems.filter(item => item.category === category);
  }

  res.status(200).json(filteredItems);
});

// Add to Cart
app.post('/api/users/cart/add', authenticateToken, async (req, res) => {
  const { item } = req.body;
  const userId = req.user.id;

  try {
    cart.push({
      id: cart.length + 1,
      user_id: userId,
      item_id: item.id,
      quantity: 1,
      created_at: new Date()
    });
    res.status(200).json({ message: 'Item added to cart' });
  } catch (err) {
    console.error('Add to cart error:', err.message);
    res.status(500).json({ message: 'Failed to add to cart' });
  }
});

// Admin Route (for redirection after login)
app.get('/api/users/admin', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  res.status(200).json({ message: 'Welcome Admin' });
});

// Start HTTP Server
const PORT = process.env.PORT || 3000;
const httpServer = http.createServer(app);

httpServer.listen(PORT, async () => {
  await initializeDatabase();
  console.log(`HTTP Server running on http://localhost:${PORT}`);
});