const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const cors = require('cors');
const http = require('http');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();

const app = express();

// Google OAuth2 Client
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '1019406651586-rgl91utq3nn9ohudbrt15o74el8eq75j.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Middleware
const corsOptions = {
  origin: ['https://delicute.onrender.com', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());
app.use(express.static('public')); // Serve static files

// Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} ${JSON.stringify(req.body)}`);
  next();
});

// In-memory storage
let users = [];
let cart = [];
const otpStore = {};

// Seed admin user
async function initializeDatabase() {
  try {
    const adminEmail = 'svasudevareddy18604@gmail.com';
    const adminPassword = 'vasudev';
    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    if (!users.some(user => user.email === adminEmail)) {
      users.push({
        id: 1,
        name: 'Admin',
        email: adminEmail,
        phone: '1234567890',
        password: hashedPassword,
        address: 'Admin Address',
        role: 'admin',
        created_at: new Date(),
      });
      console.log('Admin user seeded');
    }
  } catch (err) {
    console.error('Database initialization error:', err.message);
    throw err;
  }
}

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Authentication middleware
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ message: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Token verification failed:', err.message);
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// Generate OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Routes

// Request OTP
app.post('/api/users/request-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    console.log('No email provided');
    return res.status(400).json({ message: 'Email required' });
  }

  const otp = generateOTP();
  otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 }; // 5-minute expiry

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'DELICUTE OTP Verification',
    text: `Your OTP is ${otp}. Valid for 5 minutes.`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`OTP sent to ${email}`);
    res.json({ message: 'OTP sent' });
  } catch (err) {
    console.error('Email error:', err.message);
    res.status(500).json({ message: 'Failed to send OTP' });
  }
});

// Signup
app.post('/api/users/signup', async (req, res) => {
  const { name, email, phone, password, address, otp } = req.body;
  console.log(`Signup attempt: ${email}, OTP: ${otp}`);

  if (!otpStore[email] || otpStore[email].otp !== otp || Date.now() > otpStore[email].expires) {
    console.log(`Invalid or expired OTP for ${email}`);
    return res.status(400).json({ message: 'Invalid or expired OTP' });
  }

  try {
    if (users.some(user => user.email === email)) {
      console.log(`User already exists: ${email}`);
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = {
      id: users.length + 1,
      name,
      email,
      phone,
      password: hashedPassword,
      address,
      role: 'user',
      created_at: new Date(),
    };
    users.push(user);
    const token = jwt.sign({ id: user.id, email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    delete otpStore[email];
    console.log(`Signup successful: ${email}`);
    res.status(201).json({ token });
  } catch (err) {
    console.error('Signup error:', err.message);
    res.status(500).json({ message: 'Signup failed' });
  }
});

// Login
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  console.log(`Login attempt: ${email}`);

  try {
    const user = users.find(u => u.email === email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      console.log(`Invalid credentials for ${email}`);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    console.log(`Login successful: ${email}`);
    res.json({ token });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ message: 'Login failed' });
  }
});

// Google Login
app.post('/api/users/google', async (req, res) => {
  const { id_token } = req.body;
  console.log('Google login attempt');

  if (!id_token) {
    console.log('No id_token provided');
    return res.status(400).json({ message: 'id_token required' });
  }

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: id_token,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { email, name } = payload;

    let user = users.find(u => u.email === email);
    if (!user) {
      const hashedPassword = await bcrypt.hash('google_dummy_' + Math.random(), 10);
      user = {
        id: users.length + 1,
        name: name || 'Google User',
        email,
        phone: '1234567890',
        password: hashedPassword,
        address: 'Google Address',
        role: 'user',
        created_at: new Date(),
      };
      users.push(user);
      console.log(`New Google user created: ${email}`);
    }

    const token = jwt.sign({ id: user.id, email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    console.log(`Google login successful: ${email}`);
    res.json({ token });
  } catch (err) {
    console.error('Google login error:', err.message);
    res.status(500).json({ message: 'Google login failed' });
  }
});

// Reset Password
app.post('/api/users/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  console.log(`Password reset attempt: ${email}`);

  if (!otpStore[email] || otpStore[email].otp !== otp || Date.now() > otpStore[email].expires) {
    console.log(`Invalid or expired OTP for ${email}`);
    return res.status(400).json({ message: 'Invalid or expired OTP' });
  }

  try {
    const user = users.find(u => u.email === email);
    if (!user) {
      console.log(`User not found: ${email}`);
      return res.status(404).json({ message: 'User not found' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    delete otpStore[email];
    console.log(`Password reset successful: ${email}`);
    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({ message: 'Reset password failed' });
  }
});

// Menu
app.get('/api/users/menu', authenticateToken, (req, res) => {
  const menuItems = [
    { id: 1, name: 'Butter Chicken', price: 350, category: 'Non-Veg', image: 'https://images.unsplash.com/photo-1603894584373-5' },
    { id: 2, name: 'Paneer Tikka', price: 300, category: 'Vegetarian', image: 'https://images.unsplash.com/photo-1596797038530-2' },
    { id: 3, name: 'Gulab Jamun', price: 150, category: 'Desserts', image: 'https://images.unsplash.com/photo-1623855344311-9' },
  ];

  const { search, category } = req.query;
  let filteredItems = menuItems;

  if (search) {
    filteredItems = filteredItems.filter(item => item.name.toLowerCase().includes(search.toLowerCase()));
  }
  if (category) {
    filteredItems = filteredItems.filter(item => item.category === category);
  }

  console.log(`Menu fetched for user ${req.user.email}`);
  res.json(filteredItems);
});

// Add to Cart
app.post('/api/users/cart/add', authenticateToken, (req, res) => {
  const { item } = req.body;
  console.log(`Add to cart attempt for user ${req.user.email}`);

  if (!item || !item.id) {
    console.log('Invalid item data');
    return res.status(400).json({ message: 'Invalid item data' });
  }

  try {
    cart.push({
      id: cart.length + 1,
      user_id: req.user.id,
      item_id: item.id,
      quantity: 1,
      created_at: new Date(),
    });
    console.log(`Item ${item.id} added to cart for user ${req.user.email}`);
    res.json({ message: 'Item added to cart' });
  } catch (err) {
    console.error('Cart error:', err.message);
    res.status(500).json({ message: 'Failed to add to cart' });
  }
});

// Admin Route
app.get('/api/users/admin', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    console.log(`Admin access denied for ${req.user.email}`);
    return res.status(403).json({ message: 'Admin access required' });
  }
  console.log(`Admin accessed by ${req.user.email}`);
  res.json({ message: 'Admin dashboard' });
});

// Test Endpoint
app.get('/api/users/test', (req, res) => {
  console.log('Test endpoint accessed');
  res.json({ message: 'Server is running' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err.message);
  res.status(500).json({ message: 'Internal server error' });
});

// Start server
const PORT = process.env.PORT || 3000;
const httpServer = http.createServer(app);

httpServer.listen(PORT, async () => {
  try {
    await initializeDatabase();
    console.log(`HTTP Server running on http://localhost:${PORT}`);
  } catch (err) {
    console.error('Startup error:', err.message);
    process.exit(1);
  }
});