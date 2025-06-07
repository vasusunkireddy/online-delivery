const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const paypal = require('@paypal/checkout-server-sdk');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Razorpay Instance
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// PayPal Client
const paypalClient = new paypal.core.PayPalHttpClient(
  new paypal.core.SandboxEnvironment(
    process.env.PAYPAL_CLIENT_ID,
    process.env.PAYPAL_CLIENT_SECRET
  )
);

// Google OAuth Client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Nodemailer Transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Routes
router.get('/', (req, res) => {
  res.sendFile(__dirname + '/../public/index.html');
});

router.get('/auth/google', (req, res) => {
  const url = googleClient.generateAuthUrl({
    scope: ['profile', 'email'],
    redirect_uri: `${process.env.SERVER_URL}/api/index/auth/google/callback`
  });
  res.redirect(url);
});

router.get('/auth/google/callback', async (req, res) => {
  try {
    const { code } = req.query;
    const { tokens } = await googleClient.getToken({
      code,
      redirect_uri: `${process.env.SERVER_URL}/api/index/auth/google/callback`
    });
    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const { name, email } = ticket.getPayload();

    let user = (await pool.query('SELECT * FROM users WHERE email = $1', [email])).rows[0];
    if (!user) {
      const result = await pool.query(
        'INSERT INTO users (name, email, role) VALUES ($1, $2, $3) RETURNING *',
        [name, email, 'user']
      );
      user = result.rows[0];
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.redirect(`${process.env.CLIENT_URL}/userdashboard.html?token=${token}`);
  } catch (error) {
    console.error('Google auth error:', error);
    res.status(500).json({ error: 'Google authentication failed' });
  }
});

router.post('/auth/signup', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (name, email, phone, password, role) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, email, phone, hashedPassword, 'user']
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(400).json({ error: 'Email already exists or invalid data' });
  }
});

router.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

router.post('/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await pool.query(
      'INSERT INTO password_resets (email, otp, expires_at) VALUES ($1, $2, $3)',
      [email, otp, expiresAt]
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP for password reset is ${otp}. It is valid for 10 minutes.`
    };
    await transporter.sendMail(mailOptions);
    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

router.post('/auth/reset-password', async (req, res) => {
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
      await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);
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

router.get('/menu', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM menu_items');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching menu:', error);
    res.status(500).json({ error: 'Failed to fetch menu items' });
  }
});

router.get('/offers', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM offers');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching offers:', error);
    res.status(500).json({ error: 'Failed to fetch offers' });
  }
});

router.post('/orders', authenticateToken, async (req, res) => {
  const { items, total } = req.body;
  if (!items || !total) {
    return res.status(400).json({ error: 'Items and total are required' });
  }

  try {
    const order = await pool.query(
      'INSERT INTO orders (user_id, items, total) VALUES ($1, $2, $3) RETURNING *',
      [req.user.id, JSON.stringify(items), total]
    );

    const options = {
      amount: total * 100,
      currency: 'INR',
      receipt: `order_${order.rows[0].id}`
    };
    const razorpayOrder = await razorpay.orders.create(options);
    res.json({
      orderId: razorpayOrder.id,
      amount: razorpayOrder.amount,
      currency: razorpayOrder.currency
    });
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

router.post('/payment/verify', authenticateToken, async (req, res) => {
  const { orderId, paymentId, signature } = req.body;
  const generatedSignature = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(`${orderId}|${paymentId}`)
    .digest('hex');

  if (generatedSignature === signature) {
    await pool.query('UPDATE orders SET status = $1 WHERE id = $2', ['completed', orderId.split('_')[1]]);
    res.json({ message: 'Payment verified successfully' });
  } else {
    res.status(400).json({ error: 'Invalid signature' });
  }
});

router.post('/paypal/create-order', authenticateToken, async (req, res) => {
  const { total } = req.body;
  const request = new paypal.orders.OrdersCreateRequest();
  request.prefer('return=representation');
  request.requestBody({
    intent: 'CAPTURE',
    purchase_units: [{
      amount: {
        currency_code: process.env.PAYPAL_CURRENCY,
        value: total.toString()
      }
    }],
    application_context: {
      return_url: process.env.PAYPAL_RETURN_URL,
      cancel_url: process.env.PAYPAL_CANCEL_URL
    }
  });

  try {
    const order = await paypalClient.execute(request);
    res.json({ orderId: order.result.id });
  } catch (error) {
    console.error('PayPal create order error:', error);
    res.status(500).json({ error: 'Failed to create PayPal order' });
  }
});

router.get('/paypal/success', authenticateToken, async (req, res) => {
  const { token } = req.query;
  const request = new paypal.orders.OrdersCaptureRequest(token);
  try {
    const capture = await paypalClient.execute(request);
    await pool.query('UPDATE orders SET status = $1 WHERE id = $2', ['completed', capture.result.purchase_units[0].reference_id]);
    res.redirect(`${process.env.CLIENT_URL}/success`);
  } catch (error) {
    console.error('PayPal capture error:', error);
    res.redirect(`${process.env.CLIENT_URL}/cancel`);
  }
});

router.get('/paypal/cancel', (req, res) => {
  res.redirect(`${process.env.CLIENT_URL}/cancel`);
});

router.post('/contact', async (req, res) => {
  const { name, email, message } = req.body;
  if (!name || !email || !message) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    await pool.query(
      'INSERT INTO contact_messages (name, email, message) VALUES ($1, $2, $3)',
      [name, email, message]
    );
    res.json({ message: 'Message sent successfully' });
  } catch (error) {
    console.error('Error saving contact message:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

module.exports = router;