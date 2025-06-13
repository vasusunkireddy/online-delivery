const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const nodemailer = require('nodemailer');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

module.exports = (sequelize, User, Cart, MenuItem, RestaurantStatus) => {
  const { Op } = sequelize;

  // Passport Google Strategy
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.SERVER_URL) {
    console.error('Missing Google OAuth environment variables');
    throw new Error('GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and SERVER_URL must be defined');
  }

  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: `${process.env.SERVER_URL}/api/auth/google/callback`,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          let user = await User.findOne({ where: { googleId: profile.id } });
          if (!user) {
            user = await User.findOne({ where: { email: profile.emails[0].value } });
            if (!user) {
              user = await User.create({
                googleId: profile.id,
                name: profile.displayName,
                email: profile.emails[0].value,
              });
            } else {
              user.googleId = profile.id;
              await user.save();
            }
          }
          return done(null, user);
        } catch (error) {
          return done(error, null);
        }
      }
    )
  );

  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findByPk(id);
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  });

  // Email transporter
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  // Rate limiter for sensitive routes
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 requests per window
    message: { message: 'Too many requests, please try again later' },
  });

  // Middleware to verify JWT
  const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Access token required' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ message: 'Invalid or expired token' });
      req.user = user;
      next();
    });
  };

  // Validation middleware
  const signupValidation = [
    body('name').notEmpty().trim().withMessage('Name is required'),
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('phone').isMobilePhone().withMessage('Valid phone number is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  ];

  const loginValidation = [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('password').notEmpty().withMessage('Password is required'),
  ];

  const forgotPasswordValidation = [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  ];

  const verifyOtpValidation = [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits'),
  ];

  const resetPasswordValidation = [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('newPassword').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  ];

  const cartValidation = [
    body('itemId').notEmpty().withMessage('Item ID is required'),
    body('name').notEmpty().trim().withMessage('Item name is required'),
    body('price').isFloat({ min: 0 }).withMessage('Valid price is required'),
    body('image').optional().isURL().withMessage('Valid image URL is required'),
    body('quantity').optional().isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),
  ];

  // Routes
  router.get('/status', async (req, res, next) => {
    try {
      const status = await RestaurantStatus.findOne();
      if (!status) return res.status(404).json({ message: 'Status not found' });
      res.json({ status: status.status });
    } catch (error) {
      next(error);
    }
  });

  router.get('/menu', async (req, res, next) => {
    try {
      const menuItems = await MenuItem.findAll();
      res.json(menuItems);
    } catch (error) {
      next(error);
    }
  });

  router.post('/signup', authLimiter, signupValidation, async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    const { name, email, phone, password } = req.body;
    try {
      let user = await User.findOne({ where: { email } });
      if (user) return res.status(400).json({ message: 'Email already exists' });

      const hashedPassword = await bcrypt.hash(password, 10);
      user = await User.create({ name, email, phone, password: hashedPassword });
      const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token, message: 'Signup successful' });
    } catch (error) {
      next(error);
    }
  });

  router.post('/login', authLimiter, loginValidation, async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    const { email, password } = req.body;
    try {
      const user = await User.findOne({ where: { email } });
      if (!user) return res.status(400).json({ message: 'Invalid credentials' });

      if (!user.password) return res.status(400).json({ message: 'Please use Google login' });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

      const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token, message: 'Login successful' });
    } catch (error) {
      next(error);
    }
  });

  router.post('/auth/google', async (req, res, next) => {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ message: 'Google credential required' });

    try {
      // Placeholder for Google token verification
      const profile = await new Promise((resolve, reject) => {
        passport.authenticate('google', { session: false }, (err, user) => {
          if (err) return reject(err);
          if (!user) return reject(new Error('Google authentication failed'));
          resolve(user);
        })({ body: { credential } }, res, next);
      });

      const token = jwt.sign({ id: profile.id, email: profile.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token, message: 'Google login successful' });
    } catch (error) {
      next(error);
    }
  });

  router.post('/forgot-password', authLimiter, forgotPasswordValidation, async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    const { email } = req.body;
    try {
      const user = await User.findOne({ where: { email } });
      if (!user) return res.status(400).json({ message: 'User not found' });

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      user.resetPasswordToken = otp;
      user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
      await user.save();

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Password Reset OTP',
        text: `Your OTP for password reset is: ${otp}. It is valid for 1 hour.`,
      };

      await transporter.sendMail(mailOptions);
      res.json({ message: 'OTP sent to your email' });
    } catch (error) {
      next(error);
    }
  });

  router.post('/verify-otp', authLimiter, verifyOtpValidation, async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    const { email, otp } = req.body;
    try {
      const user = await User.findOne({
        where: {
          email,
          resetPasswordToken: otp,
          resetPasswordExpires: { [Op.gt]: Date.now() },
        },
      });
      if (!user) return res.status(400).json({ message: 'Invalid or expired OTP' });

      res.json({ message: 'OTP verified' });
    } catch (error) {
      next(error);
    }
  });

  router.post('/reset-password', authLimiter, resetPasswordValidation, async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    const { email, newPassword } = req.body;
    try {
      const user = await User.findOne({
        where: {
          email,
          resetPasswordExpires: { [Op.gt]: Date.now() },
        },
      });
      if (!user) return res.status(400).json({ message: 'Invalid or expired OTP' });

      user.password = await bcrypt.hash(newPassword, 10);
      user.resetPasswordToken = null;
      user.resetPasswordExpires = null;
      await user.save();

      res.json({ message: 'Password reset successfully' });
    } catch (error) {
      next(error);
    }
  });

  router.post('/cart', authenticateToken, cartValidation, async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    const { itemId, name, price, image, quantity = 1 } = req.body;
    try {
      const menuItem = await MenuItem.findByPk(itemId);
      if (!menuItem) return res.status(400).json({ message: 'Menu item not found' });

      const existingCartItem = await Cart.findOne({ where: { userId: req.user.id, itemId } });
      if (existingCartItem) {
        existingCartItem.quantity += quantity;
        await existingCartItem.save();
        return res.json({ message: 'Item quantity updated in cart', cartItem: existingCartItem });
      }

      const cartItem = await Cart.create({
        userId: req.user.id,
        itemId,
        name,
        price,
        image,
        quantity,
      });
      res.json({ message: 'Item added to cart', cartItem });
    } catch (error) {
      next(error);
    }
  });

  router.get('/cart', authenticateToken, async (req, res, next) => {
    try {
      const cartItems = await Cart.findAll({ where: { userId: req.user.id } });
      res.json(cartItems);
    } catch (error) {
      next(error);
    }
  });

  // Error handling middleware
  router.use((err, req, res, next) => {
    console.error('Error:', err.message);
    res.status(500).json({ message: 'Server error' });
  });

  return router;
};