const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const nodemailer = require('nodemailer');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

module.exports = (sequelize, User, Cart, MenuItem, RestaurantStatus, Address, Favorite, Coupon, Order) => {
  const { Op } = sequelize;

  // Validate all required environment variables
  const requiredEnvVars = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'SERVER_URL', 'JWT_SECRET', 'EMAIL_USER', 'EMAIL_PASS'];
  const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
  if (missingEnvVars.length > 0) {
    console.error(`Missing environment variables: ${missingEnvVars.join(', ')}`);
    throw new Error(`The following environment variables must be defined: ${missingEnvVars.join(', ')}`);
  }

  // Passport Google OAuth setup
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

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { message: 'Too many requests, please try again later' },
  });

  const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
      console.log('No token provided in request');
      return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        console.log('Token verification error:', err.message, 'Token:', token);
        return res.status(403).json({ message: 'Invalid or expired token', error: err.message });
      }
      console.log('Token verified, user:', user);
      req.user = user;
      next();
    });
  };

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
    body('quantity').optional().isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),
  ];

  const addressValidation = [
    body('fullName').notEmpty().trim().withMessage('Full name is required'),
    body('mobile').isMobilePhone().withMessage('Valid mobile number is required'),
    body('houseNo').notEmpty().trim().withMessage('House/Flat number is required'),
    body('location').notEmpty().trim().withMessage('Location/Street is required'),
    body('landmark').optional().trim(),
  ];

  const favoriteValidation = [
    body('id').notEmpty().withMessage('Item ID is required'),
    body('name').notEmpty().trim().withMessage('Item name is required'),
    body('image').optional().isURL().withMessage('Valid image URL is required'),
  ];

  const orderValidation = [
    body('addressId')
      .notEmpty()
      .withMessage('Address ID is required')
      .isInt()
      .withMessage('Address ID must be an integer')
      .toInt(),
    body('items').isArray({ min: 1 }).withMessage('At least one item is required'),
    body('items.*.id').notEmpty().withMessage('Item ID is required'),
    body('items.*.name').notEmpty().withMessage('Item name is required'),
    body('items.*.price').isFloat({ min: 0 }).withMessage('Item price must be a non-negative number'),
    body('items.*.quantity').isInt({ min: 1 }).withMessage('Item quantity must be a positive integer'),
    body('items.*.image').optional().isURL().withMessage('Item image must be a valid URL'),
    body('couponCode').optional().trim(),
    body('paymentMethod').notEmpty().withMessage('Payment method is required'),
    body('deliveryCost').isFloat({ min: 0 }).withMessage('Delivery cost must be a non-negative number'),
  ];

  // Restaurant Status
  router.get('/status', async (req, res, next) => {
    try {
      const status = await RestaurantStatus.findOne();
      if (!status) return res.status(404).json({ message: 'Status not found' });
      res.json({ status: status.status });
    } catch (error) {
      next(error);
    }
  });

  // Menu Items
  router.get('/menu', async (req, res, next) => {
    try {
      const menuItems = await MenuItem.findAll();
      res.json(menuItems);
    } catch (error) {
      next(error);
    }
  });

  // Signup
  router.post('/signup', authLimiter, signupValidation, async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    const { name, email, phone, password } = req.body;
    try {
      let user = await User.findOne({ where: { email } });
      if (user) return res.status(400).json({ message: 'Email already exists' });

      const hashedPassword = await bcrypt.hash(password, 10);
      user = await User.create({ name, email, phone, password: hashedPassword });
      const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });
      res.json({ token, message: 'Signup successful' });
    } catch (error) {
      next(error);
    }
  });

  // Login
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

      const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });
      res.json({ token, message: 'Login successful' });
    } catch (error) {
      next(error);
    }
  });

  // Google OAuth Routes
  router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

  router.get(
    '/auth/google/callback',
    passport.authenticate('google', { session: false, failureRedirect: '/index.html' }),
    (req, res) => {
      const user = req.user;
      const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });
      res.redirect(`/userdashboard.html?token=${token}`);
    }
  );

  // Refresh Token
  router.post('/refresh-token', authenticateToken, async (req, res, next) => {
    try {
      const user = await User.findByPk(req.user.id);
      if (!user) return res.status(404).json({ message: 'User not found' });
      const newToken = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });
      res.json({ token: newToken, message: 'Token refreshed' });
    } catch (error) {
      next(error);
    }
  });

  // Forgot Password
  router.post('/forgot-password', authLimiter, forgotPasswordValidation, async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    const { email } = req.body;
    try {
      const user = await User.findOne({ where: { email } });
      if (!user) return res.status(400).json({ message: 'User not found' });

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      user.resetPasswordToken = otp;
      user.resetPasswordExpires = Date.now() + 3600000;
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

  // Verify OTP
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

  // Reset Password
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

  // Profile Endpoints
  router.get('/profile', authenticateToken, async (req, res, next) => {
    try {
      const user = await User.findByPk(req.user.id);
      if (!user) return res.status(404).json({ message: 'User not found' });
      res.json({ name: user.name, email: user.email, phone: user.phone, image: user.image });
    } catch (error) {
      next(error);
    }
  });

  router.put('/profile', authenticateToken, async (req, res, next) => {
    const { name, image } = req.body;
    if (!name) return res.status(400).json({ message: 'Name is required' });

    try {
      const user = await User.findByPk(req.user.id);
      if (!user) return res.status(404).json({ message: 'User not found' });

      user.name = name;
      if (image) user.image = image;
      await user.save();

      res.json({ name: user.name, email: user.email, phone: user.phone, image: user.image });
    } catch (error) {
      next(error);
    }
  });

  // Address Endpoints
  router.get('/addresses', authenticateToken, async (req, res, next) => {
    try {
      const addresses = await Address.findAll({ where: { userId: req.user.id } });
      res.json(addresses);
    } catch (error) {
      next(error);
    }
  });

  router.post('/addresses', authenticateToken, addressValidation, async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    const { fullName, mobile, houseNo, location, landmark } = req.body;
    try {
      const address = await Address.create({
        userId: req.user.id,
        fullName,
        mobile,
        houseNo,
        location,
        landmark,
      });
      res.json({ message: 'Address added', address });
    } catch (error) {
      next(error);
    }
  });

  router.delete('/addresses/:id', authenticateToken, async (req, res, next) => {
    try {
      const address = await Address.findOne({ where: { id: req.params.id, userId: req.user.id } });
      if (!address) return res.status(404).json({ message: 'Address not found' });

      await address.destroy();
      res.json({ message: 'Address deleted' });
    } catch (error) {
      next(error);
    }
  });

  // Favorites Endpoints
  router.get('/favorites', authenticateToken, async (req, res, next) => {
    try {
      const favorites = await Favorite.findAll({ where: { userId: req.user.id } });
      res.json(favorites);
    } catch (error) {
      next(error);
    }
  });

  router.post('/favorites', authenticateToken, favoriteValidation, async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    const { id, name, image } = req.body;
    try {
      const existingFavorite = await Favorite.findOne({ where: { userId: req.user.id, id } });
      if (existingFavorite) return res.status(400).json({ message: 'Item already in favorites' });

      const favorite = await Favorite.create({
        userId: req.user.id,
        id,
        name,
        image,
      });
      res.json({ message: 'Added to favorites', favorite });
    } catch (error) {
      next(error);
    }
  });

  router.delete('/favorites/:id', authenticateToken, async (req, res, next) => {
    try {
      const favorite = await Favorite.findOne({ where: { id: req.params.id, userId: req.user.id } });
      if (!favorite) return res.status(404).json({ message: 'Favorite not found' });

      await favorite.destroy();
      res.json({ message: 'Removed from favorites' });
    } catch (error) {
      next(error);
    }
  });

  // Cart Endpoints
  router.post('/cart/add', authenticateToken, cartValidation, async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    const { itemId, quantity = 1 } = req.body;
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
        name: menuItem.name,
        price: menuItem.price,
        image: menuItem.image,
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

  router.put('/cart/:id', authenticateToken, cartValidation, async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    const { quantity } = req.body;
    try {
      const cartItem = await Cart.findOne({ where: { id: req.params.id, userId: req.user.id } });
      if (!cartItem) return res.status(404).json({ message: 'Cart item not found' });

      cartItem.quantity = quantity;
      await cartItem.save();
      res.json({ message: 'Cart item updated', cartItem });
    } catch (error) {
      next(error);
    }
  });

  router.delete('/cart/:id', authenticateToken, async (req, res, next) => {
    try {
      console.log(`Deleting cart item with ID ${req.params.id} for user ${req.user.id}`);
      const cartItem = await Cart.findOne({ where: { id: req.params.id, userId: req.user.id } });
      if (!cartItem) {
        console.log(`Cart item ${req.params.id} not found for user ${req.user.id}`);
        return res.status(404).json({ message: 'Cart item not found' });
      }

      await cartItem.destroy();
      res.json({ message: 'Cart item removed' });
    } catch (error) {
      next(error);
    }
  });

  // Coupon Endpoints
  router.get('/coupons', authenticateToken, async (req, res, next) => {
    try {
      const coupons = await Coupon.findAll();
      res.json(coupons);
    } catch (error) {
      next(error);
    }
  });

  router.get('/coupons/validate', authenticateToken, async (req, res, next) => {
    const { code } = req.query;
    if (!code) return res.status(400).json({ message: 'Coupon code is required' });

    try {
      const coupon = await Coupon.findOne({ where: { code } });
      if (!coupon) return res.status(400).json({ message: 'Invalid coupon code' });

      res.json({ code: coupon.code, discount: coupon.discount });
    } catch (error) {
      next(error);
    }
  });

  // Order Endpoints
  router.post('/orders', authenticateToken, orderValidation, async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    const { addressId, items, couponCode, paymentMethod, deliveryCost } = req.body;
    try {
      const address = await Address.findOne({ where: { id: addressId, userId: req.user.id } });
      if (!address) return res.status(400).json({ message: 'Invalid address' });

      let discount = 0;
      if (couponCode) {
        const coupon = await Coupon.findOne({ where: { code: couponCode } });
        if (!coupon) return res.status(400).json({ message: 'Invalid coupon code' });
        discount = coupon.discount;
      }

      let total = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
      total = total - (total * discount) / 100 + deliveryCost;

      const order = await Order.create({
        userId: req.user.id,
        addressId,
        items,
        couponCode,
        paymentMethod,
        deliveryCost,
        total,
        status: 'Placed',
      });

      await Cart.destroy({ where: { userId: req.user.id } });

      res.json({ message: 'Order placed', order });
    } catch (error) {
      next(error);
    }
  });

  router.get('/orders', authenticateToken, async (req, res, next) => {
    try {
      const orders = await Order.findAll({ where: { userId: req.user.id } });
      res.json(orders);
    } catch (error) {
      next(error);
    }
  });

  router.put('/orders/:id/track', authenticateToken, async (req, res, next) => {
    try {
      const order = await Order.findOne({ where: { id: req.params.id, userId: req.user.id } });
      if (!order) return res.status(404).json({ message: 'Order not found' });

      const statuses = ['Placed', 'Preparing', 'Shipped', 'Delivered'];
      const currentIndex = statuses.indexOf(order.status);
      if (currentIndex < statuses.length - 1) {
        order.status = statuses[currentIndex + 1];
        await order.save();
      }

      res.json({ message: 'Order status updated', status: order.status });
    } catch (error) {
      next(error);
    }
  });

  // Error Handling Middleware
  router.use((err, req, res, next) => {
    console.error('Error:', err.message, 'Stack:', err.stack);
    res.status(500).json({ message: 'Server error', error: err.message });
  });

  return router;
};