const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const { Op } = require('sequelize');
const cloudinary = require('cloudinary').v2;
const sgMail = require('@sendgrid/mail');
const { body, query, validationResult } = require('express-validator');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Initialize Google OAuth client
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Configure SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Ensure upload directory exists
const uploadDir = path.join(__dirname, '../public/Uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(null, `${uniqueSuffix}${path.extname(file.originalname).toLowerCase()}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: (req, file, cb) => {
    if (!['image/jpeg', 'image/png'].includes(file.mimetype)) {
      return cb(new Error('Only JPEG or PNG images are allowed'));
    }
    cb(null, true);
  },
}).single('image');

// Middleware to verify JWT
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    console.log('No token provided in request');
    return res.status(401).json({ message: 'No token provided' });
  }
  const token = authHeader.replace('Bearer ', '');
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// Validation chains
const profileValidation = [
  body('name').notEmpty().trim().withMessage('Name is required'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
];

const addressValidation = [
  body('fullName').notEmpty().trim().withMessage('Full name is required'),
  body('mobile').matches(/^\d{10}$/).withMessage('Valid 10-digit mobile number is required'),
  body('houseNo').notEmpty().trim().withMessage('House number is required'),
  body('location').notEmpty().trim().withMessage('Location is required'),
  body('landmark').optional().trim(),
];

const favoriteValidation = [
  body('itemId').notEmpty().trim().withMessage('Item ID is required'),
  body('name').notEmpty().trim().withMessage('Item name is required'),
  body('image').optional().isString().withMessage('Valid image URL is required'),
];

const cartValidation = [
  body('itemId').notEmpty().trim().withMessage('Item ID is required'),
  body('name').notEmpty().trim().withMessage('Item name is required'),
  body('price').isFloat({ min: 0 }).withMessage('Valid price is required'),
  body('image').optional().isString().withMessage('Valid image URL is required'),
  body('quantity').isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),
];

const cartUpdateValidation = [
  body('quantity').isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),
];

const orderValidation = [
  body('addressId').isInt().withMessage('Valid address ID is required'),
  body('items').isArray({ min: 1 }).withMessage('Items array is required'),
  body('items.*.itemId').notEmpty().trim().withMessage('Item ID is required'),
  body('items.*.name').notEmpty().trim().withMessage('Item name is required'),
  body('items.*.price').isFloat({ min: 0 }).withMessage('Valid price is required'),
  body('items.*.quantity').isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),
  body('items.*.image').optional().isString().withMessage('Valid image URL is required'),
  body('couponCode').optional().isString().trim(),
  body('paymentMethod').isIn(['cod', 'online']).withMessage('Invalid payment method'),
  body('deliveryCost').isFloat({ min: 0 }).withMessage('Valid delivery cost is required'),
];

const cancelOrderValidation = [
  body('reason').notEmpty().trim().withMessage('Cancellation reason is required'),
];

module.exports = (User, Cart, MenuItem, RestaurantStatus, Address, Favorite, Coupon, Order) => {
  // Image Upload Endpoint
  router.post('/upload', authenticateJWT, upload, async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: 'No image file provided' });
      }
      let imageUrl;
      try {
        const result = await cloudinary.uploader.upload(req.file.path, {
          resource_type: 'image',
          folder: 'delicute',
        });
        imageUrl = result.secure_url;
        fs.unlinkSync(req.file.path); // Delete local file
        console.log(`Image uploaded to Cloudinary: ${imageUrl}`);
      } catch (cloudinaryError) {
        console.warn('Cloudinary upload failed, using local storage:', cloudinaryError.message);
        imageUrl = `/Uploads/${req.file.filename}`;
      }
      res.status(200).json({ url: imageUrl });
    } catch (error) {
      console.error('Upload image error:', error.message);
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path); // Cleanup on error
      }
      res.status(500).json({ message: 'Failed to upload image' });
    }
  });

  // Get menu items
  router.get('/menu', async (req, res) => {
    try {
      const menuItems = await MenuItem.findAll({
        attributes: ['id', 'name', 'price', 'image', 'description', 'category'],
      });
      const sanitizedItems = menuItems.map(item => ({
        _id: item.id,
        ...item.toJSON(),
        price: parseFloat(item.price) || 0,
        image: item.image || '/Uploads/default-menu.png',
      }));
      res.status(200).json(sanitizedItems);
    } catch (error) {
      console.error('Error fetching menu:', error.message);
      res.status(500).json({ message: 'Failed to fetch menu items' });
    }
  });

  // Login
  router.post('/login', [
    body('email').notEmpty().trim().withMessage('Email or mobile number is required'),
    body('password').notEmpty().withMessage('Password is required'),
  ], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    const { email, password } = req.body;
    try {
      const user = await User.findOne({
        where: { [Op.or]: [{ email: email.toLowerCase() }, { phone: email }] },
      });
      if (!user || !user.password) {
        return res.status(401).json({ message: 'Invalid email/mobile or password' });
      }
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ message: 'Invalid email/mobile or password' });
      }
      const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
      console.log(`User logged in: ${user.email}`);
      res.status(200).json({
        token,
        user: {
          _id: user.id,
          name: user.name,
          email: user.email,
          phone: user.phone,
          image: user.image || '/Uploads/default-profile.png',
        },
      });
    } catch (error) {
      console.error('Login error:', error.message);
      res.status(500).json({ message: 'Failed to login' });
    }
  });

  // Signup
  router.post('/signup', [
    body('name').notEmpty().trim().withMessage('Name is required'),
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('phone').matches(/^\d{10}$/).withMessage('Valid 10-digit mobile number is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  ], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    const { name, email, phone, password } = req.body;
    try {
      const existingUser = await User.findOne({
        where: { [Op.or]: [{ email: email.toLowerCase() }, { phone }] },
      });
      if (existingUser) {
        return res.status(400).json({ message: 'Email or mobile number already exists' });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = await User.create({
        name,
        email: email.toLowerCase(),
        phone,
        password: hashedPassword,
        image: '/Uploads/default-profile.png',
      });
      const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
      console.log(`User signed up: ${user.email}`);
      res.status(201).json({
        token,
        user: {
          _id: user.id,
          name: user.name,
          email: user.email,
          phone: user.phone,
          image: user.image,
        },
      });
    } catch (error) {
      console.error('Signup error:', error.message);
      res.status(500).json({ message: 'Failed to signup' });
    }
  });

  // Google Sign-In
  router.post('/auth/google', [
    body('credential').notEmpty().withMessage('Google credential is required'),
  ], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    const { credential } = req.body;
    try {
      const ticket = await client.verifyIdToken({
        idToken: credential,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
      const payload = ticket.getPayload();
      const { sub: googleId, email, name } = payload;
      let user = await User.findOne({ where: { googleId } });
      if (!user) {
        user = await User.findOne({ where: { email: email.toLowerCase() } });
        if (user) {
          return res.status(400).json({ message: 'Email already registered with another method' });
        }
        user = await User.create({
          name,
          email: email.toLowerCase(),
          googleId,
          phone: null,
          image: '/Uploads/default-profile.png',
        });
      }
      const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
      console.log(`Google login: ${user.email}`);
      res.status(200).json({
        token,
        user: {
          _id: user.id,
          name: user.name,
          email: user.email,
          phone: user.phone,
          image: user.image,
        },
      });
    } catch (error) {
      console.error('Google login error:', error.message);
      res.status(401).json({ message: 'Failed to authenticate with Google' });
    }
  });

  // Forgot Password
  router.post('/forgot-password', [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  ], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    const { email } = req.body;
    try {
      const user = await User.findOne({ where: { email: email.toLowerCase() } });
      if (!user) {
        return res.status(404).json({ message: 'Email not found' });
      }
      const otp = Math.floor(100000 + Math.random() * 600000).toString();
      await User.update(
        { resetPasswordToken: otp, resetPasswordExpires: new Date(Date.now() + 10 * 60 * 1000) },
        { where: { email: email.toLowerCase() } }
      );
      const msg = {
        to: email,
        from: process.env.SENDGRID_FROM_EMAIL,
        subject: 'Delicute Password Reset OTP',
        text: `Your OTP for password reset is: ${otp}. It is valid for 10 minutes.`,
        html: `<p>Your OTP for password reset is: <strong>${otp}</strong>. It is valid for 10 minutes.</p>`,
      };
      await sgMail.send(msg);
      console.log(`OTP sent to: ${email}`);
      res.status(200).json({ message: 'OTP sent to email' });
    } catch (error) {
      console.error('Forgot password error:', error.message);
      res.status(500).json({ message: 'Failed to send OTP' });
    }
  });

  // Verify OTP
  router.post('/verify-otp', [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('otp').notEmpty().trim().withMessage('OTP is required'),
  ], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    const { email, otp } = req.body;
    try {
      const user = await User.findOne({
        where: {
          email: email.toLowerCase(),
          resetPasswordToken: otp,
          resetPasswordExpires: { [Op.gt]: new Date() },
        },
      });
      if (!user) {
        return res.status(400).json({ message: 'Invalid or expired OTP' });
      }
      res.status(200).json({ message: 'OTP verified successfully' });
    } catch (error) {
      console.error('OTP verification error:', error.message);
      res.status(500).json({ message: 'Failed to verify OTP' });
    }
  });

  // Reset Password
  router.post('/reset-password', [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('newPassword').isLength({ min: 6 }).withMessage('New password must be at least 6 characters'),
    body('confirmPassword').custom((value, { req }) => value === req.body.newPassword).withMessage('Passwords do not match'),
  ], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    const { email, newPassword } = req.body;
    try {
      const user = await User.findOne({ where: { email: email.toLowerCase() } });
      if (!user) {
        return res.status(404).json({ message: 'Email not found' });
      }
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await User.update(
        { password: hashedPassword, resetPasswordToken: null, resetPasswordExpires: null },
        { where: { email: email.toLowerCase() } }
      );
      console.log(`Password reset for: ${email}`);
      res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
      console.error('Reset password error:', error.message);
      res.status(500).json({ message: 'Failed to reset password' });
    }
  });

  // Get Profile
  router.get('/profile', authenticateJWT, async (req, res) => {
    try {
      const user = await User.findByPk(req.userId, {
        attributes: ['id', 'name', 'email', 'phone', 'image'],
      });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      res.status(200).json({
        _id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        image: user.image || '/Uploads/default-profile.png',
      });
    } catch (error) {
      console.error(`Get profile error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to fetch profile' });
    }
  });

  // Update Profile
  router.put('/profile', authenticateJWT, upload, profileValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Profile validation errors:', errors.array());
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    const { name, email } = req.body;
    try {
      const user = await User.findByPk(req.userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      let imageUrl = user.image || '/Uploads/default-profile.png';
      if (req.file) {
        try {
          const result = await cloudinary.uploader.upload(req.file.path, {
            resource_type: 'image',
            folder: 'delicute',
          });
          imageUrl = result.secure_url;
          fs.unlinkSync(req.file.path); // Delete local file
          console.log(`Profile image uploaded to Cloudinary: ${imageUrl}`);
          // Optionally delete old Cloudinary image
          if (user.image && user.image.includes('cloudinary.com')) {
            const publicId = user.image.split('/').pop().split('.')[0];
            await cloudinary.uploader.destroy(`delicute/${publicId}`).catch(err => console.warn('Failed to delete old image:', err.message));
          }
        } catch (cloudinaryError) {
          console.warn('Cloudinary upload failed, using local storage:', cloudinaryError.message);
          imageUrl = `/Uploads/${req.file.filename}`;
        }
      }
      const existingEmail = await User.findOne({
        where: { email: email.toLowerCase(), id: { [Op.ne]: req.userId } },
      });
      if (existingEmail) {
        if (req.file && fs.existsSync(req.file.path)) {
          fs.unlinkSync(req.file.path); // Cleanup on error
        }
        return res.status(400).json({ message: 'Email already in use' });
      }
      await user.update({ name, email: email.toLowerCase(), image: imageUrl });
      res.status(200).json({
        _id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        image: user.image,
      });
    } catch (error) {
      console.error(`Update profile error for user ${req.userId}:`, error.message);
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path); // Cleanup on error
      }
      res.status(500).json({ message: 'Failed to update profile' });
    }
  });

  // Get Addresses
  router.get('/addresses', authenticateJWT, async (req, res) => {
    try {
      const addresses = await Address.findAll({ where: { userId: req.userId } });
      res.status(200).json(addresses.map(addr => ({ _id: addr.id, ...addr.toJSON() })));
    } catch (error) {
      console.error(`Get addresses error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to fetch addresses' });
    }
  });

  // Get Single Address
  router.get('/addresses/:id', authenticateJWT, async (req, res) => {
    try {
      const address = await Address.findOne({
        where: { id: req.params.id, userId: req.userId },
      });
      if (!address) {
        return res.status(404).json({ message: 'Address not found' });
      }
      res.status(200).json({ _id: address.id, ...address.toJSON() });
    } catch (error) {
      console.error(`Get address error for user ${req.userId}, address ${req.params.id}:`, error.message);
      res.status(500).json({ message: 'Failed to fetch address' });
    }
  });

  // Add Address
  router.post('/addresses', authenticateJWT, addressValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Address validation errors:', errors.array());
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    const { fullName, mobile, houseNo, location, landmark } = req.body;
    try {
      const address = await Address.create({
        userId: req.userId,
        fullName,
        mobile,
        houseNo,
        location,
        landmark,
      });
      res.status(201).json({ _id: address.id, ...address.toJSON() });
    } catch (error) {
      console.error(`Add address error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to add address' });
    }
  });

  // Update Address
  router.put('/addresses/:id', authenticateJWT, addressValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Address validation errors:', errors.array());
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    const { fullName, mobile, houseNo, location, landmark } = req.body;
    try {
      const address = await Address.findOne({
        where: { id: req.params.id, userId: req.userId },
      });
      if (!address) {
        return res.status(404).json({ message: 'Address not found' });
      }
      await address.update({
        fullName,
        mobile,
        houseNo,
        location,
        landmark,
      });
      res.status(200).json({ _id: address.id, ...address.toJSON() });
    } catch (error) {
      console.error(`Update address error for user ${req.userId}, address ${req.params.id}:`, error.message);
      res.status(500).json({ message: 'Failed to update address' });
    }
  });

  // Delete Address
  router.delete('/addresses/:id', authenticateJWT, async (req, res) => {
    try {
      const address = await Address.findOne({
        where: { id: req.params.id, userId: req.userId },
      });
      if (!address) {
        return res.status(404).json({ message: 'Address not found' });
      }
      const orderCount = await Order.count({
        where: { addressId: req.params.id, status: { [Op.ne]: 'cancelled' } },
      });
      if (orderCount > 0) {
        return res.status(400).json({ message: 'Cannot delete address used in active orders' });
      }
      await address.destroy();
      res.status(200).json({ message: 'Address deleted' });
    } catch (error) {
      console.error(`Delete address error for user ${req.userId}, address ${req.params.id}:`, error.message);
      res.status(500).json({ message: 'Failed to delete address' });
    }
  });

  // Get Favorites
  router.get('/favorites', authenticateJWT, async (req, res) => {
    try {
      const favorites = await Favorite.findAll({ where: { userId: req.userId } });
      const sanitizedFavorites = favorites.map(fav => ({
        _id: fav.id,
        ...fav.toJSON(),
        image: fav.image || '/Uploads/default-menu.png',
      }));
      res.status(200).json(sanitizedFavorites);
    } catch (error) {
      console.error(`Get favorites error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to fetch favorites' });
    }
  });

  // Add Favorite
  router.post('/favorites', authenticateJWT, favoriteValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Favorites validation errors:', errors.array());
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    const { itemId, name, image } = req.body;
    console.log('Favorites request payload:', req.body);
    try {
      const menuItem = await MenuItem.findByPk(itemId);
      if (!menuItem) {
        console.log(`Menu item not found for itemId: ${itemId}`);
        return res.status(404).json({ message: 'Menu item not found' });
      }
      const [favorite, created] = await Favorite.findOrCreate({
        where: { userId: req.userId, itemId },
        defaults: {
          userId: req.userId,
          itemId,
          name,
          image: image || menuItem.image || '/Uploads/default-menu.png',
        },
      });
      if (!created) {
        return res.status(400).json({ message: 'Item already in favorites' });
      }
      res.status(201).json({ _id: favorite.id, ...favorite.toJSON() });
    } catch (error) {
      console.error(`Add favorite error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to add favorite' });
    }
  });

  // Remove Favorite
  router.delete('/favorites/:id', authenticateJWT, async (req, res) => {
    try {
      const favorite = await Favorite.findOne({
        where: { itemId: req.params.id, userId: req.userId },
      });
      if (!favorite) {
        return res.status(404).json({ message: 'Favorite not found' });
      }
      await favorite.destroy();
      res.status(200).json({ message: 'Favorite removed' });
    } catch (error) {
      console.error(`Remove favorite error for user ${req.userId}, item ${req.params.id}:`, error.message);
      res.status(500).json({ message: 'Failed to remove favorite' });
    }
  });

  // Get Cart
  router.get('/cart', authenticateJWT, async (req, res) => {
    try {
      const cartItems = await Cart.findAll({ where: { userId: req.userId } });
      const sanitizedCartItems = cartItems.map(item => ({
        _id: item.id,
        ...item.toJSON(),
        image: item.image || '/Uploads/default-menu.png',
      }));
      res.status(200).json(sanitizedCartItems);
    } catch (error) {
      console.error(`Get cart error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to fetch cart' });
    }
  });

  // Add to Cart
  router.post('/cart', authenticateJWT, cartValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Cart validation errors:', errors.array());
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    const { itemId, name, price, image, quantity } = req.body;
    console.log('Cart request payload:', req.body);
    try {
      const menuItem = await MenuItem.findByPk(itemId);
      if (!menuItem) {
        console.log(`Menu item not found for itemId: ${itemId}`);
        return res.status(404).json({ message: 'Menu item not found' });
      }
      let cartItem = await Cart.findOne({ where: { userId: req.userId, itemId } });
      if (cartItem) {
        cartItem.quantity += quantity;
        await cartItem.save();
      } else {
        cartItem = await Cart.create({
          userId: req.userId,
          itemId,
          name,
          price: parseFloat(price),
          image: image || menuItem.image || '/Uploads/default-menu.png',
          quantity,
        });
      }
      res.status(201).json({ _id: cartItem.id, ...cartItem.toJSON() });
    } catch (error) {
      console.error(`Add to cart error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to add item to cart' });
    }
  });

  // Update Cart Quantity
  router.put('/cart/:itemId', authenticateJWT, cartUpdateValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Cart update validation errors:', errors.array());
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    const { quantity } = req.body;
    try {
      const cartItem = await Cart.findOne({
        where: { itemId: req.params.itemId, userId: req.userId },
      });
      if (!cartItem) {
        return res.status(404).json({ message: 'Cart item not found' });
      }
      await cartItem.update({ quantity });
      res.status(200).json({ _id: cartItem.id, ...cartItem.toJSON() });
    } catch (error) {
      console.error(`Update cart error for user ${req.userId}, item ${req.params.itemId}:`, error.message);
      res.status(500).json({ message: 'Failed to update quantity' });
    }
  });

  // Remove from Cart
  router.delete('/cart/:itemId', authenticateJWT, async (req, res) => {
    try {
      const cartItem = await Cart.findOne({
        where: { itemId: req.params.id, userId: req.userId },
      });
      if (!cartItem) {
        return res.status(404).json({ message: 'Cart item not found' });
      }
      await cartItem.destroy();
      res.status(200).json({ message: 'Item removed from cart' });
    } catch (error) {
      console.error(`Remove cart error for user ${req.userId}, item ${req.params.id}:`, error.message);
      res.status(500).json({ message: 'Failed to remove item from cart' });
    }
  });

  // Get Coupons
  router.get('/coupons', authenticateJWT, async (req, res) => {
    try {
      const coupons = await Coupon.findAll();
      const sanitizedCoupons = coupons.map(coupon => ({
        _id: coupon.id,
        ...coupon.toJSON(),
        image: coupon.image || '/Uploads/default-coupon.png',
      }));
      res.status(200).json(sanitizedCoupons);
    } catch (error) {
      console.error(`Get coupons error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to fetch coupons' });
    }
  });

  // Validate Coupon
  router.get('/coupons/validate', authenticateJWT, [
    query('code').notEmpty().trim().withMessage('Coupon code is required'),
  ], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Coupon validation errors:', errors.array());
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    const { code } = req.query;
    try {
      const coupon = await Coupon.findOne({ where: { code } });
      if (!coupon) {
        return res.status(404).json({ message: 'Invalid coupon code' });
      }
      res.status(200).json({ code: coupon.code, discount: coupon.discount });
    } catch (error) {
      console.error(`Validate coupon error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to validate coupon' });
    }
  });

  // Place Order
  router.post('/orders', authenticateJWT, orderValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Order validation errors:', errors.array());
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    const { addressId, items, couponCode, paymentMethod, deliveryCost } = req.body;
    console.log('Order request payload:', req.body);
    try {
      const address = await Address.findOne({ where: { id: addressId, userId: req.userId } });
      if (!address) {
        return res.status(404).json({ message: 'Address not found' });
      }
      for (const item of items) {
        const menuItem = await MenuItem.findByPk(item.itemId);
        if (!menuItem) {
          return res.status(404).json({ message: `Menu item ${item.itemId} not found` });
        }
      }
      let total = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
      let discount = 0;
      if (couponCode) {
        const coupon = await Coupon.findOne({ where: { code: couponCode } });
        if (!coupon) {
          return res.status(404).json({ message: 'Invalid coupon code' });
        }
        discount = (total * coupon.discount) / 100;
      }
      total = Math.max(0, total - discount + (deliveryCost || 0));
      const order = await Order.create({
        userId: req.userId,
        addressId,
        items: items.map(item => ({
          ...item,
          image: item.image || '/Uploads/default-menu.png',
        })),
        total,
        couponCode,
        paymentMethod,
        deliveryCost: deliveryCost || 0,
        status: 'pending',
        date: new Date(),
      });
      await Cart.destroy({ where: { userId: req.userId } });
      console.log(`Order placed: ${order.id}`);
      res.status(201).json({
        _id: order.id,
        items: order.items,
        total: parseFloat(order.total),
        deliveryCost: parseFloat(order.deliveryCost),
        status: order.status,
        address: { _id: address.id, ...address.toJSON() },
      });
    } catch (error) {
      console.error(`Place order error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to place order' });
    }
  });

  // Get Orders
  router.get('/orders', authenticateJWT, async (req, res) => {
    try {
      const orders = await Order.findAll({
        where: { userId: req.userId },
        include: [
          { model: Address, attributes: ['id', 'fullName', 'mobile', 'houseNo', 'location', 'landmark'] },
        ],
        order: [['date', 'DESC']],
      });
      const formattedOrders = orders.map(order => ({
        _id: order.id,
        date: order.date ? order.date.toISOString().split('T')[0] : new Date().toISOString().split('T')[0],
        items: order.items.map(item => ({
          ...item,
          image: item.image || '/Uploads/default-menu.png',
        })),
        itemNames: order.items.map(item => item.name).join(', '),
        total: parseFloat(order.total) || 0,
        deliveryCost: parseFloat(order.deliveryCost) || 0,
        status: order.status || 'pending',
        cancelReason: order.cancelReason || '',
        address: order.Address ? { _id: order.Address.id, ...order.Address.toJSON() } : null,
      }));
      res.status(200).json(formattedOrders);
    } catch (error) {
      console.error(`Get orders error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to fetch orders' });
    }
  });

  // Cancel Order
  router.put('/orders/:id/cancel', authenticateJWT, cancelOrderValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Cancel order validation errors:', errors.array());
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    const { reason } = req.body;
    try {
      const order = await Order.findOne({ where: { id: req.params.id, userId: req.userId } });
      if (!order) {
        return res.status(404).json({ message: 'Order not found' });
      }
      if (!['pending', 'confirmed'].includes(order.status)) {
        return res.status(400).json({ message: 'Order cannot be cancelled' });
      }
      await order.update({ status: 'cancelled', cancelReason: reason });
      console.log(`Order cancelled: ${order.id}`);
      res.status(200).json({ message: 'Order cancelled successfully' });
    } catch (error) {
      console.error(`Cancel order error for user ${req.userId}, order ${req.params.id}:`, error.message);
      res.status(500).json({ message: 'Failed to cancel order' });
    }
  });

  // Clear Order History
  router.delete('/orders/clear', authenticateJWT, async (req, res) => {
    try {
      await Order.destroy({ where: { userId: req.userId } });
      console.log(`Order history cleared for user: ${req.userId}`);
      res.status(200).json({ message: 'Order history cleared' });
    } catch (error) {
      console.error(`Clear orders error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to clear order history' });
    }
  });

  // Track/Update Order Status
  router.put('/orders/:id/track', authenticateJWT, async (req, res) => {
    try {
      const order = await Order.findOne({ where: { id: req.params.id, userId: req.userId } });
      if (!order) {
        return res.status(404).json({ message: 'Order not found' });
      }
      const statusOrder = ['pending', 'confirmed', 'shipped', 'delivered'];
      const currentIndex = statusOrder.indexOf(order.status);
      if (currentIndex < statusOrder.length - 1 && order.status !== 'cancelled') {
        await order.update({ status: statusOrder[currentIndex + 1] });
      }
      console.log(`Order status updated: ${order.id} to ${order.status}`);
      res.status(200).json({ _id: order.id, status: order.status });
    } catch (error) {
      console.error(`Track order error for user ${req.userId}, order ${req.params.id}:`, error.message);
      res.status(500).json({ message: 'Failed to track order' });
    }
  });

  // Get Restaurant Status
  router.get('/status', async (req, res) => {
    try {
      const status = await RestaurantStatus.findOne({ order: [['id', 'DESC']] });
      res.status(200).json({ status: status ? status.status : 'open' });
    } catch (error) {
      console.error('Error fetching status:', error.message);
      res.status(500).json({ message: 'Failed to fetch restaurant status' });
    }
  });

  // Error handling middleware
  router.use((err, req, res, next) => {
    console.error(`Error in route ${req.method} ${req.path}:`, err.message);
    if (err.message.includes('Only JPEG or PNG images are allowed')) {
      return res.status(400).json({ message: err.message });
    }
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'File size exceeds 2MB limit' });
    }
    res.status(500).json({
      message: process.env.NODE_ENV === 'development' ? err.message : 'Server error',
    });
  });

  return router;
};
