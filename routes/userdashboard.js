const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const path = require('path');
const { body, query, validationResult } = require('express-validator');
const { Op } = require('sequelize');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');

// Ensure upload directory exists
const uploadDir = path.join(__dirname, '../public/Uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer storage configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const randomName = crypto.randomBytes(16).toString('hex');
    cb(null, `${randomName}${ext}`);
  },
});

// Multer file filter for images
const fileFilter = (req, file, cb) => {
  const allowedTypes = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'image/bmp',
    'image/tiff',
  ];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Only JPEG, PNG, GIF, WebP, BMP, and TIFF images are allowed'), false);
  }
};

// Multer middleware for single image upload
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter,
}).single('image');

// JWT authentication middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    console.log('No token provided in request');
    return res.status(401).json({ message: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (error) {
    console.log('JWT verification error:', error.message);
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// Validation rules
const profileValidation = [
  body('name').notEmpty().trim().withMessage('Name is required'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('image').optional().isString().withMessage('Valid image path is required'),
];

const addressValidation = [
  body('fullName').notEmpty().trim().withMessage('Full name is required'),
  body('mobile').matches(/^\d{10}$/).withMessage('Valid 10-digit mobile number is required'),
  body('houseNo').notEmpty().trim().withMessage('House/Flat number is required'),
  body('location').notEmpty().trim().withMessage('Location is required'),
  body('landmark').optional().trim(),
];

const favoriteValidation = [
  body('itemId').notEmpty().withMessage('Item ID is required'),
  body('name').notEmpty().trim().withMessage('Item name is required'),
  body('image').optional().isString().withMessage('Valid image path is required'),
];

const cartValidation = [
  body('itemId').notEmpty().withMessage('Item ID is required'),
  body('name').notEmpty().trim().withMessage('Item name is required'),
  body('price').isFloat({ min: 0 }).withMessage('Valid price is required'),
  body('image').optional().isString().withMessage('Valid image path is required'),
  body('quantity').isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),
];

const cartUpdateValidation = [
  body('quantity').isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),
];

const orderValidation = [
  body('addressId').isInt().withMessage('Valid address ID is required'),
  body('items').isArray({ min: 1 }).withMessage('Items array is required'),
  body('items.*.itemId').notEmpty().withMessage('Item ID is required'),
  body('items.*.name').notEmpty().trim().withMessage('Item name is required'),
  body('items.*.price').isFloat({ min: 0 }).withMessage('Valid price is required'),
  body('items.*.quantity').isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),
  body('couponCode').optional().isString().trim(),
  body('paymentMethod').isIn(['cod', 'online']).withMessage('Invalid payment method'),
  body('deliveryCost').isFloat({ min: 0 }).withMessage('Valid delivery cost is required'),
];

const cancelOrderValidation = [
  body('reason').notEmpty().trim().withMessage('Cancellation reason is required'),
];

module.exports = (User, Cart, MenuItem, RestaurantStatus, Address, Favorite, Coupon, Order) => {
  /**
   * @route GET /userdashboard
   * @desc Serve user dashboard HTML
   * @access Public
   */
  router.get('/userdashboard', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/userdashboard.html'));
  });

  /**
   * @route GET /api/menu
   * @desc Fetch all menu items
   * @access Public
   */
  router.get('/menu', async (req, res) => {
    try {
      const menuItems = await MenuItem.findAll();
      res.status(200).json(menuItems);
    } catch (error) {
      console.error('Error fetching menu:', error.message);
      res.status(500).json({ message: 'Failed to fetch menu' });
    }
  });

  /**
   * @route GET /api/status
   * @desc Fetch restaurant status
   * @access Public
   */
  router.get('/status', async (req, res) => {
    try {
      const status = await RestaurantStatus.findOne({ order: [['id', 'DESC']] });
      res.status(200).json({ status: status ? status.status : 'open' });
    } catch (error) {
      console.error('Error fetching restaurant status:', error.message);
      res.status(500).json({ message: 'Failed to fetch restaurant status' });
    }
  });

  /**
   * @route GET /api/profile
   * @desc Fetch user profile
   * @access Private
   */
  router.get('/profile', authenticateJWT, async (req, res) => {
    try {
      const user = await User.findByPk(req.userId, {
        attributes: ['id', 'name', 'email', 'phone', 'image'],
      });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      res.status(200).json({
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        image: user.image || '/Uploads/default-profile.png',
      });
    } catch (error) {
      console.error(`Profile fetch error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to fetch profile' });
    }
  });

  /**
   * @route PUT /api/profile
   * @desc Update user profile with optional image upload
   * @access Private
   */
  router.put('/profile', authenticateJWT, upload, profileValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    try {
      const { name, email } = req.body;
      let imagePath = req.body.image; // Fallback to string image if provided
      const user = await User.findByPk(req.userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      const existingEmail = await User.findOne({
        where: { email: email.toLowerCase(), id: { [Op.ne]: req.userId } },
      });
      if (existingEmail) {
        return res.status(400).json({ message: 'Email already in use' });
      }
      // Handle uploaded file
      if (req.file) {
        // Delete old image if it exists and isn't default
        if (user.image && user.image !== '/Uploads/default-profile.png') {
          const oldImagePath = path.join(__dirname, '../public', user.image);
          if (fs.existsSync(oldImagePath)) {
            fs.unlinkSync(oldImagePath);
          }
        }
        imagePath = `/Uploads/${req.file.filename}`;
      }
      await user.update({
        name,
        email: email.toLowerCase(),
        image: imagePath || user.image || '/Uploads/default-profile.png',
      });
      res.status(200).json({
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        image: user.image,
      });
    } catch (error) {
      console.error(`Profile update error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to update profile' });
    }
  });

  /**
   * @route GET /api/addresses
   * @desc Fetch all user addresses
   * @access Private
   */
  router.get('/addresses', authenticateJWT, async (req, res) => {
    try {
      const addresses = await Address.findAll({ where: { userId: req.userId } });
      res.status(200).json(addresses);
    } catch (error) {
      console.error(`Addresses fetch error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to fetch addresses' });
    }
  });

  /**
   * @route GET /api/addresses/:id
   * @desc Fetch a single address
   * @access Private
   */
  router.get('/addresses/:id', authenticateJWT, async (req, res) => {
    try {
      const address = await Address.findOne({
        where: { id: req.params.id, userId: req.userId },
      });
      if (!address) {
        return res.status(404).json({ message: 'Address not found' });
      }
      res.status(200).json(address);
    } catch (error) {
      console.error(`Address fetch error for user ${req.userId}, address ${req.params.id}:`, error.message);
      res.status(500).json({ message: 'Failed to fetch address' });
    }
  });

  /**
   * @route POST /api/addresses
   * @desc Add a new address
   * @access Private
   */
  router.post('/addresses', authenticateJWT, addressValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    try {
      const { fullName, mobile, houseNo, location, landmark } = req.body;
      const address = await Address.create({
        userId: req.userId,
        fullName,
        mobile,
        houseNo,
        location,
        landmark,
      });
      res.status(201).json(address);
    } catch (error) {
      console.error(`Add address error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to add address' });
    }
  });

  /**
   * @route PUT /api/addresses/:id
   * @desc Update an existing address
   * @access Private
   */
  router.put('/addresses/:id', authenticateJWT, addressValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    try {
      const { fullName, mobile, houseNo, location, landmark } = req.body;
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
      res.status(200).json(address);
    } catch (error) {
      console.error(`Update address error for user ${req.userId}, address ${req.params.id}:`, error.message);
      res.status(500).json({ message: 'Failed to update address' });
    }
  });

  /**
   * @route DELETE /api/addresses/:id
   * @desc Delete an address
   * @access Private
   */
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

  /**
   * @route GET /api/favorites
   * @desc Fetch all user favorites
   * @access Private
   */
  router.get('/favorites', authenticateJWT, async (req, res) => {
    try {
      const favorites = await Favorite.findAll({ where: { userId: req.userId } });
      res.status(200).json(favorites);
    } catch (error) {
      console.error(`Favorites fetch error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to fetch favorites' });
    }
  });

  /**
   * @route POST /api/favorites
   * @desc Add an item to favorites
   * @access Private
   */
  router.post('/favorites', authenticateJWT, favoriteValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    try {
      const { itemId, name, image } = req.body;
      const menuItem = await MenuItem.findByPk(itemId);
      if (!menuItem) {
        return res.status(404).json({ message: 'Menu item not found' });
      }
      const [favorite, created] = await Favorite.findOrCreate({
        where: { userId: req.userId, itemId },
        defaults: {
          userId: req.userId,
          itemId,
          name,
          price: menuItem.price,
          image: image || menuItem.image || '/Uploads/default-menu.png',
        },
      });
      if (!created) {
        return res.status(400).json({ message: 'Item already in favorites' });
      }
      res.status(201).json(favorite);
    } catch (error) {
      console.error(`Add favorite error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to add favorite' });
    }
  });

  /**
   * @route DELETE /api/favorites/:id
   * @desc Remove an item from favorites
   * @access Private
   */
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
      console.error(`Delete favorite error for user ${req.userId}, item ${req.params.id}:`, error.message);
      res.status(500).json({ message: 'Failed to remove favorite' });
    }
  });

  /**
   * @route GET /api/coupons
   * @desc Fetch all coupons
   * @access Private
   */
  router.get('/coupons', authenticateJWT, async (req, res) => {
    try {
      const coupons = await Coupon.findAll();
      res.status(200).json(coupons);
    } catch (error) {
      console.error(`Coupons fetch error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to fetch coupons' });
    }
  });

  /**
   * @route GET /api/coupons/validate
   * @desc Validate a coupon code
   * @access Private
   */
  router.get('/coupons/validate', authenticateJWT, [
    query('code').notEmpty().trim().withMessage('Coupon code is required'),
  ], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    try {
      const { code } = req.query;
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

  /**
   * @route GET /api/cart
   * @desc Fetch all cart items
   * @access Private
   */
  router.get('/cart', authenticateJWT, async (req, res) => {
    try {
      const cartItems = await Cart.findAll({ where: { userId: req.userId } });
      res.status(200).json(cartItems);
    } catch (error) {
      console.error(`Cart fetch error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to fetch cart' });
    }
  });

  /**
   * @route POST /api/cart
   * @desc Add an item to cart
   * @access Private
   */
  router.post('/cart', authenticateJWT, cartValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    try {
      const { itemId, name, price, image, quantity } = req.body;
      const menuItem = await MenuItem.findByPk(itemId);
      if (!menuItem) {
        return res.status(404).json({ message: 'Menu item not found' });
      }
      const [cartItem, created] = await Cart.findOrCreate({
        where: { userId: req.userId, itemId },
        defaults: {
          userId: req.userId,
          itemId,
          name,
          price: parseFloat(price),
          image: image || menuItem.image || '/Uploads/default-menu.png',
          quantity,
        },
      });
      if (!created) {
        cartItem.quantity += quantity;
        await cartItem.save();
      }
      res.status(201).json(cartItem);
    } catch (error) {
      console.error(`Add to cart error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to add to cart' });
    }
  });

  /**
   * @route PUT /api/cart/:itemId
   * @desc Update cart item quantity
   * @access Private
   */
  router.put('/cart/:itemId', authenticateJWT, cartUpdateValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    try {
      const { quantity } = req.body;
      const cartItem = await Cart.findOne({
        where: { itemId: req.params.itemId, userId: req.userId },
      });
      if (!cartItem) {
        return res.status(404).json({ message: 'Cart item not found' });
      }
      await cartItem.update({ quantity });
      res.status(200).json(cartItem);
    } catch (error) {
      console.error(`Update cart error for user ${req.userId}, item ${req.params.itemId}:`, error.message);
      res.status(500).json({ message: 'Failed to update cart' });
    }
  });

  /**
   * @route DELETE /api/cart/:itemId
   * @desc Remove an item from cart
   * @access Private
   */
  router.delete('/cart/:itemId', authenticateJWT, async (req, res) => {
    try {
      const cartItem = await Cart.findOne({
        where: { itemId: req.params.itemId, userId: req.userId },
      });
      if (!cartItem) {
        return res.status(404).json({ message: 'Cart item not found' });
      }
      await cartItem.destroy();
      res.status(200).json({ message: 'Item removed from cart' });
    } catch (error) {
      console.error(`Delete cart item error for user ${req.userId}, item ${req.params.itemId}:`, error.message);
      res.status(500).json({ message: 'Failed to remove item' });
    }
  });

  /**
   * @route POST /api/orders
   * @desc Place a new order
   * @access Private
   */
  router.post('/orders', authenticateJWT, orderValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    try {
      const { addressId, items, couponCode, paymentMethod, deliveryCost } = req.body;
      const address = await Address.findOne({ where: { id: addressId, userId: req.userId } });
      if (!address) {
        return res.status(404).json({ message: 'Address not found' });
      }
      for (const item of items) {
        const menuItem = await MenuItem.findByPk(item.itemId);
        if (!menuItem) {
          return res.status(404).json({ message: `Menu item ${item.name} not found` });
        }
      }
      let discount = 0;
      if (couponCode) {
        const coupon = await Coupon.findOne({ where: { code: couponCode } });
        if (!coupon) {
          return res.status(404).json({ message: 'Invalid coupon code' });
        }
        discount = coupon.discount;
      }
      let total = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
      total = total - (total * discount / 100) + (deliveryCost || 0);
      const orderDate = new Date();
      console.log(`Creating order for user ${req.userId} with date: ${orderDate.toISOString()}`);
      const order = await Order.create({
        userId: req.userId,
        addressId,
        items,
        total,
        couponCode,
        paymentMethod,
        deliveryCost: deliveryCost || 0,
        status: 'pending',
        date: orderDate,
      });
      await Cart.destroy({ where: { userId: req.userId } });
      res.status(201).json({ message: 'Order placed successfully', order });
    } catch (error) {
      console.error(`Place order error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to place order' });
    }
  });

  /**
   * @route GET /api/orders
   * @desc Fetch all user orders
   * @access Private
   */
  router.get('/orders', authenticateJWT, async (req, res) => {
    try {
      const orders = await Order.findAll({
        where: { userId: req.userId },
        attributes: ['id', 'date', 'total', 'status', 'couponCode', 'paymentMethod', 'deliveryCost', 'cancelReason'],
        include: [
          {
            model: Address,
            attributes: ['id', 'fullName', 'mobile', 'houseNo', 'location', 'landmark'],
          },
        ],
        order: [['date', 'DESC']],
      });
      const formattedOrders = orders.map(order => ({
        id: order.id,
        date: order.date ? order.date.toISOString() : new Date().toISOString(),
        items: order.items ? order.items.map(item => item.name) : [],
        total: order.total || 0,
        status: order.status,
        delivery: order.deliveryCost === 0 || order.deliveryCost === null ? 'Free' : `₹${order.deliveryCost.toFixed(2)}`,
        cancelReason: order.cancelReason || '',
        address: order.Address || null,
      }));
      res.status(200).json(formattedOrders);
    } catch (error) {
      console.error(`Orders fetch error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to fetch orders' });
    }
  });

  /**
   * @route PUT /api/orders/:id/track
   * @desc Track or update order status
   * @access Private
   */
  router.put('/orders/:id/track', authenticateJWT, async (req, res) => {
    try {
      const order = await Order.findOne({ where: { id: req.params.id, userId: req.userId } });
      if (!order) {
        return res.status(404).json({ message: 'Order not found' });
      }
      const statuses = ['pending', 'confirmed', 'shipped', 'delivered'];
      const currentIndex = statuses.indexOf(order.status);
      if (currentIndex < statuses.length - 1 && order.status !== 'cancelled') {
        await order.update({ status: statuses[currentIndex + 1] });
      }
      res.status(200).json({ status: order.status });
    } catch (error) {
      console.error(`Track order error for user ${req.userId}, order ${req.params.id}:`, error.message);
      res.status(500).json({ message: 'Failed to track order' });
    }
  });

  /**
   * @route PUT /api/orders/:id/cancel
   * @desc Cancel an order with reason
   * @access Private
   */
  router.put('/orders/:id/cancel', authenticateJWT, cancelOrderValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }
    try {
      const { reason } = req.body;
      const order = await Order.findOne({ where: { id: req.params.id, userId: req.userId } });
      if (!order) {
        return res.status(404).json({ message: 'Order not found' });
      }
      if (!['pending', 'confirmed'].includes(order.status)) {
        return res.status(400).json({ message: 'Order cannot be cancelled' });
      }
      await order.update({ status: 'cancelled', cancelReason: reason });
      res.status(200).json({ message: 'Order cancelled' });
    } catch (error) {
      console.error(`Cancel order error for user ${req.userId}, order ${req.params.id}:`, error.message);
      res.status(500).json({ message: 'Failed to cancel order' });
    }
  });

  /**
   * @route DELETE /api/orders/clear
   * @desc Clear all user orders
   * @access Private
   */
  router.delete('/orders/clear', authenticateJWT, async (req, res) => {
    try {
      await Order.destroy({ where: { userId: req.userId } });
      res.status(200).json({ message: 'Order history cleared' });
    } catch (error) {
      console.error(`Clear order history error for user ${req.userId}:`, error.message);
      res.status(500).json({ message: 'Failed to clear order history' });
    }
  });

  // Error handling middleware
  router.use((err, req, res, next) => {
    console.error(`Error in route ${req.method} ${req.path}:`, err.message);
    if (err.message.includes('Only JPEG, PNG, GIF, WebP, BMP, and TIFF images are allowed')) {
      return res.status(400).json({ message: err.message });
    }
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'File size exceeds 5MB limit' });
    }
    res.status(500).json({
      message: process.env.NODE_ENV === 'development' ? err.message : 'Server error',
    });
  });

  return router;
};