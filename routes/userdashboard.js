const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const path = require('path');
const { body, validationResult } = require('express-validator');

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

const profileValidation = [
  body('name').notEmpty().trim().withMessage('Name is required'),
];

const addressValidation = [
  body('fullName').notEmpty().trim().withMessage('Full name is required'),
  body('mobile').isMobilePhone().withMessage('Valid mobile number is required'),
  body('houseNo').notEmpty().trim().withMessage('House/Flat number is required'),
  body('location').notEmpty().trim().withMessage('Location is required'),
  body('landmark').optional().trim(),
];

const favoriteValidation = [
  body('id').notEmpty().withMessage('Item ID is required'),
  body('name').notEmpty().trim().withMessage('Item name is required'),
  body('image').optional().isURL().withMessage('Valid image URL is required'),
];

const cartValidation = [
  body('id').notEmpty().withMessage('Item ID is required'),
  body('name').notEmpty().trim().withMessage('Item name is required'),
  body('price').isFloat({ min: 0 }).withMessage('Valid price is required'),
  body('image').optional().isURL().withMessage('Valid image URL is required'),
  body('quantity').optional().isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),
];

const cartUpdateValidation = [
  body('quantity').isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),
];

const orderValidation = [
  body('addressId').isInt().withMessage('Valid address ID is required'),
  body('items').isArray({ min: 1 }).withMessage('Items array is required'),
  body('couponCode').optional().isString().trim(),
  body('paymentMethod').isIn(['cod']).withMessage('Invalid payment method'),
  body('deliveryCost').isFloat({ min: 0 }).withMessage('Valid delivery cost is required'),
];

module.exports = (sequelize, User, Cart, MenuItem, Address, Favorite, Coupon, Order) => {
  router.get('/userdashboard', (req, res) => {
    res.sendFile(path.join(__dirname, '../public/userdashboard.html'));
  });

  router.get('/api/profile', authenticateJWT, async (req, res) => {
    try {
      const user = await User.findByPk(req.userId, { attributes: ['id', 'name', 'email', 'phone', 'image'] });
      if (!user) return res.status(404).json({ message: 'User not found' });
      res.json(user);
    } catch (error) {
      console.error('Profile error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.put('/api/profile', authenticateJWT, profileValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    try {
      const { name, image } = req.body;
      const user = await User.findByPk(req.userId);
      if (!user) return res.status(404).json({ message: 'User not found' });
      user.name = name;
      if (image) user.image = image;
      await user.save();
      res.json({ id: user.id, name: user.name, email: user.email, phone: user.phone, image: user.image });
    } catch (error) {
      console.error('Update profile error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.get('/api/addresses', authenticateJWT, async (req, res) => {
    try {
      const addresses = await Address.findAll({ where: { userId: req.userId } });
      res.json(addresses);
    } catch (error) {
      console.error('Addresses error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.post('/api/addresses', authenticateJWT, addressValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

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
      console.error('Add address error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.delete('/api/addresses/:id', authenticateJWT, async (req, res) => {
    try {
      const address = await Address.findOne({ where: { id: req.params.id, userId: req.userId } });
      if (!address) return res.status(404).json({ message: 'Address not found' });
      await address.destroy();
      res.json({ message: 'Address deleted' });
    } catch (error) {
      console.error('Delete address error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.get('/api/favorites', authenticateJWT, async (req, res) => {
    try {
      const favorites = await Favorite.findAll({ where: { userId: req.userId } });
      res.json(favorites);
    } catch (error) {
      console.error('Favorites error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.post('/api/favorites', authenticateJWT, favoriteValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    try {
      const { id: itemId, name, image } = req.body;
      const menuItem = await MenuItem.findByPk(itemId);
      if (!menuItem) return res.status(400).json({ message: 'Menu item not found' });
      const favorite = await Favorite.create({
        userId: req.userId,
        itemId,
        name,
        image,
      });
      res.status(201).json(favorite);
    } catch (error) {
      console.error('Add favorite error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.delete('/api/favorites/:id', authenticateJWT, async (req, res) => {
    try {
      const favorite = await Favorite.findOne({ where: { itemId: req.params.id, userId: req.userId } });
      if (!favorite) return res.status(404).json({ message: 'Favorite not found' });
      await favorite.destroy();
      res.json({ message: 'Favorite removed' });
    } catch (error) {
      console.error('Delete favorite error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.get('/api/coupons', authenticateJWT, async (req, res) => {
    try {
      const coupons = await Coupon.findAll();
      res.json(coupons);
    } catch (error) {
      console.error('Coupons error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.get('/api/coupons/validate', authenticateJWT, async (req, res) => {
    try {
      const { code } = req.query;
      if (!code) return res.status(400).json({ message: 'Coupon code required' });
      const coupon = await Coupon.findOne({ where: { code } });
      if (!coupon) return res.status(400).json({ message: 'Invalid coupon code' });
      res.json({ code: coupon.code, discount: coupon.discount });
    } catch (error) {
      console.error('Validate coupon error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.post('/api/cart', authenticateJWT, cartValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    try {
      const { id: itemId, name, price, image, quantity = 1 } = req.body;
      const menuItem = await MenuItem.findByPk(itemId);
      if (!menuItem) return res.status(400).json({ message: 'Menu item not found' });
      const existingCartItem = await Cart.findOne({ where: { userId: req.userId, itemId } });
      if (existingCartItem) {
        existingCartItem.quantity += quantity;
        await existingCartItem.save();
        return res.json(existingCartItem);
      }
      const cartItem = await Cart.create({
        userId: req.userId,
        itemId,
        name,
        price,
        image,
        quantity,
      });
      res.status(201).json(cartItem);
    } catch (error) {
      console.error('Add to cart error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.get('/api/cart', authenticateJWT, async (req, res) => {
    try {
      const cartItems = await Cart.findAll({ where: { userId: req.userId } });
      res.json(cartItems);
    } catch (error) {
      console.error('Cart error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.put('/api/cart/:id', authenticateJWT, cartUpdateValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    try {
      const { quantity } = req.body;
      const cartItem = await Cart.findOne({ where: { itemId: req.params.id, userId: req.userId } });
      if (!cartItem) return res.status(404).json({ message: 'Cart item not found' });
      cartItem.quantity = quantity;
      await cartItem.save();
      res.json(cartItem);
    } catch (error) {
      console.error('Update cart error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.delete('/api/cart/:id', authenticateJWT, async (req, res) => {
    try {
      const cartItem = await Cart.findOne({ where: { itemId: req.params.id, userId: req.userId } });
      if (!cartItem) return res.status(404).json({ message: 'Cart item not found' });
      await cartItem.destroy();
      res.json({ message: 'Item removed from cart' });
    } catch (error) {
      console.error('Delete cart item error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.post('/api/orders', authenticateJWT, orderValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    try {
      const { addressId, items, couponCode, paymentMethod, deliveryCost } = req.body;
      const address = await Address.findOne({ where: { id: addressId, userId: req.userId } });
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
        userId: req.userId,
        addressId,
        items,
        total,
        couponCode,
        paymentMethod,
        deliveryCost,
        status: 'pending',
      });

      await Cart.destroy({ where: { userId: req.userId } });
      res.status(201).json(order);
    } catch (error) {
      console.error('Place order error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.get('/api/orders', authenticateJWT, async (req, res) => {
    try {
      const orders = await Order.findAll({
        where: { userId: req.userId },
        attributes: ['id', 'date', 'total', 'status', 'couponCode', 'paymentMethod', 'deliveryCost'],
        include: [
          {
            model: Address,
            attributes: ['fullName', 'mobile', 'houseNo', 'location', 'landmark'],
          },
        ],
      });
      const formattedOrders = orders.map(order => ({
        id: order.id,
        date: order.date.toISOString().split('T')[0],
        items: order.items.map(item => item.name),
        total: order.total,
        status: order.status,
        delivery: order.deliveryCost === 0 ? 'Free' : `₹${order.deliveryCost}`,
      }));
      res.json(formattedOrders);
    } catch (error) {
      console.error('Order history error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.put('/api/orders/:id/track', authenticateJWT, async (req, res) => {
    try {
      const order = await Order.findOne({ where: { id: req.params.id, userId: req.userId } });
      if (!order) return res.status(404).json({ message: 'Order not found' });
      const statuses = ['pending', 'confirmed', 'shipped', 'delivered'];
      const currentIndex = statuses.indexOf(order.status);
      if (currentIndex < statuses.length - 1) {
        order.status = statuses[currentIndex + 1];
        await order.save();
      }
      res.json({ status: order.status });
    } catch (error) {
      console.error('Track order error:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  router.use((err, req, res, next) => {
    console.error('Error:', err.message);
    res.status(500).json({ message: 'Server error' });
  });

  return router;
};