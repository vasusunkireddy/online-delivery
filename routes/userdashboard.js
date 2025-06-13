const express = require('express');
const router = express.Router();
const path = require('path');
const jwt = require('jsonwebtoken');

// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded; // Attach user data to request
      next();
    } catch (error) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }
  } else {
    return res.status(401).json({ message: 'Authorization header missing' });
  }
};

module.exports = (sequelize, User, Cart, MenuItem, Address, Favorite, Coupon, Order) => {
  // Serve userdashboard.html
  router.get('/userdashboard', authenticateJWT, (req, res) => {
    res.sendFile(path.join(__dirname, '../userdashboard.html')); // Adjust path if html is in a different folder
  });

  // Get user profile
  router.get('/api/profile', authenticateJWT, async (req, res) => {
    try {
      const user = await User.findByPk(req.user.id, {
        attributes: ['id', 'name', 'email', 'phone', 'image'],
      });
      if (!user) return res.status(404).json({ message: 'User not found' });
      res.json({
        id: user.id,
        name: user.name,
        email: user.email,
        mobile: user.phone,
        image: user.image || 'https://via.placeholder.com/48',
      });
    } catch (error) {
      console.error('Error fetching profile:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Update user profile
  router.put('/api/profile', authenticateJWT, async (req, res) => {
    try {
      const { name } = req.body;
      if (!name) return res.status(400).json({ message: 'Name is required' });

      const user = await User.findByPk(req.user.id);
      if (!user) return res.status(404).json({ message: 'User not found' });

      user.name = name;
      // Handle image upload if provided (assuming you have a file upload middleware)
      if (req.body.image) {
        user.image = req.body.image; // Replace with actual file upload logic
      }
      await user.save();

      res.json({
        id: user.id,
        name: user.name,
        email: user.email,
        mobile: user.phone,
        image: user.image || 'https://via.placeholder.com/48',
      });
    } catch (error) {
      console.error('Error updating profile:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Get all addresses
  router.get('/api/addresses', authenticateJWT, async (req, res) => {
    try {
      const addresses = await Address.findAll({ where: { userId: req.user.id } });
      res.json(addresses.map(addr => ({
        id: addr.id,
        fullName: addr.fullName,
        mobile: addr.mobile,
        houseNo: addr.houseNo,
        location: addr.location,
        landmark: addr.landmark,
      })));
    } catch (error) {
      console.error('Error fetching addresses:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Add new address
  router.post('/api/addresses', authenticateJWT, async (req, res) => {
    try {
      const { fullName, mobile, houseNo, location, landmark } = req.body;
      if (!fullName || !mobile || !houseNo || !location) {
        return res.status(400).json({ message: 'Required fields missing' });
      }

      const address = await Address.create({
        userId: req.user.id,
        fullName,
        mobile,
        houseNo,
        location,
        landmark,
      });
      res.status(201).json(address);
    } catch (error) {
      console.error('Error adding address:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Delete address
  router.delete('/api/addresses/:id', authenticateJWT, async (req, res) => {
    try {
      const address = await Address.findOne({
        where: { id: req.params.id, userId: req.user.id },
      });
      if (!address) return res.status(404).json({ message: 'Address not found' });

      await address.destroy();
      res.json({ message: 'Address deleted' });
    } catch (error) {
      console.error('Error deleting address:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Get menu items
  router.get('/api/menu', authenticateJWT, async (req, res) => {
    try {
      const menuItems = await MenuItem.findAll();
      res.json(menuItems);
    } catch (error) {
      console.error('Error fetching menu:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Get coupons
  router.get('/api/coupons', authenticateJWT, async (req, res) => {
    try {
      const coupons = await Coupon.findAll();
      res.json(coupons);
    } catch (error) {
      console.error('Error fetching coupons:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Validate coupon
  router.get('/api/coupons/validate', authenticateJWT, async (req, res) => {
    try {
      const { code } = req.query;
      if (!code) return res.status(400).json({ message: 'Coupon code required' });

      const coupon = await Coupon.findOne({ where: { code } });
      if (!coupon) return res.status(404).json({ message: 'Invalid coupon code' });

      res.json({ code: coupon.code, discount: coupon.discount });
    } catch (error) {
      console.error('Error validating coupon:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Get favorites
  router.get('/api/favorites', authenticateJWT, async (req, res) => {
    try {
      const favorites = await Favorite.findAll({ where: { userId: req.user.id } });
      res.json(favorites);
    } catch (error) {
      console.error('Error fetching favorites:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Add to favorites
  router.post('/api/favorites', authenticateJWT, async (req, res) => {
    try {
      const { id, name, image } = req.body;
      if (!id || !name) return res.status(400).json({ message: 'Item ID and name required' });

      const favorite = await Favorite.create({
        userId: req.user.id,
        itemId: id,
        name,
        image,
      });
      res.status(201).json(favorite);
    } catch (error) {
      console.error('Error adding favorite:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Remove from favorites
  router.delete('/api/favorites/:id', authenticateJWT, async (req, res) => {
    try {
      const favorite = await Favorite.findOne({
        where: { itemId: req.params.id, userId: req.user.id },
      });
      if (!favorite) return res.status(404).json({ message: 'Favorite not found' });

      await favorite.destroy();
      res.json({ message: 'Favorite removed' });
    } catch (error) {
      console.error('Error removing favorite:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Get cart
  router.get('/api/cart', authenticateJWT, async (req, res) => {
    try {
      const cartItems = await Cart.findAll({ where: { userId: req.user.id } });
      res.json(cartItems);
    } catch (error) {
      console.error('Error fetching cart:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Add to cart
  router.post('/api/cart', authenticateJWT, async (req, res) => {
    try {
      const { id, name, price, image, quantity = 1 } = req.body;
      if (!id || !name || !price) {
        return res.status(400).json({ message: 'Item ID, name, and price required' });
      }

      const existingItem = await Cart.findOne({
        where: { userId: req.user.id, itemId: id },
      });

      if (existingItem) {
        existingItem.quantity += quantity;
        await existingItem.save();
        res.json(existingItem);
      } else {
        const cartItem = await Cart.create({
          userId: req.user.id,
          itemId: id,
          name,
          price,
          image,
          quantity,
        });
        res.status(201).json(cartItem);
      }
    } catch (error) {
      console.error('Error adding to cart:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Update cart quantity
  router.put('/api/cart/:id', authenticateJWT, async (req, res) => {
    try {
      const { quantity } = req.body;
      if (!quantity || quantity < 1) {
        return res.status(400).json({ message: 'Valid quantity required' });
      }

      const cartItem = await Cart.findOne({
        where: { itemId: req.params.id, userId: req.user.id },
      });
      if (!cartItem) return res.status(404).json({ message: 'Cart item not found' });

      cartItem.quantity = quantity;
      await cartItem.save();
      res.json(cartItem);
    } catch (error) {
      console.error('Error updating cart:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Remove from cart
  router.delete('/api/cart/:id', authenticateJWT, async (req, res) => {
    try {
      const cartItem = await Cart.findOne({
        where: { itemId: req.params.id, userId: req.user.id },
      });
      if (!cartItem) return res.status(404).json({ message: 'Cart item not found' });

      await cartItem.destroy();
      res.json({ message: 'Item removed from cart' });
    } catch (error) {
      console.error('Error removing from cart:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Place order
  router.post('/api/orders', authenticateJWT, async (req, res) => {
    try {
      const { addressId, items, couponCode, paymentMethod, deliveryCost } = req.body;
      if (!addressId || !items || items.length === 0 || !paymentMethod) {
        return res.status(400).json({ message: 'Address, items, and payment method required' });
      }

      const address = await Address.findOne({
        where: { id: addressId, userId: req.user.id },
      });
      if (!address) return res.status(404).json({ message: 'Address not found' });

      let total = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
      let discount = 0;
      if (couponCode) {
        const coupon = await Coupon.findOne({ where: { code: couponCode } });
        if (coupon) {
          discount = (total * coupon.discount) / 100;
        }
      }
      total -= discount;

      const order = await Order.create({
        userId: req.user.id,
        addressId,
        items,
        total,
        couponCode,
        paymentMethod,
        deliveryCost: deliveryCost || 0,
        status: 'pending',
        date: new Date(),
      });

      // Clear cart after order placement
      await Cart.destroy({ where: { userId: req.user.id } });

      res.status(201).json({ message: 'Order placed successfully', order });
    } catch (error) {
      console.error('Error placing order:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Get order history
  router.get('/api/orders', authenticateJWT, async (req, res) => {
    try {
      const orders = await Order.findAll({
        where: { userId: req.user.id },
        include: [{ model: Address, attributes: ['fullName', 'houseNo', 'location', 'landmark', 'mobile'] }],
      });
      res.json(orders.map(order => ({
        id: order.id,
        date: order.date.toISOString(),
        items: order.items.map(item => item.name),
        total: order.total,
        status: order.status,
        address: order.Address ? `${order.Address.fullName}, ${order.Address.houseNo}, ${order.Address.location}${order.Address.landmark ? `, ${order.Address.landmark}` : ''}, Mobile: ${order.Address.mobile}` : '',
      })));
    } catch (error) {
      console.error('Error fetching orders:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // Track order
  router.put('/api/orders/:id/track', authenticateJWT, async (req, res) => {
    try {
      const order = await Order.findOne({
        where: { id: req.params.id, userId: req.user.id },
      });
      if (!order) return res.status(404).json({ message: 'Order not found' });

      // Simulate tracking by advancing status (in real app, this would involve external systems)
      const statusOrder = ['pending', 'confirmed', 'shipped', 'delivered'];
      const currentIndex = statusOrder.indexOf(order.status);
      if (currentIndex < statusOrder.length - 1) {
        order.status = statusOrder[currentIndex + 1];
        await order.save();
      }

      res.json({ status: order.status });
    } catch (error) {
      console.error('Error tracking order:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  return router;
};