const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const { Op } = require('sequelize');
const cloudinary = require('cloudinary').v2;
const sgMail = require('@sendgrid/mail');

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });
  const token = authHeader.replace('Bearer ', '');
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

module.exports = (User, Cart, MenuItem, RestaurantStatus, Address, Favorite, Coupon, Order) => {
  // Image Upload Endpoint
  router.post('/upload', verifyToken, async (req, res) => {
    try {
      if (!req.files || !req.files.image) {
        return res.status(400).json({ error: 'No image file provided' });
      }
      const file = req.files.image;
      if (!['image/jpeg', 'image/png'].includes(file.mimetype)) {
        return res.status(400).json({ error: 'Only JPEG or PNG images are allowed' });
      }
      if (file.size > 2 * 1024 * 1024) {
        return res.status(400).json({ error: 'Image size must be less than 2MB' });
      }
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { resource_type: 'image' },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        stream.end(file.data);
      });
      res.json({ url: result.secure_url });
    } catch (error) {
      console.error('Upload image error:', error.message);
      res.status(500).json({ error: 'Failed to upload image' });
    }
  });

  // Get menu items
  router.get('/menu', async (req, res) => {
    try {
      const menuItems = await MenuItem.findAll();
      res.json(menuItems);
    } catch (error) {
      console.error('Error fetching menu:', error.message);
      res.status(500).json({ error: 'Failed to fetch menu' });
    }
  });

  // Login
  router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Please provide email or mobile number and password' });
    try {
      const user = await User.findOne({
        where: { [Op.or]: [{ email: email.toLowerCase() }, { phone: email }] },
      });
      if (!user || !user.password) return res.status(401).json({ error: 'Invalid email/mobile or password' });
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(401).json({ error: 'Invalid email/mobile or password' });
      const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token, user: { id: user.id, name: user.name, email: user.email, phone: user.phone, image: user.image } });
    } catch (error) {
      console.error('Login error:', error.message);
      res.status(500).json({ error: 'Failed to login' });
    }
  });

  // Signup
  router.post('/signup', async (req, res) => {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !phone || !password) return res.status(400).json({ error: 'Please fill in all fields' });
    if (!/^\d{10}$/.test(phone)) return res.status(400).json({ error: 'Please enter a valid 10-digit mobile number' });
    try {
      const existingUser = await User.findOne({
        where: { [Op.or]: [{ email: email.toLowerCase() }, { phone }] },
      });
      if (existingUser) return res.status(400).json({ error: 'Email or mobile number already exists' });
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = await User.create({
        name,
        email: email.toLowerCase(),
        phone,
        password: hashedPassword,
      });
      const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token, user: { id: user.id, name: user.name, email: user.email, phone: user.phone, image: user.image } });
    } catch (error) {
      console.error('Signup error:', error.message);
      res.status(500).json({ error: 'Failed to signup' });
    }
  });

  // Google Sign-In
  router.post('/auth/google', async (req, res) => {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'No credential provided' });
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
        if (user) return res.status(400).json({ error: 'Email already registered with another method' });
        user = await User.create({
          name,
          email: email.toLowerCase(),
          googleId,
          phone: null,
        });
      }
      const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token, user: { id: user.id, name: user.name, email: user.email, phone: user.phone, image: user.image } });
    } catch (error) {
      console.error('Google login error:', error.message);
      res.status(401).json({ error: 'Failed to authenticate with Google' });
    }
  });

  // Forgot Password
  router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });
    try {
      const user = await User.findOne({ where: { email: email.toLowerCase() } });
      if (!user) return res.status(404).json({ error: 'Email not found' });
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
      res.json({ message: 'OTP sent to email' });
    } catch (error) {
      console.error('Forgot password error:', error.message);
      res.status(500).json({ error: 'Failed to send OTP' });
    }
  });

  // Verify OTP
  router.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required' });
    try {
      const user = await User.findOne({
        where: {
          email: email.toLowerCase(),
          resetPasswordToken: otp,
          resetPasswordExpires: { [Op.gt]: new Date() },
        },
      });
      if (!user) return res.status(400).json({ error: 'Invalid or expired OTP' });
      res.json({ message: 'OTP verified successfully' });
    } catch (error) {
      console.error('OTP verification error:', error.message);
      res.status(500).json({ error: 'Failed to verify OTP' });
    }
  });

  // Reset Password
  router.post('/reset-password', async (req, res) => {
    const { email, newPassword, confirmPassword } = req.body;
    if (!email || !newPassword || !confirmPassword) return res.status(400).json({ error: 'All fields are required' });
    if (newPassword !== confirmPassword) return res.status(400).json({ error: 'Passwords do not match' });
    try {
      const user = await User.findOne({ where: { email: email.toLowerCase() } });
      if (!user) return res.status(404).json({ error: 'Email not found' });
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await User.update(
        { password: hashedPassword, resetPasswordToken: null, resetPasswordExpires: null },
        { where: { email: email.toLowerCase() } }
      );
      res.json({ message: 'Password reset successfully' });
    } catch (error) {
      console.error('Reset password error:', error.message);
      res.status(500).json({ error: 'Failed to reset password' });
    }
  });

  // Get Profile
  router.get('/profile', verifyToken, async (req, res) => {
    try {
      const user = await User.findByPk(req.user.id, {
        attributes: ['id', 'name', 'email', 'phone', 'image'],
      });
      if (!user) return res.status(404).json({ error: 'User not found' });
      res.json(user);
    } catch (error) {
      console.error('Get profile error:', error.message);
      res.status(500).json({ error: 'Failed to fetch profile' });
    }
  });

  // Update Profile
  router.put('/profile', verifyToken, async (req, res) => {
    const { name, email } = req.body;
    if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });
    try {
      const user = await User.findByPk(req.user.id);
      if (!user) return res.status(404).json({ error: 'User not found' });
      let imageUrl = user.image;
      if (req.files && req.files.image) {
        const file = req.files.image;
        if (!['image/jpeg', 'image/png'].includes(file.mimetype)) {
          return res.status(400).json({ error: 'Only JPEG or PNG images are allowed' });
        }
        if (file.size > 2 * 1024 * 1024) {
          return res.status(400).json({ error: 'Image size must be less than 2MB' });
        }
        const result = await new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { resource_type: 'image' },
            (error, result) => {
              if (error) reject(error);
              else resolve(result);
            }
          );
          stream.end(file.data);
        });
        imageUrl = result.secure_url;
      }
      await user.update({ name, email: email.toLowerCase(), image: imageUrl });
      res.json({ id: user.id, name: user.name, email: user.email, phone: user.phone, image: user.image });
    } catch (error) {
      console.error('Update profile error:', error.message);
      res.status(500).json({ error: 'Failed to update profile' });
    }
  });

  // Get Addresses
  router.get('/addresses', verifyToken, async (req, res) => {
    try {
      const addresses = await Address.findAll({ where: { userId: req.user.id } });
      res.json(addresses);
    } catch (error) {
      console.error('Get addresses error:', error.message);
      res.status(500).json({ error: 'Failed to fetch addresses' });
    }
  });

  // Add Address
  router.post('/addresses', verifyToken, async (req, res) => {
    const { fullName, mobile, houseNo, location, landmark } = req.body;
    if (!fullName || !mobile || !houseNo || !location) return res.status(400).json({ error: 'All required fields must be provided' });
    if (!/^\d{10}$/.test(mobile)) return res.status(400).json({ error: 'Please enter a valid 10-digit mobile number' });
    try {
      const address = await Address.create({
        userId: req.user.id,
        fullName,
        mobile,
        houseNo,
        location,
        landmark,
      });
      res.json(address);
    } catch (error) {
      console.error('Add address error:', error.message);
      res.status(500).json({ error: 'Failed to add address' });
    }
  });

  // Update Address
  router.put('/addresses/:id', verifyToken, async (req, res) => {
    const { fullName, mobile, houseNo, location, landmark } = req.body;
    if (!fullName || !mobile || !houseNo || !location) return res.status(400).json({ error: 'All required fields must be provided' });
    if (!/^\d{10}$/.test(mobile)) return res.status(400).json({ error: 'Please enter a valid 10-digit mobile number' });
    try {
      const address = await Address.findOne({ where: { id: req.params.id, userId: req.user.id } });
      if (!address) return res.status(404).json({ error: 'Address not found' });
      await address.update({
        fullName,
        mobile,
        houseNo,
        location,
        landmark,
      });
      res.json(address);
    } catch (error) {
      console.error('Update address error:', error.message);
      res.status(500).json({ error: 'Failed to update address' });
    }
  });

  // Delete Address
  router.delete('/addresses/:id', verifyToken, async (req, res) => {
    try {
      const address = await Address.findOne({ where: { id: req.params.id, userId: req.user.id } });
      if (!address) return res.status(404).json({ error: 'Address not found' });
      await address.destroy();
      res.json({ message: 'Address deleted' });
    } catch (error) {
      console.error('Delete address error:', error.message);
      res.status(500).json({ error: 'Failed to delete address' });
    }
  });

  // Get Favorites
  router.get('/favorites', verifyToken, async (req, res) => {
    try {
      const favorites = await Favorite.findAll({ where: { userId: req.user.id } });
      res.json(favorites);
    } catch (error) {
      console.error('Get favorites error:', error.message);
      res.status(500).json({ error: 'Failed to fetch favorites' });
    }
  });

  // Add Favorite
  router.post('/favorites', verifyToken, async (req, res) => {
    const { itemId, name, image } = req.body;
    if (!itemId || !name) return res.status(400).json({ error: 'Item ID and name are required' });
    try {
      const [favorite, created] = await Favorite.findOrCreate({
        where: { userId: req.user.id, itemId },
        defaults: { userId: req.user.id, itemId, name, image },
      });
      if (!created) return res.status(400).json({ error: 'Item already in favorites' });
      res.json(favorite);
    } catch (error) {
      console.error('Add favorite error:', error.message);
      res.status(500).json({ error: 'Failed to add favorite' });
    }
  });

  // Remove Favorite
  router.delete('/favorites/:id', verifyToken, async (req, res) => {
    try {
      const favorite = await Favorite.findOne({ where: { itemId: req.params.id, userId: req.user.id } });
      if (!favorite) return res.status(404).json({ error: 'Favorite not found' });
      await favorite.destroy();
      res.json({ message: 'Favorite removed' });
    } catch (error) {
      console.error('Remove favorite error:', error.message);
      res.status(500).json({ error: 'Failed to remove favorite' });
    }
  });

  // Get Cart
  router.get('/cart', verifyToken, async (req, res) => {
    try {
      const cartItems = await Cart.findAll({ where: { userId: req.user.id } });
      res.json(cartItems);
    } catch (error) {
      console.error('Get cart error:', error.message);
      res.status(500).json({ error: 'Failed to fetch cart' });
    }
  });

  // Add to Cart
  router.post('/cart', verifyToken, async (req, res) => {
    const { itemId, name, price, image, quantity } = req.body;
    if (!itemId || !name || !price || !quantity) return res.status(400).json({ error: 'Item ID, name, price, and quantity are required' });
    try {
      const menuItem = await MenuItem.findByPk(itemId);
      if (!menuItem) return res.status(404).json({ error: 'Menu item not found' });
      const cartItem = await Cart.findOne({ where: { userId: req.user.id, itemId } });
      if (cartItem) {
        await cartItem.update({ quantity: cartItem.quantity + quantity });
      } else {
        await Cart.create({
          userId: req.user.id,
          itemId,
          name,
          price,
          image,
          quantity,
        });
      }
      res.json({ message: 'Item added to cart' });
    } catch (error) {
      console.error('Add to cart error:', error.message);
      res.status(500).json({ error: 'Failed to add item to cart' });
    }
  });

  // Update Cart Quantity
  router.put('/cart/:itemId', verifyToken, async (req, res) => {
    const { quantity } = req.body;
    if (!quantity || quantity < 1) return res.status(400).json({ error: 'Valid quantity is required' });
    try {
      const cartItem = await Cart.findOne({ where: { itemId: req.params.itemId, userId: req.user.id } });
      if (!cartItem) return res.status(404).json({ error: 'Cart item not found' });
      await cartItem.update({ quantity });
      res.json({ message: 'Quantity updated' });
    } catch (error) {
      console.error('Update cart error:', error.message);
      res.status(500).json({ error: 'Failed to update quantity' });
    }
  });

  // Remove from Cart
  router.delete('/cart/:itemId', verifyToken, async (req, res) => {
    try {
      const cartItem = await Cart.findOne({ where: { itemId: req.params.itemId, userId: req.user.id } });
      if (!cartItem) return res.status(404).json({ error: 'Cart item not found' });
      await cartItem.destroy();
      res.json({ message: 'Item removed from cart' });
    } catch (error) {
      console.error('Remove cart error:', error.message);
      res.status(500).json({ error: 'Failed to remove item' });
    }
  });

  // Get Coupons
  router.get('/coupons', verifyToken, async (req, res) => {
    try {
      const coupons = await Coupon.findAll();
      res.json(coupons);
    } catch (error) {
      console.error('Get coupons error:', error.message);
      res.status(500).json({ error: 'Failed to fetch coupons' });
    }
  });

  // Validate Coupon
  router.get('/coupons/validate', verifyToken, async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).json({ error: 'Coupon code is required' });
    try {
      const coupon = await Coupon.findOne({ where: { code } });
      if (!coupon) return res.status(404).json({ error: 'Invalid coupon code' });
      res.json({ code: coupon.code, discount: coupon.discount });
    } catch (error) {
      console.error('Validate coupon error:', error.message);
      res.status(500).json({ error: 'Failed to validate coupon' });
    }
  });

  // Place Order
  router.post('/orders', verifyToken, async (req, res) => {
    const { addressId, items, couponCode, paymentMethod, deliveryCost } = req.body;
    if (!addressId || !items || !paymentMethod) return res.status(400).json({ error: 'Address, items, and payment method are required' });
    try {
      const address = await Address.findOne({ where: { id: addressId, userId: req.user.id } });
      if (!address) return res.status(404).json({ error: 'Address not found' });
      let total = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
      let discount = 0;
      if (couponCode) {
        const coupon = await Coupon.findOne({ where: { code: couponCode } });
        if (coupon) discount = (total * coupon.discount) / 100;
      }
      total -= discount;
      total += deliveryCost || 0;
      const order = await Order.create({
        userId: req.user.id,
        addressId,
        items,
        total,
        couponCode,
        paymentMethod,
        deliveryCost: deliveryCost || 0,
        status: 'pending',
      });
      await Cart.destroy({ where: { userId: req.user.id } });
      res.json(order);
    } catch (error) {
      console.error('Place order error:', error.message);
      res.status(500).json({ error: 'Failed to place order' });
    }
  });

  // Get Orders
  router.get('/orders', verifyToken, async (req, res) => {
    try {
      const orders = await Order.findAll({
        where: { userId: req.user.id },
        include: [
          { model: Address, attributes: ['fullName', 'mobile', 'houseNo', 'location', 'landmark'] },
        ],
      });
      res.json(orders.map(order => ({
        id: order.id,
        date: order.createdAt.toISOString().split('T')[0],
        items: order.items.map(item => item.name).join(', '),
        total: order.total,
        delivery: order.deliveryCost,
        status: order.status,
        address: order.Address,
      })));
    } catch (error) {
      console.error('Get orders error:', error.message);
      res.status(500).json({ error: 'Failed to fetch orders' });
    }
  });

  // Cancel Order
  router.put('/orders/:id/cancel', verifyToken, async (req, res) => {
    const { reason } = req.body;
    if (!reason) return res.status(400).json({ error: 'Reason is required' });
    try {
      const order = await Order.findOne({ where: { id: req.params.id, userId: req.user.id } });
      if (!order) return res.status(404).json({ error: 'Order not found' });
      if (!['pending', 'confirmed'].includes(order.status)) {
        return res.status(400).json({ error: 'Order cannot be cancelled' });
      }
      await order.update({ status: 'cancelled', cancellationReason: reason });
      res.json({ message: 'Order cancelled successfully' });
    } catch (error) {
      console.error('Cancel order error:', error.message);
      res.status(500).json({ error: 'Failed to cancel order' });
    }
  });

  // Clear Order History
  router.delete('/orders/clear', verifyToken, async (req, res) => {
    try {
      await Order.destroy({ where: { userId: req.user.id } });
      res.json({ message: 'Order history cleared' });
    } catch (error) {
      console.error('Clear orders error:', error.message);
      res.status(500).json({ error: 'Failed to clear order history' });
    }
  });

  // Track/Update Order Status
  router.put('/orders/:id/track', verifyToken, async (req, res) => {
    try {
      const order = await Order.findOne({ where: { id: req.params.id, userId: req.user.id } });
      if (!order) return res.status(404).json({ error: 'Order not found' });
      const statusOrder = ['pending', 'confirmed', 'shipped', 'delivered'];
      const currentIndex = statusOrder.indexOf(order.status);
      if (currentIndex < statusOrder.length - 1) {
        await order.update({ status: statusOrder[currentIndex + 1] });
      }
      res.json({ id: order.id, status: order.status });
    } catch (error) {
      console.error('Track order error:', error.message);
      res.status(500).json({ error: 'Failed to track order' });
    }
  });

  // Get Restaurant Status
  router.get('/status', async (req, res) => {
    try {
      const status = await RestaurantStatus.findOne({ order: [['id', 'DESC']] });
      res.json({ status: status ? status.status : 'open' });
    } catch (error) {
      console.error('Error fetching status:', error.message);
      res.status(500).json({ error: 'Failed to fetch restaurant status' });
    }
  });

  return router;
};