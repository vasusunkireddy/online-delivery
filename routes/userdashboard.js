const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs').promises;

dotenv.config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Email template for order cancellation
const getOrderEmailTemplate = (order, user, status) => {
  const itemsList = order.items && order.items.length > 0
    ? order.items.map(item => `
      <li style="margin-bottom: 8px;">
        ${item.name || 'Unknown'} (x${item.quantity || 1}) - ₹${parseFloat(item.price || 0).toFixed(2)}
      </li>
    `).join('')
    : '<li>No items</li>';

  const address = order.address
    ? [
        order.address.fullName || '',
        order.address.houseNo || '',
        order.address.location || '',
        order.address.landmark || '',
      ].filter(part => part.trim()).join(', ')
    : 'No address provided';

  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        body { font-family: 'Arial', sans-serif; background-color: #f4f4f4; color: #333; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 20px; }
        .header { background: linear-gradient(to right, #a855f7, #f43f5e); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
        .header h1 { margin: 0; font-size: 24px; font-weight: 700; }
        .content { padding: 20px; }
        .content p { line-height: 1.6; margin: 10px 0; }
        .order-details { background: #f9fafb; padding: 15px; border-radius: 6px; margin: 15px 0; }
        .order-details ul { list-style: none; padding: 0; }
        .footer { text-align: center; padding: 15px; font-size: 12px; color: #666; }
        .footer a { color: #a855f7; text-decoration: none; }
        .status-badge { display: inline-block; padding: 8px 16px; border-radius: 12px; color: white; font-weight: 600; margin: 10px 0; }
        .status-cancelled { background: #ef4444; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Delicute Order Update</h1>
        </div>
        <div class="content">
          <p>Dear ${user.name || 'Valued Customer'},</p>
          <p>We regret to inform you that your order (ID: ${order.id}) has been <strong class="status-badge status-cancelled">Cancelled</strong>.</p>
          ${order.cancellationReason ? `<p><strong>Cancellation Reason:</strong> ${order.cancellationReason}</p>` : ''}
          <div class="order-details">
            <p><strong>Order ID:</strong> ${order.id}</p>
            <p><strong>Order Date:</strong> ${order.date ? new Date(order.date).toLocaleString() : '-'}</p>
            <p><strong>Delivery Address:</strong> ${address}</p>
            <p><strong>Items:</strong></p>
            <ul>${itemsList}</ul>
            <p><strong>Delivery Cost:</strong> ₹${parseFloat(order.delivery || 0).toFixed(2)}</p>
            <p><strong>Coupon:</strong> ${order.couponCode || 'None'}</p>
            <p><strong>Total:</strong> ₹${parseFloat(order.total || 0).toFixed(2)}</p>
            <p><strong>Payment Method:</strong> ${order.paymentMethod || 'COD'}</p>
            <p><strong>Payment Status:</strong> ${order.paymentStatus || 'Pending'}</p>
          </div>
          <p>If you have any questions, please contact us at <a href="mailto:support@delicute.com">support@delicute.com</a>.</p>
        </div>
        <div class="footer">
          <p>© 2025 Delicute. All rights reserved. | <a href="https://delicute.com">Visit our website</a></p>
        </div>
      </div>
    </body>
    </html>
  `;
};

// Middleware to authenticate user
const authenticateUser = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Upload user profile image
router.post('/upload', authenticateUser, async (req, res) => {
  try {
    if (!req.files || !req.files.image) {
      return res.status(400).json({ error: 'No image file provided' });
    }
    const image = req.files.image;
    if (!['image/jpeg', 'image/png'].includes(image.mimetype)) {
      return res.status(400).json({ error: 'Only JPEG or PNG images are allowed' });
    }
    if (image.size > 2 * 1024 * 1024) {
      return res.status(413).json({ error: 'Image size must be under 2MB' });
    }
    const uploadDir = path.join(__dirname, '..', 'Uploads', 'profiles');
    await fs.mkdir(uploadDir, { recursive: true });
    const filename = `${Date.now()}-${image.name.replace(/\s/g, '-')}`;
    const imagePath = `profiles/${filename}`;
    await image.mv(path.join(uploadDir, filename));
    const connection = await pool.getConnection();
    const [users] = await connection.execute('SELECT image FROM users WHERE id = ?', [req.user.id]);
    if (users.length && users[0].image && users[0].image !== '/default-profile.png') {
      try {
        const oldImagePath = path.join(__dirname, '..', 'Uploads', users[0].image);
        await fs.access(oldImagePath);
        await fs.unlink(oldImagePath);
      } catch (unlinkError) {
        if (unlinkError.code !== 'ENOENT') {
          console.warn(`Failed to delete old image: ${users[0].image}`, unlinkError.message);
        }
      }
    }
    await connection.execute('UPDATE users SET image = ? WHERE id = ?', [imagePath, req.user.id]);
    connection.release();
    res.json({ url: `/Uploads/${imagePath}` });
  } catch (error) {
    console.error('Upload profile image error:', error.message);
    res.status(500).json({ error: error.message || 'Failed to upload profile image' });
  }
});

// Get user profile
router.get('/profile', authenticateUser, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [users] = await connection.execute(
      'SELECT id, name, email, phone AS mobile, image FROM users WHERE id = ?',
      [req.user.id]
    );
    connection.release();
    if (!users.length) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({
      ...users[0],
      image: users[0].image ? `/Uploads/${users[0].image}` : '/Uploads/default-profile.png',
    });
  } catch (error) {
    console.error('Get profile error:', error.message);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update user profile
router.put('/profile', authenticateUser, async (req, res) => {
  const { name, email } = req.body;
  if (!name || !email) {
    return res.status(400).json({ error: 'Name and email are required' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  try {
    const connection = await pool.getConnection();
    const [existingEmail] = await connection.execute(
      'SELECT id FROM users WHERE email = ? AND id != ?',
      [email, req.user.id]
    );
    if (existingEmail.length) {
      connection.release();
      return res.status(400).json({ error: 'Email already in use' });
    }
    await connection.execute(
      'UPDATE users SET name = ?, email = ? WHERE id = ?',
      [name, email, req.user.id]
    );
    const [users] = await connection.execute(
      'SELECT id, name, email, phone AS mobile, image FROM users WHERE id = ?',
      [req.user.id]
    );
    connection.release();
    res.json({
      ...users[0],
      image: users[0].image ? `/Uploads/${users[0].image}` : '/Uploads/default-profile.png',
    });
  } catch (error) {
    console.error('Update profile error:', error.message);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Get user addresses
router.get('/addresses', authenticateUser, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [addresses] = await connection.execute(
      'SELECT id, full_name AS fullName, mobile, house_no AS houseNo, location, landmark FROM addresses WHERE user_id = ?',
      [req.user.id]
    );
    connection.release();
    res.json(addresses);
  } catch (error) {
    console.error('Get addresses error:', error.message);
    res.status(500).json({ error: 'Failed to fetch addresses' });
  }
});

// Add user address
router.post('/addresses', authenticateUser, async (req, res) => {
  const { fullName, mobile, houseNo, location, landmark } = req.body;
  if (!fullName || !mobile || !houseNo || !location) {
    return res.status(400).json({ error: 'Full name, mobile, house number, and location are required' });
  }
  if (!/^\d{10}$/.test(mobile)) {
    return res.status(400).json({ error: 'Mobile number must be 10 digits' });
  }
  try {
    const connection = await pool.getConnection();
    const [result] = await connection.execute(
      'INSERT INTO addresses (user_id, full_name, mobile, house_no, location, landmark) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, fullName, mobile, houseNo, location, landmark || null]
    );
    connection.release();
    res.json({ message: 'Address added successfully', addressId: result.insertId });
  } catch (error) {
    console.error('Add address error:', error.message);
    res.status(500).json({ error: 'Failed to add address' });
  }
});

// Update user address
router.put('/addresses/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;
  const { fullName, mobile, houseNo, location, landmark } = req.body;
  if (!fullName || !mobile || !houseNo || !location) {
    return res.status(400).json({ error: 'Full name, mobile, house number, and location are required' });
  }
  if (!/^\d{10}$/.test(mobile)) {
    return res.status(400).json({ error: 'Mobile number must be 10 digits' });
  }
  try {
    const connection = await pool.getConnection();
    const [existing] = await connection.execute(
      'SELECT id FROM addresses WHERE id = ? AND user_id = ?',
      [id, req.user.id]
    );
    if (!existing.length) {
      connection.release();
      return res.status(404).json({ error: 'Address not found' });
    }
    await connection.execute(
      'UPDATE addresses SET full_name = ?, mobile = ?, house_no = ?, location = ?, landmark = ? WHERE id = ? AND user_id = ?',
      [fullName, mobile, houseNo, location, landmark || null, id, req.user.id]
    );
    connection.release();
    res.json({ message: 'Address updated successfully' });
  } catch (error) {
    console.error('Update address error:', error.message);
    res.status(500).json({ error: 'Failed to update address' });
  }
});

// Delete user address
router.delete('/addresses/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;
  try {
    const connection = await pool.getConnection();
    const [result] = await connection.execute(
      'DELETE FROM addresses WHERE id = ? AND user_id = ?',
      [id, req.user.id]
    );
    connection.release();
    if (!result.affectedRows) {
      return res.status(404).json({ error: 'Address not found' });
    }
    res.json({ message: 'Address deleted successfully' });
  } catch (error) {
    console.error('Delete address error:', error.message);
    res.status(500).json({ error: 'Failed to delete address' });
  }
});

// Get user cart
router.get('/cart', authenticateUser, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [items] = await connection.execute(
      'SELECT c.id, c.item_id AS itemId, c.name, c.price, c.image, c.quantity FROM cart c WHERE c.user_id = ?',
      [req.user.id]
    );
    connection.release();
    res.json(
      items.map((item) => ({
        ...item,
        image: item.image ? `/Uploads/${item.image}` : '/Uploads/default-menu.png',
      }))
    );
  } catch (error) {
    console.error('Get cart error:', error.message);
    res.status(500).json({ error: 'Failed to fetch cart items' });
  }
});

// Add item to cart
router.post('/cart', authenticateUser, async (req, res) => {
  const { itemId, quantity = 1 } = req.body;
  if (!itemId || !Number.isInteger(quantity) || quantity < 1) {
    return res.status(400).json({ error: 'Valid item ID and quantity are required' });
  }
  try {
    const connection = await pool.getConnection();
    const [items] = await connection.execute(
      'SELECT id, name, price, image, stock FROM menu_items WHERE id = ?',
      [itemId]
    );
    if (!items.length) {
      connection.release();
      return res.status(404).json({ error: 'Menu item not found' });
    }
    const item = items[0];
    if (item.stock < quantity) {
      connection.release();
      return res.status(400).json({ error: `Only ${item.stock} ${item.name} available in stock` });
    }
    const [existing] = await connection.execute(
      'SELECT id, quantity FROM cart WHERE user_id = ? AND item_id = ?',
      [req.user.id, itemId]
    );
    if (existing.length) {
      const newQuantity = existing[0].quantity + quantity;
      if (newQuantity > item.stock) {
        connection.release();
        return res.status(400).json({ error: `Only ${item.stock} ${item.name} available in stock` });
      }
      await connection.execute(
        'UPDATE cart SET quantity = ? WHERE user_id = ? AND item_id = ?',
        [newQuantity, req.user.id, itemId]
      );
    } else {
      await connection.execute(
        'INSERT INTO cart (user_id, item_id, name, price, image, quantity) VALUES (?, ?, ?, ?, ?, ?)',
        [req.user.id, itemId, item.name, item.price, item.image, quantity]
      );
    }
    connection.release();
    res.json({ message: 'Item added to cart' });
  } catch (error) {
    console.error('Add to cart error:', error.message);
    res.status(500).json({ error: error.message || 'Failed to add item to cart' });
  }
});

// Update cart item quantity
router.put('/cart/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;
  if (!Number.isInteger(quantity) || quantity < 1) {
    return res.status(400).json({ error: 'Valid quantity is required' });
  }
  try {
    const connection = await pool.getConnection();
    const [cartItems] = await connection.execute(
      'SELECT c.item_id, c.quantity, m.stock, m.name FROM cart c JOIN menu_items m ON c.item_id = m.id WHERE c.id = ? AND c.user_id = ?',
      [id, req.user.id]
    );
    if (!cartItems.length) {
      connection.release();
      return res.status(404).json({ error: 'Cart item not found' });
    }
    const { stock, name } = cartItems[0];
    if (quantity > stock) {
      connection.release();
      return res.status(400).json({ error: `Only ${stock} ${name} available in stock` });
    }
    const [result] = await connection.execute(
      'UPDATE cart SET quantity = ? WHERE id = ? AND user_id = ?',
      [quantity, id, req.user.id]
    );
    connection.release();
    if (!result.affectedRows) {
      return res.status(404).json({ error: 'Cart item not found' });
    }
    res.json({ message: 'Cart updated' });
  } catch (error) {
    console.error('Update cart error:', error.message);
    res.status(500).json({ error: error.message || 'Failed to update cart' });
  }
});

// Remove item from cart
router.delete('/cart/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;
  try {
    const connection = await pool.getConnection();
    const [result] = await connection.execute(
      'DELETE FROM cart WHERE id = ? AND user_id = ?',
      [id, req.user.id]
    );
    connection.release();
    if (!result.affectedRows) {
      return res.status(404).json({ error: 'Cart item not found' });
    }
    res.json({ message: 'Item removed from cart' });
  } catch (error) {
    console.error('Remove from cart error:', error.message);
    res.status(500).json({ error: 'Failed to remove item from cart' });
  }
});

// Clear cart
router.delete('/cart/clear', authenticateUser, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.execute('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
    connection.release();
    res.json({ message: 'Cart cleared' });
  } catch (error) {
    console.error('Clear cart error:', error.message);
    res.status(500).json({ error: 'Failed to clear cart' });
  }
});

// Get all menu items
router.get('/menu', authenticateUser, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [items] = await connection.execute(
      'SELECT id, name, price, category, description, image, stock FROM menu_items WHERE stock > 0'
    );
    connection.release();
    res.json(
      items.map((item) => ({
        ...item,
        image: item.image ? `/Uploads/${item.image}` : '/Uploads/default-menu.png',
      }))
    );
  } catch (error) {
    console.error('Get menu items error:', error.message);
    res.status(500).json({ error: 'Failed to fetch menu items' });
  }
});

// Get specific menu item by ID
router.get('/menu/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;
  try {
    const connection = await pool.getConnection();
    const [items] = await connection.execute(
      'SELECT id, name, price, category, description, image, stock FROM menu_items WHERE id = ?',
      [id]
    );
    connection.release();
    if (!items.length) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    res.json({
      ...items[0],
      image: items[0].image ? `/Uploads/${items[0].image}` : '/Uploads/default-menu.png',
    });
  } catch (error) {
    console.error('Get menu item error:', error.message);
    res.status(500).json({ error: 'Failed to fetch menu item' });
  }
});

// Get coupons
router.get('/coupons', authenticateUser, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [coupons] = await connection.execute(
      'SELECT id, code, discount, description, image FROM coupons WHERE expires_at > NOW()'
    );
    connection.release();
    res.json(
      coupons.map((coupon) => ({
        ...coupon,
        image: coupon.image ? `/Uploads/${coupon.image}` : '/Uploads/default-coupon.png',
      }))
    );
  } catch (error) {
    console.error('Get coupons error:', error.message);
    res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

// Validate coupon
router.get('/coupons/validate', authenticateUser, async (req, res) => {
  const { code } = req.query;
  if (!code) {
    return res.status(400).json({ error: 'Coupon code is required' });
  }
  try {
    const connection = await pool.getConnection();
    const [coupons] = await connection.execute(
      'SELECT id, code, discount FROM coupons WHERE code = ? AND expires_at > NOW()',
      [code]
    );
    connection.release();
    if (!coupons.length) {
      return res.status(400).json({ error: 'Invalid or expired coupon code' });
    }
    res.json(coupons[0]);
  } catch (error) {
    console.error('Validate coupon error:', error.message);
    res.status(500).json({ error: 'Failed to validate coupon' });
  }
});

// Get user favorites
router.get('/favorites', authenticateUser, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [favorites] = await connection.execute(
      `
      SELECT f.id, f.item_id AS itemId, m.name, m.price, m.category, m.description, m.image
      FROM favorites f
      JOIN menu_items m ON f.item_id = m.id
      WHERE f.user_id = ?
      `,
      [req.user.id]
    );
    connection.release();
    res.json(
      favorites.map((favorite) => ({
        ...favorite,
        image: favorite.image ? `/Uploads/${favorite.image}` : '/Uploads/default-menu.png',
      }))
    );
  } catch (error) {
    console.error('Get favorites error:', error.message);
    res.status(500).json({ error: 'Failed to fetch favorites' });
  }
});

// Add to favorites
router.post('/favorites', authenticateUser, async (req, res) => {
  const { itemId } = req.body;
  if (!itemId || !Number.isInteger(parseInt(itemId))) {
    return res.status(400).json({ error: 'Valid item ID is required' });
  }
  try {
    const connection = await pool.getConnection();
    const [items] = await connection.execute('SELECT id, name FROM menu_items WHERE id = ?', [itemId]);
    if (!items.length) {
      connection.release();
      return res.status(404).json({ error: 'Menu item not found' });
    }
    const [existing] = await connection.execute(
      'SELECT id FROM favorites WHERE user_id = ? AND item_id = ?',
      [req.user.id, itemId]
    );
    if (existing.length) {
      connection.release();
      return res.status(400).json({ error: 'Item already in favorites' });
    }
    await connection.execute(
      'INSERT INTO favorites (user_id, item_id, name) VALUES (?, ?, ?)',
      [req.user.id, itemId, items[0].name]
    );
    connection.release();
    res.json({ message: 'Item added to favorites' });
  } catch (error) {
    console.error('Add to favorites error:', error.message);
    res.status(500).json({ error: error.message || 'Failed to add to favorites' });
  }
});

// Remove from favorites
router.delete('/favorites/:itemId', authenticateUser, async (req, res) => {
  const { itemId } = req.params;
  try {
    const connection = await pool.getConnection();
    const [result] = await connection.execute(
      'DELETE FROM favorites WHERE user_id = ? AND item_id = ?',
      [req.user.id, itemId]
    );
    connection.release();
    if (!result.affectedRows) {
      return res.status(404).json({ error: 'Favorite not found' });
    }
    res.json({ message: 'Item removed from favorites' });
  } catch (error) {
    console.error('Remove from favorites error:', error.message);
    res.status(500).json({ error: 'Failed to remove from favorites' });
  }
});

// Get all user orders
router.get('/orders', authenticateUser, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [orders] = await connection.execute(
      `
      SELECT o.id, o.user_id, o.address_id, o.coupon_code AS couponCode, o.payment_method AS paymentMethod, 
             o.delivery_cost AS delivery, o.total, o.status, o.date, o.payment_status AS paymentStatus, 
             a.full_name AS fullName, a.mobile, a.house_no AS houseNo, a.location, a.landmark,
             o.cancellation_reason AS cancellationReason
      FROM orders o
      LEFT JOIN addresses a ON o.address_id = a.id
      WHERE o.user_id = ?
      `,
      [req.user.id]
    );
    const orderIds = orders.map((order) => order.id);
    const [items] = orderIds.length > 0
      ? await connection.execute(
          'SELECT order_id, item_id AS itemId, name, price, quantity, image FROM order_items WHERE order_id IN (?)',
          [orderIds]
        )
      : [[], []];
    connection.release();
    const ordersWithItems = orders.map((order) => ({
      ...order,
      address: order.fullName
        ? {
            fullName: order.fullName,
            mobile: order.mobile,
            houseNo: order.houseNo,
            location: order.location,
            landmark: order.landmark,
          }
        : null,
      items: items
        .filter((item) => item.order_id === order.id)
        .map((item) => ({
          ...item,
          image: item.image ? `/Uploads/${item.image}` : '/Uploads/default-menu.png',
        })),
    }));
    res.json(ordersWithItems);
  } catch (error) {
    console.error('Get orders error:', error.message);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Get specific user order by ID
router.get('/orders/:id', authenticateUser, async (req, res) => {
  const { id } = req.params;
  try {
    const connection = await pool.getConnection();
    const [orders] = await connection.execute(
      `
      SELECT o.id, o.user_id, o.address_id, o.coupon_code AS couponCode, o.payment_method AS paymentMethod, 
             o.delivery_cost AS delivery, o.total, o.status, o.date, o.payment_status AS paymentStatus, 
             a.full_name AS fullName, a.mobile, a.house_no AS houseNo, a.location, a.landmark,
             o.cancellation_reason AS cancellationReason
      FROM orders o
      LEFT JOIN addresses a ON o.address_id = a.id
      WHERE o.user_id = ? AND o.id = ?
      `,
      [req.user.id, id]
    );
    if (!orders.length) {
      connection.release();
      return res.status(404).json({ error: 'Order not found' });
    }
    const [items] = await connection.execute(
      'SELECT order_id, item_id AS itemId, name, price, quantity, image FROM order_items WHERE order_id = ?',
      [id]
    );
    connection.release();
    const order = orders[0];
    res.json({
      ...order,
      address: order.fullName
        ? {
            fullName: order.fullName,
            mobile: order.mobile,
            houseNo: order.houseNo,
            location: order.location,
            landmark: order.landmark,
          }
        : null,
      items: items.map((item) => ({
        ...item,
        image: item.image ? `/Uploads/${item.image}` : '/Uploads/default-menu.png',
      })),
    });
  } catch (error) {
    console.error('Get order error:', error.message);
    res.status(500).json({ error: 'Failed to fetch order' });
  }
});

// Place order
router.post('/orders', authenticateUser, async (req, res) => {
  const { addressId, items, couponCode, paymentMethod, deliveryCost, total, status, date } = req.body;
  if (!addressId || !items || !Array.isArray(items) || items.length === 0 || !paymentMethod || !total) {
    return res.status(400).json({ error: 'Address ID, items, payment method, and total are required' });
  }
  try {
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    // Validate address
    const [addresses] = await connection.execute(
      'SELECT id FROM addresses WHERE id = ? AND user_id = ?',
      [addressId, req.user.id]
    );
    if (!addresses.length) {
      await connection.rollback();
      connection.release();
      return res.status(400).json({ error: 'Invalid address ID' });
    }

    // Validate coupon if provided
    if (couponCode) {
      const [coupons] = await connection.execute(
        'SELECT id, discount FROM coupons WHERE code = ? AND expires_at > NOW()',
        [couponCode]
      );
      if (!coupons.length) {
        await connection.rollback();
        connection.release();
        return res.status(400).json({ error: 'Invalid or expired coupon code' });
      }
      const expectedDiscount = (total * coupons[0].discount) / 100;
      if (Math.abs(total - (items.reduce((sum, item) => sum + item.price * item.quantity, 0) - expectedDiscount)) > 0.01) {
        await connection.rollback();
        connection.release();
        return res.status(400).json({ error: 'Invalid total amount after coupon discount' });
      }
    }

    // Validate items and stock
    for (const item of items) {
      const [menuItems] = await connection.execute(
        'SELECT id, name, price, image, stock FROM menu_items WHERE id = ?',
        [item.itemId]
      );
      if (!menuItems.length) {
        await connection.rollback();
        connection.release();
        return res.status(400).json({ error: `Menu item ${item.itemId} not found` });
      }
      const menuItem = menuItems[0];
      if (menuItem.stock < item.quantity) {
        await connection.rollback();
        connection.release();
        return res.status(400).json({ error: `Insufficient stock for ${menuItem.name}` });
      }
      if (Math.abs(menuItem.price - item.price) > 0.01) {
        await connection.rollback();
        connection.release();
        return res.status(400).json({ error: `Invalid price for ${menuItem.name}` });
      }
      await connection.execute(
        'UPDATE menu_items SET stock = stock - ? WHERE id = ?',
        [item.quantity, item.itemId]
      );
    }

    // Insert order
    const [orderResult] = await connection.execute(
      `
      INSERT INTO orders (user_id, address_id, coupon_code, payment_method, delivery_cost, total, status, payment_status, date)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        req.user.id,
        addressId,
        couponCode || null,
        paymentMethod,
        deliveryCost || 0,
        total,
        status || 'pending',
        paymentMethod === 'cod' ? 'pending' : 'failed',
        date || new Date().toISOString().slice(0, 19).replace('T', ' '),
      ]
    );
    const orderId = orderResult.insertId;

    // Insert order items
    for (const item of items) {
      await connection.execute(
        'INSERT INTO order_items (order_id, item_id, name, price, quantity, image) VALUES (?, ?, ?, ?, ?, ?)',
        [orderId, item.itemId, item.name, item.price, item.quantity, item.image]
      );
    }

    // Clear cart
    await connection.execute('DELETE FROM cart WHERE user_id = ?', [req.user.id]);

    await connection.commit();
    connection.release();
    res.json({ message: 'Order placed successfully', orderId });
  } catch (error) {
    console.error('Place order error:', error.message);
    try {
      await connection.rollback();
    } catch (rollbackError) {
      console.error('Rollback error:', rollbackError.message);
    }
    connection.release();
    res.status(500).json({ error: error.message || 'Failed to place order' });
  }
});

// Cancel user order
router.post('/orders/:id/cancel', authenticateUser, async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;
  if (!reason) {
    return res.status(400).json({ error: 'Cancellation reason is required' });
  }
  try {
    const connection = await pool.getConnection();
    const [orders] = await connection.execute(
      `
      SELECT o.id, o.user_id, o.address_id, o.coupon_code, o.payment_method, o.delivery_cost, o.total,
             o.status, o.date, o.payment_status, a.full_name, a.mobile, a.house_no, a.location, a.landmark,
             u.name AS user_name, u.email AS user_email
      FROM orders o
      LEFT JOIN addresses a ON o.address_id = a.id
      JOIN users u ON o.user_id = u.id
      WHERE o.user_id = ? AND o.id = ?
      `,
      [req.user.id, id]
    );
    if (!orders.length) {
      connection.release();
      return res.status(404).json({ error: 'Order not found' });
    }
    const order = orders[0];
    if (!['pending', 'confirmed'].includes(order.status)) {
      connection.release();
      return res.status(400).json({ error: 'Only pending or confirmed orders can be cancelled' });
    }
    const [items] = await connection.execute(
      'SELECT order_id, item_id, name, price, quantity, image FROM order_items WHERE order_id = ?',
      [id]
    );
    // Restock items
    for (const item of items) {
      await connection.execute(
        'UPDATE menu_items SET stock = stock + ? WHERE id = ?',
        [item.quantity, item.item_id]
      );
    }
    await connection.execute(
      'UPDATE orders SET status = ?, cancellation_reason = ? WHERE id = ? AND user_id = ?',
      ['cancelled', reason, id, req.user.id]
    );
    connection.release();
    const orderData = {
      ...order,
      user: { name: order.user_name, email: order.user_email },
      address: {
        fullName: order.full_name,
        mobile: order.mobile,
        houseNo: order.house_no,
        location: order.location,
        landmark: order.landmark,
      },
      items: items.map((item) => ({
        ...item,
        image: item.image ? `/Uploads/${item.image}` : '/Uploads/default-menu.png',
      })),
      delivery: order.delivery_cost,
      couponCode: order.coupon_code,
      paymentStatus: order.payment_status || 'pending',
      cancellationReason: reason,
    };
    const mailOptions = {
      from: '"Delicute Restaurant" <support@delicute.com>',
      to: order.user_email,
      subject: `Your Delicute Order #${order.id} - Cancelled`,
      html: getOrderEmailTemplate(orderData, orderData.user, 'cancelled'),
    };
    try {
      await transporter.sendMail(mailOptions);
      console.log(`Cancellation email sent to ${order.user_email} for order ${order.id}`);
    } catch (emailError) {
      console.error('Email sending error:', emailError.message);
    }
    res.json({ message: 'Order cancelled successfully' });
  } catch (error) {
    console.error('Cancel order error:', error.message);
    res.status(500).json({ error: error.message || 'Failed to cancel order' });
  }
});

// Clear user orders
router.delete('/orders/clear', authenticateUser, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [orders] = await connection.execute(
      'SELECT id FROM orders WHERE user_id = ? AND status IN ("pending", "confirmed")',
      [req.user.id]
    );
    for (const order of orders) {
      const [items] = await connection.execute(
        'SELECT item_id, quantity FROM order_items WHERE order_id = ?',
        [order.id]
      );
      for (const item of items) {
        await connection.execute(
          'UPDATE menu_items SET stock = stock + ? WHERE id = ?',
          [item.quantity, item.item_id]
        );
      }
    }
    await connection.execute(
      'UPDATE orders SET status = ?, cancellation_reason = ? WHERE user_id = ? AND status IN ("pending", "confirmed")',
      ['cancelled', 'Cleared by user', req.user.id]
    );
    connection.release();
    res.json({ message: 'Pending and confirmed orders cancelled successfully' });
  } catch (error) {
    console.error('Clear orders error:', error.message);
    res.status(500).json({ error: 'Failed to clear orders' });
  }
});

module.exports = router;