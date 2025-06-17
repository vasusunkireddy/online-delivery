const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;

// Configure multer for file uploads
const upload = multer({
  dest: path.join(__dirname, '../public/uploads'),
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
  fileFilter: (req, file, cb) => {
    if (['image/jpeg', 'image/png'].includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only JPEG or PNG images are allowed'), false);
    }
  },
});

// Database pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Middleware to verify user JWT
const authenticateUserToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'user') {
      return res.status(403).json({ error: 'Access denied: User role required' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Refresh token endpoint
router.post('/refresh-token', authenticateUserToken, async (req, res) => {
  try {
    const newToken = jwt.sign(
      { id: req.user.id, role: req.user.role, email: req.user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token: newToken });
  } catch (error) {
    console.error('Refresh token error:', error.message);
    res.status(500).json({ error: 'Failed to refresh token' });
  }
});

// Get user profile
router.get('/profile', authenticateUserToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, email, mobile, image FROM users WHERE id = ?', [req.user.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error('Profile fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update user profile
router.put('/profile', authenticateUserToken, async (req, res) => {
  const { name, email } = req.body;
  if (!name || !email) {
    return res.status(400).json({ error: 'Name and email are required' });
  }
  try {
    const [existingEmail] = await pool.query('SELECT id FROM users WHERE email = ? AND id != ?', [email, req.user.id]);
    if (existingEmail.length > 0) {
      return res.status(400).json({ error: 'Email already in use' });
    }
    const updates = { name, email };
    if (req.body.image) {
      updates.image = req.body.image;
    }
    const fields = Object.keys(updates).map((key) => `${key} = ?`).join(', ');
    const values = Object.values(updates).concat([req.user.id]);
    await pool.query(`UPDATE users SET ${fields} WHERE id = ?`, values);
    const [updatedUser] = await pool.query('SELECT id, name, email, mobile, image FROM users WHERE id = ?', [req.user.id]);
    res.json(updatedUser[0]);
  } catch (error) {
    console.error('Profile update error:', error.message);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Upload profile image
router.post('/upload', authenticateUserToken, upload.single('image'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No image provided' });
  }
  try {
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: 'delicute/profiles',
      allowed_formats: ['jpg', 'png'],
    });
    await fs.unlink(req.file.path); // Delete local file
    const [user] = await pool.query('SELECT image FROM users WHERE id = ?', [req.user.id]);
    if (user[0].image && user[0].image.includes('cloudinary')) {
      const publicId = user[0].image.split('/').pop().split('.')[0];
      await cloudinary.uploader.destroy(`delicute/profiles/${publicId}`).catch(() => {});
    }
    res.json({ url: result.secure_url });
  } catch (error) {
    console.error('Image upload error:', error.message);
    if (req.file) await fs.unlink(req.file.path).catch(() => {});
    res.status(500).json({ error: 'Failed to upload image' });
  }
});

// Get all addresses
router.get('/addresses', authenticateUserToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, full_name AS fullName, mobile, house_no AS houseNo, location, landmark FROM addresses WHERE user_id = ?',
      [req.user.id]
    );
    res.json(rows);
  } catch (error) {
    console.error('Addresses fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch addresses' });
  }
});

// Add address
router.post('/addresses', authenticateUserToken, async (req, res) => {
  const { fullName, mobile, houseNo, location, landmark } = req.body;
  if (!fullName || !mobile || !houseNo || !location) {
    return res.status(400).json({ error: 'Full name, mobile, house number, and location are required' });
  }
  if (!/^\d{10}$/.test(mobile)) {
    return res.status(400).json({ error: 'Valid mobile number is required' });
  }
  try {
    const [result] = await pool.query(
      'INSERT INTO addresses (user_id, full_name, mobile, house_no, location, landmark) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, fullName, mobile, houseNo, location, landmark || null]
    );
    res.json({ message: 'Address added', id: result.insertId });
  } catch (error) {
    console.error('Add address error:', error.message);
    res.status(500).json({ error: 'Failed to add address' });
  }
});

// Update address
router.put('/addresses/:id', authenticateUserToken, async (req, res) => {
  const { id } = req.params;
  const { fullName, mobile, houseNo, location, landmark } = req.body;
  if (!fullName || !mobile || !houseNo || !location) {
    return res.status(400).json({ error: 'Full name, mobile, house number, and location are required' });
  }
  if (!/^\d{10}$/.test(mobile)) {
    return res.status(400).json({ error: 'Valid mobile number is required' });
  }
  try {
    const [rows] = await pool.query('SELECT id FROM addresses WHERE id = ? AND user_id = ?', [id, req.user.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Address not found' });
    }
    await pool.query(
      'UPDATE addresses SET full_name = ?, mobile = ?, house_no = ?, location = ?, landmark = ? WHERE id = ?',
      [fullName, mobile, houseNo, location, landmark || null, id]
    );
    res.json({ message: 'Address updated' });
  } catch (error) {
    console.error('Update address error:', error.message);
    res.status(500).json({ error: 'Failed to update address' });
  }
});

// Delete address
router.delete('/addresses/:id', authenticateUserToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query('SELECT id FROM addresses WHERE id = ? AND user_id = ?', [id, req.user.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Address not found' });
    }
    await pool.query('DELETE FROM addresses WHERE id = ?', [id]);
    res.json({ message: 'Address deleted' });
  } catch (error) {
    console.error('Delete address error:', error.message);
    res.status(500).json({ error: 'Failed to delete address' });
  }
});

// Get menu items
router.get('/menu', authenticateUserToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, price, category, description, image, stock FROM menu_items WHERE stock > 0');
    res.json(rows.map(row => ({
      ...row,
      image: row.image || null,
      stock: row.stock || 0
    })));
  } catch (error) {
    console.error('Menu fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch menu' });
  }
});

// Get single menu item
router.get('/menu/:id', authenticateUserToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query('SELECT id, name, price, category, description, image, stock FROM menu_items WHERE id = ?', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    res.json({
      ...rows[0],
      image: rows[0].image || null,
      stock: rows[0].stock || 0
    });
  } catch (error) {
    console.error('Menu item fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch menu item' });
  }
});

// Get coupons
router.get('/coupons', authenticateUserToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, code, discount, description, image FROM coupons');
    res.json(rows.map(row => ({
      ...row,
      image: row.image || null
    })));
  } catch (error) {
    console.error('Coupons fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

// Validate coupon
router.get('/coupons/validate', authenticateUserToken, async (req, res) => {
  const { code } = req.query;
  if (!code) {
    return res.status(400).json({ error: 'Coupon code is required' });
  }
  try {
    const [rows] = await pool.query('SELECT id, code, discount FROM coupons WHERE code = ?', [code]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Invalid coupon code' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error('Coupon validation error:', error.message);
    res.status(500).json({ error: 'Failed to validate coupon' });
  }
});

// Get favorites
router.get('/favorites', authenticateUserToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, item_id AS itemId, name, image, price FROM favorites WHERE user_id = ?',
      [req.user.id]
    );
    res.json(rows.map(row => ({
      ...row,
      image: row.image || null
    })));
  } catch (error) {
    console.error('Favorites fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch favorites' });
  }
});

// Add to favorites
router.post('/favorites', authenticateUserToken, async (req, res) => {
  const { itemId, name, image, price } = req.body;
  if (!itemId || !name || !price) {
    return res.status(400).json({ error: 'Item ID, name, and price are required' });
  }
  try {
    const [menuItem] = await pool.query('SELECT id FROM menu_items WHERE id = ?', [itemId]);
    if (menuItem.length === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    const [existing] = await pool.query('SELECT id FROM favorites WHERE user_id = ? AND item_id = ?', [req.user.id, itemId]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Item already in favorites' });
    }
    const [result] = await pool.query(
      'INSERT INTO favorites (user_id, item_id, name, image, price) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, itemId, name, image || null, parseFloat(price)]
    );
    res.json({ message: 'Added to favorites', id: result.insertId });
  } catch (error) {
    console.error('Add favorite error:', error.message);
    res.status(500).json({ error: 'Failed to add favorite' });
  }
});

// Remove from favorites
router.delete('/favorites/:id', authenticateUserToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query('SELECT id FROM favorites WHERE item_id = ? AND user_id = ?', [id, req.user.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Favorite not found' });
    }
    await pool.query('DELETE FROM favorites WHERE item_id = ? AND user_id = ?', [id, req.user.id]);
    res.json({ message: 'Removed from favorites' });
  } catch (error) {
    console.error('Remove favorite error:', error.message);
    res.status(500).json({ error: 'Failed to remove favorite' });
  }
});

// Get cart
router.get('/cart', authenticateUserToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, item_id AS itemId, name, price, image, quantity FROM cart WHERE user_id = ?',
      [req.user.id]
    );
    res.json(rows.map(row => ({
      ...row,
      image: row.image || null
    })));
  } catch (error) {
    console.error('Cart fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch cart' });
  }
});

router.post('/cart', authenticateUserToken, async (req, res) => {
  const { itemId, name, price, image, quantity = 1 } = req.body;
  if (!itemId || !name || !price || quantity < 1) {
    return res.status(400).json({ error: 'Item ID, name, price, and valid quantity are required' });
  }
  const connection = await req.app.get('dbPool').getConnection();
  try {
    await connection.beginTransaction();
    const [menuItem] = await connection.query('SELECT id, stock FROM menu_items WHERE id = ? FOR UPDATE', [itemId]);
    if (menuItem.length === 0) {
      throw new Error('Menu item not found');
    }
    if (menuItem[0].stock < quantity) {
      throw new Error(`Only ${menuItem[0].stock} ${name} available in stock`);
    }
    const [existing] = await connection.query(
      'SELECT id, quantity FROM cart WHERE user_id = ? AND item_id = ?',
      [req.user.id, itemId]
    );
    let cartId;
    if (existing.length > 0) {
      const newQuantity = existing[0].quantity + quantity;
      if (newQuantity > menuItem[0].stock) {
        throw new Error(`Only ${menuItem[0].stock} ${name} available in stock`);
      }
      await connection.query(
        'UPDATE cart SET quantity = ?, updated_at = NOW() WHERE id = ?',
        [newQuantity, existing[0].id]
      );
      cartId = existing[0].id;
    } else {
      const [result] = await connection.query(
        'INSERT INTO cart (user_id, item_id, name, price, image, quantity) VALUES (?, ?, ?, ?, ?, ?)',
        [req.user.id, itemId, name, parseFloat(price), image || null, quantity]
      );
      cartId = result.insertId;
    }
    await connection.commit();
    res.json({ message: 'Added to cart', id: cartId }); // Single response
  } catch (error) {
    await connection.rollback();
    console.error('Add to cart error:', error.message);
    res.status(400).json({ error: error.message || 'Failed to add to cart' });
  } finally {
    connection.release();
  }
});

// Update cart quantity
router.put('/cart/:id', authenticateUserToken, async (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;
  if (!quantity || quantity < 1) {
    return res.status(400).json({ error: 'Valid quantity is required' });
  }
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [cartItem] = await connection.query(
      'SELECT item_id, name, quantity FROM cart WHERE id = ? AND user_id = ? FOR UPDATE',
      [id, req.user.id]
    );
    if (cartItem.length === 0) {
      throw new Error('Cart item not found');
    }
    const [menuItem] = await connection.query('SELECT stock FROM menu_items WHERE id = ?', [cartItem[0].item_id]);
    if (menuItem.length === 0) {
      throw new Error('Menu item not found');
    }
    if (quantity > menuItem[0].stock) {
      throw new Error(`Only ${menuItem[0].stock} ${cartItem[0].name} available in stock`);
    }
    await connection.query(
      'UPDATE cart SET quantity = ?, updated_at = NOW() WHERE id = ?',
      [quantity, id]
    );
    await connection.commit();
    res.json({ message: 'Cart updated' });
  } catch (error) {
    await connection.rollback();
    console.error('Update cart error:', error.message);
    res.status(400).json({ error: error.message || 'Failed to update cart' });
  } finally {
    connection.release();
  }
});

// Remove from cart
router.delete('/cart/:id', authenticateUserToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query('SELECT id FROM cart WHERE id = ? AND user_id = ?', [id, req.user.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Cart item not found' });
    }
    await pool.query('DELETE FROM cart WHERE id = ?', [id]);
    res.json({ message: 'Item removed from cart' });
  } catch (error) {
    console.error('Remove from cart error:', error.message);
    res.status(500).json({ error: 'Failed to remove from cart' });
  }
});

// Clear cart
router.delete('/cart/clear', authenticateUserToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
    res.json({ message: 'Cart cleared' });
  } catch (error) {
    console.error('Clear cart error:', error.message);
    res.status(500).json({ error: 'Failed to clear cart' });
  }
});

// Get orders
router.get('/orders', authenticateUserToken, async (req, res) => {
  try {
    const [orders] = await pool.query(`
      SELECT o.id, o.total, o.delivery, o.status, o.created_at AS date, o.cancellation_reason AS cancellationReason,
             GROUP_CONCAT(oi.quantity, ' x ', mi.name) AS items
      FROM orders o
      LEFT JOIN order_items oi ON o.id = oi.order_id
      LEFT JOIN menu_items mi ON oi.menu_item_id = mi.id
      WHERE o.user_id = ?
      GROUP BY o.id
    `, [req.user.id]);
    res.json(orders.map(order => ({
      ...order,
      items: order.items ? order.items.split(',') : [],
      date: new Date(order.date).toLocaleString(),
      total: parseFloat(order.total || 0).toFixed(2),
      delivery: parseFloat(order.delivery || 0).toFixed(2)
    })));
  } catch (error) {
    console.error('Orders fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Get single order
router.get('/orders/:id', authenticateUserToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [orders] = await pool.query(`
      SELECT o.id, o.total, o.delivery, o.status, o.created_at AS date, o.cancellation_reason AS cancellationReason
      FROM orders o
      WHERE o.id = ? AND o.user_id = ?
    `, [id, req.user.id]);
    if (orders.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json({
      ...orders[0],
      date: new Date(orders[0].date).toLocaleString(),
      total: parseFloat(orders[0].total || 0).toFixed(2),
      delivery: parseFloat(orders[0].delivery || 0).toFixed(2)
    });
  } catch (error) {
    console.error('Order fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch order' });
  }
});

// Place order
router.post('/orders', authenticateUserToken, async (req, res) => {
  const { addressId, items, couponCode, paymentMethod, deliveryCost, total } = req.body;
  if (!addressId || !items || !Array.isArray(items) || items.length === 0 || !paymentMethod || total == null) {
    return res.status(400).json({ error: 'Address, items, payment method, and total are required' });
  }
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [address] = await connection.query('SELECT id FROM addresses WHERE id = ? AND user_id = ?', [addressId, req.user.id]);
    if (address.length === 0) {
      throw new Error('Invalid address');
    }
    let couponId = null;
    if (couponCode) {
      const [coupon] = await connection.query('SELECT id FROM coupons WHERE code = ?', [couponCode]);
      if (coupon.length === 0) {
        throw new Error('Invalid coupon code');
      }
      couponId = coupon[0].id;
    }
    for (const item of items) {
      const [menuItem] = await connection.query('SELECT id, stock, price FROM menu_items WHERE id = ? FOR UPDATE', [item.itemId]);
      if (menuItem.length === 0) {
        throw new Error(`Menu item ${item.name} not found`);
      }
      if (menuItem[0].stock < item.quantity) {
        throw new Error(`Only ${menuItem[0].stock} ${item.name} available in stock`);
      }
      if (parseFloat(item.price).toFixed(2) !== parseFloat(menuItem[0].price).toFixed(2)) {
        throw new Error(`Price mismatch for ${item.name}`);
      }
      await connection.query('UPDATE menu_items SET stock = stock - ? WHERE id = ?', [item.quantity, item.itemId]);
    }
    const [orderResult] = await connection.query(
      'INSERT INTO orders (user_id, address_id, coupon_id, total, delivery, payment_method, payment_status, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [req.user.id, addressId, couponId, parseFloat(total), parseFloat(deliveryCost || 0), paymentMethod, 'pending', 'pending']
    );
    const orderId = orderResult.insertId;
    for (const item of items) {
      await connection.query(
        'INSERT INTO order_items (order_id, menu_item_id, quantity, price) VALUES (?, ?, ?, ?)',
        [orderId, item.itemId, item.quantity, parseFloat(item.price)]
      );
    }
    await connection.query('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
    await connection.commit();
    res.json({ message: 'Order placed', orderId });
  } catch (error) {
    await connection.rollback();
    console.error('Place order error:', error.message);
    res.status(400).json({ error: error.message || 'Failed to place order' });
  } finally {
    connection.release();
  }
});

// Cancel order
router.put('/orders/:id/cancel', authenticateUserToken, async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;
  if (!reason) {
    return res.status(400).json({ error: 'Cancellation reason is required' });
  }
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [order] = await connection.query('SELECT id, status FROM orders WHERE id = ? AND user_id = ? FOR UPDATE', [id, req.user.id]);
    if (order.length === 0) {
      throw new Error('Order not found');
    }
    if (!['pending', 'confirmed'].includes(order[0].status)) {
      throw new Error('Order cannot be cancelled');
    }
    const [orderItems] = await connection.query('SELECT menu_item_id, quantity FROM order_items WHERE order_id = ?', [id]);
    for (const item of orderItems) {
      await connection.query('UPDATE menu_items SET stock = stock + ? WHERE id = ?', [item.quantity, item.menu_item_id]);
    }
    await connection.query('UPDATE orders SET status = ?, cancellation_reason = ? WHERE id = ?', ['cancelled', reason, id]);
    await connection.commit();
    res.json({ message: 'Order cancelled' });
  } catch (error) {
    await connection.rollback();
    console.error('Cancel order error:', error.message);
    res.status(400).json({ error: error.message || 'Failed to cancel order' });
  } finally {
    connection.release();
  }
});

// Clear order history
router.delete('/orders/clear', authenticateUserToken, async (req, res) => {
  try {
    await pool.query('UPDATE orders SET status = ?, cancellation_reason = ? WHERE user_id = ? AND status IN (?, ?)', ['cancelled', 'Cleared by user', req.user.id, 'pending', 'confirmed']);
    res.json({ message: 'Order history cleared' });
  } catch (error) {
    console.error('Clear order history error:', error.message);
    res.status(500).json({ error: 'Failed to clear order history' });
  }
});

// Logout
router.post('/logout', authenticateUserToken, async (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

module.exports = router;