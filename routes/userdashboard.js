const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config();

// Multer setup for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'Uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('Only JPEG and PNG images are allowed'));
  },
  limits: { fileSize: 2 * 1024 * 1024 } // 2MB limit
});

// Database pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// Middleware to verify user JWT
function authenticateUser(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err || user.isAdmin) return res.status(403).json({ error: 'User access required' });
    req.user = user;
    next();
  });
}

// Serve static files from Uploads directory
router.use('/Uploads', express.static(path.join(__dirname, '../Uploads')));

// Image upload endpoint
router.post('/upload', authenticateUser, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No image provided' });
    const imageUrl = `/Uploads/${req.file.filename}`;
    console.log('Image uploaded:', { userId: req.user.id, imageUrl }); // Enhanced debug log
    res.json({ url: imageUrl });
  } catch (error) {
    console.error('Error uploading image:', { userId: req.user.id, error: error.message });
    res.status(500).json({ error: 'Failed to upload image', details: error.message });
  }
});

// Get user profile
router.get('/profile', authenticateUser, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, name, email, phone, image FROM users WHERE id = ?', [req.user.id]);
    if (users.length === 0) return res.status(404).json({ error: 'User not found' });
    const user = users[0];
    user.image = user.image || '/Uploads/default-profile.png';
    console.log('Profile fetched:', { userId: user.id, image: user.image });
    res.json(user);
  } catch (error) {
    console.error('Error fetching profile:', { userId: req.user.id, error: error.message });
    res.status(500).json({ error: 'Failed to fetch profile', details: error.message });
  }
});

// Update user profile
router.put('/profile', authenticateUser, async (req, res) => {
  const { name, email, image } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });

  try {
    const [existingUser] = await pool.query('SELECT image FROM users WHERE id = ?', [req.user.id]);
    if (!image && !existingUser[0].image) {
      return res.status(400).json({ error: 'Profile image is mandatory' });
    }

    const imageToSave = image || existingUser[0].image || '/Uploads/default-profile.png';
    const [result] = await pool.query(
      'UPDATE users SET name = ?, email = ?, image = ? WHERE id = ?',
      [name, email, imageToSave, req.user.id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });

    const [updatedUser] = await pool.query('SELECT id, name, email, phone, image FROM users WHERE id = ?', [req.user.id]);
    console.log('Profile updated:', { userId: updatedUser[0].id, image: updatedUser[0].image });
    res.json(updatedUser[0]);
  } catch (error) {
    console.error('Error updating profile:', { userId: req.user.id, error: error.message });
    res.status(500).json({ error: 'Failed to update profile', details: error.message });
  }
});

// Get all addresses
router.get('/addresses', authenticateUser, async (req, res) => {
  try {
    const [addresses] = await pool.query('SELECT * FROM addresses WHERE user_id = ?', [req.user.id]);
    res.json(addresses.map(addr => ({
      id: addr.id,
      fullName: addr.full_name,
      mobile: addr.mobile,
      houseNo: addr.house_no,
      location: addr.location,
      landmark: addr.landmark
    })));
  } catch (error) {
    console.error('Error fetching addresses:', { userId: req.user.id, error: error.message });
    res.status(500).json({ error: 'Failed to fetch addresses', details: error.message });
  }
});

// Get single address
router.get('/addresses/:id', authenticateUser, async (req, res) => {
  try {
    const [addresses] = await pool.query('SELECT * FROM addresses WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (addresses.length === 0) return res.status(404).json({ error: 'Address not found' });
    const addr = addresses[0];
    res.json({
      id: addr.id,
      fullName: addr.full_name,
      mobile: addr.mobile,
      houseNo: addr.house_no,
      location: addr.location,
      landmark: addr.landmark
    });
  } catch (error) {
    console.error('Error fetching address:', { userId: req.user.id, addressId: req.params.id, error: error.message });
    res.status(500).json({ error: 'Failed to fetch address', details: error.message });
  }
});

// Add address
router.post('/addresses', authenticateUser, async (req, res) => {
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
    console.log('Address added:', { userId: req.user.id, addressId: result.insertId });
    res.json({ message: 'Address added successfully', addressId: result.insertId });
  } catch (error) {
    console.error('Error adding address:', { userId: req.user.id, error: error.message });
    res.status(500).json({ error: 'Failed to add address', details: error.message });
  }
});

// Update address
router.put('/addresses/:id', authenticateUser, async (req, res) => {
  const { fullName, mobile, houseNo, location, landmark } = req.body;
  if (!fullName || !mobile || !houseNo || !location) {
    return res.status(400).json({ error: 'Full name, mobile, house number, and location are required' });
  }
  if (!/^\d{10}$/.test(mobile)) {
    return res.status(400).json({ error: 'Valid mobile number is required' });
  }

  try {
    const [result] = await pool.query(
      'UPDATE addresses SET full_name = ?, mobile = ?, house_no = ?, location = ?, landmark = ? WHERE id = ? AND user_id = ?',
      [fullName, mobile, houseNo, location, landmark || null, req.params.id, req.user.id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Address not found' });
    console.log('Address updated:', { userId: req.user.id, addressId: req.params.id });
    res.json({ message: 'Address updated successfully' });
  } catch (error) {
    console.error('Error updating address:', { userId: req.user.id, addressId: req.params.id, error: error.message });
    res.status(500).json({ error: 'Failed to update address', details: error.message });
  }
});

// Delete address
router.delete('/addresses/:id', authenticateUser, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM addresses WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Address not found' });
    console.log('Address deleted:', { userId: req.user.id, addressId: req.params.id });
    res.json({ message: 'Address deleted successfully' });
  } catch (error) {
    console.error('Error deleting address:', { userId: req.user.id, addressId: req.params.id, error: error.message });
    res.status(500).json({ error: 'Failed to delete address', details: error.message });
  }
});

// Get all favorites
router.get('/favorites', authenticateUser, async (req, res) => {
  try {
    const [favorites] = await pool.query('SELECT id, item_id AS itemId, name, image, price FROM favorites WHERE user_id = ?', [req.user.id]);
    res.json(favorites);
  } catch (error) {
    console.error('Error fetching favorites:', { userId: req.user.id, error: error.message });
    res.status(500).json({ error: 'Failed to fetch favorites', details: error.message });
  }
});

// Add favorite
router.post('/favorites', authenticateUser, async (req, res) => {
  const { itemId, name, image, price } = req.body;
  if (!itemId || !name || !price) {
    return res.status(400).json({ error: 'Item ID, name, and price are required' });
  }

  try {
    const [existing] = await pool.query('SELECT id FROM favorites WHERE user_id = ? AND item_id = ?', [req.user.id, itemId]);
    if (existing.length > 0) return res.status(400).json({ error: 'Item already in favorites' });

    const [result] = await pool.query(
      'INSERT INTO favorites (user_id, item_id, name, image, price) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, itemId, name, image || null, parseFloat(price)]
    );
    console.log('Favorite added:', { userId: req.user.id, itemId, favoriteId: result.insertId });
    res.json({ message: 'Added to favorites successfully', favoriteId: result.insertId });
  } catch (error) {
    console.error('Error adding favorite:', { userId: req.user.id, itemId, error: error.message });
    res.status(500).json({ error: 'Failed to add favorite', details: error.message });
  }
});

// Delete favorite
router.delete('/favorites/:itemId', authenticateUser, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM favorites WHERE user_id = ? AND item_id = ?', [req.user.id, req.params.itemId]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Favorite not found' });
    console.log('Favorite deleted:', { userId: req.user.id, itemId: req.params.itemId });
    res.json({ message: 'Removed from favorites successfully' });
  } catch (error) {
    console.error('Error deleting favorite:', { userId: req.user.id, itemId: req.params.itemId, error: error.message });
    res.status(500).json({ error: 'Failed to remove favorite', details: error.message });
  }
});

// Get cart
router.get('/cart', authenticateUser, async (req, res) => {
  try {
    const [cartItems] = await pool.query('SELECT id, item_id AS itemId, name, price, image, quantity FROM cart WHERE user_id = ?', [req.user.id]);
    console.log('Cart fetched:', { userId: req.user.id, itemCount: cartItems.length });
    res.json(cartItems);
  } catch (error) {
    console.error('Error fetching cart:', { userId: req.user.id, error: error.message });
    res.status(500).json({ error: 'Failed to fetch cart', details: error.message });
  }
});

// Add to cart
router.post('/cart', authenticateUser, async (req, res) => {
  const { itemId, name, price, image, quantity } = req.body;
  if (!itemId || !name || !price || !quantity || quantity < 1) {
    return res.status(400).json({ error: 'Item ID, name, price, and valid quantity are required' });
  }

  try {
    const [existing] = await pool.query('SELECT id, quantity FROM cart WHERE user_id = ? AND item_id = ?', [req.user.id, itemId]);
    let cartItem;
    if (existing.length > 0) {
      const newQuantity = existing[0].quantity + quantity;
      await pool.query('UPDATE cart SET quantity = ? WHERE id = ?', [newQuantity, existing[0].id]);
      [cartItem] = await pool.query('SELECT id, item_id AS itemId, name, price, image, quantity FROM cart WHERE id = ?', [existing[0].id]);
    } else {
      const [result] = await pool.query(
        'INSERT INTO cart (user_id, item_id, name, price, image, quantity) VALUES (?, ?, ?, ?, ?, ?)',
        [req.user.id, itemId, name, parseFloat(price), image || null, quantity]
      );
      [cartItem] = await pool.query('SELECT id, item_id AS itemId, name, price, image, quantity FROM cart WHERE id = ?', [result.insertId]);
    }
    console.log('Item added to cart:', { userId: req.user.id, itemId, cartId: cartItem[0].id });
    res.json({ message: 'Added to cart successfully', item: cartItem[0] });
  } catch (error) {
    console.error('Error adding to cart:', { userId: req.user.id, itemId, error: error.message });
    res.status(500).json({ error: 'Failed to add to cart', details: error.message });
  }
});

// Update cart quantity
router.put('/cart/:id', authenticateUser, async (req, res) => {
  const { quantity } = req.body;
  const cartId = req.params.id;
  if (!quantity || quantity < 1) {
    return res.status(400).json({ error: 'Valid quantity (at least 1) is required' });
  }

  try {
    const [existing] = await pool.query('SELECT id, item_id AS itemId FROM cart WHERE id = ? AND user_id = ?', [cartId, req.user.id]);
    if (existing.length === 0) {
      console.log('Cart item not found:', { userId: req.user.id, cartId });
      return res.status(404).json({ error: 'Cart item not found', details: `Cart ID ${cartId} not found for user` });
    }

    const [result] = await pool.query(
      'UPDATE cart SET quantity = ? WHERE id = ? AND user_id = ?',
      [quantity, cartId, req.user.id]
    );
    if (result.affectedRows === 0) {
      console.log('No rows updated for cart item:', { userId: req.user.id, cartId });
      return res.status(404).json({ error: 'Cart item not found', details: `Failed to update cart ID ${cartId}` });
    }

    const [updatedItems] = await pool.query(
      'SELECT id, item_id AS itemId, name, price, image, quantity FROM cart WHERE id = ? AND user_id = ?',
      [cartId, req.user.id]
    );
    console.log('Cart updated:', { userId: req.user.id, cartId, quantity });
    res.json({ message: 'Cart updated successfully', item: updatedItems[0] });
  } catch (error) {
    console.error('Error updating cart:', { userId: req.user.id, cartId, error: error.message });
    res.status(500).json({ error: 'Failed to update cart', details: error.message });
  }
});

// Delete from cart
router.delete('/cart/:id', authenticateUser, async (req, res) => {
  const cartId = req.params.id;
  try {
    const [existing] = await pool.query('SELECT id FROM cart WHERE id = ? AND user_id = ?', [cartId, req.user.id]);
    if (existing.length === 0) {
      console.log('Cart item not found for deletion:', { userId: req.user.id, cartId });
      return res.status(404).json({ error: 'Cart item not found', details: `Cart ID ${cartId} not found` });
    }

    const [result] = await pool.query('DELETE FROM cart WHERE id = ? AND user_id = ?', [cartId, req.user.id]);
    if (result.affectedRows === 0) {
      console.log('No rows deleted for cart item:', { userId: req.user.id, cartId });
      return res.status(404).json({ error: 'Cart item not found', details: `Failed to delete cart ID ${cartId}` });
    }
    console.log('Item removed from cart:', { userId: req.user.id, cartId });
    res.json({ message: 'Removed from cart successfully' });
  } catch (error) {
    console.error('Error deleting from cart:', { userId: req.user.id, cartId, error: error.message });
    res.status(500).json({ error: 'Failed to remove from cart', details: error.message });
  }
});

// Validate coupon
router.get('/coupons/validate', authenticateUser, async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).json({ error: 'Coupon code is required' });

  try {
    const [coupons] = await pool.query('SELECT id, code, discount FROM coupons WHERE code = ?', [code]);
    if (coupons.length === 0) return res.status(404).json({ error: 'Invalid coupon code' });
    console.log('Coupon validated:', { userId: req.user.id, code });
    res.json(coupons[0]);
  } catch (error) {
    console.error('Error validating coupon:', { userId: req.user.id, code, error: error.message });
    res.status(500).json({ error: 'Failed to validate coupon', details: error.message });
  }
});

// Get all coupons
router.get('/coupons', authenticateUser, async (req, res) => {
  try {
    const [coupons] = await pool.query('SELECT id, code, discount, image FROM coupons');
    res.json(coupons);
  } catch (error) {
    console.error('Error fetching coupons:', { userId: req.user.id, error: error.message });
    res.status(500).json({ error: 'Failed to fetch coupons', details: error.message });
  }
});

// Place order
router.post('/orders', authenticateUser, async (req, res) => {
  const { addressId, items, couponCode, paymentMethod, deliveryCost, total, status, date } = req.body;
  if (!addressId || !items || !items.length || !paymentMethod || !total) {
    return res.status(400).json({ error: 'Address, items, payment method, and total are required' });
  }
  if (paymentMethod !== 'cod') {
    return res.status(400).json({ error: 'Only COD is supported currently' });
  }

  try {
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      const [addresses] = await connection.query('SELECT id FROM addresses WHERE id = ? AND user_id = ?', [addressId, req.user.id]);
      if (addresses.length === 0) {
        throw new Error('Invalid address');
      }

      let calculatedTotal = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
      let discount = 0;

      if (couponCode) {
        const [coupons] = await connection.query('SELECT discount FROM coupons WHERE code = ?', [couponCode]);
        if (coupons.length === 0) {
          throw new Error('Invalid coupon code');
        }
        discount = (calculatedTotal * coupons[0].discount) / 100;
      }

      calculatedTotal = calculatedTotal - discount + (parseFloat(deliveryCost) || 0);
      if (Math.abs(calculatedTotal - parseFloat(total)) > 0.01) {
        throw new Error('Total mismatch');
      }

      const [orderResult] = await connection.query(
        'INSERT INTO orders (user_id, address_id, total, status, created_at, coupon_code, payment_method, delivery_cost) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [req.user.id, addressId, calculatedTotal, status || 'pending', date || new Date(), couponCode || null, paymentMethod, deliveryCost || 0]
      );
      const orderId = orderResult.insertId;

      for (const item of items) {
        if (!item.itemId || !item.quantity || !item.price) {
          throw new Error('Invalid item data');
        }
        await connection.query(
          'INSERT INTO order_items (order_id, item_id, name, quantity, price, image) VALUES (?, ?, ?, ?, ?, ?)',
          [orderId, item.itemId, item.name || 'Unknown', item.quantity, item.price, item.image || null]
        );
      }

      await connection.query('DELETE FROM cart WHERE user_id = ?', [req.user.id]);

      await connection.commit();
      console.log('Order placed:', { orderId, userId: req.user.id, total: calculatedTotal });
      res.json({ message: 'Order placed successfully', orderId });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error placing order:', { userId: req.user.id, error: error.message });
    res.status(500).json({ error: error.message || 'Failed to place order', details: error.message });
  }
});

// Get all orders
router.get('/orders', authenticateUser, async (req, res) => {
  try {
    const [orders] = await pool.query(`
      SELECT o.id, o.total, o.status, o.created_at AS date, o.coupon_code, o.payment_method, o.delivery_cost,
             GROUP_CONCAT(oi.quantity, ' x ', oi.name) AS items,
             a.full_name, a.house_no, a.location, a.landmark, a.mobile
      FROM orders o
      LEFT JOIN order_items oi ON o.id = oi.order_id
      LEFT JOIN addresses a ON o.address_id = a.id
      WHERE o.user_id = ?
      GROUP BY o.id
    `, [req.user.id]);

    res.json(orders.map(order => ({
      id: order.id,
      date: new Date(order.date).toISOString(),
      items: order.items ? order.items.split(',').map(item => {
        const parts = item.trim().split(' x ');
        const quantity = parseInt(parts[0]);
        const name = parts.slice(1).join(' x ');
        return { name, quantity };
      }) : [],
      total: parseFloat(order.total).toFixed(2),
      delivery: parseFloat(order.delivery_cost || 0).toFixed(2),
      status: order.status,
      couponCode: order.coupon_code || null,
      paymentMethod: order.payment_method,
      address: {
        fullName: order.full_name || 'No address provided',
        houseNo: order.house_no || 'N/A',
        location: order.location || 'N/A',
        landmark: order.landmark || '',
        mobile: order.mobile || 'N/A'
      }
    })));
  } catch (error) {
    console.error('Error fetching orders:', { userId: req.user.id, error: error.message });
    res.status(500).json({ error: 'Failed to fetch orders', details: error.message });
  }
});

// Track order
router.get('/orders/:id/track', authenticateUser, async (req, res) => {
  try {
    const [orders] = await pool.query('SELECT id, status FROM orders WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (orders.length === 0) return res.status(404).json({ error: 'Order not found' });
    console.log('Order tracked:', { userId: req.user.id, orderId: req.params.id, status: orders[0].status });
    res.json(orders[0]);
  } catch (error) {
    console.error('Error tracking order:', { userId: req.user.id, orderId: req.params.id, error: error.message });
    res.status(500).json({ error: 'Failed to track order', details: error.message });
  }
});

// Cancel order
router.put('/orders/:id/cancel', authenticateUser, async (req, res) => {
  const { reason } = req.body;
  if (!reason) return res.status(400).json({ error: 'Cancellation reason is required' });

  try {
    const [orders] = await pool.query('SELECT status FROM orders WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (orders.length === 0) return res.status(404).json({ error: 'Order not found' });
    if (!['pending', 'confirmed'].includes(orders[0].status)) {
      return res.status(400).json({ error: 'Order cannot be cancelled at this stage' });
    }

    await pool.query('UPDATE orders SET status = ?, cancel_reason = ? WHERE id = ?', ['cancelled', reason, req.params.id]);
    console.log('Order cancelled:', { userId: req.user.id, orderId: req.params.id });
    res.json({ message: 'Order cancelled successfully' });
  } catch (error) {
    console.error('Error cancelling order:', { userId: req.user.id, orderId: req.params.id, error: error.message });
    res.status(500).json({ error: 'Failed to cancel order', details: error.message });
  }
});

// Clear order history
router.delete('/orders/clear', authenticateUser, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM orders WHERE user_id = ?', [req.user.id]);
    console.log('Order history cleared:', { userId: req.user.id, deletedCount: result.affectedRows });
    res.json({ message: 'Order history cleared successfully' });
  } catch (error) {
    console.error('Error clearing order history:', { userId: req.user.id, error: error.message });
    res.status(500).json({ error: 'Failed to clear order history', details: error.message });
  }
});

// Get menu items
router.get('/menu', authenticateUser, async (req, res) => {
  try {
    const [menuItems] = await pool.query('SELECT id, name, description, price, image, category FROM menu_items');
    res.json(menuItems.map(item => ({
      id: item.id,
      name: item.name,
      description: item.description || '',
      price: parseFloat(item.price).toFixed(2),
      image: item.image || '/Uploads/default-menu.png',
      category: item.category || 'Other'
    })));
  } catch (error) {
    console.error('Error fetching menu:', { userId: req.user.id, error: error.message });
    res.status(500).json({ error: 'Failed to fetch menu', details: error.message });
  }
});

module.exports = router;