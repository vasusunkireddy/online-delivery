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

// Image upload endpoint
router.post('/upload', authenticateUser, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No image provided' });
    res.json({ url: `/Uploads/${req.file.filename}` });
  } catch (error) {
    console.error('Error uploading image:', error);
    res.status(500).json({ error: 'Failed to upload image' });
  }
});

// Get user profile
router.get('/profile', authenticateUser, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, name, email, phone, image FROM users WHERE id = ?', [req.user.id]);
    if (users.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(users[0]);
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update user profile
router.put('/profile', authenticateUser, async (req, res) => {
  const { name, email, image } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });

  try {
    const [result] = await pool.query(
      'UPDATE users SET name = ?, email = ?, image = ? WHERE id = ?',
      [name, email, image || null, req.user.id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
    const [updatedUser] = await pool.query('SELECT id, name, email, phone, image FROM users WHERE id = ?', [req.user.id]);
    res.json(updatedUser[0]);
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'Failed to update profile' });
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
    console.error('Error fetching addresses:', error);
    res.status(500).json({ error: 'Failed to fetch addresses' });
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
    console.error('Error fetching address:', error);
    res.status(500).json({ error: 'Failed to fetch address' });
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
    await pool.query(
      'INSERT INTO addresses (user_id, full_name, mobile, house_no, location, landmark) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, fullName, mobile, houseNo, location, landmark || null]
    );
    res.json({ message: 'Address added successfully' });
  } catch (error) {
    console.error('Error adding address:', error);
    res.status(500).json({ error: 'Failed to add address' });
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
    res.json({ message: 'Address updated successfully' });
  } catch (error) {
    console.error('Error updating address:', error);
    res.status(500).json({ error: 'Failed to update address' });
  }
});

// Delete address
router.delete('/addresses/:id', authenticateUser, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM addresses WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Address not found' });
    res.json({ message: 'Address deleted successfully' });
  } catch (error) {
    console.error('Error deleting address:', error);
    res.status(500).json({ error: 'Failed to delete address' });
  }
});

// Get all favorites
router.get('/favorites', authenticateUser, async (req, res) => {
  try {
    const [favorites] = await pool.query('SELECT id, item_id AS itemId, name, image, price FROM favorites WHERE user_id = ?', [req.user.id]);
    res.json(favorites);
  } catch (error) {
    console.error('Error fetching favorites:', error);
    res.status(500).json({ error: 'Failed to fetch favorites' });
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

    await pool.query(
      'INSERT INTO favorites (user_id, item_id, name, image, price) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, itemId, name, image || null, parseFloat(price)]
    );
    res.json({ message: 'Added to favorites successfully' });
  } catch (error) {
    console.error('Error adding favorite:', error);
    res.status(500).json({ error: 'Failed to add favorite' });
  }
});

// Delete favorite
router.delete('/favorites/:itemId', authenticateUser, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM favorites WHERE user_id = ? AND item_id = ?', [req.user.id, req.params.itemId]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Favorite not found' });
    res.json({ message: 'Removed from favorites successfully' });
  } catch (error) {
    console.error('Error deleting favorite:', error);
    res.status(500).json({ error: 'Failed to remove favorite' });
  }
});

// Get cart
router.get('/cart', authenticateUser, async (req, res) => {
  try {
    const [cartItems] = await pool.query('SELECT id, item_id AS itemId, name, price, image, quantity FROM cart WHERE user_id = ?', [req.user.id]);
    res.json(cartItems);
  } catch (error) {
    console.error('Error fetching cart:', error);
    res.status(500).json({ error: 'Failed to fetch cart' });
  }
});

// Add to cart
router.post('/cart', authenticateUser, async (req, res) => {
  const { itemId, name, price, image, quantity } = req.body;
  if (!itemId || !name || !price || !quantity) {
    return res.status(400).json({ error: 'Item ID, name, price, and quantity are required' });
  }

  try {
    const [existing] = await pool.query('SELECT id, quantity FROM cart WHERE user_id = ? AND item_id = ?', [req.user.id, itemId]);
    if (existing.length > 0) {
      await pool.query('UPDATE cart SET quantity = ? WHERE id = ?', [existing[0].quantity + quantity, existing[0].id]);
    } else {
      await pool.query(
        'INSERT INTO cart (user_id, item_id, name, price, image, quantity) VALUES (?, ?, ?, ?, ?, ?)',
        [req.user.id, itemId, name, parseFloat(price), image || null, quantity]
      );
    }
    res.json({ message: 'Added to cart successfully' });
  } catch (error) {
    console.error('Error adding to cart:', error);
    res.status(500).json({ error: 'Failed to add to cart' });
  }
});

// Update cart quantity
router.put('/cart/:itemId', authenticateUser, async (req, res) => {
  const { quantity } = req.body;
  if (!quantity || quantity < 1) {
    return res.status(400).json({ error: 'Valid quantity is required' });
  }

  try {
    const [result] = await pool.query(
      'UPDATE cart SET quantity = ? WHERE user_id = ? AND item_id = ?',
      [quantity, req.user.id, req.params.itemId]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Cart item not found' });
    res.json({ message: 'Cart updated successfully' });
  } catch (error) {
    console.error('Error updating cart:', error);
    res.status(500).json({ error: 'Failed to update cart' });
  }
});

// Delete from cart
router.delete('/cart/:itemId', authenticateUser, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM cart WHERE user_id = ? AND item_id = ?', [req.user.id, req.params.itemId]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Cart item not found' });
    res.json({ message: 'Removed from cart successfully' });
  } catch (error) {
    console.error('Error deleting from cart:', error);
    res.status(500).json({ error: 'Failed to remove from cart' });
  }
});

// Validate coupon
router.get('/coupons/validate', authenticateUser, async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).json({ error: 'Coupon code is required' });

  try {
    const [coupons] = await pool.query('SELECT id, code, discount FROM coupons WHERE code = ?', [code]);
    if (coupons.length === 0) return res.status(404).json({ error: 'Invalid coupon code' });
    res.json(coupons[0]);
  } catch (error) {
    console.error('Error validating coupon:', error);
    res.status(500).json({ error: 'Failed to validate coupon' });
  }
});

// Get all coupons
router.get('/coupons', authenticateUser, async (req, res) => {
  try {
    const [coupons] = await pool.query('SELECT id, code, discount, image FROM coupons');
    res.json(coupons);
  } catch (error) {
    console.error('Error fetching coupons:', error);
    res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

// Place order
router.post('/orders', authenticateUser, async (req, res) => {
  const { addressId, items, couponCode, paymentMethod, deliveryCost } = req.body;
  if (!addressId || !items || !items.length || !paymentMethod) {
    return res.status(400).json({ error: 'Address, items, and payment method are required' });
  }
  if (paymentMethod !== 'cod') {
    return res.status(400).json({ error: 'Only COD is supported currently' });
  }

  try {
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Verify address exists and belongs to the user
      const [addresses] = await connection.query('SELECT id FROM addresses WHERE id = ? AND user_id = ?', [addressId, req.user.id]);
      if (addresses.length === 0) {
        throw new Error('Invalid address');
      }

      let total = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
      let discount = 0;

      if (couponCode) {
        const [coupons] = await connection.query('SELECT discount FROM coupons WHERE code = ?', [couponCode]);
        if (coupons.length === 0) {
          throw new Error('Invalid coupon code');
        }
        discount = (total * coupons[0].discount) / 100;
      }

      total = total - discount + (parseFloat(deliveryCost) || 0);

      const [orderResult] = await connection.query(
        'INSERT INTO orders (user_id, total, status) VALUES (?, ?, ?)',
        [req.user.id, total, 'pending']
      );
      const orderId = orderResult.insertId;

      for (const item of items) {
        await connection.query(
          'INSERT INTO order_items (order_id, item_id, quantity, price) VALUES (?, ?, ?, ?)',
          [orderId, item.itemId, item.quantity, item.price]
        );
      }

      await connection.query('DELETE FROM cart WHERE user_id = ?', [req.user.id]);

      await connection.commit();
      res.json({ message: 'Order placed successfully', orderId });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error placing order:', error);
    res.status(500).json({ error: error.message || 'Failed to place order' });
  }
});

// Get all orders
router.get('/orders', authenticateUser, async (req, res) => {
  try {
    const [orders] = await pool.query(`
      SELECT o.id, o.total, o.status, o.created_at AS date, 
             GROUP_CONCAT(oi.quantity, ' x ', m.name) AS items,
             (SELECT full_name FROM addresses WHERE user_id = o.user_id LIMIT 1) AS full_name,
             (SELECT house_no FROM addresses WHERE user_id = o.user_id LIMIT 1) AS house_no,
             (SELECT location FROM addresses WHERE user_id = o.user_id LIMIT 1) AS location,
             (SELECT landmark FROM addresses WHERE user_id = o.user_id LIMIT 1) AS landmark,
             (SELECT mobile FROM addresses WHERE user_id = o.user_id LIMIT 1) AS mobile,
             CASE WHEN o.status = 'delivered' THEN 'Free' ELSE '0.00' END AS delivery
      FROM orders o
      LEFT JOIN order_items oi ON o.id = oi.order_id
      LEFT JOIN menu_items m ON oi.item_id = m.id
      WHERE o.user_id = ?
      GROUP BY o.id
    `, [req.user.id]);

    res.json(orders.map(order => ({
      id: order.id,
      date: new Date(order.date).toLocaleDateString(),
      items: order.items ? order.items.split(',').map(item => {
        const parts = item.trim().split(' x ');
        const quantity = parseInt(parts[0]);
        const name = parts.slice(1).join(' x ');
        return { name, quantity };
      }) : [],
      total: parseFloat(order.total).toFixed(2),
      delivery: order.delivery,
      status: order.status,
      address: {
        fullName: order.full_name || 'No address provided',
        houseNo: order.house_no || 'N/A',
        location: order.location || 'N/A',
        landmark: order.landmark || '',
        mobile: order.mobile || 'N/A'
      }
    })));
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Track order
router.get('/orders/:id/track', authenticateUser, async (req, res) => {
  try {
    const [orders] = await pool.query('SELECT id, status FROM orders WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (orders.length === 0) return res.status(404).json({ error: 'Order not found' });
    res.json(orders[0]);
  } catch (error) {
    console.error('Error tracking order:', error);
    res.status(500).json({ error: 'Failed to track order' });
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

    await pool.query('UPDATE orders SET status = ? WHERE id = ?', ['cancelled', req.params.id]);
    res.json({ message: 'Order cancelled successfully' });
  } catch (error) {
    console.error('Error cancelling order:', error);
    res.status(500).json({ error: 'Failed to cancel order' });
  }
});

// Clear order history
router.delete('/orders/clear', authenticateUser, async (req, res) => {
  try {
    await pool.query('DELETE FROM orders WHERE user_id = ?', [req.user.id]);
    res.json({ message: 'Order history cleared successfully' });
  } catch (error) {
    console.error('Error clearing order history:', error);
    res.status(500).json({ error: 'Failed to clear order history' });
  }
});

module.exports = router;