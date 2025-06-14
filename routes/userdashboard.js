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
    console.log('Image uploaded:', imageUrl); // Debug log
    res.json({ url: imageUrl });
  } catch (error) {
    console.error('Error uploading image:', error.message);
    res.status(500).json({ error: 'Failed to upload image', details: error.message });
  }
});

// Get user profile
router.get('/profile', authenticateUser, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, name, email, phone, image FROM users WHERE id = ?', [req.user.id]);
    if (users.length === 0) return res.status(404).json({ error: 'User not found' });
    const user = users[0];
    // Set default image if none exists
    user.image = user.image || '/Uploads/default-profile.png';
    console.log('Profile fetched:', { id: user.id, image: user.image }); // Debug log
    res.json(user);
  } catch (error) {
    console.error('Error fetching profile:', error.message);
    res.status(500).json({ error: 'Failed to fetch profile', details: error.message });
  }
});

// Update user profile
router.put('/profile', authenticateUser, async (req, res) => {
  const { name, email, image } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });

  try {
    // Check if user has an existing image
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
    console.log('Profile updated:', { id: updatedUser[0].id, image: updatedUser[0].image }); // Debug log
    res.json(updatedUser[0]);
  } catch (error) {
    console.error('Error updating profile:', error.message);
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
    console.error('Error fetching addresses:', error.message);
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
    console.error('Error fetching address:', error.message);
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
    await pool.query(
      'INSERT INTO addresses (user_id, full_name, mobile, house_no, location, landmark) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, fullName, mobile, houseNo, location, landmark || null]
    );
    console.log('Address added for user:', req.user.id); // Debug log
    res.json({ message: 'Address added successfully' });
  } catch (error) {
    console.error('Error adding address:', error.message);
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
    console.log('Address updated:', req.params.id); // Debug log
    res.json({ message: 'Address updated successfully' });
  } catch (error) {
    console.error('Error updating address:', error.message);
    res.status(500).json({ error: 'Failed to update address', details: error.message });
  }
});

// Delete address
router.delete('/addresses/:id', authenticateUser, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM addresses WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Address not found' });
    console.log('Address deleted:', req.params.id); // Debug log
    res.json({ message: 'Address deleted successfully' });
  } catch (error) {
    console.error('Error deleting address:', error.message);
    res.status(500).json({ error: 'Failed to delete address', details: error.message });
  }
});

// Get all favorites
router.get('/favorites', authenticateUser, async (req, res) => {
  try {
    const [favorites] = await pool.query('SELECT id, item_id AS itemId, name, image, price FROM favorites WHERE user_id = ?', [req.user.id]);
    res.json(favorites);
  } catch (error) {
    console.error('Error fetching favorites:', error.message);
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

    await pool.query(
      'INSERT INTO favorites (user_id, item_id, name, image, price) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, itemId, name, image || null, parseFloat(price)]
    );
    console.log('Favorite added:', { userId: req.user.id, itemId }); // Debug log
    res.json({ message: 'Added to favorites successfully' });
  } catch (error) {
    console.error('Error adding favorite:', error.message);
    res.status(500).json({ error: 'Failed to add favorite', details: error.message });
  }
});

// Delete favorite
router.delete('/favorites/:itemId', authenticateUser, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM favorites WHERE user_id = ? AND item_id = ?', [req.user.id, req.params.itemId]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Favorite not found' });
    console.log('Favorite deleted:', req.params.itemId); // Debug log
    res.json({ message: 'Removed from favorites successfully' });
  } catch (error) {
    console.error('Error deleting favorite:', error.message);
    res.status(500).json({ error: 'Failed to remove favorite', details: error.message });
  }
});

// Get cart
router.get('/cart', authenticateUser, async (req, res) => {
  try {
    const [cartItems] = await pool.query('SELECT id, item_id AS itemId, name, price, image, quantity FROM cart WHERE user_id = ?', [req.user.id]);
    console.log('Cart fetched for user:', { userId: req.user.id, items: cartItems.length }); // Debug log
    res.json(cartItems);
  } catch (error) {
    console.error('Error fetching cart:', error.message);
    res.status(500).json({ error: 'Failed to fetch cart', details: error.message });
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
    console.log('Item added to cart:', { userId: req.user.id, itemId }); // Debug log
    res.json({ message: 'Added to cart successfully' });
  } catch (error) {
    console.error('Error adding to cart:', error.message);
    res.status(500).json({ error: 'Failed to add to cart', details: error.message });
  }
});

// Update cart quantity
router.put('/cart/:itemId', authenticateUser, async (req, res) => {
  const { quantity } = req.body;
  const itemId = req.params.itemId;
  if (!quantity || quantity < 1) {
    return res.status(400).json({ error: 'Valid quantity is required' });
  }

  try {
    // Check if item exists in cart
    const [existing] = await pool.query('SELECT id FROM cart WHERE user_id = ? AND item_id = ?', [req.user.id, itemId]);
    if (existing.length === 0) {
      console.log('Cart item not found:', { userId: req.user.id, itemId }); // Debug log
      return res.status(404).json({ error: 'Cart item not found', details: `Item ID ${itemId} not found for user` });
    }

    const [result] = await pool.query(
      'UPDATE cart SET quantity = ? WHERE user_id = ? AND item_id = ?',
      [quantity, req.user.id, itemId]
    );
    if (result.affectedRows === 0) {
      console.log('No rows updated for cart item:', { userId: req.user.id, itemId }); // Debug log
      return res.status(404).json({ error: 'Cart item not found', details: `Failed to update item ID ${itemId}` });
    }

    // Fetch updated cart item
    const [updatedItems] = await pool.query(
      'SELECT id, item_id AS itemId, name, price, image, quantity FROM cart WHERE user_id = ? AND item_id = ?',
      [req.user.id, itemId]
    );
    console.log('Cart updated:', { userId: req.user.id, itemId, quantity }); // Debug log
    res.json({ message: 'Cart updated successfully', item: updatedItems[0] });
  } catch (error) {
    console.error('Error updating cart:', error.message);
    res.status(500).json({ error: 'Failed to update cart', details: error.message });
  }
});

// Delete from cart
router.delete('/cart/:itemId', authenticateUser, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM cart WHERE user_id = ? AND item_id = ?', [req.user.id, req.params.itemId]);
    if (result.affectedRows === 0) {
      console.log('Cart item not found for deletion:', req.params.itemId); // Debug log
      return res.status(404).json({ error: 'Cart item not found' });
    }
    console.log('Item removed from cart:', req.params.itemId); // Debug log
    res.json({ message: 'Removed from cart successfully' });
  } catch (error) {
    console.error('Error deleting from cart:', error.message);
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
    console.log('Coupon validated:', code); // Debug log
    res.json(coupons[0]);
  } catch (error) {
    console.error('Error validating coupon:', error.message);
    res.status(500).json({ error: 'Failed to validate coupon', details: error.message });
  }
});

// Get all coupons
router.get('/coupons', authenticateUser, async (req, res) => {
  try {
    const [coupons] = await pool.query('SELECT id, code, discount, image FROM coupons');
    res.json(coupons);
  } catch (error) {
    console.error('Error fetching coupons:', error.message);
    res.status(500).json({ error: 'Failed to fetch coupons', details: error.message });
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
      console.log('Order placed:', { orderId, userId: req.user.id }); // Debug log
      res.json({ message: 'Order placed successfully', orderId });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error placing order:', error.message);
    res.status(500).json({ error: error.message || 'Failed to place order', details: error.message });
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
    console.error('Error fetching orders:', error.message);
    res.status(500).json({ error: 'Failed to fetch orders', details: error.message });
  }
});

// Track order
router.get('/orders/:id/track', authenticateUser, async (req, res) => {
  try {
    const [orders] = await pool.query('SELECT id, status FROM orders WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (orders.length === 0) return res.status(404).json({ error: 'Order not found' });
    console.log('Order tracked:', { orderId: req.params.id, status: orders[0].status }); // Debug log
    res.json(orders[0]);
  } catch (error) {
    console.error('Error tracking order:', error.message);
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

    await pool.query('UPDATE orders SET status = ? WHERE id = ?', ['cancelled', req.params.id]);
    console.log('Order cancelled:', req.params.id); // Debug log
    res.json({ message: 'Order cancelled successfully' });
  } catch (error) {
    console.error('Error cancelling order:', error.message);
    res.status(500).json({ error: 'Failed to cancel order', details: error.message });
  }
});

// Clear order history
router.delete('/orders/clear', authenticateUser, async (req, res) => {
  try {
    await pool.query('DELETE FROM orders WHERE user_id = ?', [req.user.id]);
    console.log('Order history cleared for user:', req.user.id); // Debug log
    res.json({ message: 'Order history cleared successfully' });
  } catch (error) {
    console.error('Error clearing order history:', error.message);
    res.status(500).json({ error: 'Failed to clear order history', details: error.message });
  }
});

module.exports = router;