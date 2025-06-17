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
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
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

// Middleware to verify admin JWT
const authenticateAdminToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied: Admin role required' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Check session
router.get('/check-session', authenticateAdminToken, async (req, res) => {
  res.json({ message: 'Session valid' });
});

// Get restaurant status
router.get('/status', authenticateAdminToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT status FROM restaurant_status ORDER BY updated_at DESC LIMIT 1');
    const status = rows.length > 0 ? rows[0].status : 'closed';
    res.json({ status });
  } catch (error) {
    console.error('Status fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch status' });
  }
});

// Toggle restaurant status
router.put('/status', authenticateAdminToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT status FROM restaurant_status ORDER BY updated_at DESC LIMIT 1');
    const currentStatus = rows.length > 0 ? rows[0].status : 'closed';
    const newStatus = currentStatus === 'open' ? 'closed' : 'open';
    await pool.query('INSERT INTO restaurant_status (status) VALUES (?)', [newStatus]);
    res.json({ status: newStatus });
  } catch (error) {
    console.error('Status toggle error:', error.message);
    res.status(500).json({ error: 'Failed to toggle status' });
  }
});

// Get all menu items
router.get('/menu', authenticateAdminToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, price, category, description, image FROM menu_items');
    res.json(rows.map(row => ({
      ...row,
      image: row.image || null // Ensure null if no image
    })));
  } catch (error) {
    console.error('Menu fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch menu items' });
  }
});

// Add menu item
router.post('/menu', authenticateAdminToken, upload.single('image'), async (req, res) => {
  const { name, price, category, description } = req.body;
  if (!name || !price || !category) {
    return res.status(400).json({ error: 'Name, price, and category are required' });
  }
  try {
    let imageUrl = null;
    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: 'delicute/menu',
        allowed_formats: ['jpg', 'png'],
      });
      imageUrl = result.secure_url;
      await fs.unlink(req.file.path); // Delete local file
    }
    const [result] = await pool.query(
      'INSERT INTO menu_items (name, price, category, description, image) VALUES (?, ?, ?, ?, ?)',
      [name, parseFloat(price), category, description || null, imageUrl]
    );
    res.json({ message: 'Menu item added', id: result.insertId });
  } catch (error) {
    console.error('Add menu item error:', error.message);
    if (req.file) await fs.unlink(req.file.path).catch(() => {});
    res.status(500).json({ error: 'Failed to add menu item' });
  }
});

// Update menu item
router.put('/menu/:id', authenticateAdminToken, upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { name, price, category, description } = req.body;
  if (!name || !price || !category) {
    return res.status(400).json({ error: 'Name, price, and category are required' });
  }
  try {
    const [rows] = await pool.query('SELECT image FROM menu_items WHERE id = ?', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    let imageUrl = rows[0].image;
    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: 'delicute/menu',
        allowed_formats: ['jpg', 'png'],
      });
      imageUrl = result.secure_url;
      await fs.unlink(req.file.path); // Delete local file
      if (rows[0].image) {
        const publicId = rows[0].image.split('/').pop().split('.')[0];
        await cloudinary.uploader.destroy(`delicute/menu/${publicId}`).catch(() => {});
      }
    }
    await pool.query(
      'UPDATE menu_items SET name = ?, price = ?, category = ?, description = ?, image = ? WHERE id = ?',
      [name, parseFloat(price), category, description || null, imageUrl, id]
    );
    res.json({ message: 'Menu item updated' });
  } catch (error) {
    console.error('Update menu item error:', error.message);
    if (req.file) await fs.unlink(req.file.path).catch(() => {});
    res.status(500).json({ error: 'Failed to update menu item' });
  }
});

// Delete menu item
router.delete('/menu/:id', authenticateAdminToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query('SELECT image FROM menu_items WHERE id = ?', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    if (rows[0].image) {
      const publicId = rows[0].image.split('/').pop().split('.')[0];
      await cloudinary.uploader.destroy(`delicute/menu/${publicId}`).catch(() => {});
    }
    await pool.query('DELETE FROM menu_items WHERE id = ?', [id]);
    res.json({ message: 'Menu item deleted' });
  } catch (error) {
    console.error('Delete menu item error:', error.message);
    res.status(500).json({ error: 'Failed to delete menu item' });
  }
});

// Get all coupons
router.get('/coupons', authenticateAdminToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, code, discount, description, image FROM coupons');
    res.json(rows.map(row => ({
      ...row,
      image: row.image || null // Ensure null if no image
    })));
  } catch (error) {
    console.error('Coupon fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

// Add coupon
router.post('/coupons', authenticateAdminToken, upload.single('image'), async (req, res) => {
  const { code, discount, description } = req.body;
  if (!code || !discount) {
    return res.status(400).json({ error: 'Code and discount are required' });
  }
  try {
    let imageUrl = null;
    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: 'delicute/coupons',
        allowed_formats: ['jpg', 'png'],
      });
      imageUrl = result.secure_url;
      await fs.unlink(req.file.path); // Delete local file
    }
    const [result] = await pool.query(
      'INSERT INTO coupons (code, discount, description, image) VALUES (?, ?, ?, ?)',
      [code, parseFloat(discount), description || null, imageUrl]
    );
    res.json({ message: 'Coupon added', id: result.insertId });
  } catch (error) {
    console.error('Add coupon error:', error.message);
    if (req.file) await fs.unlink(req.file.path).catch(() => {});
    res.status(500).json({ error: 'Failed to add coupon' });
  }
});

// Update coupon
router.put('/coupons/:id', authenticateAdminToken, upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { code, discount, description } = req.body;
  if (!code || !discount) {
    return res.status(400).json({ error: 'Code and discount are required' });
  }
  try {
    const [rows] = await pool.query('SELECT image FROM coupons WHERE id = ?', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Coupon not found' });
    }
    let imageUrl = rows[0].image;
    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: 'delicute/coupons',
        allowed_formats: ['jpg', 'png'],
      });
      imageUrl = result.secure_url;
      await fs.unlink(req.file.path); // Delete local file
      if (rows[0].image) {
        const publicId = rows[0].image.split('/').pop().split('.')[0];
        await cloudinary.uploader.destroy(`delicute/coupons/${publicId}`).catch(() => {});
      }
    }
    await pool.query(
      'UPDATE coupons SET code = ?, discount = ?, description = ?, image = ? WHERE id = ?',
      [code, parseFloat(discount), description || null, imageUrl, id]
    );
    res.json({ message: 'Coupon updated' });
  } catch (error) {
    console.error('Update coupon error:', error.message);
    if (req.file) await fs.unlink(req.file.path).catch(() => {});
    res.status(500).json({ error: 'Failed to update coupon' });
  }
});

// Delete coupon
router.delete('/coupons/:id', authenticateAdminToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query('SELECT image FROM coupons WHERE id = ?', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Coupon not found' });
    }
    if (rows[0].image) {
      const publicId = rows[0].image.split('/').pop().split('.')[0];
      await cloudinary.uploader.destroy(`delicute/coupons/${publicId}`).catch(() => {});
    }
    await pool.query('DELETE FROM coupons WHERE id = ?', [id]);
    res.json({ message: 'Coupon deleted' });
  } catch (error) {
    console.error('Delete coupon error:', error.message);
    res.status(500).json({ error: 'Failed to delete coupon' });
  }
});

// Get all customers
router.get('/customers', authenticateAdminToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, email, phone, status FROM users WHERE role = ?', ['user']);
    res.json(rows);
  } catch (error) {
    console.error('Customer fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

// Toggle customer status
router.put('/customers/:id/status', authenticateAdminToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!['active', 'blocked'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  try {
    const [rows] = await pool.query('SELECT id FROM users WHERE id = ? AND role = ?', [id, 'user']);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }
    await pool.query('UPDATE users SET status = ? WHERE id = ?', [status, id]);
    res.json({ message: `Customer ${status === 'blocked' ? 'blocked' : 'unblocked'}` });
  } catch (error) {
    console.error('Toggle customer status error:', error.message);
    res.status(500).json({ error: 'Failed to update customer status' });
  }
});

// Get all orders
router.get('/orders', authenticateAdminToken, async (req, res) => {
  try {
    const [orders] = await pool.query(`
      SELECT 
        o.id, o.user_id, o.total, o.delivery, o.payment_status, o.status, o.created_at,
        u.name AS user_name, u.email AS user_email,
        a.full_name, a.house_no, a.location, a.landmark, a.mobile,
        c.code AS coupon_code
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      LEFT JOIN addresses a ON o.address_id = a.id
      LEFT JOIN coupons c ON o.coupon_id = c.id
    `);
    const orderIds = orders.map((order) => order.id);
    let items = [];
    if (orderIds.length > 0) {
      [items] = await pool.query(`
        SELECT oi.order_id, oi.quantity, oi.price, m.name
        FROM order_items oi
        JOIN menu_items m ON oi.menu_item_id = m.id
        WHERE oi.order_id IN (?)
      `, [orderIds]);
    }
    const ordersWithDetails = orders.map((order) => ({
      id: order.id,
      user: { name: order.user_name || 'Unknown', email: order.user_email || '-' },
      address: {
        fullName: order.full_name || '',
        houseNo: order.house_no || '',
        location: order.location || '',
        landmark: order.landmark || '',
        mobile: order.mobile || '',
      },
      items: items
        .filter((item) => item.order_id === order.id)
        .map((item) => ({
          name: item.name || 'Unknown',
          quantity: item.quantity,
          price: item.price,
        })),
      total: order.total || 0,
      delivery: order.delivery || 0,
      couponCode: order.coupon_code || null,
      paymentStatus: order.payment_status || 'pending',
      status: order.status || 'pending',
      date: order.created_at,
    }));
    res.json(ordersWithDetails);
  } catch (error) {
    console.error('Order fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Get order details
router.get('/orders/:id', authenticateAdminToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [orders] = await pool.query(`
      SELECT 
        o.id, o.user_id, o.total, o.delivery, o.payment_method, o.payment_status, o.status, o.created_at,
        u.name AS user_name, u.email AS user_email,
        a.full_name, a.house_no, a.location, a.landmark, a.mobile,
        c.code AS coupon_code
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      LEFT JOIN addresses a ON o.address_id = a.id
      LEFT JOIN coupons c ON o.coupon_id = c.id
      WHERE o.id = ?
    `, [id]);
    if (orders.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    const order = orders[0];
    const [items] = await pool.query(`
      SELECT oi.quantity, oi.price, m.name
      FROM order_items oi
      JOIN menu_items m ON oi.menu_item_id = m.id
      WHERE oi.order_id = ?
    `, [id]);
    const orderDetails = {
      id: order.id,
      user: { name: order.user_name || 'Unknown', email: order.user_email || '-' },
      address: {
        fullName: order.full_name || '',
        houseNo: order.house_no || '',
        location: order.location || '',
        landmark: order.landmark || '',
        mobile: order.mobile || '',
      },
      items: items.map((item) => ({
        name: item.name || 'Unknown',
        quantity: item.quantity,
        price: item.price,
      })),
      total: order.total || 0,
      delivery: order.delivery || 0,
      couponCode: order.coupon_code || null,
      paymentMethod: order.payment_method || 'cod',
      paymentStatus: order.payment_status || 'pending',
      status: order.status || 'pending',
      date: order.created_at,
    };
    res.json(orderDetails);
  } catch (error) {
    console.error('Order details fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch order details' });
  }
});

// Update order status
router.put('/orders/:id', authenticateAdminToken, async (req, res) => {
  const { id } = req.params;
  const { status, paymentStatus } = req.body;
  if (!status || !['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  try {
    const [rows] = await pool.query('SELECT id FROM orders WHERE id = ?', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    const updates = { status };
    if (paymentStatus && ['pending', 'paid', 'failed'].includes(paymentStatus)) {
      updates.payment_status = paymentStatus;
    }
    const fields = Object.keys(updates).map((key) => `${key} = ?`).join(', ');
    const values = Object.values(updates).concat([id]);
    await pool.query(`UPDATE orders SET ${fields} WHERE id = ?`, values);
    res.json({ message: 'Order updated' });
  } catch (error) {
    console.error('Update order error:', error.message);
    res.status(500).json({ error: 'Failed to update order' });
  }
});

// Logout
router.post('/logout', authenticateAdminToken, async (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

module.exports = router;