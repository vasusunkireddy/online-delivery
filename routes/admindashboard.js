const express = require('express');
const router = express.Router();
const path = require('path');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const nodemailer = require('nodemailer');
const cors = require('cors');

// Enable CORS for all routes (adjust origin as needed for production)
router.use(cors({
  origin: ['http://localhost:3000', 'https://your-frontend-domain.com'], // Update with your frontend domain
  credentials: true,
}));

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, '../public/uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer configuration for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${Date.now()}-${Math.random().toString(36).substring(7)}${ext}`);
  },
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Only JPEG, PNG, GIF, and WebP images are allowed'), false);
  }
};

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter,
});

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Middleware to verify admin JWT
const authenticateAdmin = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_fallback');
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied: Admin only' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Serve static files (e.g., uploaded images)
router.use('/uploads', express.static(uploadDir));

// Serve admindashboard.html
router.get('/', authenticateAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, '../public', 'admindashboard.html'));
});

// File Upload API
router.post('/api/files/upload', authenticateAdmin, upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    res.json({ fileUrl });
  } catch (error) {
    console.error('File upload error:', error.message);
    res.status(500).json({ error: 'Failed to upload file', details: error.message });
  }
});

// Profile APIs
router.get('/api/auth/admin/me', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [users] = await connection.query(
      'SELECT id, name, email, phone, profile_image FROM users WHERE id = ? AND role = ?',
      [req.user.id, 'admin']
    );
    if (users.length === 0) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    res.json(users[0]);
  } catch (error) {
    console.error('Fetch admin profile error:', error.message);
    res.status(500).json({ error: 'Failed to fetch profile', details: error.message });
  } finally {
    if (connection) await connection.end();
  }
});

router.put('/api/auth/admin/profile', authenticateAdmin, async (req, res) => {
  const { profileImage } = req.body;
  if (!profileImage) {
    return res.status(400).json({ error: 'Profile image URL is required' });
  }

  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    await connection.query(
      'UPDATE users SET profile_image = ? WHERE id = ? AND role = ?',
      [profileImage, req.user.id, 'admin']
    );
    res.json({ message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Update admin profile error:', error.message);
    res.status(500).json({ error: 'Failed to update profile', details: error.message });
  } finally {
    if (connection) await connection.end();
  }
});

// Menu APIs
router.get('/api/menu', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [items] = await connection.query('SELECT * FROM menu_items');
    res.json(items);
  } catch (error) {
    console.error('Error fetching menu items:', error);
    res.status(500).json({ error: 'Failed to fetch menu items', details: error.message });
  } finally {
    if (connection) await connection.end();
  }
});

router.post('/api/menu', authenticateAdmin, async (req, res) => {
  const { name, price, discount, image, description } = req.body;
  if (!name || !price || !category) {
    return res.status(400).json({ error: 'Missing required fields: name, price, category' });
  }

  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [rows] = await connection.query(
      'INSERT INTO menu_items (name, price, category, image, description) VALUES (?, ?, ?, ?, ?)',
      [name, price, category, image || null, description || null]
    );

    res.json({ id: rows.insertId, name, price, category, image, description });
  } catch (error) {
    console.error('Error creating menu item:', error);
    res.status(500).json({ error: 'Failed to create menu item', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

router.post('/api/menu', authenticateAdmin, async (req, res) => {
  const { name, price, category, image, description } = req.body;
  if (!name || !price || !category) {
    return res.status(400).json({ error: 'Missing required fields: name, price, category' });
  }

  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [result] = await connection.query(
      'INSERT INTO menu_items (name, price, category, image, description) VALUES (?, ?, ?, ?, ?)',
      [name, price, category, image || null, description || null]
    );

    res.json({ id: result.insertId, name, price, category, image, description });
  } catch (error) {
    console.error('Error creating menu item:', error);
    res.status(500).json({ error: 'Failed to create menu item', details: error.message });
  } finally {
    if (connection) await connection.end();
  }
});

router.get('/api/menu/:id', authenticateAdmin, async (req, res) => {
  // Validate ID
  const id = parseInt(req.params.id, 10);
  if (isNaN(id) || id <= 0) {
    return res.status(400).json({ error: 'Invalid menu item ID' });
  }

  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [rows] = await connection.query('SELECT id, name, price, category, image, description FROM menu_items WHERE id = ?', [id]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }

    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching menu item:', error.message);
    res.status(500).json({ error: 'Failed to fetch menu item', details: error.message });
  } finally {
    if (connection) await connection.end();
  }
});
router.put('/api/menu/:id', authenticateAdmin, async (req, res) => {
  const { name, price, category, description, image } = req.body;
  if (!name || !price || !category) {
    return res.status(400).json({ error: 'Missing required fields: name, price, category' });
  }

  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [rows] = await connection.query(
      'UPDATE menu_items SET name = ?, price = ?, category = ?, image = ?, description = ? WHERE id = ?',
      [name, price, category, image || null, description || null, req.params.id]
    );

    if (rows.affectedRows === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }

    res.json({ message: 'Menu item updated successfully' });
  } catch (error) {
    console.error('Error updating menu item:', error);
    res.status(500).json({ error: 'Failed to update menu item', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

router.delete('/api/menu/:id', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [rows] = await connection.query('DELETE FROM menu_items WHERE id = ?', [req.params.id]);

    if (rows.affectedRows === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }

    res.json({ message: 'Menu item deleted successfully' });
  } catch (error) {
    console.error('Error deleting menu item:', error);
    res.status(500).json({ error: 'Failed to delete menu item', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

// Order APIs
router.get('/api/orders', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [rows] = await connection.query(`
      SELECT o.*, u.name AS customerName, u.email AS customerEmail, u.phone AS customerPhone
      FROM orders o
      JOIN users u ON o.user_id = u.id
    `);
    res.json(rows);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

router.get('/api/orders/:id', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [rows] = await connection.query(`
      SELECT o.*, u.name AS customerName, u.email AS customerEmail, u.phone AS customerPhone
      FROM orders o
      JOIN users u ON o.user_id = u.id
      WHERE o.id = ?
    `, [req.params.id]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching order:', error);
    res.status(500).json({ error: 'Failed to fetch order', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

router.put('/api/orders/:id', authenticateAdmin, async (req, res) => {
  const { status } = req.body;
  if (!status) {
    return res.status(400).json({ error: 'Status is required' });
  }

  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [rows] = await connection.query(
      'UPDATE orders SET status = ? WHERE id = ?',
      [status, req.params.id]
    );

    if (rows.affectedRows === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    res.json({ message: 'Order status updated successfully' });
  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).json({ error: 'Failed to update order status', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

router.post('/api/orders/:id/refund', authenticateAdmin, async (req, res) => {
  const { paymentMethod } = req.body;
  if (!['PhonePe', 'GPay'].includes(paymentMethod)) {
    return res.status(400).json({ error: 'Invalid payment method' });
  }

  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [rows] = await connection.query(
      'SELECT * FROM orders WHERE id = ?',
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const order = rows[0];
    if (order.status !== 'Cancelled' || order.payment_status !== 'Paid') {
      return res.status(400).json({ error: 'Order not eligible for refund' });
    }

    // Simulate refund processing (replace with actual payment gateway integration)
    await connection.query(
      'UPDATE orders SET payment_status = ? WHERE id = ?',
      ['Refunded', req.params.id]
    );

    res.json({ message: 'Refund processed successfully' });
  } catch (error) {
    console.error('Error processing refund:', error);
    res.status(500).json({ error: 'Failed to process refund', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

router.delete('/api/orders/:id', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [rows] = await connection.query(
      'SELECT status FROM orders WHERE id = ?',
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    if (!['Delivered', 'Cancelled'].includes(rows[0].status)) {
      return res.status(400).json({ error: 'Only Delivered or Cancelled orders can be deleted' });
    }

    await connection.query('DELETE FROM orders WHERE id = ?', [req.params.id]);
    res.json({ message: 'Order deleted successfully' });
  } catch (error) {
    console.error('Error deleting order:', error);
    res.status(500).json({ error: 'Failed to delete order', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

router.get('/api/orders/user/:userId', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [rows] = await connection.query(
      'SELECT * FROM orders WHERE user_id = ?',
      [req.params.userId]
    );

    res.json(rows);
  } catch (error) {
    console.error('Error fetching user orders:', error);
    res.status(500).json({ error: 'Failed to fetch user orders', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

// Coupon APIs
router.get('/api/coupons', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [rows] = await connection.query('SELECT * FROM coupons');
    res.json(rows);
  } catch (error) {
    console.error('Error fetching coupons:', error);
    res.status(500).json({ error: 'Failed to fetch coupons', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

router.post('/api/coupons', authenticateAdmin, async (req, res) => {
  const { code, discount, image, description } = req.body;
  if (!code || !discount) {
    return res.status(400).json({ error: 'Code and discount are required' });
  }

  if (!/^[A-Z0-9]{5,15}$/.test(code)) {
    return res.status(400).json({ error: 'Invalid coupon code format' });
  }

  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [rows] = await connection.query(
      'SELECT * FROM coupons WHERE code = ?',
      [code]
    );

    if (rows.length > 0) {
      return res.status(400).json({ error: 'Coupon code already exists' });
    }

    const [result] = await connection.query(
      'INSERT INTO coupons (code, discount, image, description) VALUES (?, ?, ?, ?)',
      [code, discount, image || null, description || null]
    );

    res.json({ id: result.insertId, code, discount, image, description });
  } catch (error) {
    console.error('Error creating coupon:', error);
    res.status(500).json({ error: 'Failed to create coupon', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

router.get('/api/coupons/:id', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [rows] = await connection.query(
      'SELECT * FROM coupons WHERE id = ?',
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Coupon not found' });
    }

    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching coupon:', error);
    res.status(500).json({ error: 'Failed to fetch coupon', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

router.put('/api/coupons/:id', authenticateAdmin, async (req, res) => {
  const { code, discount, image, description } = req.body;
  if (!code || !discount) {
    return res.status(400).json({ error: 'Code and discount are required' });
  }

  if (!/^[A-Z0-9]{5,15}$/.test(code)) {
    return res.status(400).json({ error: 'Invalid coupon code format' });
  }

  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [rows] = await connection.query(
      'SELECT * FROM coupons WHERE code = ? AND id != ?',
      [code, req.params.id]
    );

    if (rows.length > 0) {
      return res.status(400).json({ error: 'Coupon code already exists' });
    }

    const [result] = await connection.query(
      'UPDATE coupons SET code = ?, discount = ?, image = ?, description = ? WHERE id = ?',
      [code, discount, image || null, description || null, req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Coupon not found' });
    }

    res.json({ message: 'Coupon updated successfully' });
  } catch (error) {
    console.error('Error updating coupon:', error);
    res.status(500).json({ error: 'Failed to update coupon', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

router.delete('/api/coupons/:id', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [result] = await connection.query(
      'DELETE FROM coupons WHERE id = ?',
      [req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Coupon not found' });
    }

    res.json({ message: 'Coupon deleted successfully' });
  } catch (error) {
    console.error('Error deleting coupon:', error);
    res.status(500).json({ error: 'Failed to delete coupon', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

// Customer APIs
router.get('/api/users', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [rows] = await connection.query(
      'SELECT id, name, email, phone, address, status FROM users WHERE role = ?',
      ['user']
    );

    res.json(rows);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

router.get('/api/users/:id', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [rows] = await connection.query(
      'SELECT id, name, email, phone, address, status FROM users WHERE id = ? AND role = ?',
      [req.params.id, 'user']
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

router.put('/api/users/:id/status', authenticateAdmin, async (req, res) => {
  const { status } = req.body;
  if (!['Active', 'Blocked'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'delicute',
    });

    const [result] = await connection.query(
      'UPDATE users SET status = ? WHERE id = ? AND role = ?',
      [status, req.params.id, 'user']
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: `User ${status.toLowerCase()} successfully` });
  } catch (error) {
    console.error('Error updating user status:', error);
    res.status(500).json({ error: 'Failed to update user status', details: error.message });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

// Contact APIs
router.get('/api/contact', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME
    });

    const [messages] = await connection.query('SELECT * FROM contacts');
    res.json(messages);
  } catch (error) {
    console.error('Fetch contact messages error:', error.message);
    res.status(500).json({ error: 'Failed to fetch contact messages', details: error.message });
  } finally {
    if (connection) await connection.end();
  }
});

router.post('/api/contact/:id/reply', authenticateAdmin, async (req, res) => {
  const { subject, message } = req.body;
  if (!subject || !message) {
    return res.status(400).json({ error: 'Subject and message are required' });
  }

  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME
    });

    const [contacts] = await connection.query('SELECT email FROM contacts WHERE id = ?', [req.params.id]);
    if (contacts.length === 0) {
      return res.status(404).json({ error: 'Contact message not found' });
    }

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: contacts[0].email,
      subject: subject,
      text: message
    };

    await transporter.sendMail(mailOptions);
    await connection.query('UPDATE contacts SET status = ? WHERE id = ?', ['Replied', req.params.id]);
    res.json({ message: 'Reply sent successfully' });
  } catch (error) {
    console.error('Send contact reply error:', error.message);
    res.status(500).json({ error: 'Failed to send reply', details: error.message });
  } finally {
    if (connection) await connection.end();
  }
});

router.delete('/api/contact/:id', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME
    });

    const [result] = await connection.query('DELETE FROM contacts WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Contact message not found' });
    }

    res.json({ message: 'Contact message deleted successfully' });
  } catch (error) {
    console.error('Delete contact message error:', error.message);
    res.status(500).json({ error: 'Failed to delete contact message', details: error.message });
  } finally {
    if (connection) await connection.end();
  }
});

// Restaurant Status APIs
router.get('/api/restaurant/status', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME
    });

    const [status] = await connection.query('SELECT is_open FROM restaurant_status WHERE id = 1');
    if (status.length === 0) {
      await connection.query('INSERT INTO restaurant_status (id, is_open) VALUES (1, false)');
      return res.json({ isOpen: false });
    }

    res.json({ isOpen: status[0].is_open });
  } catch (error) {
    console.error('Fetch restaurant status error:', error.message);
    res.status(500).json({ error: 'Failed to fetch restaurant status', details: error.message });
  } finally {
    if (connection) await connection.end();
  }
});

router.put('/api/restaurant/status', authenticateAdmin, async (req, res) => {
  let connection;
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME
    });

    const [status] = await connection.query('SELECT is_open FROM restaurant_status WHERE id = 1');
    const newStatus = !status[0]?.is_open;

    if (status.length === 0) {
      await connection.query('INSERT INTO restaurant_status (id, is_open) VALUES (1, ?)', [newStatus]);
    } else {
      await connection.query('UPDATE restaurant_status SET is_open = ? WHERE id = 1', [newStatus]);
    }

    res.json({ isOpen: newStatus });
  } catch (error) {
    console.error('Update restaurant status error:', error.message);
    res.status(500).json({ error: 'Failed to update restaurant status', details: error.message });
  } finally {
    if (connection) await connection.end();
  }
});

module.exports = router;