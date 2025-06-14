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
    cb(null, 'uploads/');
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
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Database pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// Middleware to verify admin JWT
function authenticateAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err || !user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    req.user = user;
    next();
  });
}

// Get all menu items (public endpoint, used in index.js)
router.get('/menu', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM menu_items');
    res.json(rows);
  } catch (error) {
    console.error('Error fetching menu items:', error);
    res.status(500).json({ error: 'Failed to fetch menu items' });
  }
});

// Add menu item
router.post('/menu', authenticateAdmin, upload.single('image'), async (req, res) => {
  const { name, price, category, description } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;

  if (!name || !price || !category) {
    return res.status(400).json({ error: 'Name, price, and category are required' });
  }

  try {
    await pool.query(
      'INSERT INTO menu_items (name, price, category, description, image) VALUES (?, ?, ?, ?, ?)',
      [name, parseFloat(price), category, description || null, image]
    );
    res.json({ message: 'Menu item added successfully' });
  } catch (error) {
    console.error('Error adding menu item:', error);
    res.status(500).json({ error: 'Failed to add menu item' });
  }
});

// Update menu item
router.put('/menu/:id', authenticateAdmin, upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { name, price, category, description } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;

  if (!name || !price || !category) {
    return res.status(400).json({ error: 'Name, price, and category are required' });
  }

  try {
    const [existing] = await pool.query('SELECT image FROM menu_items WHERE id = ?', [id]);
    if (existing.length === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }

    const updateFields = { name, price: parseFloat(price), category, description: description || null };
    const queryParams = [name, parseFloat(price), category, description || null];

    if (image) {
      updateFields.image = image;
      queryParams.push(image);
    }

    queryParams.push(id);

    await pool.query(
      `UPDATE menu_items SET name = ?, price = ?, category = ?, description = ?${image ? ', image = ?' : ''} WHERE id = ?`,
      queryParams
    );
    res.json({ message: 'Menu item updated successfully' });
  } catch (error) {
    console.error('Error updating menu item:', error);
    res.status(500).json({ error: 'Failed to update menu item' });
  }
});

// Delete menu item
router.delete('/menu/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query('DELETE FROM menu_items WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    res.json({ message: 'Menu item deleted successfully' });
  } catch (error) {
    console.error('Error deleting menu item:', error);
    res.status(500).json({ error: 'Failed to delete menu item' });
  }
});

// Get all coupons
router.get('/coupons', authenticateAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM coupons');
    res.json(rows);
  } catch (error) {
    console.error('Error fetching coupons:', error);
    res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

// Add coupon
router.post('/coupons', authenticateAdmin, upload.single('image'), async (req, res) => {
  const { code, discount } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;

  if (!code || !discount) {
    return res.status(400).json({ error: 'Code and discount are required' });
  }

  try {
    await pool.query(
      'INSERT INTO coupons (code, discount, image) VALUES (?, ?, ?)',
      [code, parseFloat(discount), image]
    );
    res.json({ message: 'Coupon added successfully' });
  } catch (error) {
    console.error('Error adding coupon:', error);
    res.status(500).json({ error: 'Failed to add coupon' });
  }
});

// Update coupon
router.put('/coupons/:id', authenticateAdmin, upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { code, discount } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;

  if (!code || !discount) {
    return res.status(400).json({ error: 'Code and discount are required' });
  }

  try {
    const [existing] = await pool.query('SELECT image FROM coupons WHERE id = ?', [id]);
    if (existing.length === 0) {
      return res.status(404).json({ error: 'Coupon not found' });
    }

    const updateFields = { code, discount: parseFloat(discount) };
    const queryParams = [code, parseFloat(discount)];

    if (image) {
      updateFields.image = image;
      queryParams.push(image);
    }

    queryParams.push(id);

    await pool.query(
      `UPDATE coupons SET code = ?, discount = ?${image ? ', image = ?' : ''} WHERE id = ?`,
      queryParams
    );
    res.json({ message: 'Coupon updated successfully' });
  } catch (error) {
    console.error('Error updating coupon:', error);
    res.status(500).json({ error: 'Failed to update coupon' });
  }
});

// Delete coupon
router.delete('/coupons/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query('DELETE FROM coupons WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Coupon not found' });
    }
    res.json({ message: 'Coupon deleted successfully' });
  } catch (error) {
    console.error('Error deleting coupon:', error);
    res.status(500).json({ error: 'Failed to delete coupon' });
  }
});

// Get all customers
router.get('/customers', authenticateAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, email, phone FROM users WHERE is_admin = FALSE');
    res.json(rows);
  } catch (error) {
    console.error('Error fetching customers:', error);
    res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

// Get all orders
router.get('/orders', authenticateAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT o.id, o.user_id, o.total, o.status, u.name
      FROM orders o
      JOIN users u ON o.user_id = u.id
    `);
    res.json(rows.map(row => ({
      id: row.id,
      User: { name: row.name },
      total: row.total,
      status: row.status
    })));
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Update order status
router.put('/orders/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  try {
    const [result] = await pool.query('UPDATE orders SET status = ? WHERE id = ?', [status, id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json({ message: 'Order status updated successfully' });
  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

module.exports = router;