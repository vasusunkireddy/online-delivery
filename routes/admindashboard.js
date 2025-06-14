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
  if (!token) {
    console.warn('Authentication failed: No token provided');
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.warn('Authentication failed: Invalid token', err.message);
      return res.status(403).json({ error: 'Invalid token' });
    }
    if (!user.isAdmin) {
      console.warn('Authentication failed: User is not admin', user);
      return res.status(403).json({ error: 'Admin access required' });
    }
    req.user = user;
    next();
  });
}

// Health check endpoint for debugging
router.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'OK', message: 'Backend and database are connected' });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(500).json({ status: 'ERROR', error: 'Database connection failed' });
  }
});

// Get all menu items (public endpoint)
router.get('/menu', async (req, res) => {
  try {
    console.log('Fetching menu items...');
    const [rows] = await pool.query('SELECT id, name, price, category, description, image FROM menu_items');
    console.log(`Fetched ${rows.length} menu items`);
    if (rows.length === 0) {
      console.warn('No menu items found in database');
      return res.json([]); // Return empty array for frontend consistency
    }
    // Ensure image paths are absolute for frontend access
    const items = rows.map(item => ({
      ...item,
      image: item.image ? `${process.env.BASE_URL || 'http://localhost:3000'}${item.image}` : null
    }));
    res.json(items);
  } catch (error) {
    console.error('Error fetching menu items:', error);
    res.status(500).json({ error: 'Failed to fetch menu items', details: error.message });
  }
});

// Add menu item
router.post('/menu', authenticateAdmin, upload.single('image'), async (req, res) => {
  const { name, price, category, description } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;

  if (!name || !price || !category) {
    console.warn('Missing required fields:', { name, price, category });
    return res.status(400).json({ error: 'Name, price, and category are required' });
  }

  try {
    console.log('Adding menu item:', { name, price, category, description, image });
    const [result] = await pool.query(
      'INSERT INTO menu_items (name, price, category, description, image) VALUES (?, ?, ?, ?, ?)',
      [name, parseFloat(price), category, description || null, image]
    );
    console.log(`Menu item added with ID: ${result.insertId}`);
    res.status(201).json({ message: 'Menu item added successfully', id: result.insertId });
  } catch (error) {
    console.error('Error adding menu item:', error);
    res.status(500).json({ error: 'Failed to add menu item', details: error.message });
  }
});

// Update menu item
router.put('/menu/:id', authenticateAdmin, upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { name, price, category, description } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;

  if (!name || !price || !category) {
    console.warn('Missing required fields:', { name, price, category });
    return res.status(400).json({ error: 'Name, price, and category are required' });
  }

  try {
    console.log(`Updating menu item ID: ${id}`);
    const [existing] = await pool.query('SELECT image FROM menu_items WHERE id = ?', [id]);
    if (existing.length === 0) {
      console.warn(`Menu item not found: ID ${id}`);
      return res.status(404).json({ error: 'Menu item not found' });
    }

    const queryParams = [name, parseFloat(price), category, description || null];
    let query = 'UPDATE menu_items SET name = ?, price = ?, category = ?, description = ?';
    if (image) {
      query += ', image = ?';
      queryParams.push(image);
    }
    query += ' WHERE id = ?';
    queryParams.push(id);

    await pool.query(query, queryParams);
    console.log(`Menu item updated: ID ${id}`);
    res.json({ message: 'Menu item updated successfully' });
  } catch (error) {
    console.error('Error updating menu item:', error);
    res.status(500).json({ error: 'Failed to update menu item', details: error.message });
  }
});

// Delete menu item
router.delete('/menu/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    console.log(`Deleting menu item ID: ${id}`);
    const [result] = await pool.query('DELETE FROM menu_items WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      console.warn(`Menu item not found: ID ${id}`);
      return res.status(404).json({ error: 'Menu item not found' });
    }
    console.log(`Menu item deleted: ID ${id}`);
    res.json({ message: 'Menu item deleted successfully' });
  } catch (error) {
    console.error('Error deleting menu item:', error);
    res.status(500).json({ error: 'Failed to delete menu item', details: error.message });
  }
});

// Get all coupons
router.get('/coupons', authenticateAdmin, async (req, res) => {
  try {
    console.log('Fetching coupons...');
    const [rows] = await pool.query('SELECT id, code, discount, description, image FROM coupons');
    console.log(`Fetched ${rows.length} coupons`);
    if (rows.length === 0) {
      console.warn('No coupons found in database');
      return res.json([]);
    }
    const coupons = rows.map(coupon => ({
      ...coupon,
      image: coupon.image ? `${process.env.BASE_URL || 'http://localhost:3000'}${coupon.image}` : null
    }));
    res.json(coupons);
  } catch (error) {
    console.error('Error fetching coupons:', error);
    res.status(500).json({ error: 'Failed to fetch coupons', details: error.message });
  }
});

// Add coupon
router.post('/coupons', authenticateAdmin, upload.single('image'), async (req, res) => {
  const { code, discount, description } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;

  if (!code || !discount) {
    console.warn('Missing required fields:', { code, discount });
    return res.status(400).json({ error: 'Code and discount are required' });
  }

  try {
    console.log('Adding coupon:', { code, discount, description, image });
    const [result] = await pool.query(
      'INSERT INTO coupons (code, discount, description, image) VALUES (?, ?, ?, ?)',
      [code, parseFloat(discount), description || null, image]
    );
    console.log(`Coupon added with ID: ${result.insertId}`);
    res.status(201).json({ message: 'Coupon added successfully', id: result.insertId });
  } catch (error) {
    console.error('Error adding coupon:', error);
    res.status(500).json({ error: 'Failed to add coupon', details: error.message });
  }
});

// Update coupon
router.put('/coupons/:id', authenticateAdmin, upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { code, discount, description } = req.body;
  const image = req.file ? `/uploads/${req.file.filename}` : null;

  if (!code || !discount) {
    console.warn('Missing required fields:', { code, discount });
    return res.status(400).json({ error: 'Code and discount are required' });
  }

  try {
    console.log(`Updating coupon ID: ${id}`);
    const [existing] = await pool.query('SELECT image FROM coupons WHERE id = ?', [id]);
    if (existing.length === 0) {
      console.warn(`Coupon not found: ID ${id}`);
      return res.status(404).json({ error: 'Coupon not found' });
    }

    const queryParams = [code, parseFloat(discount), description || null];
    let query = 'UPDATE coupons SET code = ?, discount = ?, description = ?';
    if (image) {
      query += ', image = ?';
      queryParams.push(image);
    }
    query += ' WHERE id = ?';
    queryParams.push(id);

    await pool.query(query, queryParams);
    console.log(`Coupon updated: ID ${id}`);
    res.json({ message: 'Coupon updated successfully' });
  } catch (error) {
    console.error('Error updating coupon:', error);
    res.status(500).json({ error: 'Failed to update coupon', details: error.message });
  }
});

// Delete coupon
router.delete('/coupons/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    console.log(`Deleting coupon ID: ${id}`);
    const [result] = await pool.query('DELETE FROM coupons WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      console.warn(`Coupon not found: ID ${id}`);
      return res.status(404).json({ error: 'Coupon not found' });
    }
    console.log(`Coupon deleted: ID ${id}`);
    res.json({ message: 'Coupon deleted successfully' });
  } catch (error) {
    console.error('Error deleting coupon:', error);
    res.status(500).json({ error: 'Failed to delete coupon', details: error.message });
  }
});

// Get all customers
router.get('/customers', authenticateAdmin, async (req, res) => {
  try {
    console.log('Fetching customers...');
    const [rows] = await pool.query(
      'SELECT id, name, email, phone, status FROM users WHERE is_admin = FALSE'
    );
    console.log(`Fetched ${rows.length} customers`);
    if (rows.length === 0) {
      console.warn('No customers found in database');
      return res.json([]);
    }
    res.json(rows);
  } catch (error) {
    console.error('Error fetching customers:', error);
    res.status(500).json({ error: 'Failed to fetch customers', details: error.message });
  }
});

// Update customer status (block/unblock)
router.put('/customers/:id/status', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!['active', 'blocked'].includes(status)) {
    console.warn('Invalid status provided:', status);
    return res.status(400).json({ error: 'Invalid status. Must be "active" or "blocked"' });
  }

  try {
    console.log(`Updating customer status ID: ${id}, Status: ${status}`);
    const [existing] = await pool.query('SELECT id FROM users WHERE id = ? AND is_admin = FALSE', [id]);
    if (existing.length === 0) {
      console.warn(`Customer not found: ID ${id}`);
      return res.status(404).json({ error: 'Customer not found' });
    }

    await pool.query('UPDATE users SET status = ? WHERE id = ?', [status, id]);
    console.log(`Customer status updated: ID ${id}, Status: ${status}`);
    res.json({ message: `Customer ${status === 'blocked' ? 'blocked' : 'unblocked'} successfully` });
  } catch (error) {
    console.error('Error updating customer status:', error);
    res.status(500).json({ error: 'Failed to update customer status', details: error.message });
  }
});

// Get all orders with items
router.get('/orders', authenticateAdmin, async (req, res) => {
  try {
    console.log('Fetching orders...');
    // Fetch orders with user info
    const [orders] = await pool.query(`
      SELECT o.id, o.user_id, o.total, o.status, u.name
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
    `);
    console.log(`Fetched ${orders.length} orders`);

    // Fetch order items for each order
    let orderItems = [];
    if (orders.length > 0) {
      const orderIds = orders.map(order => order.id);
      const [items] = await pool.query(`
        SELECT oi.order_id, oi.quantity, m.name
        FROM order_items oi
        LEFT JOIN menu_items m ON oi.menu_item_id = m.id
        WHERE oi.order_id IN (?)
      `, [orderIds]);
      orderItems = items;
      console.log(`Fetched ${orderItems.length} order items for ${orderIds.length} orders`);
    } else {
      console.warn('No orders found in database');
    }

    // Combine orders with their items
    const ordersWithItems = orders.map(order => ({
      id: order.id,
      User: { name: order.name || 'Unknown User' }, // Handle missing user
      total: parseFloat(order.total || 0).toFixed(2), // Ensure total is a string with 2 decimals
      status: order.status || 'pending', // Default status
      items: orderItems
        .filter(item => item.order_id === order.id)
        .map(item => ({
          name: item.name || 'Unknown Item', // Handle missing menu item
          quantity: item.quantity || 1
        }))
    }));

    res.json(ordersWithItems);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders', details: error.message });
  }
});

// Update order status
router.put('/orders/:id', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'].includes(status)) {
    console.warn('Invalid status provided:', status);
    return res.status(400).json({ error: 'Invalid status' });
  }

  try {
    console.log(`Updating order status ID: ${id}, Status: ${status}`);
    const [result] = await pool.query('UPDATE orders SET status = ? WHERE id = ?', [status, id]);
    if (result.affectedRows === 0) {
      console.warn(`Order not found: ID ${id}`);
      return res.status(404).json({ error: 'Order not found' });
    }
    console.log(`Order status updated: ID ${id}, Status: ${status}`);
    res.json({ message: 'Order status updated successfully' });
  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).json({ error: 'Failed to update order status', details: error.message });
  }
});

module.exports = router;