const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Configure Multer with Cloudinary storage
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'delicute',
    allowed_formats: ['jpg', 'png'],
    transformation: [{ width: 500, height: 500, crop: 'limit' }],
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/png') {
      cb(null, true);
    } else {
      cb(new Error('Only JPEG and PNG images are allowed'), false);
    }
  },
});

// Middleware to verify admin JWT
const verifyAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.admin) {
      return res.status(403).json({ error: 'Not an admin' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    console.error('JWT verification error:', error.message);
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Get database pool from app settings
const getPool = (req) => req.app.get('dbPool');

// Menu Items Routes
router.get('/menu', verifyAdmin, async (req, res, next) => {
  console.log('Handling GET /api/admin/dashboard/menu');
  try {
    const pool = await getPool(req);
    const [rows] = await pool.query('SELECT * FROM menu_items');
    res.json(rows);
  } catch (error) {
    console.error('Error in GET /menu:', error.message);
    next(error);
  }
});

router.post('/menu', verifyAdmin, upload.single('image'), async (req, res, next) => {
  console.log('Handling POST /api/admin/dashboard/menu');
  const { name, price, category, description } = req.body;
  if (!name || !price || !category) {
    return res.status(400).json({ error: 'Name, price, and category are required' });
  }
  try {
    const pool = await getPool(req);
    const imageUrl = req.file ? req.file.path : null;
    const [result] = await pool.query(
      'INSERT INTO menu_items (name, price, category, description, image) VALUES (?, ?, ?, ?, ?)',
      [name, parseFloat(price), category, description || null, imageUrl]
    );
    res.status(201).json({ id: result.insertId, message: 'Menu item added' });
  } catch (error) {
    console.error('Error in POST /menu:', error.message);
    next(error);
  }
});

router.put('/menu/:id', verifyAdmin, upload.single('image'), async (req, res, next) => {
  console.log(`Handling PUT /api/admin/dashboard/menu/${req.params.id}`);
  const { id } = req.params;
  const { name, price, category, description } = req.body;
  if (!name || !price || !category) {
    return res.status(400).json({ error: 'Name, price, and category are required' });
  }
  try {
    const pool = await getPool(req);
    let imageUrl = req.file ? req.file.path : null;
    if (!imageUrl) {
      const [rows] = await pool.query('SELECT image FROM menu_items WHERE id = ?', [id]);
      imageUrl = rows[0]?.image;
    }
    const [result] = await pool.query(
      'UPDATE menu_items SET name = ?, price = ?, category = ?, description = ?, image = ? WHERE id = ?',
      [name, parseFloat(price), category, description || null, imageUrl, id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    res.json({ message: 'Menu item updated' });
  } catch (error) {
    console.error(`Error in PUT /menu/${id}:`, error.message);
    next(error);
  }
});

router.delete('/menu/:id', verifyAdmin, async (req, res, next) => {
  console.log(`Handling DELETE /api/admin/dashboard/menu/${req.params.id}`);
  const { id } = req.params;
  try {
    const pool = await getPool(req);
    const [rows] = await pool.query('SELECT image FROM menu_items WHERE id = ?', [id]);
    if (rows[0]?.image) {
      const publicId = rows[0].image.split('/').pop().split('.')[0];
      await cloudinary.uploader.destroy(`delicute/${publicId}`);
    }
    const [result] = await pool.query('DELETE FROM menu_items WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    res.json({ message: 'Menu item deleted' });
  } catch (error) {
    console.error(`Error in DELETE /menu/${id}:`, error.message);
    next(error);
  }
});

// Coupons Routes
router.get('/coupons', verifyAdmin, async (req, res, next) => {
  console.log('Handling GET /api/admin/dashboard/coupons');
  try {
    const pool = await getPool(req);
    const [rows] = await pool.query('SELECT * FROM coupons');
    res.json(rows);
  } catch (error) {
    console.error('Error in GET /coupons:', error.message);
    next(error);
  }
});

router.post('/coupons', verifyAdmin, upload.single('image'), async (req, res, next) => {
  console.log('Handling POST /api/admin/dashboard/coupons');
  const { code, discount, description } = req.body;
  if (!code || !discount) {
    return res.status(400).json({ error: 'Code and discount are required' });
  }
  try {
    const pool = await getPool(req);
    const imageUrl = req.file ? req.file.path : null;
    const [result] = await pool.query(
      'INSERT INTO coupons (code, discount, description, image) VALUES (?, ?, ?, ?)',
      [code, parseFloat(discount), description || null, imageUrl]
    );
    res.status(201).json({ id: result.insertId, message: 'Coupon added' });
  } catch (error) {
    console.error('Error in POST /coupons:', error.message);
    next(error);
  }
});

router.put('/coupons/:id', verifyAdmin, upload.single('image'), async (req, res, next) => {
  console.log(`Handling PUT /api/admin/dashboard/coupons/${req.params.id}`);
  const { id } = req.params;
  const { code, discount, description } = req.body;
  if (!code || !discount) {
    return res.status(400).json({ error: 'Code and discount are required' });
  }
  try {
    const pool = await getPool(req);
    let imageUrl = req.file ? req.file.path : null;
    if (!imageUrl) {
      const [rows] = await pool.query('SELECT image FROM coupons WHERE id = ?', [id]);
      imageUrl = rows[0]?.image;
    }
    const [result] = await pool.query(
      'UPDATE coupons SET code = ?, discount = ?, description = ?, image = ? WHERE id = ?',
      [code, parseFloat(discount), description || null, imageUrl, id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Coupon not found' });
    }
    res.json({ message: 'Coupon updated' });
  } catch (error) {
    console.error(`Error in PUT /coupons/${id}:`, error.message);
    next(error);
  }
});

router.delete('/coupons/:id', verifyAdmin, async (req, res, next) => {
  console.log(`Handling DELETE /api/admin/dashboard/coupons/${req.params.id}`);
  const { id } = req.params;
  try {
    const pool = await getPool(req);
    const [rows] = await pool.query('SELECT image FROM coupons WHERE id = ?', [id]);
    if (rows[0]?.image) {
      const publicId = rows[0].image.split('/').pop().split('.')[0];
      await cloudinary.uploader.destroy(`delicute/${publicId}`);
    }
    const [result] = await pool.query('DELETE FROM coupons WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Coupon not found' });
    }
    res.json({ message: 'Coupon deleted' });
  } catch (error) {
    console.error(`Error in DELETE /coupons/${id}:`, error.message);
    next(error);
  }
});

// Customers Routes
router.get('/customers', verifyAdmin, async (req, res, next) => {
  console.log('Handling GET /api/admin/dashboard/customers');
  try {
    const pool = await getPool(req);
    const [rows] = await pool.query('SELECT id, name, email, phone, status FROM users WHERE role = "customer"');
    res.json(rows);
  } catch (error) {
    console.error('Error in GET /customers:', error.message);
    next(error);
  }
});

router.put('/customers/:id/status', verifyAdmin, async (req, res, next) => {
  console.log(`Handling PUT /api/admin/dashboard/customers/${req.params.id}/status`);
  const { id } = req.params;
  const { status } = req.body;
  if (!['active', 'blocked'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  try {
    const pool = await getPool(req);
    const [result] = await pool.query('UPDATE users SET status = ? WHERE id = ? AND role = "customer"', [status, id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }
    res.json({ message: `Customer ${status === 'blocked' ? 'blocked' : 'unblocked'}` });
  } catch (error) {
    console.error(`Error in PUT /customers/${id}/status:`, error.message);
    next(error);
  }
});

// Orders Routes
router.get('/orders', verifyAdmin, async (req, res, next) => {
  console.log('Handling GET /api/admin/dashboard/orders');
  try {
    const pool = await getPool(req);
    const [rows] = await pool.query(`
      SELECT o.*, u.name AS user_name
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
    `);
    // Parse JSON fields if stored as strings
    const orders = rows.map(order => ({
      ...order,
      items: typeof order.items === 'string' ? JSON.parse(order.items) : order.items,
      address: typeof order.address === 'string' ? JSON.parse(order.address) : order.address,
      user: { name: order.user_name },
    }));
    res.json(orders);
  } catch (error) {
    console.error('Error in GET /orders:', error.message);
    next(error);
  }
});

router.put('/orders/:id', verifyAdmin, async (req, res, next) => {
  console.log(`Handling PUT /api/admin/dashboard/orders/${req.params.id}`);
  const { id } = req.params;
  const { status } = req.body;
  if (!['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  try {
    const pool = await getPool(req);
    const [result] = await pool.query('UPDATE orders SET status = ? WHERE id = ?', [status, id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json({ message: 'Order status updated' });
  } catch (error) {
    console.error(`Error in PUT /orders/${id}:`, error.message);
    next(error);
  }
});

module.exports = router;