const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const { v4: uuidv4 } = require('uuid');

const uploadsDir = path.join(__dirname, '../public/uploads');
const maxFileSize = 5 * 1024 * 1024; // 5MB

// Temporary in-memory restaurant status (fallback)
let tempRestaurantStatus = 'closed';

// Ensure uploads directory exists
fs.mkdir(uploadsDir, { recursive: true }).catch(console.error);

// Multer storage configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const fileName = `${uuidv4()}_${file.originalname.replace(/\s+/g, '_')}`;
    cb(null, fileName);
  },
});

// Multer upload configuration
const upload = multer({
  storage,
  limits: { fileSize: maxFileSize },
  fileFilter: (req, file, cb) => {
    if (!file) {
      return cb(null, true); // Allow no file
    }
    if (!['image/jpeg', 'image/png'].includes(file.mimetype)) {
      return cb(new Error('Only JPEG or PNG images are allowed'), false);
    }
    cb(null, true);
  },
});

// Multer error handler middleware
const uploadErrorHandler = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    console.error('Multer Error:', {
      code: err.code,
      message: err.message,
      field: err.field,
    });
    if (err.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({ error: 'Unexpected field in form data. Expected "image".' });
    }
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'File too large. Maximum size is 5MB.' });
    }
    return res.status(400).json({ error: `Multer error: ${err.message}` });
  }
  if (err) {
    console.error('Upload error:', err.message);
    return res.status(400).json({ error: err.message });
  }
  next();
};

// Verify admin token
function verifyAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  console.log(`Verifying token: ${token ? 'Present' : 'Missing'}, SessionID: ${req.sessionID}, Source: Header`);
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log(`Decoded JWT: ${JSON.stringify(decoded)}`);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    console.error('JWT verification error:', error.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Check session
router.get('/check-session', verifyAdmin, (req, res) => {
  res.json({ valid: true });
});

// Get all menu items
router.get('/menu', verifyAdmin, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [items] = await pool.query('SELECT id, name, description, price, image, category FROM menu_items');
    res.json(items);
  } catch (error) {
    console.error('Error fetching menu items:', error.message);
    res.status(500).json({ error: 'Failed to fetch menu items' });
  }
});

// Add menu item
router.post('/menu', verifyAdmin, upload.single('image'), uploadErrorHandler, async (req, res) => {
  try {
    console.log('Menu POST data:', {
      body: req.body,
      file: req.file ? `${req.file.originalname} (${(req.file.size / 1024).toFixed(2)}KB)` : 'None',
    });
    const { name, price, description, category } = req.body;
    if (!name || !price || !category) {
      return res.status(400).json({ error: 'Name, price, and category are required' });
    }
    if (isNaN(parseFloat(price)) || parseFloat(price) <= 0) {
      return res.status(400).json({ error: 'Price must be a positive number' });
    }
    const pool = req.app.get('dbPool');
    let imagePath = null;
    if (req.file) {
      imagePath = `/uploads/${req.file.filename}`;
      console.log(`Uploaded menu image: ${req.file.filename}, size: ${(req.file.size / 1024).toFixed(2)}KB`);
    }
    const [result] = await pool.query(
      'INSERT INTO menu_items (name, price, description, category, image) VALUES (?, ?, ?, ?, ?)',
      [name, parseFloat(price), description || null, category, imagePath]
    );
    res.json({ id: result.insertId, message: 'Menu item added' });
  } catch (error) {
    console.error('Error adding menu item:', error.message);
    if (req.file) {
      await fs.unlink(path.join(uploadsDir, req.file.filename)).catch(() => {});
    }
    res.status(500).json({ error: 'Failed to add menu item' });
  }
});

// Update menu item
router.put('/menu/:id', verifyAdmin, upload.single('image'), uploadErrorHandler, async (req, res) => {
  try {
    console.log('Menu PUT data:', {
      body: req.body,
      file: req.file ? `${req.file.originalname} (${(req.file.size / 1024).toFixed(2)}KB)` : 'None',
    });
    const { id } = req.params;
    const { name, price, description, category } = req.body;
    if (!name || !price || !category) {
      return res.status(400).json({ error: 'Name, price, and category are required' });
    }
    if (isNaN(parseFloat(price)) || parseFloat(price) <= 0) {
      return res.status(400).json({ error: 'Price must be a positive number' });
    }
    const pool = req.app.get('dbPool');
    const [items] = await pool.query('SELECT image FROM menu_items WHERE id = ?', [id]);
    if (items.length === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    let imagePath = items[0].image;
    if (req.file) {
      imagePath = `/uploads/${req.file.filename}`;
      if (items[0].image) {
        await fs.unlink(path.join(uploadsDir, items[0].image.replace('/uploads/', ''))).catch(() => {});
      }
      console.log(`Updated menu image: ${req.file.filename}, size: ${(req.file.size / 1024).toFixed(2)}KB`);
    }
    await pool.query(
      'UPDATE menu_items SET name = ?, price = ?, description = ?, category = ?, image = ? WHERE id = ?',
      [name, parseFloat(price), description || null, category, imagePath, id]
    );
    res.json({ message: 'Menu item updated' });
  } catch (error) {
    console.error('Error updating menu item:', error.message);
    if (req.file) {
      await fs.unlink(path.join(uploadsDir, req.file.filename)).catch(() => {});
    }
    res.status(500).json({ error: 'Failed to update menu item' });
  }
});

// Delete menu item
router.delete('/menu/:id', verifyAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const pool = req.app.get('dbPool');
    const [items] = await pool.query('SELECT image FROM menu_items WHERE id = ?', [id]);
    if (items.length === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    if (items[0].image) {
      await fs.unlink(path.join(uploadsDir, items[0].image.replace('/uploads/', ''))).catch(() => {});
    }
    await pool.query('DELETE FROM menu_items WHERE id = ?', [id]);
    res.json({ message: 'Menu item deleted' });
  } catch (error) {
    console.error('Error deleting menu item:', error.message);
    res.status(500).json({ error: 'Failed to delete menu item' });
  }
});

// Get all coupons
router.get('/coupons', verifyAdmin, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [columns] = await pool.query("SHOW COLUMNS FROM coupons LIKE 'description'");
    const hasDescription = columns.length > 0;
    const descriptionField = hasDescription ? 'description' : 'NULL AS description';
    const [coupons] = await pool.query(
      `SELECT id, code, discount, image, ${descriptionField} FROM coupons WHERE expires_at > NOW()`
    );
    res.json(coupons);
  } catch (error) {
    console.error('Error fetching coupons:', error.message);
    res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

// Add coupon
router.post('/coupons', verifyAdmin, upload.single('image'), uploadErrorHandler, async (req, res) => {
  try {
    console.log('Coupon POST data:', {
      body: req.body,
      file: req.file ? `${req.file.originalname} (${(req.file.size / 1024).toFixed(2)}KB)` : 'None',
    });
    const { code, discount, description } = req.body;
    if (!code || !discount) {
      return res.status(400).json({ error: 'Code and discount are required' });
    }
    if (isNaN(parseFloat(discount)) || parseFloat(discount) <= 0 || parseFloat(discount) > 100) {
      return res.status(400).json({ error: 'Discount must be between 0 and 100' });
    }
    const pool = req.app.get('dbPool');
    const [existing] = await pool.query('SELECT id FROM coupons WHERE code = ?', [code]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Coupon code already exists' });
    }
    let imagePath = null;
    if (req.file) {
      imagePath = `/uploads/${req.file.filename}`;
      console.log(`Uploaded coupon image: ${req.file.filename}, size: ${(req.file.size / 1024).toFixed(2)}KB`);
    }
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    const [columns] = await pool.query("SHOW COLUMNS FROM coupons LIKE 'description'");
    const hasDescription = columns.length > 0;
    const fields = hasDescription
      ? '(code, discount, image, description, expires_at)'
      : '(code, discount, image, expires_at)';
    const values = hasDescription
      ? [code.toUpperCase(), parseFloat(discount), imagePath, description || null, expiresAt]
      : [code.toUpperCase(), parseFloat(discount), imagePath, expiresAt];
    const placeholders = hasDescription ? '(?, ?, ?, ?, ?)' : '(?, ?, ?, ?)';
    const [result] = await pool.query(
      `INSERT INTO coupons ${fields} VALUES ${placeholders}`,
      values
    );
    res.json({ id: result.insertId, message: 'Coupon added' });
  } catch (error) {
    console.error('Error adding coupon:', error.message);
    if (req.file) {
      await fs.unlink(path.join(uploadsDir, req.file.filename)).catch(() => {});
    }
    res.status(500).json({ error: 'Failed to add coupon' });
  }
});

// Update coupon
router.put('/coupons/:id', verifyAdmin, upload.single('image'), uploadErrorHandler, async (req, res) => {
  try {
    console.log('Coupon PUT data:', {
      body: req.body,
      file: req.file ? `${req.file.originalname} (${(req.file.size / 1024).toFixed(2)}KB)` : 'None',
    });
    const { id } = req.params;
    const { code, discount, description } = req.body;
    if (!code || !discount) {
      return res.status(400).json({ error: 'Code and discount are required' });
    }
    if (isNaN(parseFloat(discount)) || parseFloat(discount) <= 0 || parseFloat(discount) > 100) {
      return res.status(400).json({ error: 'Discount must be between 0 and 100' });
    }
    const pool = req.app.get('dbPool');
    const [coupons] = await pool.query('SELECT image FROM coupons WHERE id = ?', [id]);
    if (coupons.length === 0) {
      return res.status(404).json({ error: 'Coupon not found' });
    }
    const [existing] = await pool.query('SELECT id FROM coupons WHERE code = ? AND id != ?', [code, id]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Coupon code already exists' });
    }
    let imagePath = coupons[0].image;
    if (req.file) {
      imagePath = `/uploads/${req.file.filename}`;
      if (coupons[0].image) {
        await fs.unlink(path.join(uploadsDir, coupons[0].image.replace('/uploads/', ''))).catch(() => {});
      }
      console.log(`Updated coupon image: ${req.file.filename}, size: ${(req.file.size / 1024).toFixed(2)}KB`);
    }
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    const [columns] = await pool.query("SHOW COLUMNS FROM coupons LIKE 'description'");
    const hasDescription = columns.length > 0;
    const fields = hasDescription
      ? 'code = ?, discount = ?, image = ?, description = ?, expires_at = ?'
      : 'code = ?, discount = ?, image = ?, expires_at = ?';
    const values = hasDescription
      ? [code.toUpperCase(), parseFloat(discount), imagePath, description || null, expiresAt, id]
      : [code.toUpperCase(), parseFloat(discount), imagePath, expiresAt, id];
    await pool.query(
      `UPDATE coupons SET ${fields} WHERE id = ?`,
      values
    );
    res.json({ message: 'Coupon updated' });
  } catch (error) {
    console.error('Error updating coupon:', error.message);
    if (req.file) {
      await fs.unlink(path.join(uploadsDir, req.file.filename)).catch(() => {});
    }
    res.status(500).json({ error: 'Failed to update coupon' });
  }
});

// Delete coupon
router.delete('/coupons/:id', verifyAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const pool = req.app.get('dbPool');
    const [coupons] = await pool.query('SELECT image FROM coupons WHERE id = ?', [id]);
    if (coupons.length === 0) {
      return res.status(404).json({ error: 'Coupon not found' });
    }
    if (coupons[0].image) {
      await fs.unlink(path.join(uploadsDir, coupons[0].image.replace('/uploads/', ''))).catch(() => {});
    }
    await pool.query('DELETE FROM coupons WHERE id = ?', [id]);
    res.json({ message: 'Coupon deleted' });
  } catch (error) {
    console.error('Error deleting coupon:', error.message);
    res.status(500).json({ error: 'Failed to delete coupon' });
  }
});

// Remaining routes (unchanged for brevity)
router.get('/customers', verifyAdmin, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [columns] = await pool.query("SHOW COLUMNS FROM users LIKE 'status'");
    const statusField = columns.length > 0 ? 'status' : "'active' AS status";
    const query = `SELECT id, name, email, phone, ${statusField} FROM users WHERE role = 'user'`;
    const [customers] = await pool.query(query);
    res.json(customers);
  } catch (error) {
    console.error('Error fetching customers:', error.message);
    res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

// ... (other routes like /customers/:id/status, /orders, /orders/:id, /restaurant/status, /logout remain unchanged)

module.exports = router;