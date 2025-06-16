const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs').promises;
const dotenv = require('dotenv');

dotenv.config();

// Database connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Middleware to verify JWT and admin status
const authenticateAdmin = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Check session
router.get('/admin/dashboard/check-session', authenticateAdmin, async (req, res) => {
  try {
    res.json({ message: 'Session valid' });
  } catch (error) {
    console.error('Check session error:', error.message);
    res.status(500).json({ error: 'Failed to check session' });
  }
});

// Toggle restaurant status
router.put('/admin/dashboard/restaurant/status', authenticateAdmin, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute('SELECT status FROM restaurant_status WHERE id = 1');
    if (!rows.length) {
      await connection.execute('INSERT INTO restaurant_status (id, status) VALUES (1, "closed")');
      connection.release();
      return res.json({ status: 'closed' });
    }
    const currentStatus = rows[0].status;
    const newStatus = currentStatus === 'open' ? 'closed' : 'open';
    await connection.execute(
      'UPDATE restaurant_status SET status = ?, updated_at = NOW() WHERE id = 1',
      [newStatus]
    );
    connection.release();
    res.json({ status: newStatus });
  } catch (error) {
    console.error('Toggle restaurant status error:', error.message);
    res.status(500).json({ error: 'Failed to toggle restaurant status' });
  }
});

// Get all menu items
router.get('/admin/dashboard/menu', authenticateAdmin, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [items] = await connection.execute(
      'SELECT id, name, price, category, description, image FROM menu_items'
    );
    connection.release();
    res.json(items);
  } catch (error) {
    console.error('Get menu items error:', error.message);
    res.status(500).json({ error: 'Failed to fetch menu items' });
  }
});

// Add menu item
router.post('/admin/dashboard/menu', authenticateAdmin, async (req, res) => {
  const { name, price, category, description } = req.body;
  const image = req.files?.image;
  if (!name || !price || !category) {
    return res.status(400).json({ error: 'Name, price, and category are required' });
  }
  try {
    let imagePath = null;
    if (image) {
      if (!['image/jpeg', 'image/png'].includes(image.mimetype)) {
        return res.status(400).json({ error: 'Only JPEG or PNG images are allowed' });
      }
      if (image.size > 5 * 1024 * 1024) {
        return res.status(413).json({ error: 'Image size must be under 5MB' });
      }
      const uploadDir = path.join(__dirname, '..', 'Uploads');
      await fs.mkdir(uploadDir, { recursive: true });
      const filename = `${Date.now()}-${image.name.replace(/\s/g, '-')}`;
      imagePath = filename;
      await image.mv(path.join(uploadDir, filename));
    }
    const connection = await pool.getConnection();
    await connection.execute(
      'INSERT INTO menu_items (name, price, category, description, image, stock) VALUES (?, ?, ?, ?, ?, 100)',
      [name, parseFloat(price), category, description || null, imagePath]
    );
    connection.release();
    res.json({ message: 'Menu item added successfully' });
  } catch (error) {
    console.error('Add menu item error:', error.message);
    res.status(500).json({ error: 'Failed to add menu item' });
  }
});

// Update menu item
router.put('/admin/dashboard/menu/:item_id', authenticateAdmin, async (req, res) => {
  const { item_id } = req.params;
  const { name, price, category, description } = req.body;
  const image = req.files?.image;
  if (!name || !price || !category) {
    return res.status(400).json({ error: 'Name, price, and category are required' });
  }
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute('SELECT image FROM menu_items WHERE id = ?', [item_id]);
    if (!rows.length) {
      connection.release();
      return res.status(404).json({ error: 'Menu item not found' });
    }
    let imagePath = rows[0].image;
    if (image) {
      if (!['image/jpeg', 'image/png'].includes(image.mimetype)) {
        return res.status(400).json({ error: 'Only JPEG or PNG images are allowed' });
      }
      if (image.size > 5 * 1024 * 1024) {
        return res.status(413).json({ error: 'Image size must be under 5MB' });
      }
      const uploadDir = path.join(__dirname, '..', 'Uploads');
      await fs.mkdir(uploadDir, { recursive: true });
      const filename = `${Date.now()}-${image.name.replace(/\s/g, '-')}`;
      imagePath = filename;
      await image.mv(path.join(uploadDir, filename));
      if (rows[0].image) {
        try {
          const oldImagePath = path.join(uploadDir, rows[0].image);
          await fs.access(oldImagePath); // Check if file exists
          await fs.unlink(oldImagePath);
        } catch (unlinkError) {
          if (unlinkError.code !== 'ENOENT') {
            console.warn(`Failed to delete old image: ${rows[0].image}`, unlinkError.message);
          }
        }
      }
    }
    await connection.execute(
      'UPDATE menu_items SET name = ?, price = ?, category = ?, description = ?, image = ? WHERE id = ?',
      [name, parseFloat(price), category, description || null, imagePath, item_id]
    );
    connection.release();
    res.json({ message: 'Menu item updated successfully' });
  } catch (error) {
    console.error('Update menu item error:', error.message);
    res.status(500).json({ error: 'Failed to update menu item' });
  }
});

// Delete menu item
router.delete('/admin/dashboard/menu/:item_id', authenticateAdmin, async (req, res) => {
  const { item_id } = req.params;
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute('SELECT image FROM menu_items WHERE id = ?', [item_id]);
    if (!rows.length) {
      connection.release();
      return res.status(404).json({ error: 'Menu item not found' });
    }
    if (rows[0].image) {
      try {
        const imagePath = path.join(__dirname, '..', 'Uploads', rows[0].image);
        await fs.access(imagePath); // Check if file exists
        await fs.unlink(imagePath);
      } catch (unlinkError) {
        if (unlinkError.code !== 'ENOENT') {
          console.warn(`Failed to delete image: ${rows[0].image}`, unlinkError.message);
        }
      }
    }
    await connection.execute('DELETE FROM menu_items WHERE id = ?', [item_id]);
    connection.release();
    res.json({ message: 'Menu item deleted successfully' });
  } catch (error) {
    console.error('Delete menu item error:', error.message);
    res.status(500).json({ error: 'Failed to delete menu item' });
  }
});

// Get all coupons
router.get('/admin/dashboard/coupons', authenticateAdmin, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [coupons] = await connection.execute(
      'SELECT id, code, discount, description, image FROM coupons'
    );
    connection.release();
    res.json(coupons);
  } catch (error) {
    console.error('Get coupons error:', error.message);
    res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

// Add coupon
router.post('/admin/dashboard/coupons', authenticateAdmin, async (req, res) => {
  const { code, discount, description } = req.body;
  const image = req.files?.image;
  if (!code || !discount) {
    return res.status(400).json({ error: 'Code and discount are required' });
  }
  try {
    let imagePath = null;
    if (image) {
      if (!['image/jpeg', 'image/png'].includes(image.mimetype)) {
        return res.status(400).json({ error: 'Only JPEG or PNG images are allowed' });
      }
      if (image.size > 5 * 1024 * 1024) {
        return res.status(413).json({ error: 'Image size must be under 5MB' });
      }
      const uploadDir = path.join(__dirname, '..', 'Uploads');
      await fs.mkdir(uploadDir, { recursive: true });
      const filename = `${Date.now()}-${image.name.replace(/\s/g, '-')}`;
      imagePath = filename;
      await image.mv(path.join(uploadDir, filename));
    }
    const connection = await pool.getConnection();
    await connection.execute(
      'INSERT INTO coupons (code, discount, description, image, expires_at) VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 30 DAY))',
      [code, parseFloat(discount), description || null, imagePath]
    );
    connection.release();
    res.json({ message: 'Coupon added successfully' });
  } catch (error) {
    console.error('Add coupon error:', error.message);
    res.status(500).json({ error: 'Failed to add coupon' });
  }
});

// Update coupon
router.put('/admin/dashboard/coupons/:coupon_id', authenticateAdmin, async (req, res) => {
  const { coupon_id } = req.params;
  const { code, discount, description } = req.body;
  const image = req.files?.image;
  if (!code || !discount) {
    return res.status(400).json({ error: 'Code and discount are required' });
  }
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute('SELECT image FROM coupons WHERE id = ?', [coupon_id]);
    if (!rows.length) {
      connection.release();
      return res.status(404).json({ error: 'Coupon not found' });
    }
    let imagePath = rows[0].image;
    if (image) {
      if (!['image/jpeg', 'image/png'].includes(image.mimetype)) {
        return res.status(400).json({ error: 'Only JPEG or PNG images are allowed' });
      }
      if (image.size > 5 * 1024 * 1024) {
        return res.status(413).json({ error: 'Image size must be under 5MB' });
      }
      const uploadDir = path.join(__dirname, '..', 'Uploads');
      await fs.mkdir(uploadDir, { recursive: true });
      const filename = `${Date.now()}-${image.name.replace(/\s/g, '-')}`;
      imagePath = filename;
      await image.mv(path.join(uploadDir, filename));
      if (rows[0].image) {
        try {
          const oldImagePath = path.join(uploadDir, rows[0].image);
          await fs.access(oldImagePath); // Check if file exists
          await fs.unlink(oldImagePath);
        } catch (unlinkError) {
          if (unlinkError.code !== 'ENOENT') {
            console.warn(`Failed to delete old image: ${rows[0].image}`, unlinkError.message);
          }
        }
      }
    }
    await connection.execute(
      'UPDATE coupons SET code = ?, discount = ?, description = ?, image = ? WHERE id = ?',
      [code, parseFloat(discount), description || null, imagePath, coupon_id]
    );
    connection.release();
    res.json({ message: 'Coupon updated successfully' });
  } catch (error) {
    console.error('Update coupon error:', error.message);
    res.status(500).json({ error: 'Failed to update coupon' });
  }
});

// Delete coupon
router.delete('/admin/dashboard/coupons/:coupon_id', authenticateAdmin, async (req, res) => {
  const { coupon_id } = req.params;
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute('SELECT image FROM coupons WHERE id = ?', [coupon_id]);
    if (!rows.length) {
      connection.release();
      return res.status(404).json({ error: 'Coupon not found' });
    }
    if (rows[0].image) {
      try {
        const imagePath = path.join(__dirname, '..', 'Uploads', rows[0].image);
        await fs.access(imagePath); // Check if file exists
        await fs.unlink(imagePath);
      } catch (unlinkError) {
        if (unlinkError.code !== 'ENOENT') {
          console.warn(`Failed to delete image: ${rows[0].image}`, unlinkError.message);
        }
      }
    }
    await connection.execute('DELETE FROM coupons WHERE id = ?', [coupon_id]);
    connection.release();
    res.json({ message: 'Coupon deleted successfully' });
  } catch (error) {
    console.error('Delete coupon error:', error.message);
    res.status(500).json({ error: 'Failed to delete coupon' });
  }
});

// Get all customers
router.get('/admin/dashboard/customers', authenticateAdmin, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [customers] = await connection.execute(
      'SELECT id, name, email, phone, isAdmin AS status FROM users WHERE isAdmin = FALSE'
    );
    connection.release();
    res.json(customers.map(customer => ({
      ...customer,
      status: customer.status ? 'blocked' : 'active' // Map isAdmin to active/blocked
    })));
  } catch (error) {
    console.error('Get customers error:', error.message);
    res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

// Toggle customer status
router.put('/admin/dashboard/customers/:user_id/status', authenticateAdmin, async (req, res) => {
  const { user_id } = req.params;
  const { status } = req.body;
  if (!['active', 'blocked'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute('SELECT id FROM users WHERE id = ? AND isAdmin = FALSE', [user_id]);
    if (!rows.length) {
      connection.release();
      return res.status(404).json({ error: 'Customer not found' });
    }
    const isAdmin = status === 'blocked' ? true : false;
    await connection.execute('UPDATE users SET isAdmin = ? WHERE id = ?', [isAdmin, user_id]);
    connection.release();
    res.json({ message: `Customer ${status === 'blocked' ? 'blocked' : 'unblocked'} successfully` });
  } catch (error) {
    console.error('Toggle customer status error:', error.message);
    res.status(500).json({ error: 'Failed to toggle customer status' });
  }
});

// Get all orders
router.get('/admin/dashboard/orders', authenticateAdmin, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [orders] = await connection.execute(`
      SELECT o.id, o.user_id, o.address_id, o.coupon_code, o.payment_method, o.delivery_cost, o.total,
             o.status, o.date, o.payment_status, u.name AS user_name, u.email AS user_email,
             a.full_name, a.mobile, a.house_no, a.location, a.landmark
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      LEFT JOIN addresses a ON o.address_id = a.id
    `);
    const orderIds = orders.map(order => order.id);
    const [items] = orderIds.length > 0 ? await connection.execute(
      'SELECT order_id, item_id, name, price, quantity, image FROM order_items WHERE order_id IN (?)',
      [orderIds]
    ) : [[], []];
    connection.release();
    const ordersWithItems = orders.map(order => ({
      ...order,
      user: { name: order.user_name, email: order.user_email },
      address: {
        fullName: order.full_name,
        mobile: order.mobile,
        houseNo: order.house_no,
        location: order.location,
        landmark: order.landmark
      },
      items: items.filter(item => item.order_id === order.id),
      delivery: order.delivery_cost,
      couponCode: order.coupon_code,
      paymentStatus: order.payment_status || 'pending'
    }));
    res.json(ordersWithItems);
  } catch (error) {
    console.error('Get orders error:', error.message);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Get single order
router.get('/admin/dashboard/orders/:order_id', authenticateAdmin, async (req, res) => {
  const { order_id } = req.params;
  try {
    const connection = await pool.getConnection();
    const [orders] = await connection.execute(
      `
      SELECT o.id, o.user_id, o.address_id, o.coupon_code, o.payment_method, o.delivery_cost, o.total,
             o.status, o.date, o.payment_status, u.name AS user_name, u.email AS user_email,
             a.full_name, a.mobile, a.house_no, a.location, a.landmark
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      LEFT JOIN addresses a ON o.address_id = a.id
      WHERE o.id = ?
    `,
      [order_id]
    );
    if (!orders.length) {
      connection.release();
      return res.status(404).json({ error: 'Order not found' });
    }
    const [items] = await connection.execute(
      'SELECT item_id, name, price, quantity, image FROM order_items WHERE order_id = ?',
      [order_id]
    );
    connection.release();
    const order = orders[0];
    res.json({
      ...order,
      user: { name: order.user_name, email: order.user_email },
      address: {
        fullName: order.full_name,
        mobile: order.mobile,
        houseNo: order.house_no,
        location: order.location,
        landmark: order.landmark
      },
      items,
      delivery: order.delivery_cost,
      couponCode: order.coupon_code,
      paymentStatus: order.payment_status || 'pending'
    });
  } catch (error) {
    console.error('Get order error:', error.message);
    res.status(500).json({ error: 'Failed to fetch order' });
  }
});

// Update order status
router.put('/admin/dashboard/orders/:order_id', authenticateAdmin, async (req, res) => {
  const { order_id } = req.params;
  const { status, paymentStatus } = req.body;
  if (!status || !['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute('SELECT id FROM orders WHERE id = ?', [order_id]);
    if (!rows.length) {
      connection.release();
      return res.status(404).json({ error: 'Order not found' });
    }
    const updates = { status };
    if (paymentStatus) {
      updates.payment_status = paymentStatus;
    }
    const fields = Object.keys(updates).map(key => `${key} = ?`).join(', ');
    const values = Object.values(updates);
    await connection.execute(
      `UPDATE orders SET ${fields} WHERE id = ?`,
      [...values, order_id]
    );
    connection.release();
    res.json({ message: 'Order updated successfully' });
  } catch (error) {
    console.error('Update order status error:', error.message);
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

// Logout
router.post('/admin/dashboard/logout', authenticateAdmin, async (req, res) => {
  try {
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error.message);
    res.status(500).json({ error: 'Failed to logout' });
  }
});

module.exports = router;
