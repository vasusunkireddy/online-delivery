const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const nodemailer = require('nodemailer');

// Configure nodemailer for email sending
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Verify transporter configuration
transporter.verify((error, success) => {
  if (error) {
    console.error('Nodemailer configuration error:', error.message);
  } else {
    console.log('Nodemailer is ready to send emails');
  }
});

// Configure multer for file uploads
const upload = multer({
  dest: path.join(__dirname, '../public/uploads'),
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/bmp', 'image/tiff', 'image/svg+xml'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only JPEG, PNG, WebP, GIF, BMP, TIFF, or SVG images are allowed'), false);
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
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied: Admin role required' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Helper function to fetch order details
const fetchOrderDetails = async (orderId) => {
  try {
    const [orders] = await pool.query(`
      SELECT 
        o.id, o.user_id, o.total, o.delivery, o.payment_status, o.payment_method, o.status, o.created_at, o.reason,
        u.name AS user_name, u.email AS user_email,
        a.full_name, a.house_no, a.location, a.landmark, a.mobile,
        c.code AS coupon_code
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      LEFT JOIN addresses a ON o.address_id = a.id
      LEFT JOIN coupons c ON o.coupon_id = c.id
      WHERE o.id = ?
    `, [orderId]);
    if (orders.length === 0) {
      return null;
    }
    const order = orders[0];
    const [items] = await pool.query(`
      SELECT oi.quantity, oi.price, m.name
      FROM order_items oi
      JOIN menu_items m ON oi.menu_item_id = m.id
      WHERE oi.order_id = ?
    `, [orderId]);
    return {
      id: order.id,
      user: { name: order.user_name || 'Unknown', email: order.user_email || '-' },
      address: {
        fullName: order.full_name || '',
        houseNo: order.house_no || '',
        location: order.location || '',
        landmark: order.landmark || '',
        mobile: order.mobile || '',
      },
      items: items.map(item => ({
        name: item.name || 'Unknown',
        quantity: item.quantity,
        price: item.price,
      })),
      total: order.total || 0,
      delivery: order.delivery || 0,
      couponCode: order.coupon_code || null,
      paymentStatus: order.payment_status || 'pending',
      paymentMethod: order.payment_method || 'cod',
      status: order.status,
      reason: order.reason || null,
      created_at: order.created_at,
    };
  } catch (error) {
    console.error(`Error fetching order ${orderId}:`, error.message);
    throw error;
  }
};

// Function to send order status email
const sendOrderStatusEmail = async (order, status, reason = null) => {
  if (!order?.user?.email || order.user.email === '-') {
    console.warn(`Cannot send email for order ${order.id}: Invalid or missing email address`);
    return;
  }

  const statusMessages = {
    pending: {
      subject: 'Your Delicute Order is Pending',
      message: 'Thank you for your order! It is currently being processed. We’ll notify you once it’s confirmed.',
    },
    confirmed: {
      subject: 'Your Delicute Order is Confirmed',
      message: 'Great news! Your order has been confirmed and is being prepared with care.',
    },
    shipped: {
      subject: 'Your Delicute Order is on Its Way',
      message: 'Your order has been dispatched and will arrive soon. Enjoy your meal!',
    },
    delivered: {
      subject: 'Your Delicute Order Has Been Delivered',
      message: 'Your order has been delivered. We hope you enjoy your delicious meal!',
    },
    cancelled: {
      subject: 'Your Delicute Order Has Been Cancelled',
      message: `We’re sorry, but your order has been cancelled. Reason: ${reason || 'Not specified'}. Please contact us for assistance.`,
    },
    trashed: {
      subject: 'Your Delicute Order Has Been Archived',
      message: 'Your order has been moved to our archive for administrative purposes. Please contact us if you believe this was an error.',
    },
    restored: {
      subject: 'Your Delicute Order Has Been Restored',
      message: 'Good news! Your order has been restored and is now pending. We’ll keep you updated on its status.',
    },
  };

  const emailHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700&family=Poppins:wght@300;400;500&display=swap" rel="stylesheet">
      <style>
        body { font-family: 'Poppins', sans-serif; color: #1f2937; background: #f8fafc; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { font-family: 'Playfair Display', serif; font-size: 24px; color: #2563eb; text-align: center; }
        p { font-size: 14px; line-height: 1.6; color: #374151; }
        .items { margin: 20px 0; }
        .item { border-bottom: 1px solid #e5e7eb; padding: 10px 0; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #6b7280; }
        .button { display: inline-block; padding: 10px 20px; background: #2563eb; color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: 500; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>${statusMessages[status].subject}</h1>
        <p>Dear ${order.user.name || 'Valued Customer'},</p>
        <p>${statusMessages[status].message}</p>
        <div class="items">
          <h2 style="font-size: 18px; font-family: 'Playfair Display', serif;">Order Details</h2>
          <p>Order ID: ${order.id}</p>
          ${order.items.map(item => `
            <div class="item">
              <p><strong>${item.name}</strong> - Quantity: ${item.quantity} - Price: ₹${(parseFloat(item.price) || 0).toFixed(2)}</p>
            </div>
          `).join('')}
          <p><strong>Total:</strong> ₹${(parseFloat(order.total) || 0).toFixed(2)}</p>
          ${order.couponCode ? `<p><strong>Coupon Applied:</strong> ${order.couponCode}</p>` : ''}
          <p><strong>Delivery Address:</strong> ${order.address.fullName}, ${order.address.houseNo}, ${order.address.location}${order.address.landmark ? `, ${order.address.landmark}` : ''}, ${order.address.mobile}</p>
        </div>
        <p>We’re here to assist you! Contact us at <a href="mailto:support@delicutecloudkitchen.com">support@delicutecloudkitchen.com</a> for any queries.</p>
        <div class="footer">
          <p>Thank you for choosing Delicute Cloud Kitchen!</p>
          <p>© 2025 Delicute Cloud Kitchen. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `;

  try {
    await transporter.sendMail({
      from: '"Delicute Cloud Kitchen" <support@delicutecloudkitchen.com>',
      to: order.user.email,
      subject: statusMessages[status].subject,
      html: emailHtml,
    });
    console.log(`Email sent successfully to ${order.user.email} for order ${order.id}`);
  } catch (error) {
    console.error(`Failed to send email for order ${order.id}:`, error.message);
  }
};

// Check session
router.get('/check-session', authenticateAdminToken, async (req, res) => {
  return res.json({ message: 'Session valid' });
});

// Get restaurant status
router.get('/status', authenticateAdminToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT status FROM restaurant_status ORDER BY updated_at DESC LIMIT 1');
    const status = rows.length > 0 ? rows[0].status : 'closed';
    return res.json({ status });
  } catch (error) {
    console.error('Status fetch error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch restaurant status' });
  }
});

// Toggle restaurant status
router.put('/status', authenticateAdminToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT status FROM restaurant_status ORDER BY updated_at DESC LIMIT 1');
    const currentStatus = rows.length > 0 ? rows[0].status : 'closed';
    const newStatus = currentStatus === 'open' ? 'closed' : 'open';
    await pool.query('INSERT INTO restaurant_status (status) VALUES (?)', [newStatus]);
    return res.json({ status: newStatus });
  } catch (error) {
    console.error('Status toggle error:', error.message);
    return res.status(500).json({ error: 'Failed to toggle restaurant status' });
  }
});

// Get all menu items
router.get('/menu', authenticateAdminToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, price, category, description, image FROM menu_items');
    return res.json(rows.map(row => ({ ...row, image: row.image || null })));
  } catch (error) {
    console.error('Menu fetch error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch menu items' });
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
        allowed_formats: ['jpg', 'png', 'webp', 'gif', 'bmp', 'tiff', 'svg'],
      });
      imageUrl = result.secure_url;
      await fs.unlink(req.file.path);
    }
    const [result] = await pool.query(
      'INSERT INTO menu_items (name, price, category, description, image) VALUES (?, ?, ?, ?, ?)',
      [name, parseFloat(price), category, description || null, imageUrl]
    );
    return res.json({ message: 'Menu item added', id: result.insertId });
  } catch (error) {
    console.error('Add menu item error:', error.message);
    if (req.file) await fs.unlink(req.file.path).catch(() => {});
    return res.status(500).json({ error: 'Failed to add menu item' });
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
        allowed_formats: ['jpg', 'png', 'webp', 'gif', 'bmp', 'tiff', 'svg'],
      });
      imageUrl = result.secure_url;
      await fs.unlink(req.file.path);
      if (rows[0].image) {
        const publicId = rows[0].image.split('/').pop().split('.')[0];
        await cloudinary.uploader.destroy(`delicute/menu/${publicId}`).catch(() => {});
      }
    }
    await pool.query(
      'UPDATE menu_items SET name = ?, price = ?, category = ?, description = ?, image = ? WHERE id = ?',
      [name, parseFloat(price), category, description || null, imageUrl, id]
    );
    return res.json({ message: 'Menu item updated' });
  } catch (error) {
    console.error('Update menu item error:', error.message);
    if (req.file) await fs.unlink(req.file.path).catch(() => {});
    return res.status(500).json({ error: 'Failed to update menu item' });
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
    return res.json({ message: 'Menu item deleted' });
  } catch (error) {
    console.error('Delete menu item error:', error.message);
    return res.status(500).json({ error: 'Failed to delete menu item' });
  }
});

// Get all coupons
router.get('/coupons', authenticateAdminToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, code, discount, description, image FROM coupons');
    return res.json(rows.map(row => ({ ...row, image: row.image || null })));
  } catch (error) {
    console.error('Coupon fetch error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch coupons' });
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
        allowed_formats: ['jpg', 'png', 'webp', 'gif', 'bmp', 'tiff', 'svg'],
      });
      imageUrl = result.secure_url;
      await fs.unlink(req.file.path);
    }
    const [result] = await pool.query(
      'INSERT INTO coupons (code, discount, description, image) VALUES (?, ?, ?, ?)',
      [code, parseFloat(discount), description || null, imageUrl]
    );
    return res.json({ message: 'Coupon added', id: result.insertId });
  } catch (error) {
    console.error('Add coupon error:', error.message);
    if (req.file) await fs.unlink(req.file.path).catch(() => {});
    return res.status(500).json({ error: 'Failed to add coupon' });
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
        allowed_formats: ['jpg', 'png', 'webp', 'gif', 'bmp', 'tiff', 'svg'],
      });
      imageUrl = result.secure_url;
      await fs.unlink(req.file.path);
      if (rows[0].image) {
        const publicId = rows[0].image.split('/').pop().split('.')[0];
        await cloudinary.uploader.destroy(`delicute/coupons/${publicId}`).catch(() => {});
      }
    }
    await pool.query(
      'UPDATE coupons SET code = ?, discount = ?, description = ?, image = ? WHERE id = ?',
      [code, parseFloat(discount), description || null, imageUrl, id]
    );
    return res.json({ message: 'Coupon updated' });
  } catch (error) {
    console.error('Update coupon error:', error.message);
    if (req.file) await fs.unlink(req.file.path).catch(() => {});
    return res.status(500).json({ error: 'Failed to update coupon' });
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
    return res.json({ message: 'Coupon deleted' });
  } catch (error) {
    console.error('Delete coupon error:', error.message);
    return res.status(500).json({ error: 'Failed to delete coupon' });
  }
});

// Get all customers
router.get('/customers', authenticateAdminToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, email, phone, status FROM users WHERE role = ?', ['user']);
    return res.json(rows);
  } catch (error) {
    console.error('Customer fetch error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch customers' });
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
    return res.json({ message: `Customer ${status === 'blocked' ? 'blocked' : 'unblocked'}` });
  } catch (error) {
    console.error('Toggle customer status error:', error.message);
    return res.status(500).json({ error: 'Failed to update customer status' });
  }
});

// Get all orders (excluding trashed)
router.get('/orders', authenticateAdminToken, async (req, res) => {
  try {
    const [orders] = await pool.query(`
      SELECT 
        o.id, o.user_id, o.total, o.delivery, o.payment_status, o.payment_method, o.status, o.created_at, o.reason,
        u.name AS user_name, u.email AS user_email,
        a.full_name, a.house_no, a.location, a.landmark, a.mobile,
        c.code AS coupon_code
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      LEFT JOIN addresses a ON o.address_id = a.id
      LEFT JOIN coupons c ON o.coupon_id = c.id
      WHERE o.status != 'trashed'
    `);
    const orderIds = orders.map(order => order.id);
    let items = [];
    if (orderIds.length > 0) {
      [items] = await pool.query(`
        SELECT oi.order_id, oi.quantity, oi.price, m.name
        FROM order_items oi
        JOIN menu_items m ON oi.menu_item_id = m.id
        WHERE oi.order_id IN (?)
      `, [orderIds]);
    }
    const ordersWithDetails = orders.map(order => ({
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
        .filter(item => item.order_id === order.id)
        .map(item => ({
          name: item.name || 'Unknown',
          quantity: item.quantity,
          price: item.price,
        })),
      total: order.total || 0,
      delivery: order.delivery || 0,
      couponCode: order.coupon_code || null,
      paymentStatus: order.payment_status || 'pending',
      paymentMethod: order.payment_method || 'cod',
      status: order.status || 'pending',
      reason: order.reason || null,
      date: order.created_at,
    }));
    return res.json(ordersWithDetails);
  } catch (error) {
    console.error('Order fetch error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Get order details
router.get('/orders/:id', authenticateAdminToken, async (req, res) => {
  const { id } = req.params;
  try {
    const orderDetails = await fetchOrderDetails(id);
    if (!orderDetails) {
      return res.status(404).json({ error: 'Order not found' });
    }
    return res.json(orderDetails);
  } catch (error) {
    console.error('Order details fetch error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch order details' });
  }
});

// Update order status
router.put('/orders/:id', authenticateAdminToken, async (req, res) => {
  const { id } = req.params;
  const { status, paymentStatus, reason } = req.body;
  if (!status || !['pending', 'confirmed', 'shipped', 'delivered', 'cancelled', 'trashed'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  if (status === 'cancelled' && !reason) {
    return res.status(400).json({ error: 'Reason is required for cancellation' });
  }
  try {
    const orderDetails = await fetchOrderDetails(id);
    if (!orderDetails) {
      return res.status(404).json({ error: 'Order not found' });
    }
    const updates = { status };
    if (paymentStatus && ['pending', 'paid', 'failed'].includes(paymentStatus)) {
      updates.payment_status = paymentStatus;
    }
    if (status === 'cancelled') {
      updates.reason = reason;
    }
    const fields = Object.keys(updates).map(key => `${key} = ?`).join(', ');
    const values = Object.values(updates).concat([id]);
    await pool.query(`UPDATE orders SET ${fields} WHERE id = ?`, values);
    await sendOrderStatusEmail(orderDetails, status, reason);
    return res.json({ message: 'Order updated' });
  } catch (error) {
    console.error('Update order error:', error.message);
    return res.status(500).json({ error: 'Failed to update order' });
  }
});

// Move selected orders to trash
router.put('/orders/bulk-move-to-trash', authenticateAdminToken, async (req, res) => {
  const { orderIds } = req.body;
  if (!Array.isArray(orderIds) || orderIds.length === 0) {
    return res.status(400).json({ error: 'Order IDs array is required and cannot be empty' });
  }
  try {
    const [orders] = await pool.query(`
      SELECT 
        o.id, o.user_id, o.total, o.delivery, o.payment_status, o.payment_method, o.status, o.created_at, o.reason,
        u.name AS user_name, u.email AS user_email,
        a.full_name, a.house_no, a.location, a.landmark, a.mobile,
        c.code AS coupon_code
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      LEFT JOIN addresses a ON o.address_id = a.id
      LEFT JOIN coupons c ON o.coupon_id = c.id
      WHERE o.id IN (?) AND o.status != 'trashed'
    `, [orderIds]);
    if (orders.length === 0) {
      return res.status(404).json({ error: 'No valid orders found for the provided IDs' });
    }
    if (orders.length !== orderIds.length) {
      return res.status(400).json({ error: 'Some order IDs are invalid or already trashed' });
    }
    const validOrderIds = orders.map(order => order.id);
    const [itemsResult] = await pool.query(`
      SELECT oi.order_id, oi.quantity, oi.price, m.name
      FROM order_items oi
      JOIN menu_items m ON oi.menu_item_id = m.id
      WHERE oi.order_id IN (?)
    `, [validOrderIds]);
    const ordersWithDetails = orders.map(order => ({
      id: order.id,
      user: { name: order.user_name || 'Unknown', email: order.user_email || '-' },
      address: {
        fullName: order.full_name || '',
        houseNo: deinen
      },
      items: itemsResult
        .filter(item => item.order_id === order.id)
        .map(item => ({
          name: item.name || 'Unknown',
          quantity: item.quantity,
          price: item.price,
        })),
      total: order.total || 0,
      delivery: order.delivery || 0,
      couponCode: order.coupon_code || null,
      paymentStatus: order.payment_status || 'pending',
      paymentMethod: order.payment_method || 'cod',
      status: order.status,
      reason: order.reason || null,
      created_at: order.created_at,
    }));
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      const [result] = await connection.query(
        "UPDATE orders SET status = 'trashed', reason = NULL WHERE id IN (?)",
        [validOrderIds]
      );
      for (const order of ordersWithDetails) {
        await sendOrderStatusEmail(order, 'trashed');
      }
      await connection.commit();
      return res.json({ message: `${result.affectedRows} orders moved to trash` });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Bulk move to trash error:', error.message);
    return res.status(500).json({ error: 'Failed to move orders to trash' });
  }
});

// Move all non-trashed orders to trash
router.put('/orders/move-to-trash', authenticateAdminToken, async (req, res) => {
  try {
    const [orders] = await pool.query(`
      SELECT 
        o.id, o.user_id, o.total, o.delivery, o.payment_status, o.payment_method, o.status, o.created_at, o.reason,
        u.name AS user_name, u.email AS user_email,
        a.full_name, a.house_no, a.location, a.landmark, a.mobile,
        c.code AS coupon_code
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      LEFT JOIN addresses a ON o.address_id = a.id
      LEFT JOIN coupons c ON o.coupon_id = c.id
      WHERE o.status != 'trashed'
    `);
    if (orders.length === 0) {
      return res.status(200).json({ message: 'No orders to move to trash' });
    }
    const orderIds = orders.map(order => order.id);
    const [itemsResult] = await pool.query(`
      SELECT oi.order_id, oi.quantity, oi.price, m.name
      FROM order_items oi
      JOIN menu_items m ON oi.menu_item_id = m.id
      WHERE oi.order_id IN (?)
    `, [orderIds]);
    const ordersWithDetails = orders.map(order => ({
      id: order.id,
      user: { name: order.user_name || 'Unknown', email: order.user_email || '-' },
      address: {
        fullName: order.full_name || '',
        houseNo: order.house_no || '',
        location: order.location || '',
        landmark: order.landmark || '',
        mobile: order.mobile || '',
      },
      items: itemsResult
        .filter(item => item.order_id === order.id)
        .map(item => ({
          name: item.name || 'Unknown',
          quantity: item.quantity,
          price: item.price,
        })),
      total: order.total || 0,
      delivery: order.delivery || 0,
      couponCode: order.coupon_code || null,
      paymentStatus: order.payment_status || 'pending',
      paymentMethod: order.payment_method || 'cod',
      status: order.status,
      reason: order.reason || null,
      created_at: order.created_at,
    }));
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      const [result] = await connection.query("UPDATE orders SET status = 'trashed', reason = NULL WHERE status != 'trashed'");
      for (const order of ordersWithDetails) {
        await sendOrderStatusEmail(order, 'trashed');
      }
      await connection.commit();
      return res.json({ message: `${result.affectedRows} orders moved to trash` });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Move all orders to trash error:', error.message);
    return res.status(500).json({ error: 'Failed to move orders to trash' });
  }
});

// Get all trashed orders
router.get('/orders/trashed', authenticateAdminToken, async (req, res) => {
  try {
    const [orders] = await pool.query(`
      SELECT 
        o.id, o.user_id, o.total, o.delivery, o.payment_status, o.payment_method, o.status, o.created_at, o.reason,
        u.name AS user_name, u.email AS user_email,
        a.full_name, a.house_no, a.location, a.landmark, a.mobile,
        c.code AS coupon_code
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      LEFT JOIN addresses a ON o.address_id = a.id
      LEFT JOIN coupons c ON o.coupon_id = c.id
      WHERE o.status = 'trashed'
    `);
    const orderIds = orders.map(order => order.id);
    let items = [];
    if (orderIds.length > 0) {
      [items] = await pool.query(`
        SELECT oi.order_id, oi.quantity, oi.price, m.name
        FROM order_items oi
        JOIN menu_items m ON oi.menu_item_id = m.id
        WHERE oi.order_id IN (?)
      `, [orderIds]);
    }
    const ordersWithDetails = orders.map(order => ({
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
        .filter(item => item.order_id === order.id)
        .map(item => ({
          name: item.name || 'Unknown',
          quantity: item.quantity,
          price: item.price,
        })),
      total: order.total || 0,
      delivery: order.delivery || 0,
      couponCode: order.coupon_code || null,
      paymentStatus: order.payment_status || 'pending',
      paymentMethod: order.payment_method || 'cod',
      status: order.status || 'trashed',
      reason: order.reason || null,
      date: order.created_at,
    }));
    return res.json(ordersWithDetails);
  } catch (error) {
    console.error('Trashed orders fetch error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch trashed orders' });
  }
});

// Restore a trashed order
router.put('/orders/:id/restore', authenticateAdminToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query('SELECT status FROM orders WHERE id = ?', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    if (rows[0].status !== 'trashed') {
      return res.status(400).json({ error: 'Order is not trashed' });
    }
    const orderDetails = await fetchOrderDetails(id);
    await pool.query("UPDATE orders SET status = 'pending', reason = NULL WHERE id = ?", [id]);
    await sendOrderStatusEmail(orderDetails, 'restored');
    return res.json({ message: 'Order restored to pending status' });
  } catch (error) {
    console.error('Restore order error:', error.message);
    return res.status(500).json({ error: 'Failed to restore order' });
  }
});

// Permanently delete a trashed order
router.delete('/orders/:id/permanent', authenticateAdminToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query('SELECT status FROM orders WHERE id = ?', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    if (rows[0].status !== 'trashed') {
      return res.status(400).json({ error: 'Order is not trashed' });
    }
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      await connection.query('DELETE FROM order_items WHERE order_id = ?', [id]);
      await connection.query('DELETE FROM orders WHERE id = ?', [id]);
      await connection.commit();
      return res.json({ message: 'Order permanently deleted' });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Permanent delete order error:', error.message);
    return res.status(500).json({ error: 'Failed to permanently delete order' });
  }
});

// Permanently delete multiple trashed orders
router.delete('/orders/bulk-permanent', authenticateAdminToken, async (req, res) => {
  const { orderIds } = req.body;
  if (!Array.isArray(orderIds) || orderIds.length === 0) {
    return res.status(400).json({ error: 'Order IDs array is required and cannot be empty' });
  }
  try {
    const [orders] = await pool.query('SELECT id, status FROM orders WHERE id IN (?) AND status = ?', [orderIds, 'trashed']);
    if (orders.length === 0) {
      return res.status(404).json({ error: 'No trashed orders found for the provided IDs' });
    }
    if (orders.length !== orderIds.length) {
      return res.status(400).json({ error: 'Some order IDs are invalid or not trashed' });
    }
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      await connection.query('DELETE FROM order_items WHERE order_id IN (?)', [orderIds]);
      const [result] = await connection.query('DELETE FROM orders WHERE id IN (?)', [orderIds]);
      await connection.commit();
      return res.json({ message: `${result.affectedRows} trashed orders permanently deleted` });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Bulk delete trashed orders error:', error.message);
    return res.status(500).json({ error: 'Failed to permanently delete trashed orders' });
  }
});

// Logout
router.post('/logout', authenticateAdminToken, async (req, res) => {
  return res.json({ message: 'Logged out successfully' });
});

module.exports = router;