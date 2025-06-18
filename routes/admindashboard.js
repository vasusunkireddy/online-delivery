const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const nodemailer = require('nodemailer');

// Configure nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Verify transporter
transporter.verify((error, success) => {
  if (error) console.error('Nodemailer configuration error:', error.message);
  else console.log('Nodemailer is ready to send emails');
});

// Configure multer
const upload = multer({
  dest: path.join(__dirname, '../public/uploads'),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/bmp', 'image/tiff', 'image/svg+xml'];
    if (allowedTypes.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Invalid file type. Only JPEG, PNG, WebP, GIF, BMP, TIFF, or SVG allowed'), false);
  },
});

// Database pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Admin authentication middleware
const authenticateAdminToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized: No token provided' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Access denied: Admin role required' });
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Fetch order details
const fetchOrderDetails = async (orderId, connection = pool) => {
  try {
    const [orders] = await connection.query(`
      SELECT 
        o.id, o.user_id, o.total, o.delivery, o.payment_status, o.payment_method, o.status, o.created_at, o.reason, o.deleted_at,
        u.name AS user_name, u.email AS user_email,
        a.full_name, a.house_no, a.location, a.landmark, a.mobile,
        c.code AS coupon_code
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      LEFT JOIN addresses a ON o.address_id = a.id
      LEFT JOIN coupons c ON o.coupon_id = c.id
      WHERE o.id = ?
    `, [orderId]);
    if (!orders.length) return null;
    const order = orders[0];
    const [items] = await connection.query(`
      SELECT oi.quantity, oi.price, m.name
      FROM order_items oi
      JOIN menu_items m ON oi.menu_item_id = m.id
      WHERE oi.order_id = ?
    `, [orderId]);
    return {
      id: order.id,
      user: {
        name: order.user_name || 'Unknown',
        email: order.user_email || '-',
      },
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
      status: order.status || 'pending',
      reason: order.reason || null,
      created_at: order.created_at,
      deleted_at: order.deleted_at,
    };
  } catch (error) {
    console.error(`Error fetching order ${orderId}:`, error.message);
    throw error;
  }
};

// Send order status email and SMS
const sendOrderStatusNotifications = async (order, status, reason = null, twilioClient) => {
  const statusMessages = {
    pending: {
      email: {
        subject: 'Your Delicute Order is Pending',
        message: 'Thank you for your order! It is currently being processed. We’ll notify you once it’s confirmed.',
      },
      sms: 'Delicute: Your order is pending. We’re processing it and will update you soon!',
    },
    confirmed: {
      email: {
        subject: 'Your Delicute Order is Confirmed',
        message: 'Great news! Your order has been confirmed and is being prepared with care.',
      },
      sms: 'Delicute: Your order is confirmed and being prepared with care!',
    },
    shipped: {
      email: {
        subject: 'Your Delicute Order is on Its Way',
        message: 'Your order has been dispatched and will arrive soon. Enjoy your meal!',
      },
      sms: 'Delicute: Your order is on its way! It’ll arrive soon.',
    },
    delivered: {
      email: {
        subject: 'Your Delicute Order Has Been Delivered',
        message: 'Your order has been delivered. We hope you enjoy your delicious meal!',
      },
      sms: 'Delicute: Your order has been delivered. Enjoy your meal!',
    },
    cancelled: {
      email: {
        subject: 'Your Delicute Order Has Been Cancelled',
        message: `We’re sorry, but your order has been cancelled. Reason: ${reason || 'Not specified'}. Please contact us for assistance.`,
      },
      sms: `Delicute: Your order was cancelled. Reason: ${reason || 'Not specified'}. Contact support for help.`,
    },
    trashed: {
      email: {
        subject: 'Your Delicute Order Has Been Archived',
        message: 'Your order has been moved to our archive for administrative purposes. Please contact us if you believe this was an error.',
      },
      sms: 'Delicute: Your order has been archived. Contact support if this is an error.',
    },
    restored: {
      email: {
        subject: 'Your Delicute Order Has Been Restored',
        message: 'Good news! Your order has been restored and is now pending. We’ll keep you updated on its status.',
      },
      sms: 'Delicute: Your order has been restored and is now pending. Stay tuned for updates!',
    },
  };

  // Email notification
  if (order?.user?.email && order.user.email !== '-') {
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
        </style>
      </head>
      <body>
        <div class="container">
          <h1>${statusMessages[status].email.subject}</h1>
          <p>Dear ${order.user.name || 'Valued Customer'},</p>
          <p>${statusMessages[status].email.message}</p>
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
          <p>Contact us at <a href="mailto:support@delicutecloudkitchen.com">support@delicutecloudkitchen.com</a>.</p>
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
        subject: statusMessages[status].email.subject,
        html: emailHtml,
      });
      console.log(`Email sent to ${order.user.email} for order ${order.id}`);
    } catch (error) {
      console.error(`Failed to send email for order ${order.id}:`, error.message);
    }
  } else {
    console.warn(`Cannot send email for order ${order.id}: Invalid or missing email`);
  }

  // SMS notification
  if (order?.address?.mobile && twilioClient) {
    let mobile = order.address.mobile.trim();
    if (!mobile.startsWith('+')) {
      mobile = `+91${mobile.replace(/\D/g, '').slice(-10)}`; // Assume Indian number
    }
    if (!/^\+\d{10,15}$/.test(mobile)) {
      console.warn(`Cannot send SMS for order ${order.id}: Invalid mobile number ${mobile}`);
      return;
    }
    try {
      const result = await twilioClient.messages.create({
        body: statusMessages[status].sms,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: mobile,
      });
      console.log(`SMS sent to ${mobile} for order ${order.id}: ${result.sid}`);
    } catch (error) {
      console.error(`Failed to send SMS for order ${order.id}:`, error.message, 'Twilio error code:', error.code);
    }
  } else {
    console.warn(`Cannot send SMS for order ${order.id}:`, {
      hasMobile: !!order?.address?.mobile,
      hasTwilioClient: !!twilioClient,
      mobileValue: order?.address?.mobile || 'undefined',
    });
  }
};

// Routes
router.get('/check-session', authenticateAdminToken, async (req, res) => {
  return res.json({ message: 'Session valid' });
});

router.get('/status', authenticateAdminToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT status FROM restaurant_status ORDER BY updated_at DESC LIMIT 1');
    return res.json({ status: rows.length ? rows[0].status : 'closed' });
  } catch (error) {
    console.error('Status fetch error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch restaurant status' });
  }
});

router.put('/status', authenticateAdminToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT status FROM restaurant_status ORDER BY updated_at DESC LIMIT 1');
    const currentStatus = rows.length ? rows[0].status : 'closed';
    const newStatus = currentStatus === 'open' ? 'closed' : 'open';
    await pool.query('INSERT INTO restaurant_status (status) VALUES (?)', [newStatus]);
    return res.json({ status: newStatus });
  } catch (error) {
    console.error('Status toggle error:', error.message);
    return res.status(500).json({ error: 'Failed to toggle restaurant status' });
  }
});

router.get('/menu', authenticateAdminToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, price, category, description, image FROM menu_items WHERE deleted_at IS NULL');
    return res.json(rows.map(row => ({ ...row, image: row.image || null })));
  } catch (error) {
    console.error('Menu fetch error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch menu items' });
  }
});

router.post('/menu', authenticateAdminToken, upload.single('image'), async (req, res) => {
  const { name, price, category, description } = req.body;
  if (!name || !price || !category) return res.status(400).json({ error: 'Name, price, and category are required' });
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

router.put('/menu/:id', authenticateAdminToken, upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { name, price, category, description } = req.body;
  if (!name || !price || !category) return res.status(400).json({ error: 'Name, price, and category are required' });
  try {
    const [rows] = await pool.query('SELECT image FROM menu_items WHERE id = ? AND deleted_at IS NULL', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Menu item not found' });
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

router.delete('/menu/:id', authenticateAdminToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query('SELECT image FROM menu_items WHERE id = ? AND deleted_at IS NULL', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Menu item not found' });
    if (rows[0].image) {
      const publicId = rows[0].image.split('/').pop().split('.')[0];
      await cloudinary.uploader.destroy(`delicute/menu/${publicId}`).catch(() => {});
    }
    await pool.query('UPDATE menu_items SET deleted_at = NOW() WHERE id = ?', [id]);
    return res.json({ message: 'Menu item deleted' });
  } catch (error) {
    console.error('Delete menu item error:', error.message);
    return res.status(500).json({ error: 'Failed to delete menu item' });
  }
});

router.get('/coupons', authenticateAdminToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, code, discount, description, image FROM coupons WHERE deleted_at IS NULL');
    return res.json(rows.map(row => ({ ...row, image: row.image || null })));
  } catch (error) {
    console.error('Coupon fetch error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

router.post('/coupons', authenticateAdminToken, upload.single('image'), async (req, res) => {
  const { code, discount, description } = req.body;
  if (!code || !discount) return res.status(400).json({ error: 'Code and discount are required' });
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

router.put('/coupons/:id', authenticateAdminToken, upload.single('image'), async (req, res) => {
  const { id } = req.params;
  const { code, discount, description } = req.body;
  if (!code || !discount) return res.status(400).json({ error: 'Code and discount are required' });
  try {
    const [rows] = await pool.query('SELECT image FROM coupons WHERE id = ? AND deleted_at IS NULL', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Coupon not found' });
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

router.delete('/coupons/:id', authenticateAdminToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query('SELECT image FROM coupons WHERE id = ? AND deleted_at IS NULL', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Coupon not found' });
    if (rows[0].image) {
      const publicId = rows[0].image.split('/').pop().split('.')[0];
      await cloudinary.uploader.destroy(`delicute/coupons/${publicId}`).catch(() => {});
    }
    await pool.query('UPDATE coupons SET deleted_at = NOW() WHERE id = ?', [id]);
    return res.json({ message: 'Coupon deleted' });
  } catch (error) {
    console.error('Delete coupon error:', error.message);
    return res.status(500).json({ error: 'Failed to delete coupon' });
  }
});

router.get('/customers', authenticateAdminToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, email, phone, status FROM users WHERE role = ? AND deleted_at IS NULL', ['user']);
    return res.json(rows);
  } catch (error) {
    console.error('Customer fetch error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

router.put('/customers/:id/status', authenticateAdminToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!['active', 'blocked'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
  try {
    const [rows] = await pool.query('SELECT id FROM users WHERE id = ? AND role = ? AND deleted_at IS NULL', [id, 'user']);
    if (!rows.length) return res.status(404).json({ error: 'Customer not found' });
    await pool.query('UPDATE users SET status = ? WHERE id = ?', [status, id]);
    return res.json({ message: `Customer ${status === 'blocked' ? 'blocked' : 'unblocked'}` });
  } catch (error) {
    console.error('Toggle customer status error:', error.message);
    return res.status(500).json({ error: 'Failed to update customer status' });
  }
});

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
      WHERE o.deleted_at IS NULL
    `);
    const orderIds = orders.map(order => order.id);
    let items = [];
    if (orderIds.length) {
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
      created_at: order.created_at,
    }));
    return res.json(ordersWithDetails);
  } catch (error) {
    console.error('Order fetch error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

router.get('/orders/trashed', authenticateAdminToken, async (req, res) => {
  try {
    const [orders] = await pool.query(`
      SELECT 
        o.id, o.user_id, o.total, o.delivery, o.payment_status, o.payment_method, o.status, o.created_at, o.reason, o.deleted_at,
        u.name AS user_name, u.email AS user_email,
        a.full_name, a.house_no, a.location, a.landmark, a.mobile,
        c.code AS coupon_code
      FROM orders o
      LEFT JOIN users u ON o.user_id = u.id
      LEFT JOIN addresses a ON o.address_id = a.id
      LEFT JOIN coupons c ON o.coupon_id = c.id
      WHERE o.deleted_at IS NOT NULL
    `);
    const orderIds = orders.map(order => order.id);
    let items = [];
    if (orderIds.length) {
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
      created_at: order.created_at,
      deleted_at: order.deleted_at,
    }));
    return res.json(ordersWithDetails);
  } catch (error) {
    console.error('Trashed order fetch error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch trashed orders' });
  }
});

router.get('/orders/:id', authenticateAdminToken, async (req, res) => {
  const { id } = req.params;
  try {
    const orderDetails = await fetchOrderDetails(id);
    if (!orderDetails) return res.status(404).json({ error: 'Order not found' });
    return res.json(orderDetails);
  } catch (error) {
    console.error('Order details fetch error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch order details' });
  }
});

router.put('/orders/:id', authenticateAdminToken, async (req, res) => {
  const { id } = req.params;
  const { status, paymentStatus, reason } = req.body;
  if (!status || !['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  if (status === 'cancelled' && !reason) {
    return res.status(400).json({ error: 'Reason is required for cancellation' });
  }
  try {
    const orderDetails = await fetchOrderDetails(id);
    if (!orderDetails) return res.status(404).json({ error: 'Order not found' });
    if (orderDetails.deleted_at) return res.status(400).json({ error: 'Order is in trash' });
    const updates = { status };
    if (paymentStatus && ['pending', 'paid', 'failed'].includes(paymentStatus)) updates.payment_status = paymentStatus;
    if (status === 'cancelled') updates.reason = reason;
    const fields = Object.keys(updates).map(key => `${key} = ?`).join(', ');
    const values = Object.values(updates).concat([id]);
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      await connection.query(`UPDATE orders SET ${fields} WHERE id = ?`, values);
      await sendOrderStatusNotifications(orderDetails, status, reason, req.app.get('twilioClient'));
      await connection.commit();
      return res.json({ message: 'Order updated' });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Update order error:', error.message);
    return res.status(500).json({ error: 'Failed to update order' });
  }
});

router.put('/orders/trash', authenticateAdminToken, async (req, res) => {
  const { orderIds } = req.body;
  if (!Array.isArray(orderIds) || !orderIds.length) {
    return res.status(400).json({ error: 'Order IDs array is required and cannot be empty' });
  }
  if (!orderIds.every(id => Number.isInteger(id) && id > 0)) {
    return res.status(400).json({ error: 'All order IDs must be positive integers' });
  }
  try {
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      const [orders] = await connection.query(`
        SELECT 
          o.id, o.user_id, o.total, o.delivery, o.payment_status, o.payment_method, o.status, o.created_at, o.reason,
          u.name AS user_name, u.email AS user_email,
          a.full_name, a.house_no, a.location, a.landmark, a.mobile,
          c.code AS coupon_code
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.id
        LEFT JOIN addresses a ON o.address_id = a.id
        LEFT JOIN coupons c ON o.coupon_id = c.id
        WHERE o.id IN (?) AND o.deleted_at IS NULL
      `, [orderIds]);
      if (!orders.length) {
        await connection.rollback();
        return res.status(404).json({ error: 'No valid orders found' });
      }
      if (orders.length !== orderIds.length) {
        await connection.rollback();
        return res.status(400).json({ error: 'Some order IDs are invalid or already trashed' });
      }
      const validOrderIds = orders.map(order => order.id);
      const [items] = await connection.query(`
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
        created_at: order.created_at,
      }));
      const [result] = await connection.query(
        'UPDATE orders SET deleted_at = NOW(), reason = NULL WHERE id IN (?)',
        [validOrderIds]
      );
      for (const order of ordersWithDetails) {
        await sendOrderStatusNotifications(order, 'trashed', null, req.app.get('twilioClient'));
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
    console.error('Bulk trash error:', error.message);
    return res.status(500).json({ error: 'Failed to move orders to trash' });
  }
});

router.put('/orders/restore', authenticateAdminToken, async (req, res) => {
  const { orderIds } = req.body;
  if (!Array.isArray(orderIds) || !orderIds.length) {
    return res.status(400).json({ error: 'Order IDs array is required and cannot be empty' });
  }
  if (!orderIds.every(id => Number.isInteger(id) && id > 0)) {
    return res.status(400).json({ error: 'All order IDs must be positive integers' });
  }
  try {
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      const [orders] = await connection.query('SELECT id FROM orders WHERE id IN (?) AND deleted_at IS NOT NULL', [orderIds]);
      if (!orders.length) {
        await connection.rollback();
        return res.status(404).json({ error: 'No trashed orders found' });
      }
      if (orders.length !== orderIds.length) {
        await connection.rollback();
        return res.status(400).json({ error: 'Some order IDs are invalid or not trashed' });
      }
      const validOrderIds = orders.map(order => order.id);
      const ordersWithDetails = await Promise.all(validOrderIds.map(id => fetchOrderDetails(id, connection)));
      const [result] = await connection.query(
        'UPDATE orders SET deleted_at = NULL, status = "pending", reason = NULL WHERE id IN (?)',
        [validOrderIds]
      );
      for (const order of ordersWithDetails) {
        await sendOrderStatusNotifications(order, 'restored', null, req.app.get('twilioClient'));
      }
      await connection.commit();
      return res.json({ message: `${result.affectedRows} orders restored` });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Restore orders error:', error.message);
    return res.status(500).json({ error: 'Failed to restore orders' });
  }
});

router.delete('/orders/permanent', authenticateAdminToken, async (req, res) => {
  const { orderIds } = req.body;
  if (!Array.isArray(orderIds) || !orderIds.length) {
    return res.status(400).json({ error: 'Order IDs array is required and cannot be empty' });
  }
  if (!orderIds.every(id => Number.isInteger(id) && id > 0)) {
    return res.status(400).json({ error: 'All order IDs must be positive integers' });
  }
  try {
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      const [orders] = await connection.query('SELECT id FROM orders WHERE id IN (?) AND deleted_at IS NOT NULL', [orderIds]);
      if (!orders.length) {
        await connection.rollback();
        return res.status(404).json({ error: 'No trashed orders found' });
      }
      if (orders.length !== orderIds.length) {
        await connection.rollback();
        return res.status(400).json({ error: 'Some order IDs are invalid or not trashed' });
      }
      await connection.query('DELETE FROM order_items WHERE order_id IN (?)', [orderIds]);
      const [result] = await connection.query('DELETE FROM orders WHERE id IN (?)', [orderIds]);
      await connection.commit();
      return res.json({ message: `${result.affectedRows} orders permanently deleted` });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Permanent delete orders error:', error.message);
    return res.status(500).json({ error: 'Failed to permanently delete orders' });
  }
});

router.post('/logout', authenticateAdminToken, async (req, res) => {
  return res.json({ message: 'Logged out successfully' });
});

module.exports = router;