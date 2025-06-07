const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const paypal = require('@paypal/checkout-server-sdk');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// PayPal Client
const paypalClient = new paypal.core.PayPalHttpClient(
  new paypal.core.SandboxEnvironment(
    process.env.PAYPAL_CLIENT_ID,
    process.env.PAYPAL_CLIENT_SECRET
  )
);

// File Upload Configuration
const uploadDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});
const upload = multer({ storage });

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Get User Profile
router.get('/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, phone, role, profile_image FROM users WHERE id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update User Profile
router.put('/auth/update', authenticateToken, upload.single('profileImage'), async (req, res) => {
  const { name } = req.body;
  let profileImage = null;
  if (req.file) {
    profileImage = `/uploads/${req.file.filename}`;
  }
  try {
    const currentUser = await pool.query('SELECT profile_image FROM users WHERE id = $1', [req.user.id]);
    if (currentUser.rows[0].profile_image && profileImage) {
      const oldImagePath = path.join(__dirname, '../public', currentUser.rows[0].profile_image);
      if (fs.existsSync(oldImagePath)) {
        fs.unlinkSync(oldImagePath);
      }
    }
    const result = await pool.query(
      'UPDATE users SET name = $1, profile_image = COALESCE($2, profile_image) WHERE id = $3 RETURNING id, name, email, phone, profile_image',
      [name || currentUser.rows[0].name, profileImage, req.user.id]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Get Menu Items
router.get('/menu', async (req, res) => {
  try {
    const result = await pool.query('SELECT id AS _id, name, description, price, category, image, rating, rating_count FROM menu_items');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching menu:', error);
    res.status(500).json({ error: 'Failed to fetch menu items' });
  }
});

// Rate Menu Item
router.post('/menu/:id/rate', authenticateToken, async (req, res) => {
  const { rating, review } = req.body;
  const menuItemId = req.params.id;
  if (!rating || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'Valid rating (1-5) is required' });
  }
  try {
    await pool.query('BEGIN');
    const existingRating = await pool.query(
      'SELECT rating FROM ratings WHERE user_id = $1 AND menu_item_id = $2',
      [req.user.id, menuItemId]
    );
    if (existingRating.rows.length > 0) {
      const oldRating = existingRating.rows[0].rating;
      await pool.query(
        'UPDATE ratings SET rating = $1, review = $2, created_at = CURRENT_TIMESTAMP WHERE user_id = $3 AND menu_item_id = $4',
        [rating, review || null, req.user.id, menuItemId]
      );
      await pool.query(
        'UPDATE menu_items SET rating = ((rating * rating_count - $1 + $2) / rating_count), rating_count = rating_count WHERE id = $3',
        [oldRating, rating, menuItemId]
      );
    } else {
      await pool.query(
        'INSERT INTO ratings (user_id, menu_item_id, rating, review) VALUES ($1, $2, $3, $4)',
        [req.user.id, menuItemId, rating, review || null]
      );
      await pool.query(
        'UPDATE menu_items SET rating = ((rating * rating_count + $1) / (rating_count + 1)), rating_count = rating_count + 1 WHERE id = $2',
        [rating, menuItemId]
      );
    }
    await pool.query('COMMIT');
    res.json({ message: 'Rating submitted successfully' });
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Error submitting rating:', error);
    res.status(500).json({ error: 'Failed to submit rating' });
  }
});

// Get Coupons
router.get('/coupons', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id AS _id, code, description, discount, image FROM offers');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching coupons:', error);
    res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

// Validate Coupon
router.post('/coupons/validate', authenticateToken, async (req, res) => {
  const { couponCode } = req.body;
  if (!couponCode) {
    return res.status(400).json({ error: 'Coupon code is required' });
  }
  try {
    const result = await pool.query('SELECT id AS _id, code, discount FROM offers WHERE code = $1', [couponCode]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid coupon code' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error validating coupon:', error);
    res.status(500).json({ error: 'Failed to validate coupon' });
  }
});

// Create Order
router.post('/orders', authenticateToken, async (req, res) => {
  const { items, total, paymentMethod, coupon, deliveryAddress } = req.body;
  if (!items || !total || !paymentMethod || !deliveryAddress) {
    return res.status(400).json({ error: 'Items, total, payment method, and delivery address are required' });
  }
  try {
    let couponDiscount = 0;
    let couponCode = null;
    if (coupon) {
      const couponResult = await pool.query('SELECT discount FROM offers WHERE code = $1', [coupon]);
      if (couponResult.rows.length > 0) {
        couponDiscount = couponResult.rows[0].discount;
        couponCode = coupon;
      }
    }
    const addressResult = await pool.query('SELECT * FROM addresses WHERE id = $1 AND user_id = $2', [deliveryAddress, req.user.id]);
    if (addressResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid delivery address' });
    }
    const enrichedItems = [];
    for (const item of items) {
      const menuItem = await pool.query('SELECT name, price FROM menu_items WHERE id = $1', [item.item]);
      if (menuItem.rows.length === 0) {
        return res.status(400).json({ error: `Menu item ${item.item} not found` });
      }
      enrichedItems.push({
        item: item.item,
        itemName: menuItem.rows[0].name,
        price: menuItem.rows[0].price,
        quantity: item.quantity
      });
    }
    const orderResult = await pool.query(
      'INSERT INTO orders (user_id, items, total, payment_method, coupon_code, discount, delivery_address_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id AS _id, total, payment_method',
      [req.user.id, JSON.stringify(enrichedItems), total, paymentMethod, couponCode, couponDiscount, deliveryAddress]
    );
    const order = orderResult.rows[0];
    if (paymentMethod === 'PayPal') {
      const request = new paypal.orders.OrdersCreateRequest();
      request.prefer('return=representation');
      request.requestBody({
        intent: 'CAPTURE',
        purchase_units: [{
          amount: {
            currency_code: process.env.PAYPAL_CURRENCY,
            value: total.toString()
          },
          reference_id: order._id.toString()
        }],
        application_context: {
          return_url: process.env.PAYPAL_RETURN_URL,
          cancel_url: process.env.PAYPAL_CANCEL_URL
        }
      });
      const paypalOrder = await paypalClient.execute(request);
      res.json({ _id: order._id, orderId: paypalOrder.result.id, total: order.total, paymentMethod: order.payment_method });
    } else {
      res.json({ _id: order._id, total: order.total, paymentMethod: order.payment_method });
    }
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// Capture PayPal Payment
router.post('/payment/paypal-capture', authenticateToken, async (req, res) => {
  const { orderId } = req.body;
  try {
    const request = new paypal.orders.OrdersCaptureRequest(orderId);
    const capture = await paypalClient.execute(request);
    if (capture.result.status === 'COMPLETED') {
      await pool.query(
        'UPDATE orders SET status = $1, payment_details = $2 WHERE id = $3',
        ['completed', JSON.stringify(capture.result), capture.result.purchase_units[0].reference_id]
      );
      res.json({ message: 'Payment captured successfully' });
    } else {
      res.status(400).json({ error: 'Payment capture failed' });
    }
  } catch (error) {
    console.error('PayPal capture error:', error);
    res.status(500).json({ error: 'Failed to capture payment' });
  }
});

// UPI Payment (Placeholder - requires actual UPI gateway integration)
router.post('/payment/upi', authenticateToken, async (req, res) => {
  const { upiId, amount, deliveryAddress } = req.body;
  if (!upiId || !amount || !deliveryAddress) {
    return res.status(400).json({ error: 'UPI ID, amount, and delivery address are required' });
  }
  try {
    // Simulate UPI payment validation (replace with actual UPI gateway integration)
    const paymentDetails = { upiId, status: 'success', transactionId: `txn_${Date.now()}` };
    res.json({ message: 'UPI payment initiated successfully', paymentDetails });
  } catch (error) {
    console.error('UPI payment error:', error);
    res.status(500).json({ error: 'Failed to initiate UPI payment' });
  }
});

// Get Orders
router.get('/orders', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.id AS _id, o.user_id, o.items, o.total, o.status, o.payment_method, o.coupon_code, o.discount,
              a.id AS address_id, a.full_name, a.mobile, a.house_number, a.street, a.landmark, a.pincode,
              o.created_at
       FROM orders o
       LEFT JOIN addresses a ON o.delivery_address_id = a.id
       WHERE o.user_id = $1 AND o.status != 'delivered'
       ORDER BY o.created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows.map(order => ({
      _id: order._id,
      items: order.items,
      total: order.total,
      status: order.status,
      paymentMethod: order.payment_method,
      coupon: order.coupon_code,
      discount: order.discount,
      deliveryAddress: order.address_id ? {
        _id: order.address_id,
        fullName: order.full_name,
        mobile: order.mobile,
        houseNumber: order.house_number,
        street: order.street,
        landmark: order.landmark,
        pincode: order.pincode
      } : null,
      createdAt: order.created_at
    })));
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Get Order History
router.get('/orders/history', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.id AS _id, o.user_id, o.items, o.total, o.status, o.payment_method, o.coupon_code, o.discount,
              a.id AS address_id, a.full_name, a.mobile, a.house_number, a.street, a.landmark, a.pincode,
              o.created_at
       FROM orders o
       LEFT JOIN addresses a ON o.delivery_address_id = a.id
       WHERE o.user_id = $1
       ORDER BY o.created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows.map(order => ({
      _id: order._id,
      items: order.items,
      total: order.total,
      status: order.status,
      paymentMethod: order.payment_method,
      coupon: order.coupon_code,
      discount: order.discount,
      deliveryAddress: order.address_id ? {
        _id: order.address_id,
        fullName: order.full_name,
        mobile: order.mobile,
        houseNumber: order.house_number,
        street: order.street,
        landmark: order.landmark,
        pincode: order.pincode
      } : null,
      createdAt: order.created_at
    })));
  } catch (error) {
    console.error('Error fetching order history:', error);
    res.status(500).json({ error: 'Failed to fetch order history' });
  }
});

// Clear Order History
router.delete('/orders/history', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM orders WHERE user_id = $1', [req.user.id]);
    res.json({ message: 'Order history cleared successfully' });
  } catch (error) {
    console.error('Error clearing order history:', error);
    res.status(500).json({ error: 'Failed to clear order history' });
  }
});

// Track Order
router.get('/orders/:id/track', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id AS _id, status FROM orders WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error tracking order:', error);
    res.status(500).json({ error: 'Failed to track order' });
  }
});

// Get Order for Reorder
router.get('/orders/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id AS _id, items, total FROM orders WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching order:', error);
    res.status(500).json({ error: 'Failed to fetch order' });
  }
});

// Get Addresses
router.get('/addresses', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id AS _id, full_name, mobile, house_number, street, landmark, pincode FROM addresses WHERE user_id = $1',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching addresses:', error);
    res.status(500).json({ error: 'Failed to fetch addresses' });
  }
});

// Add Address
router.post('/addresses', authenticateToken, async (req, res) => {
  const { fullName, mobile, houseNumber, street, landmark, pincode } = req.body;
  if (!fullName || !mobile || !houseNumber || !street || !pincode) {
    return res.status(400).json({ error: 'All required fields must be provided' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO addresses (user_id, full_name, mobile, house_number, street, landmark, pincode) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id AS _id, full_name, mobile, house_number, street, landmark, pincode',
      [req.user.id, fullName, mobile, houseNumber, street, landmark || null, pincode]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error adding address:', error);
    res.status(500).json({ error: 'Failed to add address' });
  }
});

// Update Address
router.put('/addresses/:id', authenticateToken, async (req, res) => {
  const { fullName, mobile, houseNumber, street, landmark, pincode } = req.body;
  if (!fullName || !mobile || !houseNumber || !street || !pincode) {
    return res.status(400).json({ error: 'All required fields must be provided' });
  }
  try {
    const result = await pool.query(
      'UPDATE addresses SET full_name = $1, mobile = $2, house_number = $3, street = $4, landmark = $5, pincode = $6 WHERE id = $7 AND user_id = $8 RETURNING id AS _id, full_name, mobile, house_number, street, landmark, pincode',
      [fullName, mobile, houseNumber, street, landmark || null, pincode, req.params.id, req.user.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Address not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating address:', error);
    res.status(500).json({ error: 'Failed to update address' });
  }
});

// Delete Address
router.delete('/addresses/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM addresses WHERE id = $1 AND user_id = $2 RETURNING id', [req.params.id, req.user.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Address not found' });
    }
    res.json({ message: 'Address deleted successfully' });
  } catch (error) {
    console.error('Error deleting address:', error);
    res.status(500).json({ error: 'Failed to delete address' });
  }
});

module.exports = router;