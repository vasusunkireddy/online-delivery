const express = require('express');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const sanitizeHtml = require('sanitize-html');

const router = express.Router();
let dbConnection;

// Multer storage for profile image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'public/uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png/;
    const isValid = filetypes.test(path.extname(file.originalname).toLowerCase()) && filetypes.test(file.mimetype);
    cb(isValid ? null : new Error('Only JPEG/PNG images allowed'), isValid);
  },
});

// JWT authentication middleware
const authenticateToken = async (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    console.log(`No token provided for ${req.url}`);
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const [rows] = await dbConnection.execute('SELECT * FROM users WHERE id = ?', [decoded.id]);
    if (!rows.length) {
      console.log(`User not found for ID: ${decoded.id}`);
      return res.status(401).json({ error: 'User not found' });
    }
    req.user = { ...decoded, ...rows[0] };
    next();
  } catch (error) {
    console.error(`Token verification error: ${error.message}`);
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }
};

// Set database connection
function setDatabaseConnection(connection) {
  dbConnection = connection;
}

// Sanitize input
const sanitizeInput = (input) => sanitizeHtml(input, { allowedTags: [], allowedAttributes: {} });

// User Routes
router.get('/auth/me', authenticateToken, async (req, res) => {
  try {
    const [rows] = await dbConnection.execute(
      'SELECT id, name, email, phone, profile_image FROM users WHERE id = ?',
      [req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({
      id: rows[0].id,
      name: rows[0].name,
      email: rows[0].email,
      phone: rows[0].phone,
      profileImage: rows[0].profile_image || 'https://via.placeholder.com/100',
    });
  } catch (error) {
    console.error(`Fetch user error: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch user details', details: error.message });
  }
});

router.put('/auth/update', authenticateToken, upload.single('profileImage'), async (req, res) => {
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Name is required' });
  try {
    const sanitizedName = sanitizeInput(name);
    const profileImage = req.file ? `/uploads/${req.file.filename}` : req.user.profile_image;
    await dbConnection.execute('UPDATE users SET name = ?, profile_image = ? WHERE id = ?', [
      sanitizedName,
      profileImage,
      req.user.id,
    ]);
    res.json({ name: sanitizedName, profileImage });
  } catch (error) {
    console.error(`Update profile error: ${error.message}`);
    res.status(500).json({ error: 'Failed to update profile', details: error.message });
  }
});

// Menu Routes
router.get('/menu', async (req, res) => {
  try {
    const [rows] = await dbConnection.execute('SELECT * FROM menu_items');
    res.json(
      rows.map((item) => ({
        _id: item.id,
        name: item.name,
        description: item.description,
        price: parseFloat(item.price || 0),
        category: item.category,
        image: item.image || 'https://via.placeholder.com/300',
      }))
    );
  } catch (error) {
    console.error(`Fetch menu error: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch menu items', details: error.message });
  }
});

router.get('/menu/categories', async (req, res) => {
  try {
    const [rows] = await dbConnection.execute('SELECT DISTINCT category FROM menu_items WHERE category IS NOT NULL');
    res.json(rows.map((row) => row.category));
  } catch (error) {
    console.error(`Fetch categories error: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch categories', details: error.message });
  }
});

// Cart Routes
router.post('/cart/add', authenticateToken, async (req, res) => {
  const { itemId, quantity } = req.body;
  if (!itemId || !quantity || quantity < 1) return res.status(400).json({ error: 'Invalid item ID or quantity' });
  try {
    const [menuItem] = await dbConnection.execute('SELECT * FROM menu_items WHERE id = ?', [itemId]);
    if (!menuItem.length) return res.status(404).json({ error: 'Menu item not found' });
    const [cart] = await dbConnection.execute('SELECT items FROM carts WHERE user_id = ?', [req.user.id]);
    let cartItems = cart.length ? JSON.parse(cart[0].items || '[]') : [];
    const existingItemIndex = cartItems.findIndex((item) => item.itemId === itemId);
    if (existingItemIndex !== -1) {
      cartItems[existingItemIndex].quantity += quantity;
    } else {
      cartItems.push({
        itemId,
        quantity,
        itemId: {
          _id: menuItem[0].id,
          name: menuItem[0].name,
          price: parseFloat(menuItem[0].price || 0),
          image: menuItem[0].image || 'https://via.placeholder.com/300',
        },
      });
    }
    await dbConnection.execute(
      'INSERT INTO carts (user_id, items) VALUES (?, ?) ON DUPLICATE KEY UPDATE items = ?',
      [req.user.id, JSON.stringify(cartItems), JSON.stringify(cartItems)]
    );
    res.json({ cart: cartItems });
  } catch (error) {
    console.error(`Add to cart error: ${error.message}`);
    res.status(500).json({ error: 'Failed to add item to cart', details: error.message });
  }
});

router.put('/cart/update', authenticateToken, async (req, res) => {
  const { itemId, quantity } = req.body;
  if (!itemId || !quantity || quantity < 0) return res.status(400).json({ error: 'Invalid item ID or quantity' });
  try {
    const [cart] = await dbConnection.execute('SELECT items FROM carts WHERE user_id = ?', [req.user.id]);
    if (!cart.length) return res.status(404).json({ error: 'Cart not found' });
    let cartItems = JSON.parse(cart[0].items || '[]');
    const itemIndex = cartItems.findIndex((item) => item.itemId === itemId);
    if (itemIndex === -1) return res.status(404).json({ error: 'Item not found in cart' });
    if (quantity === 0) {
      cartItems.splice(itemIndex, 1);
    } else {
      cartItems[itemIndex].quantity = quantity;
    }
    await dbConnection.execute('UPDATE carts SET items = ? WHERE user_id = ?', [
      JSON.stringify(cartItems),
      req.user.id,
    ]);
    res.json({ cart: cartItems });
  } catch (error) {
    console.error(`Update cart error: ${error.message}`);
    res.status(500).json({ error: 'Failed to update cart', details: error.message });
  }
});

router.delete('/cart/remove', authenticateToken, async (req, res) => {
  const { itemId } = req.body;
  if (!itemId) return res.status(400).json({ error: 'Item ID required' });
  try {
    const [cart] = await dbConnection.execute('SELECT items FROM carts WHERE user_id = ?', [req.user.id]);
    if (!cart.length) return res.status(404).json({ error: 'Cart not found' });
    let cartItems = JSON.parse(cart[0].items || '[]');
    cartItems = cartItems.filter((item) => item.itemId !== itemId);
    await dbConnection.execute('UPDATE carts SET items = ? WHERE user_id = ?', [
      JSON.stringify(cartItems),
      req.user.id,
    ]);
    res.json({ cart: cartItems });
  } catch (error) {
    console.error(`Remove from cart error: ${error.message}`);
    res.status(500).json({ error: 'Failed to remove item from cart', details: error.message });
  }
});

// Coupon Routes
router.get('/coupons', authenticateToken, async (req, res) => {
  try {
    const [rows] = await dbConnection.execute(
      'SELECT * FROM coupons WHERE expires_at > NOW() OR expires_at IS NULL'
    );
    res.json(
      rows.map((coupon) => ({
        code: coupon.code,
        description: coupon.description,
        discount: parseFloat(coupon.discount || 0),
        minQuantity: coupon.min_quantity,
        itemCategory: coupon.item_category,
        image: coupon.image || 'https://via.placeholder.com/300',
      }))
    );
  } catch (error) {
    console.error(`Fetch coupons error: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch coupons', details: error.message });
  }
});

router.post('/coupons/apply', authenticateToken, async (req, res) => {
  const { code } = req.body;
  if (!code?.trim()) return res.status(400).json({ error: 'Coupon code required' });
  try {
    const [coupons] = await dbConnection.execute(
      'SELECT * FROM coupons WHERE code = ? AND (expires_at > NOW() OR expires_at IS NULL)',
      [sanitizeInput(code)]
    );
    if (!coupons.length) return res.status(400).json({ error: 'Invalid or expired coupon' });
    res.json({
      message: 'Coupon applied',
      discount: parseFloat(coupons[0].discount || 0),
      minQuantity: coupons[0].min_quantity,
      itemCategory: coupons[0].item_category,
    });
  } catch (error) {
    console.error(`Apply coupon error: ${error.message}`);
    res.status(500).json({ error: 'Failed to apply coupon', details: error.message });
  }
});

// Address Routes
router.get('/addresses', authenticateToken, async (req, res) => {
  try {
    const [rows] = await dbConnection.execute('SELECT * FROM addresses WHERE user_id = ?', [req.user.id]);
    res.json(
      rows.map((address) => ({
        _id: address.id,
        fullName: address.full_name,
        mobileNumber: address.mobile_number,
        houseFlatNo: address.house_flat_no,
        floorNo: address.floor_no,
        address: address.address,
        landmark: address.landmark,
      }))
    );
  } catch (error) {
    console.error(`Fetch addresses error: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch addresses', details: error.message });
  }
});

router.post('/addresses', authenticateToken, async (req, res) => {
  const { fullName, mobileNumber, houseFlatNo, floorNo, address, landmark } = req.body;
  if (!fullName || !mobileNumber || !houseFlatNo || !floorNo || !address || !landmark) {
    return res.status(400).json({ error: 'All address fields required' });
  }
  if (!/^\d{10}$/.test(mobileNumber)) return res.status(400).json({ error: 'Invalid mobile number' });
  try {
    const [result] = await dbConnection.execute(
      'INSERT INTO addresses (user_id, full_name, mobile_number, house_flat_no, floor_no, address, landmark) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [
        req.user.id,
        sanitizeInput(fullName),
        sanitizeInput(mobileNumber),
        sanitizeInput(houseFlatNo),
        sanitizeInput(floorNo),
        sanitizeInput(address),
        sanitizeInput(landmark),
      ]
    );
    res.json({ _id: result.insertId, message: 'Address added' });
  } catch (error) {
    console.error(`Add address error: ${error.message}`);
    res.status(500).json({ error: 'Failed to add address', details: error.message });
  }
});

router.put('/addresses/:id', authenticateToken, async (req, res) => {
  const { fullName, mobileNumber, houseFlatNo, floorNo, address, landmark } = req.body;
  const addressId = req.params.id;
  if (!fullName || !mobileNumber || !houseFlatNo || !floorNo || !address || !landmark) {
    return res.status(400).json({ error: 'All address fields required' });
  }
  if (!/^\d{10}$/.test(mobileNumber)) return res.status(400).json({ error: 'Invalid mobile number' });
  try {
    const [rows] = await dbConnection.execute('SELECT * FROM addresses WHERE id = ? AND user_id = ?', [
      addressId,
      req.user.id,
    ]);
    if (!rows.length) return res.status(404).json({ error: 'Address not found or unauthorized' });
    await dbConnection.execute(
      'UPDATE addresses SET full_name = ?, mobile_number = ?, house_flat_no = ?, floor_no = ?, address = ?, landmark = ? WHERE id = ?',
      [
        sanitizeInput(fullName),
        sanitizeInput(mobileNumber),
        sanitizeInput(houseFlatNo),
        sanitizeInput(floorNo),
        sanitizeInput(address),
        sanitizeInput(landmark),
        addressId,
      ]
    );
    res.json({ message: 'Address updated' });
  } catch (error) {
    console.error(`Update address error: ${error.message}`);
    res.status(500).json({ error: 'Failed to update address', details: error.message });
  }
});

router.delete('/addresses/:id', authenticateToken, async (req, res) => {
  const addressId = req.params.id;
  try {
    const [rows] = await dbConnection.execute('SELECT * FROM addresses WHERE id = ? AND user_id = ?', [
      addressId,
      req.user.id,
    ]);
    if (!rows.length) return res.status(404).json({ error: 'Address not found or unauthorized' });
    await dbConnection.execute('DELETE FROM addresses WHERE id = ?', [addressId]);
    res.json({ message: 'Address deleted' });
  } catch (error) {
    console.error(`Delete address error: ${error.message}`);
    res.status(500).json({ error: 'Failed to delete address', details: error.message });
  }
});

// Order Routes
router.post('/orders', authenticateToken, async (req, res) => {
  const { addressId, paymentMethod, items, coupon } = req.body;
  if (!addressId || !paymentMethod || !items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Address, payment method, and items required' });
  }
  try {
    const [address] = await dbConnection.execute('SELECT * FROM addresses WHERE id = ? AND user_id = ?', [
      addressId,
      req.user.id,
    ]);
    if (!address.length) return res.status(404).json({ error: 'Address not found or unauthorized' });

    // Validate items
    const validatedItems = [];
    let total = 0;
    for (const item of items) {
      const [menuItem] = await dbConnection.execute('SELECT * FROM menu_items WHERE id = ?', [item.itemId]);
      if (!menuItem.length) return res.status(404).json({ error: `Menu item ${item.itemId} not found` });
      validatedItems.push({
        itemId: menuItem[0].id,
        quantity: item.quantity,
        itemId: {
          _id: menuItem[0].id,
          name: menuItem[0].name,
          price: parseFloat(menuItem[0].price || 0),
          image: menuItem[0].image || 'https://via.placeholder.com/300',
        },
      });
      total += parseFloat(menuItem[0].price || 0) * item.quantity;
    }

    // Validate coupon
    let discount = 0;
    if (coupon) {
      const [coupons] = await dbConnection.execute(
        'SELECT * FROM coupons WHERE code = ? AND (expires_at > NOW() OR expires_at IS NULL)',
        [sanitizeInput(coupon)]
      );
      if (coupons.length) {
        discount = parseFloat(coupons[0].discount || 0);
        total -= discount;
        if (total < 0) total = 0;
      }
    }

    // Generate order ID
    const orderId = `ORD${Date.now().toString().slice(-6)}`;

    // Insert order
    const [result] = await dbConnection.execute(
      'INSERT INTO orders (user_id, address_id, order_id, items, total, status, payment_method, coupon, discount, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())',
      [
        req.user.id,
        addressId,
        orderId,
        JSON.stringify(validatedItems),
        total,
        'Pending',
        sanitizeInput(paymentMethod),
        coupon ? sanitizeInput(coupon) : null,
        discount,
      ]
    );

    // Clear cart
    await dbConnection.execute('DELETE FROM carts WHERE user_id = ?', [req.user.id]);

    res.json({ _id: result.insertId, orderId, message: 'Order placed successfully' });
  } catch (error) {
    console.error(`Place order error: ${error.message}`);
    res.status(500).json({ error: 'Failed to place order', details: error.message });
  }
});

router.get('/orders/active', authenticateToken, async (req, res) => {
  try {
    const [orders] = await dbConnection.execute(
      `SELECT o.*, a.full_name, a.address, a.landmark
       FROM orders o
       LEFT JOIN addresses a ON o.address_id = a.id
       WHERE o.user_id = ? AND o.status = 'Pending'`,
      [req.user.id]
    );
    res.json(
      orders.map((order) => ({
        _id: order.id,
        orderId: order.order_id,
        createdAt: order.created_at,
        total: parseFloat(order.total || 0),
        status: order.status,
        items: order.items ? JSON.parse(order.items) : [],
        address: {
          fullName: order.full_name || 'N/A',
          address: order.address || 'N/A',
          landmark: order.landmark || 'N/A',
        },
        paymentMethod: order.payment_method || 'N/A',
      }))
    );
  } catch (error) {
    console.error(`Fetch orders error: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch orders', details: error.message });
  }
});

router.get('/orders/:id', authenticateToken, async (req, res) => {
  const orderId = req.params.id;
  try {
    const [orders] = await dbConnection.execute(
      `SELECT o.*, a.full_name, a.address, a.landmark
       FROM orders o
       LEFT JOIN addresses a ON o.address_id = a.id
       WHERE o.id = ? AND o.user_id = ?`,
      [orderId, req.user.id]
    );
    if (!orders.length) return res.status(404).json({ error: 'Order not found' });
    const order = orders[0];
    res.json({
      _id: order.id,
      orderId: order.order_id,
      createdAt: order.created_at,
      total: parseFloat(order.total || 0),
      status: order.status,
      items: order.items ? JSON.parse(order.items) : [],
      address: {
        fullName: order.full_name || 'N/A',
        address: order.address || 'N/A',
        landmark: order.landmark || 'N/A',
      },
      paymentMethod: order.payment_method || 'N/A',
    });
  } catch (error) {
    console.error(`Fetch order details error: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch order details', details: error.message });
  }
});

router.put('/orders/:id/cancel', authenticateToken, async (req, res) => {
  const { reason } = req.body;
  const orderId = req.params.id;
  if (!reason?.trim()) return res.status(400).json({ error: 'Cancellation reason required' });
  try {
    const [orders] = await dbConnection.execute(
      'SELECT * FROM orders WHERE id = ? AND user_id = ? AND status = "Pending"',
      [orderId, req.user.id]
    );
    if (!orders.length) return res.status(404).json({ error: 'Order not found or cannot be cancelled' });
    await dbConnection.execute('UPDATE orders SET status = "Cancelled" WHERE id = ?', [orderId]);
    res.json({ message: 'Order cancelled' });
  } catch (error) {
    console.error(`Cancel order error: ${error.message}`);
    res.status(500).json({ error: 'Failed to cancel order', details: error.message });
  }
});

router.get('/orders/history', authenticateToken, async (req, res) => {
  try {
    const [orders] = await dbConnection.execute(
      `SELECT o.*, a.full_name, a.address, a.landmark
       FROM orders o
       LEFT JOIN addresses a ON o.address_id = a.id
       WHERE o.user_id = ? AND o.status IN ('Delivered', 'Cancelled')`,
      [req.user.id]
    );
    // Ensure orders is always an array
    if (!Array.isArray(orders)) {
      console.error('Orders query returned non-array:', orders);
      return res.status(500).json({ error: 'Unexpected database response' });
    }
    res.json(
      orders.map((order) => ({
        _id: order.id,
        orderId: order.order_id,
        createdAt: order.created_at,
        total: parseFloat(order.total || 0),
        status: order.status,
        items: order.items ? JSON.parse(order.items) : [],
        address: {
          fullName: order.full_name || 'N/A',
          address: order.address || 'N/A',
          landmark: order.landmark || 'N/A',
        },
        paymentMethod: order.payment_method || 'N/A',
      }))
    );
  } catch (error) {
    console.error(`Fetch order history error: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch order history', details: error.message });
  }
});

router.delete('/orders/history/clear', authenticateToken, async (req, res) => {
  try {
    await dbConnection.execute('DELETE FROM orders WHERE user_id = ? AND status IN ("Delivered", "Cancelled")', [
      req.user.id,
    ]);
    res.json({ message: 'Order history cleared' });
  } catch (error) {
    console.error(`Clear order history error: ${error.message}`);
    res.status(500).json({ error: 'Failed to clear order history', details: error.message });
  }
});

// Ratings Routes
router.post('/ratings', authenticateToken, async (req, res) => {
  const { itemId, rating, review } = req.body;
  if (!itemId || !rating || rating < 1 || rating > 5) return res.status(400).json({ error: 'Valid item ID and rating (1-5) required' });
  try {
    const [menuItem] = await dbConnection.execute('SELECT * FROM menu_items WHERE id = ?', [itemId]);
    if (!menuItem.length) return res.status(404).json({ error: 'Menu item not found' });
    const sanitizedReview = review ? sanitizeInput(review) : null;
    await dbConnection.execute(
      'INSERT INTO ratings (user_id, menu_item_id, rating, review) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE rating = ?, review = ?',
      [req.user.id, itemId, rating, sanitizedReview, rating, sanitizedReview]
    );
    res.json({ message: 'Rating submitted' });
  } catch (error) {
    console.error(`Submit rating error: ${error.message}`);
    res.status(500).json({ error: 'Failed to submit rating', details: error.message });
  }
});

// Favorites Routes
router.post('/favorites', authenticateToken, async (req, res) => {
  const { itemId } = req.body;
  if (!itemId) return res.status(400).json({ error: 'Item ID required' });
  try {
    const [menuItem] = await dbConnection.execute('SELECT * FROM menu_items WHERE id = ?', [itemId]);
    if (!menuItem.length) return res.status(404).json({ error: 'Menu item not found' });
    await dbConnection.execute(
      'INSERT INTO favorites (user_id, menu_item_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE created_at = NOW()',
      [req.user.id, itemId]
    );
    res.json({ message: 'Added to favorites' });
  } catch (error) {
    console.error(`Add favorite error: ${error.message}`);
    res.status(500).json({ error: 'Failed to add favorite', details: error.message });
  }
});

router.delete('/favorites/:itemId', authenticateToken, async (req, res) => {
  const itemId = req.params.itemId;
  try {
    const [rows] = await dbConnection.execute(
      'SELECT * FROM favorites WHERE user_id = ? AND menu_item_id = ?',
      [req.user.id, itemId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Favorite not found' });
    await dbConnection.execute('DELETE FROM favorites WHERE user_id = ? AND menu_item_id = ?', [
      req.user.id,
      itemId,
    ]);
    res.json({ message: 'Removed from favorites' });
  } catch (error) {
    console.error(`Remove favorite error: ${error.message}`);
    res.status(500).json({ error: 'Failed to remove favorite', details: error.message });
  }
});

router.get('/favorites', authenticateToken, async (req, res) => {
  try {
    const [rows] = await dbConnection.execute(
      `SELECT f.*, m.name, m.price, m.category, m.image
       FROM favorites f
       JOIN menu_items m ON f.menu_item_id = m.id
       WHERE f.user_id = ?`,
      [req.user.id]
    );
    res.json(
      rows.map((row) => ({
        id: row.menu_item_id,
        name: row.name,
        price: parseFloat(row.price || 0),
        category: row.category,
        image: row.image || 'https://via.placeholder.com/300',
      }))
    );
  } catch (error) {
    console.error(`Fetch favorites error: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch favorites', details: error.message });
  }
});

// Contact Routes
router.post('/contact', authenticateToken, async (req, res) => {
  const { subject, message } = req.body;
  console.log('Contact request body:', req.body); // Debug logging
  if (!subject?.trim() || !message?.trim()) {
    return res.status(400).json({ error: 'Subject and message required' });
  }
  try {
    const name = sanitizeInput(req.user.name || 'Anonymous');
    const email = sanitizeInput(req.user.email || '');
    await dbConnection.execute(
      'INSERT INTO contacts (user_id, name, email, subject, message) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, name, email, sanitizeInput(subject), sanitizeInput(message)]
    );
    res.json({ message: 'Message sent' });
  } catch (error) {
    console.error(`Submit contact error: ${error.message}`);
    res.status(500).json({ error: 'Failed to send message', details: error.message });
  }
});

module.exports = { router, setDatabaseConnection };