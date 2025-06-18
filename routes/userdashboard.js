const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const fs = require('fs').promises;
const { v4: uuidv4 } = require('uuid');

// Configure multer for file uploads
const upload = multer({
  dest: './public/uploads',
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
  fileFilter: (req, file, cb) => {
    if (!file) {
      cb(null, true); // Allow no file to proceed
    } else if (['image/jpeg', 'image/png'].includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only JPEG or PNG images are allowed'), false);
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

// Middleware to verify user JWT
const authenticateUserToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'user') {
      return res.status(403).json({ error: 'Access denied: User role required' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Validate Cloudinary URL
const isValidCloudinaryUrl = (url, context = 'profile') => {
  if (!url || url === null) return true; // Allow null for flexibility
  if (typeof url !== 'string') {
    console.warn(`Invalid URL type in ${context}:`, typeof url);
    return false;
  }
  const isValid = url.startsWith('https://res.cloudinary.com/') && url.includes('delicute/');
  if (!isValid) console.warn(`Invalid Cloudinary URL in ${context}:`, url);
  return isValid;
};

// Get user profile
router.get('/profile', authenticateUserToken, async (req, res) => {
  try {
    console.log('Fetching profile for user:', req.user.id);
    const [rows] = await pool.query('SELECT id, name, email, mobile, image FROM users WHERE id = ?', [req.user.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const user = rows[0];
    console.log('Profile image from DB:', user.image);
    res.status(200).json({
      ...user,
      image: isValidCloudinaryUrl(user.image, 'profile') ? user.image : null,
    });
  } catch (error) {
    console.error('Profile fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update user profile
router.put('/profile', authenticateUserToken, async (req, res) => {
  const { name, email, image } = req.body;
  if (!name || !email) {
    console.warn('Profile update missing required fields:', { name: !!name, email: !!email });
    return res.status(400).json({ error: 'Name and email are required' });
  }
  if (image && !isValidCloudinaryUrl(image, 'profile')) {
    console.warn('Invalid profile image URL provided:', image);
    return res.status(400).json({ error: 'Invalid image URL' });
  }
  try {
    const [existingEmail] = await pool.query('SELECT id FROM users WHERE email = ? AND id != ?', [email, req.user.id]);
    if (existingEmail.length > 0) {
      return res.status(400).json({ error: 'Email already in use' });
    }
    const updates = { name, email, image: image || null };
    const fields = Object.keys(updates).map((key) => `${key} = ?`).join(', ');
    const values = Object.values(updates).concat([req.user.id]);
    await pool.query(`UPDATE users SET ${fields} WHERE id = ?`, values);
    const [updatedUser] = await pool.query('SELECT id, name, email, mobile, image FROM users WHERE id = ?', [req.user.id]);
    console.log('Updated profile image in DB:', updatedUser[0].image);
    res.status(200).json({
      ...updatedUser[0],
      image: isValidCloudinaryUrl(updatedUser[0].image, 'profile') ? updatedUser[0].image : null,
    });
  } catch (error) {
    console.error('Profile update error:', error.message);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Upload profile image
router.post('/upload', authenticateUserToken, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      console.log('No image file provided, returning current profile image');
      const [user] = await pool.query('SELECT image FROM users WHERE id = ?', [req.user.id]);
      const currentImage = isValidCloudinaryUrl(user[0].image, 'profile') ? user[0].image : null;
      console.log('Current profile image:', currentImage);
      return res.status(200).json({ url: currentImage });
    }
    console.log('Uploading image:', req.file.originalname, req.file.mimetype, req.file.size);
    const uniqueId = uuidv4();
    const publicId = `profile_${req.user.id}_${uniqueId}`;
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: 'delicute/profiles',
      public_id: publicId,
      allowed_formats: ['jpg', 'png'],
      transformation: [
        { width: 200, height: 200, crop: 'fill', gravity: 'face' },
        { quality: 'auto' },
      ],
    });
    if (!isValidCloudinaryUrl(result.secure_url, 'profile')) {
      throw new Error(`Invalid Cloudinary URL returned: ${result.secure_url}`);
    }
    await fs.unlink(req.file.path);
    const [user] = await pool.query('SELECT image FROM users WHERE id = ?', [req.user.id]);
    if (user[0].image && isValidCloudinaryUrl(user[0].image, 'profile')) {
      const oldPublicId = user[0].image.split('/').pop().split('.')[0];
      await cloudinary.uploader.destroy(`delicute/profiles/${oldPublicId}`).catch((err) =>
        console.warn('Failed to delete old image:', err.message)
      );
    }
    await pool.query('UPDATE users SET image = ? WHERE id = ?', [result.secure_url, req.user.id]);
    console.log('Updated profile image:', result.secure_url);
    res.status(200).json({ url: result.secure_url });
  } catch (error) {
    console.error('Image upload error:', error.message);
    if (req.file) await fs.unlink(req.file.path).catch((err) => console.warn('Failed to delete local file:', err.message));
    res.status(500).json({ error: error.message || 'Failed to upload image' });
  }
});

// Get orders
router.get('/orders', authenticateUserToken, async (req, res) => {
  try {
    console.log('Fetching orders for user:', req.user.id);
    const [orders] = await pool.query(
      `
      SELECT 
        o.id AS orderId,
        o.total,
        o.subtotal,
        o.discount,
        o.delivery_fee AS delivery,
        o.status,
        o.created_at AS orderDate,
        o.cancellation_reason AS cancelReason,
        o.payment_method AS paymentMethod,
        o.coupon_id,
        c.code AS couponCode,
        a.full_name AS fullName,
        a.mobile AS mobile,
        a.house_no AS houseNo,
        a.location,
        a.landmark
      FROM orders o
      LEFT JOIN addresses a ON o.address_id = a.id
      LEFT JOIN coupons c ON o.coupon_id = c.id
      WHERE o.user_id = ?
      ORDER BY o.created_at DESC
      `,
      [req.user.id]
    );

    console.log('Orders found:', orders.length);
    if (orders.length === 0) {
      console.log('No orders found for user:', req.user.id);
      return res.status(200).json([]);
    }

    const orderIds = orders.map((order) => order.orderId);
    let orderItems = [];
    if (orderIds.length > 0) {
      console.log('Fetching order items for order IDs:', orderIds);
      [orderItems] = await pool.query(
        `
        SELECT 
          oi.order_id AS orderId,
          mi.name,
          oi.quantity,
          oi.price
        FROM order_items oi
        JOIN menu_items mi ON oi.menu_item_id = mi.id
        WHERE oi.order_id IN (?)
        `,
        [orderIds]
      );
      console.log('Order items found:', orderItems.length);
    }

    const response = orders.map((order) => ({
      orderId: order.orderId,
      total: parseFloat(order.total || 0).toFixed(2),
      subtotal: parseFloat(order.subtotal || 0).toFixed(2),
      discount: parseFloat(order.discount || 0).toFixed(2),
      delivery: parseFloat(order.delivery || 0).toFixed(2),
      status: order.status,
      orderDate: order.orderDate,
      cancelReason: order.cancelReason || null,
      paymentMethod: order.paymentMethod,
      couponCode: order.couponCode || null,
      address: `${order.fullName || ''}, ${order.houseNo || ''}, ${order.location || ''}${order.landmark ? `, ${order.landmark}` : ''}, Mobile: ${order.mobile || ''}`,
      addressDetails: {
        fullName: order.fullName || null,
        mobile: order.mobile || null,
        houseNo: order.houseNo || null,
        location: order.location || null,
        landmark: order.landmark || null,
      },
      items: orderItems
        .filter((item) => item.orderId === order.orderId)
        .map((item) => ({
          name: item.name,
          quantity: item.quantity,
          price: parseFloat(item.price || 0).toFixed(2),
        })),
    }));

    console.log('Returning orders response:', response.length);
    res.status(200).json(response);
  } catch (error) {
    console.error('Orders fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Get single order
router.get('/orders/:id', authenticateUserToken, async (req, res) => {
  const { id } = req.params;
  try {
    console.log('Fetching order ID:', id, 'for user:', req.user.id);
    const [orders] = await pool.query(
      `
      SELECT 
        o.id AS orderId,
        o.total,
        o.subtotal,
        o.discount,
        o.delivery_fee AS delivery,
        o.status,
        o.created_at AS orderDate,
        o.cancellation_reason AS cancelReason,
        o.payment_method AS paymentMethod,
        o.coupon_id,
        c.code AS couponCode,
        a.full_name AS fullName,
        a.mobile AS mobile,
        a.house_no AS houseNo,
        a.location,
        a.landmark
      FROM orders o
      LEFT JOIN addresses a ON o.address_id = a.id
      LEFT JOIN coupons c ON o.coupon_id = c.id
      WHERE o.id = ? AND o.user_id = ?
      `,
      [id, req.user.id]
    );

    if (orders.length === 0) {
      console.log('Order not found for ID:', id);
      return res.status(404).json({ error: 'Order not found' });
    }

    const order = orders[0];
    const [orderItems] = await pool.query(
      `
      SELECT 
        mi.name,
        oi.quantity,
        oi.price
      FROM order_items oi
      JOIN menu_items mi ON oi.menu_item_id = mi.id
      WHERE oi.order_id = ?
      `,
      [id]
    );

    const response = {
      orderId: order.orderId,
      total: parseFloat(order.total || 0).toFixed(2),
      subtotal: parseFloat(order.subtotal || 0).toFixed(2),
      discount: parseFloat(order.discount || 0).toFixed(2),
      delivery: parseFloat(order.delivery || 0).toFixed(2),
      status: order.status,
      orderDate: order.orderDate,
      cancelReason: order.cancelReason || null,
      paymentMethod: order.paymentMethod,
      couponCode: order.couponCode || null,
      address: `${order.fullName || ''}, ${order.houseNo || ''}, ${order.location || ''}${order.landmark ? `, ${order.landmark}` : ''}, Mobile: ${order.mobile || ''}`,
      addressDetails: {
        fullName: order.fullName || null,
        mobile: order.mobile || null,
        houseNo: order.houseNo || null,
        location: order.location || null,
        landmark: order.landmark || null,
      },
      items: orderItems.map((item) => ({
        name: item.name,
        quantity: item.quantity,
        price: parseFloat(item.price || 0).toFixed(2),
      })),
    };

    console.log('Returning single order response:', response.orderId);
    res.status(200).json(response);
  } catch (error) {
    console.error('Order fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch order' });
  }
});

// Place order
router.post('/orders', authenticateUserToken, async (req, res) => {
  const { addressId, items, couponCode, paymentMethod, orderDate, subtotal, discount, address } = req.body;

  if (!addressId || !items || !Array.isArray(items) || items.length === 0 || !paymentMethod || !address) {
    console.warn('Missing required order fields:', { addressId: !!addressId, items: !!items, paymentMethod: !!paymentMethod, address: !!address });
    return res.status(400).json({ error: 'Address ID, items, payment method, and address string are required' });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [addressRows] = await connection.query(
      'SELECT id, full_name, mobile, house_no, location, landmark FROM addresses WHERE id = ? AND user_id = ?',
      [addressId, req.user.id]
    );
    if (addressRows.length === 0) {
      throw new Error('Invalid address');
    }
    const addressData = addressRows[0];
    const expectedAddress = `${addressData.full_name}, ${addressData.house_no}, ${addressData.location}${addressData.landmark ? `, ${addressData.landmark}` : ''}, Mobile: ${addressData.mobile}`;
    if (address !== expectedAddress) {
      console.warn('Address mismatch:', { provided: address, expected: expectedAddress });
      throw new Error('Provided address does not match stored address');
    }

    let couponId = null;
    let discountPercentage = 0;
    if (couponCode) {
      const [coupon] = await connection.query('SELECT id, discount FROM coupons WHERE code = ?', [couponCode]);
      if (coupon.length === 0) {
        throw new Error('Invalid coupon code');
      }
      couponId = coupon[0].id;
      discountPercentage = parseFloat(coupon[0].discount || 0);
    }

    let calculatedSubtotal = 0;
    for (const item of items) {
      if (!item.itemId || !item.price || !item.quantity || item.quantity < 1 || !item.name) {
        throw new Error('Each item must have valid itemId, price, quantity, and name');
      }
      const [menuItem] = await connection.query('SELECT id, price, name FROM menu_items WHERE id = ?', [item.itemId]);
      if (menuItem.length === 0) {
        throw new Error(`Menu item ${item.itemId} not found`);
      }
      if (parseFloat(item.price).toFixed(2) !== parseFloat(menuItem[0].price).toFixed(2)) {
        throw new Error(`Price mismatch for ${menuItem[0].name}`);
      }
      calculatedSubtotal += item.quantity * parseFloat(item.price);
    }

    calculatedSubtotal = parseFloat(calculatedSubtotal.toFixed(2));

    let finalSubtotal = calculatedSubtotal;
    if (subtotal !== undefined && !isNaN(subtotal)) {
      const providedSubtotal = parseFloat(subtotal).toFixed(2);
      if (providedSubtotal !== calculatedSubtotal.toFixed(2)) {
        console.warn(`Subtotal mismatch: provided ${providedSubtotal}, calculated ${calculatedSubtotal}`);
        finalSubtotal = calculatedSubtotal;
      } else {
        finalSubtotal = parseFloat(providedSubtotal);
      }
    } else {
      console.log('No subtotal provided, using calculated subtotal:', calculatedSubtotal);
    }

    let finalDiscount = 0;
    if (couponCode) {
      const calculatedDiscount = parseFloat((calculatedSubtotal * discountPercentage) / 100).toFixed(2);
      if (discount !== undefined && !isNaN(discount)) {
        const providedDiscount = parseFloat(discount).toFixed(2);
        if (providedDiscount !== calculatedDiscount) {
          console.warn(`Discount mismatch: provided ${providedDiscount}, calculated ${calculatedDiscount}`);
          finalDiscount = parseFloat(calculatedDiscount);
        } else {
          finalDiscount = parseFloat(providedDiscount);
        }
      } else {
        finalDiscount = parseFloat(calculatedDiscount);
      }
    }

    const deliveryFee = 0;
    const total = parseFloat((finalSubtotal - finalDiscount + deliveryFee).toFixed(2));

    const [orderResult] = await connection.query(
      'INSERT INTO orders (user_id, address_id, coupon_id, subtotal, discount, delivery_fee, total, payment_method, payment_status, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [
        req.user.id,
        addressId,
        couponId,
        finalSubtotal,
        finalDiscount,
        deliveryFee,
        total,
        paymentMethod,
        paymentMethod === 'cod' ? 'pending' : 'failed',
        'Pending',
        orderDate || new Date(),
      ]
    );
    const orderId = orderResult.insertId;

    for (const item of items) {
      await connection.query(
        'INSERT INTO order_items (order_id, menu_item_id, quantity, price) VALUES (?, ?, ?, ?)',
        [orderId, item.itemId, item.quantity, parseFloat(item.price)]
      );
    }

    await connection.query('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
    await connection.commit();
    console.log('Order placed successfully:', orderId);
    res.status(200).json({ message: 'Order placed', orderId });
  } catch (error) {
    await connection.rollback();
    console.error('Place order error:', error.message);
    res.status(400).json({ error: error.message || 'Failed to place order' });
  } finally {
    connection.release();
  }
});

// Get menu
router.get('/menu', authenticateUserToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, price, category, description, image FROM menu_items');
    res.status(200).json(
      rows.map((row) => ({
        ...row,
        image: row.image && isValidCloudinaryUrl(row.image, 'menu') ? row.image : null,
        description: row.description || null,
        price: parseFloat(row.price || 0).toFixed(2),
      }))
    );
  } catch (error) {
    console.error('Menu fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch menu' });
  }
});

// Get single menu item
router.get('/menu/:id', authenticateUserToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query('SELECT id, name, price, category, description, image FROM menu_items WHERE id = ?', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    res.status(200).json({
      ...rows[0],
      image: rows[0].image && isValidCloudinaryUrl(rows[0].image, 'menu') ? rows[0].image : null,
      description: rows[0].description || null,
      price: parseFloat(rows[0].price || 0).toFixed(2),
    });
  } catch (error) {
    console.error('Menu item fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch menu item' });
  }
});

// Refresh token
router.post('/refresh-token', authenticateUserToken, async (req, res) => {
  try {
    const newToken = jwt.sign(
      { id: req.user.id, role: req.user.role, email: req.user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.status(200).json({ token: newToken });
  } catch (error) {
    console.error('Refresh token error:', error.message);
    res.status(500).json({ error: 'Failed to refresh token' });
  }
});

// Get addresses
router.get('/addresses', authenticateUserToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, full_name AS fullName, mobile, house_no AS houseNo, location, landmark FROM addresses WHERE user_id = ?',
      [req.user.id]
    );
    res.status(200).json(
      rows.map((row) => ({
        ...row,
        fullName: row.fullName || null,
        mobile: row.mobile || null,
        houseNo: row.houseNo || null,
        location: row.location || null,
        landmark: row.landmark || null,
      }))
    );
  } catch (error) {
    console.error('Addresses fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch addresses' });
  }
});

// Add address
router.post('/addresses', authenticateUserToken, async (req, res) => {
  const { fullName, mobile, houseNo, location, landmark } = req.body;
  if (!fullName || !mobile || !houseNo || !location) {
    console.warn('Missing required address fields:', { fullName: !!fullName, mobile: !!mobile, houseNo: !!houseNo, location: !!location });
    return res.status(400).json({ error: 'Full name, mobile, house number, and location are required' });
  }
  if (!/^\d{10}$/.test(mobile)) {
    return res.status(400).json({ error: 'Valid mobile number is required' });
  }
  try {
    const [result] = await pool.query(
      'INSERT INTO addresses (user_id, full_name, mobile, house_no, location, landmark) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, fullName, mobile, houseNo, location, landmark || null]
    );
    res.status(200).json({
      id: result.insertId,
      fullName,
      mobile,
      houseNo,
      location,
      landmark: landmark || null,
    });
  } catch (error) {
    console.error('Add address error:', error.message);
    res.status(500).json({ error: 'Failed to add address' });
  }
});

// Update address
router.put('/addresses/:id', authenticateUserToken, async (req, res) => {
  const { id } = req.params;
  const { fullName, mobile, houseNo, location, landmark } = req.body;
  if (!fullName || !mobile || !houseNo || !location) {
    console.warn('Missing required address fields:', { fullName: !!fullName, mobile: !!mobile, houseNo: !!houseNo, location: !!location });
    return res.status(400).json({ error: 'Full name, mobile, house number, and location are required' });
  }
  if (!/^\d{10}$/.test(mobile)) {
    return res.status(400).json({ error: 'Valid mobile number is required' });
  }
  try {
    const [rows] = await pool.query('SELECT id FROM addresses WHERE id = ? AND user_id = ?', [id, req.user.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Address not found' });
    }
    await pool.query(
      'UPDATE addresses SET full_name = ?, mobile = ?, house_no = ?, location = ?, landmark = ? WHERE id = ?',
      [fullName, mobile, houseNo, location, landmark || null, id]
    );
    res.status(200).json({
      id: parseInt(id),
      fullName,
      mobile,
      houseNo,
      location,
      landmark: landmark || null,
    });
  } catch (error) {
    console.error('Update address error:', error.message);
    res.status(500).json({ error: 'Failed to update address' });
  }
});

// Delete address
router.delete('/addresses/:id', authenticateUserToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query('SELECT id FROM addresses WHERE id = ? AND user_id = ?', [id, req.user.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Address not found' });
    }
    await pool.query('DELETE FROM addresses WHERE id = ?', [id]);
    res.status(200).json({ message: 'Address deleted' });
  } catch (error) {
    console.error('Delete address error:', error.message);
    res.status(500).json({ error: 'Failed to delete address' });
  }
});

// Get coupons
router.get('/coupons', authenticateUserToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, code, discount, description, image FROM coupons');
    res.status(200).json(
      rows.map((row) => ({
        ...row,
        image: row.image && isValidCloudinaryUrl(row.image, 'coupon') ? row.image : null,
        description: row.description || null,
        discount: parseFloat(row.discount || 0).toFixed(2),
      }))
    );
  } catch (error) {
    console.error('Coupons fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

// Apply coupon
router.get('/coupons/apply', authenticateUserToken, async (req, res) => {
  const { code } = req.query;
  if (!code) {
    return res.status(400).json({ error: 'Coupon code is required' });
  }
  try {
    const [rows] = await pool.query('SELECT id, code, discount FROM coupons WHERE code = ?', [code]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Invalid coupon code' });
    }
    res.status(200).json({
      ...rows[0],
      discount: parseFloat(rows[0].discount || 0).toFixed(2),
    });
  } catch (error) {
    console.error('Coupon apply error:', error.message);
    res.status(500).json({ error: 'Failed to apply coupon' });
  }
});

// Get favorites
router.get('/favorites', authenticateUserToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, item_id AS itemId, name, image, price FROM favorites WHERE user_id = ?',
      [req.user.id]
    );
    res.status(200).json(
      rows.map((row) => ({
        ...row,
        image: row.image && isValidCloudinaryUrl(row.image, 'favorite') ? row.image : null,
        price: parseFloat(row.price || 0).toFixed(2),
      }))
    );
  } catch (error) {
    console.error('Favorites fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch favorites' });
  }
});

// Add favorite
router.post('/favorites', authenticateUserToken, async (req, res) => {
  const { itemId, name, image, price } = req.body;
  if (!itemId || !name || !price) {
    console.warn('Missing required favorite fields:', { itemId: !!itemId, name: !!name, price: !!price });
    return res.status(400).json({ error: 'Item ID, name, and price are required' });
  }
  if (image && !isValidCloudinaryUrl(image, 'favorite')) {
    return res.status(400).json({ error: 'Invalid image URL' });
  }
  try {
    const [menuItem] = await pool.query('SELECT id FROM menu_items WHERE id = ?', [itemId]);
    if (menuItem.length === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    const [existing] = await pool.query('SELECT id FROM favorites WHERE user_id = ? AND item_id = ?', [req.user.id, itemId]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Item already in favorites' });
    }
    const [result] = await pool.query(
      'INSERT INTO favorites (user_id, item_id, name, image, price) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, itemId, name, image || null, parseFloat(price)]
    );
    res.status(200).json({ message: 'Added to favorites', id: result.insertId });
  } catch (error) {
    console.error('Add favorite error:', error.message);
    res.status(500).json({ error: 'Failed to add favorite' });
  }
});

// Remove favorite
router.delete('/favorites/:id', authenticateUserToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query('SELECT id FROM favorites WHERE item_id = ? AND user_id = ?', [id, req.user.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Favorite not found' });
    }
    await pool.query('DELETE FROM favorites WHERE item_id = ? AND user_id = ?', [id, req.user.id]);
    res.status(200).json({ message: 'Removed from favorites' });
  } catch (error) {
    console.error('Remove favorite error:', error.message);
    res.status(500).json({ error: 'Failed to remove favorite' });
  }
});

// Get cart
router.get('/cart', authenticateUserToken, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, item_id AS itemId, name, price, image, quantity, description FROM cart WHERE user_id = ?',
      [req.user.id]
    );
    res.status(200).json({
      items: rows.map((row) => ({
        ...row,
        image: row.image && isValidCloudinaryUrl(row.image, 'cart') ? row.image : null,
        description: row.description || null,
        price: parseFloat(row.price || 0).toFixed(2),
      })),
    });
  } catch (error) {
    console.error('Cart fetch error:', error.message);
    res.status(500).json({ error: 'Failed to fetch cart' });
  }
});

// Add to cart
router.post('/cart', authenticateUserToken, async (req, res) => {
  const { itemId, name, price, image, quantity = 1, description } = req.body;
  if (!itemId || !name || !price || quantity < 1) {
    console.warn('Missing required cart fields:', { itemId: !!itemId, name: !!name, price: !!price, quantity });
    return res.status(400).json({ error: 'Item ID, name, price, and valid quantity are required' });
  }
  if (image && !isValidCloudinaryUrl(image, 'cart')) {
    return res.status(400).json({ error: 'Invalid image URL' });
  }
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [menuItem] = await connection.query('SELECT id, price, description FROM menu_items WHERE id = ?', [itemId]);
    if (menuItem.length === 0) {
      throw new Error('Menu item not found');
    }
    if (parseFloat(price).toFixed(2) !== parseFloat(menuItem[0].price).toFixed(2)) {
      throw new Error(`Price mismatch for ${name}`);
    }
    const [existing] = await connection.query('SELECT id, quantity FROM cart WHERE user_id = ? AND item_id = ?', [req.user.id, itemId]);
    let cartId;
    if (existing.length > 0) {
      const newQuantity = existing[0].quantity + quantity;
      await connection.query(
        'UPDATE cart SET quantity = ?, description = ?, updated_at = NOW() WHERE id = ?',
        [newQuantity, description || menuItem[0].description || null, existing[0].id]
      );
      cartId = existing[0].id;
    } else {
      const [result] = await pool.query(
        'INSERT INTO cart (user_id, item_id, name, price, image, quantity, description) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [req.user.id, itemId, name, parseFloat(price), image || null, quantity, description || menuItem[0].description || null]
      );
      cartId = result.insertId;
    }
    await connection.commit();
    const [newItem] = await connection.query(
      'SELECT id, item_id AS itemId, name, price, image, quantity, description FROM cart WHERE id = ?',
      [cartId]
    );
    res.status(200).json({
      id: newItem[0].id,
      itemId: newItem[0].itemId,
      name: newItem[0].name,
      price: parseFloat(newItem[0].price || 0).toFixed(2),
      image: newItem[0].image && isValidCloudinaryUrl(newItem[0].image, 'cart') ? newItem[0].image : null,
      quantity: newItem[0].quantity,
      description: newItem[0].description || null,
    });
  } catch (error) {
    await connection.rollback();
    console.error('Add to cart error:', error.message);
    res.status(400).json({ error: error.message || 'Failed to add to cart' });
  } finally {
    connection.release();
  }
});

// Update cart item
router.put('/cart/:id', authenticateUserToken, async (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;
  if (!quantity || quantity < 1) {
    return res.status(400).json({ error: 'Valid quantity is required' });
  }
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [cartItem] = await connection.query('SELECT id FROM cart WHERE id = ? AND user_id = ?', [id, req.user.id]);
    if (cartItem.length === 0) {
      throw new Error('Cart item not found');
    }
    await connection.query('UPDATE cart SET quantity = ?, updated_at = NOW() WHERE id = ?', [quantity, id]);
    await connection.commit();
    res.status(200).json({ message: 'Cart updated' });
  } catch (error) {
    await connection.rollback();
    console.error('Update cart error:', error.message);
    res.status(400).json({ error: error.message || 'Failed to update cart' });
  } finally {
    connection.release();
  }
});

// Remove from cart
router.delete('/cart/:id', authenticateUserToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query('SELECT id FROM cart WHERE id = ? AND user_id = ?', [id, req.user.id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Cart item not found' });
    }
    await pool.query('DELETE FROM cart WHERE id = ?', [id]);
    res.status(200).json({ message: 'Item removed from cart' });
  } catch (error) {
    console.error('Remove from cart error:', error.message);
    res.status(500).json({ error: 'Failed to remove from cart' });
  }
});

// Clear cart
router.delete('/cart', authenticateUserToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
    res.status(200).json({ message: 'Cart cleared' });
  } catch (error) {
    console.error('Clear cart error:', error.message);
    res.status(500).json({ error: 'Failed to clear cart' });
  }
});

// Cancel order
router.put('/orders/:id/cancel', authenticateUserToken, async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;
  if (!reason) {
    return res.status(400).json({ error: 'Cancellation reason is required' });
  }
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [order] = await connection.query('SELECT id, status FROM orders WHERE id = ? AND user_id = ?', [id, req.user.id]);
    if (order.length === 0) {
      throw new Error('Order not found');
    }
    if (!['Pending', 'Confirmed'].includes(order[0].status)) {
      throw new Error('Order cannot be cancelled');
    }
    await connection.query('UPDATE orders SET status = ?, cancellation_reason = ? WHERE id = ?', ['Cancelled', reason, id]);
    await connection.commit();
    res.status(200).json({ message: 'Order cancelled' });
  } catch (error) {
    await connection.rollback();
    console.error('Cancel order error:', error.message);
    res.status(400).json({ error: 'Failed to cancel order' });
  } finally {
    connection.release();
  }
});

// Clear order history
router.delete('/orders', authenticateUserToken, async (req, res) => {
  try {
    const [orders] = await pool.query('SELECT id, status FROM orders WHERE user_id = ? AND status IN (?, ?, ?, ?)',
      [req.user.id, 'Delivered', 'Cancelled', 'Failed', 'Completed']
    );
    if (orders.length === 0) {
      return res.status(200).json({ message: 'No order history to clear' });
    }
    await pool.query('DELETE orders FROM orders WHERE user_id = ? AND status IN (?, ?, ?, ?)',
      [req.user.id, user.user.id, 'Delivered', 'Cancelled', 'Failed', 'Completed']
    );
    console.log('Order cleared successfully:', 'history cleared for user:', req.user.id);
    res.status(200).json({ message: 'Order cleared successfully' });
  } catch (error) {
    console.error('Clear order history error:', error.message);
    res.status(500).json({ error: 'Failed to clear order successfully' });
  }
});

// Logout
router.post('/logout', authenticateUserToken, async (req, res) => {
  try {
    res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error.message);
    res.status(500).json({ error: 'Failed to logout' });
  }
});

module.exports = router;