const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs').promises;
const sanitizeHtml = require('sanitize-html'); // Optional, for input sanitization

// Middleware to verify user session (already set in server.js, but kept for clarity)
const verifyUser = (req, res, next) => {
  if (!req.user) {
    console.log(`Unauthorized access to ${req.originalUrl}`);
    return res.status(401).json({ error: 'Unauthorized: Please log in' });
  }
  next();
};

// Sanitize input function
const sanitizeInput = (input) => {
  if (!input) return input;
  return sanitizeHtml(input, {
    allowedTags: [],
    allowedAttributes: {},
  });
};

// Get user profile
router.get('/profile', verifyUser, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [users] = await pool.query('SELECT id, name, email, phone, image, role FROM users WHERE id = ?', [req.user.id]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(users[0]);
  } catch (error) {
    console.error(`Error fetching profile for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update user profile
router.put('/profile', verifyUser, async (req, res) => {
  const { name, email, image } = req.body;
  const sanitizedName = sanitizeInput(name);
  const sanitizedEmail = sanitizeInput(email);
  const sanitizedImage = sanitizeInput(image);

  if (!sanitizedName || !sanitizedEmail) {
    return res.status(400).json({ error: 'Name and email are required' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sanitizedEmail)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  try {
    const pool = req.app.get('dbPool');
    const [existingUsers] = await pool.query('SELECT id FROM users WHERE email = ? AND id != ?', [sanitizedEmail, req.user.id]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Email already in use' });
    }
    await pool.query('UPDATE users SET name = ?, email = ?, image = ? WHERE id = ?', [
      sanitizedName,
      sanitizedEmail,
      sanitizedImage || null,
      req.user.id,
    ]);
    req.session.user = { ...req.session.user, name: sanitizedName, email: sanitizedEmail, image: sanitizedImage || req.session.user.image };
    res.json({
      id: req.user.id,
      name: sanitizedName,
      email: sanitizedEmail,
      image: sanitizedImage || req.user.image,
      role: req.user.role,
    });
  } catch (error) {
    console.error(`Error updating profile for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// upload profile image
router.post('/upload', verifyUser, async (req, res) => {
  if (!req.files || !req.files.image) {
    return res.status(400).json({ error: 'No image provided' });
  }
  const image = req.files.image;
  const validTypes = ['image/jpeg', 'image/png'];
  const maxSize = 2 * 1024 * 1024; // 2MB
  if (!validTypes.includes(image.mimetype)) {
    return res.status(400).json({ error: 'Only JPEG or PNG images are allowed' });
  }
  if (image.size > maxSize) {
    return res.status(400).json({ error: 'Image size exceeds 2MB' });
  }
  try {
    const uploadDir = path.join(__dirname, '..', 'uploads');
    await fs.mkdir(uploadDir, { recursive: true });
    const fileName = `${Date.now()}_${sanitizeInput(image.name)}`;
    const filePath = path.join(uploadDir, fileName);
    await image.mv(filePath);
    const imageUrl = `/uploads/${fileName}`;
    res.json({ url: imageUrl });
  } catch (error) {
    console.error(`Error uploading image for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to upload image' });
  }
});

// Get all addresses
router.get('/addresses', verifyUser, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [addresses] = await pool.query('SELECT id, full_name, mobile, house_no, location, landmark FROM addresses WHERE user_id = ?', [req.user.id]);
    res.json(addresses.map((addr) => ({
      id: addr.id,
      fullName: addr.full_name,
      mobile: addr.mobile,
      houseNo: addr.house_no,
      location: addr.location,
      landmark: addr.landmark,
    })));
  } catch (error) {
    console.error(`Error fetching addresses for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to fetch addresses' });
  }
});

// Add new address
router.post('/addresses', verifyUser, async (req, res) => {
  const { fullName, mobile, houseNo, location, landmark } = req.body;
  const sanitizedFullName = sanitizeInput(fullName);
  const sanitizedMobile = sanitizeInput(mobile);
  const sanitizedHouseNo = sanitizeInput(houseNo);
  const sanitizedLocation = sanitizeInput(location);
  const sanitizedLandmark = sanitizeInput(landmark);

  if (!sanitizedFullName || !sanitizedMobile || !sanitizedHouseNo || !sanitizedLocation) {
    return res.status(400).json({ error: 'All required fields must be provided' });
  }
  if (!/^\d{10}$/.test(sanitizedMobile)) {
    return res.status(400).json({ error: 'Invalid mobile number' });
  }
  try {
    const pool = req.app.get('dbPool');
    const [result] = await pool.query(
      'INSERT INTO addresses (user_id, full_name, mobile, house_no, location, landmark) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, sanitizedFullName, sanitizedMobile, sanitizedHouseNo, sanitizedLocation, sanitizedLandmark || null]
    );
    res.json({
      id: result.insertId,
      fullName: sanitizedFullName,
      mobile: sanitizedMobile,
      houseNo: sanitizedHouseNo,
      location: sanitizedLocation,
      landmark: sanitizedLandmark,
    });
  } catch (error) {
    console.error(`Error adding address for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to add address' });
  }
});

// Get single address
router.get('/addresses/:id', verifyUser, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [addresses] = await pool.query('SELECT id, full_name, mobile, house_no, location, landmark FROM addresses WHERE id = ? AND user_id = ?', [
      req.params.id,
      req.user.id,
    ]);
    if (addresses.length === 0) {
      return res.status(404).json({ error: 'Address not found' });
    }
    const addr = addresses[0];
    res.json({
      id: addr.id,
      fullName: addr.full_name,
      mobile: addr.mobile,
      houseNo: addr.house_no,
      location: addr.location,
      landmark: addr.landmark,
    });
  } catch (error) {
    console.error(`Error fetching address ${req.params.id} for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to fetch address' });
  }
});

// Update address
router.put('/addresses/:id', verifyUser, async (req, res) => {
  const { fullName, mobile, houseNo, location, landmark } = req.body;
  const sanitizedFullName = sanitizeInput(fullName);
  const sanitizedMobile = sanitizeInput(mobile);
  const sanitizedHouseNo = sanitizeInput(houseNo);
  const sanitizedLocation = sanitizeInput(location);
  const sanitizedLandmark = sanitizeInput(landmark);

  if (!sanitizedFullName || !sanitizedMobile || !sanitizedHouseNo || !sanitizedLocation) {
    return res.status(400).json({ error: 'All required fields must be provided' });
  }
  if (!/^\d{10}$/.test(sanitizedMobile)) {
    return res.status(400).json({ error: 'Invalid mobile number' });
  }
  try {
    const pool = req.app.get('dbPool');
    const [result] = await pool.query(
      'UPDATE addresses SET full_name = ?, mobile = ?, house_no = ?, location = ?, landmark = ? WHERE id = ? AND user_id = ?',
      [sanitizedFullName, sanitizedMobile, sanitizedHouseNo, sanitizedLocation, sanitizedLandmark || null, req.params.id, req.user.id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Address not found' });
    }
    res.json({
      id: req.params.id,
      fullName: sanitizedFullName,
      mobile: sanitizedMobile,
      houseNo: sanitizedHouseNo,
      location: sanitizedLocation,
      landmark: sanitizedLandmark,
    });
  } catch (error) {
    console.error(`Error updating address ${req.params.id} for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to update address' });
  }
});

// Delete address
router.delete('/addresses/:id', verifyUser, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [result] = await pool.query('DELETE FROM addresses WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Address not found' });
    }
    res.json({ message: 'Address deleted successfully' });
  } catch (error) {
    console.error(`Error deleting address ${req.params.id} for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to delete address' });
  }
});

// Get menu items
router.get('/menu', verifyUser, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [items] = await pool.query('SELECT id, name, description, price, image, category, stock FROM menu_items');
    res.json(items);
  } catch (error) {
    console.error(`Error fetching menu for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to fetch menu' });
  }
});

// Get single menu item
router.get('/menu/:id', verifyUser, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [items] = await pool.query('SELECT id, name, price, image, stock FROM menu_items WHERE id = ?', [req.params.id]);
    if (items.length === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    res.json(items[0]);
  } catch (error) {
    console.error(`Error fetching menu item ${req.params.id} for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to fetch menu item' });
  }
});

// Get coupons
router.get('/coupons', verifyUser, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [coupons] = await pool.query('SELECT id, code, discount, image FROM coupons WHERE expires_at > NOW()');
    res.json(coupons);
  } catch (error) {
    console.error(`Error fetching coupons for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

// Validate coupon
router.get('/coupons/validate', verifyUser, async (req, res) => {
  const { code } = req.query;
  const sanitizedCode = sanitizeInput(code);
  if (!sanitizedCode) {
    return res.status(400).json({ error: 'Coupon code is required' });
  }
  try {
    const pool = req.app.get('dbPool');
    const [coupons] = await pool.query('SELECT id, code, discount FROM coupons WHERE code = ? AND expires_at > NOW()', [sanitizedCode]);
    if (coupons.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired coupon' });
    }
    res.json(coupons[0]);
  } catch (error) {
    console.error(`Error validating coupon ${sanitizedCode} for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to validate coupon' });
  }
});

// Get favorites
router.get('/favorites', verifyUser, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [favorites] = await pool.query('SELECT id, item_id, name, price, image FROM favorites WHERE user_id = ?', [req.user.id]);
    res.json(favorites.map((fav) => ({
      id: fav.id,
      itemId: fav.item_id,
      name: fav.name,
      price: fav.price,
      image: fav.image,
    })));
  } catch (error) {
    console.error(`Error fetching favorites for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to fetch favorites' });
  }
});

// Add to favorites
router.post('/favorites', verifyUser, async (req, res) => {
  const { itemId, name, price, image } = req.body;
  const sanitizedName = sanitizeInput(name);
  const sanitizedImage = sanitizeInput(image);
  if (!itemId || !sanitizedName || !price) {
    return res.status(400).json({ error: 'Item ID, name, and price are required' });
  }
  try {
    const pool = req.app.get('dbPool');
    const [existing] = await pool.query('SELECT id FROM favorites WHERE user_id = ? AND item_id = ?', [req.user.id, itemId]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Item already in favorites' });
    }
    const [result] = await pool.query(
      'INSERT INTO favorites (user_id, item_id, name, price, image) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, itemId, sanitizedName, price, sanitizedImage || null]
    );
    res.json({ id: result.insertId, itemId, name: sanitizedName, price, image: sanitizedImage });
  } catch (error) {
    console.error(`Error adding favorite for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to add favorite' });
  }
});

// Remove from favorites
router.delete('/favorites/:id', verifyUser, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [result] = await pool.query('DELETE FROM favorites WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Favorite not found' });
    }
    res.json({ message: 'Favorite removed successfully' });
  } catch (error) {
    console.error(`Error removing favorite ${req.params.id} for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to remove favorite' });
  }
});

// Get cart
router.get('/cart', verifyUser, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [cartItems] = await pool.query(
      'SELECT c.id, c.item_id, c.quantity, c.name, c.price, c.image FROM cart c WHERE c.user_id = ?',
      [req.user.id]
    );
    res.json(cartItems);
  } catch (error) {
    console.error(`Error fetching cart for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to fetch cart' });
  }
});

// Add to cart
router.post('/cart', verifyUser, async (req, res) => {
  const { itemId, name, price, image, quantity } = req.body;
  const sanitizedName = sanitizeInput(name);
  const sanitizedImage = sanitizeInput(image);
  if (!itemId || !sanitizedName || !price || !quantity) {
    return res.status(400).json({ error: 'Item ID, name, price, and quantity are required' });
  }
  try {
    const pool = req.app.get('dbPool');
    const [menuItem] = await pool.query('SELECT id, stock FROM menu_items WHERE id = ?', [itemId]);
    if (menuItem.length === 0) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    if (menuItem[0].stock < quantity) {
      return res.status(400).json({ error: `Only ${menuItem[0].stock} items available` });
    }
    const [existing] = await pool.query('SELECT id, quantity FROM cart WHERE user_id = ? AND item_id = ?', [req.user.id, itemId]);
    if (existing.length > 0) {
      await pool.query('UPDATE cart SET quantity = ? WHERE id = ?', [existing[0].quantity + quantity, existing[0].id]);
    } else {
      await pool.query(
        'INSERT INTO cart (user_id, item_id, name, price, image, quantity) VALUES (?, ?, ?, ?, ?, ?)',
        [req.user.id, itemId, sanitizedName, price, sanitizedImage || null, quantity]
      );
    }
    res.json({ message: 'Item added to cart' });
  } catch (error) {
    console.error(`Error adding to cart for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to add to cart' });
  }
});

// Update cart item quantity
router.put('/cart/:id', verifyUser, async (req, res) => {
  const { quantity } = req.body;
  if (!quantity || quantity < 1) {
    return res.status(400).json({ error: 'Valid quantity is required' });
  }
  try {
    const pool = req.app.get('dbPool');
    const [cartItem] = await pool.query('SELECT item_id FROM cart WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (cartItem.length === 0) {
      return res.status(404).json({ error: 'Cart item not found' });
    }
    const [menuItem] = await pool.query('SELECT stock FROM menu_items WHERE id = ?', [cartItem[0].item_id]);
    if (menuItem.length === 0 || menuItem[0].stock < quantity) {
      return res.status(400).json({ error: `Only ${menuItem[0].stock || 0} items available` });
    }
    await pool.query('UPDATE cart SET quantity = ? WHERE id = ?', [quantity, req.params.id]);
    res.json({ message: 'Cart updated successfully' });
  } catch (error) {
    console.error(`Error updating cart item ${req.params.id} for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to update cart' });
  }
});

// Remove from cart
router.delete('/cart/:id', verifyUser, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [result] = await pool.query('DELETE FROM cart WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Cart item not found' });
    }
    res.json({ message: 'Item removed from cart' });
  } catch (error) {
    console.error(`Error removing cart item ${req.params.id} for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to remove from cart' });
  }
});

// Clear cart
router.delete('/cart/clear', verifyUser, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    await pool.query('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
    res.json({ message: 'Cart cleared successfully' });
  } catch (error) {
    console.error(`Error clearing cart for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to clear cart' });
  }
});

// Place order
router.post('/orders', verifyUser, async (req, res) => {
  const { addressId, items, couponCode, paymentMethod, deliveryCost, total, status, date } = req.body;
  const sanitizedCouponCode = sanitizeInput(couponCode);
  if (!addressId || !items || !items.length || !paymentMethod || total == null) {
    return res.status(400).json({ error: 'Address, items, payment method, and total are required' });
  }
  try {
    const pool = req.app.get('dbPool');
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    try {
      // Validate address
      const [address] = await connection.query('SELECT id FROM addresses WHERE id = ? AND user_id = ?', [addressId, req.user.id]);
      if (address.length === 0) {
        throw new Error('Invalid address');
      }
      // Validate coupon
      let discount = 0;
      if (sanitizedCouponCode) {
        const [coupon] = await connection.query('SELECT discount FROM coupons WHERE code = ? AND expires_at > NOW()', [sanitizedCouponCode]);
        if (coupon.length === 0) {
          throw new Error('Invalid or expired coupon');
        }
        discount = coupon[0].discount;
      }
      // Validate items and stock
      for (const item of items) {
        const sanitizedItemName = sanitizeInput(item.name);
        const sanitizedItemImage = sanitizeInput(item.image);
        const [menuItem] = await connection.query('SELECT stock FROM menu_items WHERE id = ?', [item.itemId]);
        if (menuItem.length === 0 || menuItem[0].stock < item.quantity) {
          throw new Error(`Insufficient stock for ${sanitizedItemName}`);
        }
      }
      // Create order
      const [orderResult] = await connection.query(
        'INSERT INTO orders (user_id, address_id, coupon_code, payment_method, delivery_cost, total, status, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [req.user.id, addressId, sanitizedCouponCode || null, paymentMethod, deliveryCost || 0, total, status || 'pending', date || new Date()]
      );
      const orderId = orderResult.insertId;
      // Insert order items
      for (const item of items) {
        const sanitizedItemName = sanitizeInput(item.name);
        const sanitizedItemImage = sanitizeInput(item.image);
        await connection.query(
          'INSERT INTO order_items (order_id, item_id, name, price, quantity, image) VALUES (?, ?, ?, ?, ?, ?)',
          [orderId, item.itemId, sanitizedItemName, item.price, item.quantity, sanitizedItemImage || null]
        );
        // Update stock
        await connection.query('UPDATE menu_items SET stock = stock - ? WHERE id = ?', [item.quantity, item.itemId]);
      }
      // Clear cart
      await connection.query('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
      await connection.commit();
      res.json({ id: orderId, message: 'Order placed successfully' });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error(`Error placing order for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: error.message || 'Failed to place order' });
  }
});

// Get order history
router.get('/orders', verifyUser, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [orders] = await pool.query(
      `
      SELECT o.id, o.date, o.total, o.delivery_cost AS delivery, o.status, o.coupon_code,
             GROUP_CONCAT(oi.name) AS item_names
      FROM orders o
      LEFT JOIN order_items oi ON o.id = oi.order_id
      WHERE o.user_id = ?
      GROUP BY o.id
      ORDER BY o.date DESC
    `,
      [req.user.id]
    );
    res.json(
      orders.map((order) => ({
        id: order.id,
        date: order.date,
        total: order.total,
        delivery: order.delivery,
        status: order.status,
        items: order.item_names ? order.item_names.split(',') : [],
        couponCode: order.coupon_code,
      }))
    );
  } catch (error) {
    console.error(`Error fetching orders for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Clear order history
router.delete('/orders/clear', verifyUser, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    try {
      await connection.query('DELETE FROM order_items WHERE order_id IN (SELECT id FROM orders WHERE user_id = ?)', [req.user.id]);
      await connection.query('DELETE FROM orders WHERE user_id = ?', [req.user.id]);
      await connection.commit();
      res.json({ message: 'Order history cleared successfully' });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error(`Error clearing orders for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to clear order history' });
  }
});

// Track order
router.get('/orders/:id/track', verifyUser, async (req, res) => {
  try {
    const pool = req.app.get('dbPool');
    const [orders] = await pool.query('SELECT id, status FROM orders WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (orders.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json(orders[0]);
  } catch (error) {
    console.error(`Error tracking order ${req.params.id} for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: 'Failed to track order' });
  }
});

// Cancel order
router.put('/orders/:id/cancel', verifyUser, async (req, res) => {
  const { reason } = req.body;
  const sanitizedReason = sanitizeInput(reason);
  if (!sanitizedReason) {
    return res.status(400).json({ error: 'Cancellation reason is required' });
  }
  try {
    const pool = req.app.get('dbPool');
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    try {
      const [orders] = await connection.query('SELECT id, status FROM orders WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
      if (orders.length === 0) {
        throw new Error('Order not found');
      }
      if (!['pending', 'confirmed'].includes(orders[0].status.toLowerCase())) {
        throw new Error('Order cannot be cancelled at this stage');
      }
      // Restore stock
      const [orderItems] = await connection.query('SELECT item_id, quantity FROM order_items WHERE order_id = ?', [req.params.id]);
      for (const item of orderItems) {
        await connection.query('UPDATE menu_items SET stock = stock + ? WHERE id = ?', [item.quantity, item.item_id]);
      }
      // Update order status
      await connection.query('UPDATE orders SET status = ?, cancellation_reason = ? WHERE id = ?', ['cancelled', sanitizedReason, req.params.id]);
      await connection.commit();
      res.json({ message: 'Order cancelled successfully' });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error(`Error cancelling order ${req.params.id} for user ${req.user.id}:`, error.message);
    res.status(500).json({ error: error.message || 'Failed to cancel order' });
  }
});

module.exports = router;