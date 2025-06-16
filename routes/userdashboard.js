const express = require('express');
const router = express.Router();
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
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

// Utility to format date for MySQL
const formatDateForMySQL = (date) => {
  if (!date) return new Date().toISOString().slice(0, 19).replace('T', ' ');
  const d = new Date(date);
  if (isNaN(d.getTime())) throw new Error('Invalid date format');
  return d.toISOString().slice(0, 19).replace('T', ' ');
};

// Initialize database tables
async function initializeTables() {
  const connection = await pool.getConnection();
  try {
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS addresses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        full_name VARCHAR(255) NOT NULL,
        mobile VARCHAR(15) NOT NULL,
        house_no VARCHAR(100) NOT NULL,
        location VARCHAR(255) NOT NULL,
        landmark VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS favorites (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        item_id INT,
        name VARCHAR(255) NOT NULL,
        image VARCHAR(255),
        price DECIMAL(10,2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (item_id) REFERENCES menu_items(id) ON DELETE CASCADE
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS coupons (
        id INT AUTO_INCREMENT PRIMARY KEY,
        code VARCHAR(50) UNIQUE NOT NULL,
        discount DECIMAL(5,2) NOT NULL,
        image VARCHAR(255),
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS cart (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        item_id INT,
        name VARCHAR(255) NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        image VARCHAR(255),
        quantity INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (item_id) REFERENCES menu_items(id) ON DELETE CASCADE
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS orders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        address_id INT,
        coupon_code VARCHAR(50),
        payment_method ENUM('cod') DEFAULT 'cod',
        delivery_cost DECIMAL(10,2) DEFAULT 0,
        total DECIMAL(10,2) NOT NULL,
        status ENUM('pending', 'confirmed', 'preparing', 'delivered', 'cancelled') DEFAULT 'pending',
        date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        cancellation_reason TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (address_id) REFERENCES addresses(id) ON DELETE SET NULL,
        FOREIGN KEY (coupon_code) REFERENCES coupons(code) ON DELETE SET NULL
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS order_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        order_id INT,
        item_id INT,
        name VARCHAR(255) NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        quantity INT NOT NULL,
        image VARCHAR(255),
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
        FOREIGN KEY (item_id) REFERENCES menu_items(id) ON DELETE SET NULL
      )
    `);

    // Seed default coupons
    await connection.execute(`
      INSERT IGNORE INTO coupons (code, discount, image, expires_at) VALUES
      ('WELCOME10', 10.00, '/Uploads/coupon1.jpg', DATE_ADD(NOW(), INTERVAL 30 DAY)),
      ('SAVE20', 20.00, '/Uploads/coupon2.jpg', DATE_ADD(NOW(), INTERVAL 30 DAY))
    `);
    console.log('Database tables initialized');
  } catch (error) {
    console.error('Table initialization error:', error.message);
    throw error;
  } finally {
    connection.release();
  }
}

initializeTables().catch(err => console.error('Initialization failed:', err));

// JWT authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Token verification failed:', err.message);
      return res.status(403).json({ error: 'Session expired or invalid token' });
    }
    req.user = user;
    next();
  });
}

// Refresh token endpoint
router.post('/refresh-token', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, { ignoreExpiration: true });
    const newToken = jwt.sign({ id: decoded.id, mobile: decoded.mobile }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token: newToken });
  } catch (error) {
    console.error('Refresh token error:', error.message);
    res.status(403).json({ error: 'Invalid token' });
  }
});

// Image upload handling
router.post('/user/upload', authenticateToken, async (req, res) => {
  try {
    if (!req.files || !req.files.image) {
      return res.status(400).json({ error: 'No image file provided' });
    }
    const image = req.files.image;
    const validTypes = ['image/jpeg', 'image/png'];
    const maxSize = 2 * 1024 * 1024; // 2MB

    if (!validTypes.includes(image.mimetype)) {
      return res.status(400).json({ error: 'Only JPEG or PNG images are allowed' });
    }
    if (image.size > maxSize) {
      return res.status(400).json({ error: 'Image size must not exceed 2MB' });
    }

    const fileName = `${uuidv4()}${path.extname(image.name)}`;
    const uploadPath = path.join(__dirname, '..', 'Uploads', fileName);
    await image.mv(uploadPath);
    res.json({ url: `/Uploads/${fileName}` });
  } catch (error) {
    console.error('Image upload error:', error.message);
    res.status(500).json({ error: 'Failed to upload image' });
  }
});

// User Profile
router.get('/user/profile', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT id, name, email, phone AS mobile, image FROM users WHERE id = ?',
      [req.user.id]
    );
    connection.release();
    if (!rows.length) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error('Profile fetch error:', error.message);
    res.status(500).json({ error: 'Failed to retrieve profile' });
  }
});

router.put('/user/profile', authenticateToken, async (req, res) => {
  const { name, email, image } = req.body;
  if (!name || !email) {
    return res.status(400).json({ error: 'Name and email are required' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  try {
    const connection = await pool.getConnection();
    const [existing] = await connection.execute(
      'SELECT id FROM users WHERE email = ? AND id != ?',
      [email, req.user.id]
    );
    if (existing.length) {
      connection.release();
      return res.status(400).json({ error: 'Email already in use' });
    }
    const [result] = await connection.execute(
      'UPDATE users SET name = ?, email = ?, image = ? WHERE id = ?',
      [name, email, image || null, req.user.id]
    );
    connection.release();
    if (!result.affectedRows) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ id: req.user.id, name, email, mobile: req.user.mobile, image });
  } catch (error) {
    console.error('Profile update error:', error.message);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Addresses
router.get('/user/addresses', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT id, full_name AS fullName, mobile, house_no AS houseNo, location, landmark FROM addresses WHERE user_id = ?',
      [req.user.id]
    );
    connection.release();
    res.json(rows);
  } catch (error) {
    console.error('Addresses fetch error:', error.message);
    res.status(500).json({ error: 'Failed to retrieve addresses' });
  }
});

router.post('/user/addresses', authenticateToken, async (req, res) => {
  const { fullName, mobile, houseNo, location, landmark } = req.body;
  if (!fullName || !mobile || !houseNo || !location) {
    return res.status(400).json({ error: 'All required fields must be provided' });
  }
  if (!/^\d{10}$/.test(mobile)) {
    return res.status(400).json({ error: 'Mobile number must be 10 digits' });
  }
  try {
    const connection = await pool.getConnection();
    const [result] = await connection.execute(
      'INSERT INTO addresses (user_id, full_name, mobile, house_no, location, landmark) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, fullName, mobile, houseNo, location, landmark || null]
    );
    connection.release();
    res.json({ id: result.insertId, fullName, mobile, houseNo, location, landmark });
  } catch (error) {
    console.error('Address add error:', error.message);
    res.status(500).json({ error: 'Failed to add address' });
  }
});

router.put('/user/addresses/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { fullName, mobile, houseNo, location, landmark } = req.body;
  if (!fullName || !mobile || !houseNo || !location) {
    return res.status(400).json({ error: 'All required fields must be provided' });
  }
  if (!/^\d{10}$/.test(mobile)) {
    return res.status(400).json({ error: 'Mobile number must be 10 digits' });
  }
  try {
    const connection = await pool.getConnection();
    const [existing] = await connection.execute(
      'SELECT id FROM addresses WHERE id = ? AND user_id = ?',
      [id, req.user.id]
    );
    if (!existing.length) {
      connection.release();
      return res.status(404).json({ error: 'Address not found' });
    }
    const [result] = await connection.execute(
      'UPDATE addresses SET full_name = ?, mobile = ?, house_no = ?, location = ?, landmark = ? WHERE id = ? AND user_id = ?',
      [fullName, mobile, houseNo, location, landmark || null, id, req.user.id]
    );
    connection.release();
    if (!result.affectedRows) {
      return res.status(404).json({ error: 'Address not found' });
    }
    res.json({ id, fullName, mobile, houseNo, location, landmark });
  } catch (error) {
    console.error('Address update error:', error.message);
    res.status(500).json({ error: 'Failed to update address' });
  }
});

router.delete('/user/addresses/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const connection = await pool.getConnection();
    const [existing] = await connection.execute(
      'SELECT id FROM addresses WHERE id = ? AND user_id = ?',
      [id, req.user.id]
    );
    if (!existing.length) {
      connection.release();
      return res.status(404).json({ error: 'Address not found' });
    }
    await connection.execute('DELETE FROM addresses WHERE id = ? AND user_id = ?', [id, req.user.id]);
    connection.release();
    res.json({ message: 'Address deleted successfully' });
  } catch (error) {
    console.error('Address delete error:', error.message);
    res.status(500).json({ error: 'Failed to delete address' });
  }
});

// Menu
router.get('/user/menu', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT id, name, description, price, image, category, stock FROM menu_items WHERE stock >= 0'
    );
    connection.release();
    res.json(rows);
  } catch (error) {
    console.error('Menu fetch error:', error.message);
    res.status(500).json({ error: 'Failed to retrieve menu' });
  }
});

router.get('/user/menu/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT id, name, description, price, image, category, stock FROM menu_items WHERE id = ?',
      [id]
    );
    connection.release();
    if (!rows.length) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error('Menu item fetch error:', error.message);
    res.status(500).json({ error: 'Failed to retrieve menu item' });
  }
});

// Favorites
router.get('/user/favorites', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT id, item_id AS itemId, name, image, price FROM favorites WHERE user_id = ?',
      [req.user.id]
    );
    connection.release();
    res.json(rows);
  } catch (error) {
    console.error('Favorites fetch error:', error.message);
    res.status(500).json({ error: 'Failed to retrieve favorites' });
  }
});

router.post('/user/favorites', authenticateToken, async (req, res) => {
  const { itemId, name, image, price } = req.body;
  if (!itemId || !name || !price || isNaN(price) || price < 0) {
    return res.status(400).json({ error: 'Item ID, name, and valid price are required' });
  }
  try {
    const connection = await pool.getConnection();
    const [existing] = await connection.execute(
      'SELECT id FROM favorites WHERE user_id = ? AND item_id = ?',
      [req.user.id, itemId]
    );
    if (existing.length) {
      connection.release();
      return res.status(400).json({ error: 'Item already in favorites' });
    }
    const [result] = await connection.execute(
      'INSERT INTO favorites (user_id, item_id, name, image, price) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, itemId, name, image || null, parseFloat(price)]
    );
    connection.release();
    res.json({ id: result.insertId, itemId, name, image, price });
  } catch (error) {
    console.error('Favorite add error:', error.message);
    res.status(500).json({ error: 'Failed to add favorite' });
  }
});

router.delete('/user/favorites/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const connection = await pool.getConnection();
    const [existing] = await connection.execute(
      'SELECT id FROM favorites WHERE item_id = ? AND user_id = ?',
      [id, req.user.id]
    );
    if (!existing.length) {
      connection.release();
      return res.status(404).json({ error: 'Favorite not found' });
    }
    await connection.execute('DELETE FROM favorites WHERE item_id = ? AND user_id = ?', [id, req.user.id]);
    connection.release();
    res.json({ message: 'Favorite removed successfully' });
  } catch (error) {
    console.error('Favorite delete error:', error.message);
    res.status(500).json({ error: 'Failed to remove favorite' });
  }
});

// Coupons
router.get('/user/coupons', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT id, code, discount, image FROM coupons WHERE expires_at > NOW() OR expires_at IS NULL'
    );
    connection.release();
    res.json(rows);
  } catch (error) {
    console.error('Coupons fetch error:', error.message);
    res.status(500).json({ error: 'Failed to retrieve coupons' });
  }
});

router.get('/user/coupons/validate', authenticateToken, async (req, res) => {
  const { code } = req.query;
  if (!code) {
    return res.status(400).json({ error: 'Coupon code is required' });
  }
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT code, discount FROM coupons WHERE code = ? AND (expires_at > NOW() OR expires_at IS NULL)',
      [code]
    );
    connection.release();
    if (!rows.length) {
      return res.status(400).json({ error: 'Invalid or expired coupon code' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error('Coupon validation error:', error.message);
    res.status(500).json({ error: 'Failed to validate coupon' });
  }
});

// Cart
router.get('/user/cart', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT c.id, c.item_id AS itemId, c.quantity, c.name, c.price, c.image, m.stock ' +
      'FROM cart c JOIN menu_items m ON c.item_id = m.id WHERE c.user_id = ?',
      [req.user.id]
    );
    connection.release();
    res.json(rows);
  } catch (error) {
    console.error('Cart fetch error:', error.message);
    res.status(500).json({ error: 'Failed to retrieve cart' });
  }
});

router.post('/user/cart', authenticateToken, async (req, res) => {
  const { itemId, name, price, image, quantity } = req.body;
  if (!itemId || !name || !price || !quantity || isNaN(price) || price < 0 || isNaN(quantity) || quantity < 1) {
    return res.status(400).json({ error: 'Invalid item details or quantity' });
  }
  try {
    const connection = await pool.getConnection();
    const [menuItem] = await connection.execute(
      'SELECT stock, name FROM menu_items WHERE id = ?',
      [itemId]
    );
    if (!menuItem.length || menuItem[0].stock < quantity) {
      connection.release();
      return res.status(400).json({ error: `Insufficient stock for ${name}` });
    }
    const [existing] = await connection.execute(
      'SELECT id, quantity FROM cart WHERE user_id = ? AND item_id = ?',
      [req.user.id, itemId]
    );
    if (existing.length) {
      const newQuantity = existing[0].quantity + quantity;
      if (newQuantity > menuItem[0].stock) {
        connection.release();
        return res.status(400).json({ error: `Only ${menuItem[0].stock} ${name} available` });
      }
      await connection.execute(
        'UPDATE cart SET quantity = ? WHERE id = ?',
        [newQuantity, existing[0].id]
      );
    } else {
      await connection.execute(
        'INSERT INTO cart (user_id, item_id, name, price, image, quantity) VALUES (?, ?, ?, ?, ?, ?)',
        [req.user.id, itemId, name, parseFloat(price), image || null, quantity]
      );
    }
    connection.release();
    res.json({ message: 'Item added to cart successfully' });
  } catch (error) {
    console.error('Cart add error:', error.message);
    res.status(500).json({ error: 'Failed to add item to cart' });
  }
});

router.put('/user/cart/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;
  if (!quantity || isNaN(quantity) || quantity < 1) {
    return res.status(400).json({ error: 'Quantity must be at least 1' });
  }
  try {
    const connection = await pool.getConnection();
    const [cartItem] = await connection.execute(
      'SELECT c.item_id, c.quantity, c.name, m.stock FROM cart c JOIN menu_items m ON c.item_id = m.id WHERE c.id = ? AND c.user_id = ?',
      [id, req.user.id]
    );
    if (!cartItem.length) {
      connection.release();
      return res.status(404).json({ error: 'Cart item not found' });
    }
    if (quantity > cartItem[0].stock) {
      connection.release();
      return res.status(400).json({ error: `Only ${cartItem[0].stock} ${cartItem[0].name} available` });
    }
    await connection.execute(
      'UPDATE cart SET quantity = ? WHERE id = ? AND user_id = ?',
      [quantity, id, req.user.id]
    );
    connection.release();
    res.json({ message: 'Cart item quantity updated successfully' });
  } catch (error) {
    console.error('Cart update error:', error.message);
    res.status(500).json({ error: 'Failed to update cart item' });
  }
});

router.delete('/user/cart/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const connection = await pool.getConnection();
    const [existing] = await connection.execute(
      'SELECT id FROM cart WHERE id = ? AND user_id = ?',
      [id, req.user.id]
    );
    if (!existing.length) {
      connection.release();
      return res.status(404).json({ error: 'Cart item not found' });
    }
    await connection.execute('DELETE FROM cart WHERE id = ? AND user_id = ?', [id, req.user.id]);
    connection.release();
    res.json({ message: 'Item removed from cart successfully' });
  } catch (error) {
    console.error('Cart item delete error:', error.message);
    res.status(500).json({ error: 'Failed to remove item from cart' });
  }
});

router.delete('/user/cart/clear', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.execute('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
    connection.release();
    res.json({ message: 'Cart cleared successfully' });
  } catch (error) {
    console.error('Cart clear error:', error.message);
    res.status(500).json({ error: 'Failed to clear cart' });
  }
});

// Orders
router.post('/user/orders', authenticateToken, async (req, res) => {
  const { addressId, items, couponCode, paymentMethod, deliveryCost, total, status, date } = req.body;
  if (!addressId || !items || !items.length || !total || isNaN(total) || total < 0) {
    return res.status(400).json({ error: 'Address, items, and valid total are required' });
  }
  try {
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    try {
      // Validate address
      const [address] = await connection.execute(
        'SELECT id FROM addresses WHERE id = ? AND user_id = ?',
        [addressId, req.user.id]
      );
      if (!address.length) {
        throw new Error('Invalid address selected');
      }

      // Validate coupon
      if (couponCode) {
        const [coupon] = await connection.execute(
          'SELECT code FROM coupons WHERE code = ? AND (expires_at > NOW() OR expires_at IS NULL)',
          [couponCode]
        );
        if (!coupon.length) {
          throw new Error('Invalid or expired coupon code');
        }
      }

      // Validate items and stock
      for (const item of items) {
        if (!item.itemId || !item.name || !item.price || !item.quantity || isNaN(item.price) || item.price < 0 || isNaN(item.quantity) || item.quantity < 1) {
          throw new Error('Invalid item details');
        }
        const [menuItem] = await connection.execute(
          'SELECT stock, name FROM menu_items WHERE id = ?',
          [item.itemId]
        );
        if (!menuItem.length || menuItem[0].stock < item.quantity) {
          throw new Error(`Insufficient stock for ${menuItem[0]?.name || 'item'}`);
        }
      }

      // Format date
      const formattedDate = formatDateForMySQL(date);

      // Create order
      const [orderResult] = await connection.execute(
        'INSERT INTO orders (user_id, address_id, coupon_code, payment_method, delivery_cost, total, status, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [req.user.id, addressId, couponCode || null, paymentMethod || 'cod', parseFloat(deliveryCost) || 0, parseFloat(total), status || 'pending', formattedDate]
      );

      // Insert order items and update stock
      for (const item of items) {
        await connection.execute(
          'INSERT INTO order_items (order_id, item_id, name, price, quantity, image) VALUES (?, ?, ?, ?, ?, ?)',
          [orderResult.insertId, item.itemId, item.name, parseFloat(item.price), item.quantity, item.image || null]
        );
        await connection.execute(
          'UPDATE menu_items SET stock = stock - ? WHERE id = ?',
          [item.quantity, item.itemId]
        );
      }

      // Clear cart
      await connection.execute('DELETE FROM cart WHERE user_id = ?', [req.user.id]);

      await connection.commit();
      connection.release();
      res.json({ id: orderResult.insertId, message: 'Order placed successfully' });
    } catch (error) {
      await connection.rollback();
      connection.release();
      throw error;
    }
  } catch (error) {
    console.error('Order placement error:', error.message);
    res.status(400).json({ error: error.message || 'Failed to place order' });
  }
});

router.get('/user/orders', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [orders] = await connection.execute(
      'SELECT o.id, o.date, o.total, o.delivery_cost AS delivery, o.status, o.cancellation_reason, ' +
      'GROUP_CONCAT(oi.name) AS item_names ' +
      'FROM orders o LEFT JOIN order_items oi ON o.id = oi.order_id ' +
      'WHERE o.user_id = ? GROUP BY o.id ORDER BY o.date DESC',
      [req.user.id]
    );
    const result = orders.map(order => ({
      id: order.id,
      date: order.date.toISOString(),
      total: parseFloat(order.total),
      delivery: parseFloat(order.delivery),
      status: order.status,
      items: order.item_names ? order.item_names.split(',') : [],
      cancellationReason: order.cancellation_reason || null
    }));
    connection.release();
    res.json(result);
  } catch (error) {
    console.error('Orders fetch error:', error.message);
    res.status(500).json({ error: 'Failed to retrieve orders' });
  }
});

router.put('/user/orders/:id/cancel', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;
  if (!reason) {
    return res.status(400).json({ error: 'Cancellation reason is required' });
  }
  try {
    const connection = await pool.getConnection();
    await connection.beginTransaction();
    try {
      const [order] = await connection.execute(
        'SELECT status FROM orders WHERE id = ? AND user_id = ?',
        [id, req.user.id]
      );
      if (!order.length) {
        throw new Error('Order not found');
      }
      if (!['pending', 'confirmed'].includes(order[0].status.toLowerCase())) {
        throw new Error('Order cannot be cancelled at this stage');
      }

      // Restore stock
      const [orderItems] = await connection.execute(
        'SELECT item_id, quantity FROM order_items WHERE order_id = ?',
        [id]
      );
      for (const item of orderItems) {
        if (item.item_id) {
          await connection.execute(
            'UPDATE menu_items SET stock = stock + ? WHERE id = ?',
            [item.quantity, item.item_id]
          );
        }
      }

      await connection.execute(
        'UPDATE orders SET status = "cancelled", cancellation_reason = ? WHERE id = ? AND user_id = ?',
        [reason, id, req.user.id]
      );

      await connection.commit();
      connection.release();
      res.json({ message: 'Order cancelled successfully' });
    } catch (error) {
      await connection.rollback();
      connection.release();
      throw error;
    }
  } catch (error) {
    console.error('Order cancellation error:', error.message);
    res.status(400).json({ error: error.message || 'Failed to cancel order' });
  }
});

router.get('/user/orders/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT id, status FROM orders WHERE id = ? AND user_id = ?',
      [id, req.user.id]
    );
    connection.release();
    if (!rows.length) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    console.error('Order tracking error:', error.message);
    res.status(500).json({ error: 'Failed to track order' });
  }
});

router.delete('/user/orders/clear', authenticateToken, async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.execute(
      'DELETE FROM orders WHERE user_id = ? AND status = "delivered"',
      [req.user.id]
    );
    connection.release();
    res.json({ message: 'Delivered orders cleared successfully' });
  } catch (error) {
    console.error('Order history clear error:', error.message);
    res.status(500).json({ error: 'Failed to clear order history' });
  }
});

// Logout
router.post('/logout', authenticateToken, (req, res) => {
  // In a real app, you might invalidate the token in a blacklist or similar
  res.json({ message: 'Logged out successfully' });
});

module.exports = router;