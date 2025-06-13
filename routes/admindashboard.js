const express = require('express');
const router = express.Router();
let db;

router.setDatabaseConnection = (connection) => {
  db = connection;
};

// Example admin route: Fetch all admin cart items
router.get('/cart', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM admin_cart');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch admin cart: ' + error.message });
  }
});

module.exports = router;