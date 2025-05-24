const express = require('express');
const { verifyToken, isAdmin } = require('../middleware/auth');
const pool = require('../config/db');
const router = express.Router();

// Protect all admin routes
router.use(verifyToken, isAdmin);

// Get All Orders
router.get('/orders', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM orders ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Order Status
router.put('/orders/:id', async (req, res) => {
  const { status } = req.body;
  try {
    await pool.query('UPDATE orders SET status = $1 WHERE id = $2', [status, req.params.id]);
    res.json({ message: 'Order updated' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Add Menu Item
router.post('/menu', async (req, res) => {
  const { name, description, price, category } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO menu_items (name, description, price, category) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, description, price, category]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Update Menu Item
router.put('/menu/:id', async (req, res) => {
  const { name, description, price, category } = req.body;
  try {
    await pool.query(
      'UPDATE menu_items SET name = $1, description = $2, price = $3, category = $4 WHERE id = $5',
      [name, description, price, category, req.params.id]
    );
    res.json({ message: 'Menu item updated' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete Menu Item
router.delete('/menu/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM menu_items WHERE id = $1', [req.params.id]);
    res.json({ message: 'Menu item deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;