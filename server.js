const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');
const path = require('path');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Logger Setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.printf(({ level, message, timestamp, stack, ...metadata }) => {
      let log = `${timestamp} [${level.toUpperCase()}]: ${message}`;
      if (stack) {
        log += `\nStack Trace:\n${stack}`;
      }
      if (Object.keys(metadata).length > 0) {
        log += `\nMetadata: ${JSON.stringify(metadata, null, 2)}`;
      }
      return log;
    })
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error', format: winston.format.json() }),
    new winston.transports.File({ filename: 'combined.log', format: winston.format.json() }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ level, message, timestamp, stack, ...metadata }) => {
          let log = `${timestamp} [${level}]: ${message}`;
          if (stack) {
            log += `\nStack Trace:\n${stack}`;
          }
          if (Object.keys(metadata).length > 0) {
            log += `\nMetadata: ${JSON.stringify(metadata, null, 2)}`;
          }
          return log;
        })
      )
    })
  ]
});

// Validate Environment Variables
const requiredEnv = ['DATABASE_URL', 'GOOGLE_CLIENT_ID', 'JWT_SECRET', 'EMAIL_USER', 'EMAIL_PASS'];
requiredEnv.forEach(key => {
  if (!process.env[key]) {
    logger.error(`Missing required environment variable: ${key}`);
    process.exit(1);
  }
});

// ... (Middleware, PostgreSQL Pool, Google OAuth, Nodemailer setup unchanged) ...

// Initialize Database
async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255),
        email VGA(255) UNIQUE,
        phone VARCHAR(20),
        password VARCHAR(255),
        address TEXT,
        role VARCHAR(50) DEFAULT 'user'
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS otps (
        email VARCHAR(255) PRIMARY KEY,
        otp VARCHAR(6),
        expires_at TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS menu_items (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255),
        description TEXT,
        price DECIMAL(10,2),
        image TEXT,
        category VARCHAR(100),
        is_popular BOOLEAN DEFAULT FALSE
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS carts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        item_id INTEGER REFERENCES menu_items(id),
        quantity INTEGER
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS promotions (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255),
        description TEXT,
        code VARCHAR(50),
        discount DECIMAL(10,2),
        image TEXT
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        order_id VARCHAR(50),
        date TIMESTAMP,
        total DECIMAL(10,2),
        status VARCHAR(50),
        address_id INTEGER,
        payment_method VARCHAR(50)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS order_items (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id),
        item_id INTEGER REFERENCES menu_items(id),
        quantity INTEGER,
        price DECIMAL(10,2)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS favourites (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        item_id INTEGER REFERENCES menu_items(id)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS addresses (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        name VARCHAR(255),
        street TEXT,
        city VARCHAR(100),
        state VARCHAR(100),
        zip VARCHAR(20),
        mobile VARCHAR(20),
        is_default BOOLEAN DEFAULT FALSE
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS loyalty (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        points INTEGER DEFAULT 0
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS loyalty_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        action VARCHAR(255),
        points INTEGER,
        date TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS referrals (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        code VARCHAR(50),
        link TEXT
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS support_tickets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        subject VARCHAR(255),
        description TEXT,
        status VARCHAR(50),
        date TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS support_chat (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        sender VARCHAR(255),
        message TEXT,
        timestamp TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS faqs (
        id SERIAL PRIMARY KEY,
        question TEXT,
        answer TEXT
      );
    `);

    // Seed admin user
    const adminEmail = 'svasudevareddy18604@gmail.com';
    const adminPassword = 'vasudev';
    const hashedPassword = await bcrypt.hash(adminPassword, 10);
    await pool.query(`
      INSERT INTO users (name, email, password, role)
      SELECT 'Admin', $1, $2, 'admin'
      WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = $1::VARCHAR)
    `, [adminEmail, hashedPassword]);

    // Seed default menu items
    const menuCount = await pool.query('SELECT COUNT(*) FROM menu_items');
    if (menuCount.rows[0].count == 0) {
      const defaultMenu = [
        {
          name: 'Margherita Pizza',
          description: 'Classic pizza with tomato and mozzarella',
          price: 250,
          image: 'https://images.unsplash.com/photo-1595854341625-f33eece6d2d4?ixlib=rb-4.0.3&auto=format&fit=crop&w=300&h=200&q=80',
          category: 'Vegetarian',
          is_popular: true
        },
        {
          name: 'Butter Chicken',
          description: 'Creamy tomato-based chicken curry',
          price: 350,
          image: 'https://images.unsplash.com/photo-1603894584373-5ac82b2ae398?ixlib=rb-4.0.3&auto=format&fit=crop&w=300&h=200&q=80',
          category: 'Non-Veg',
          is_popular: true
        },
        {
          name: 'Chocolate Lava Cake',
          description: 'Warm cake with molten chocolate center',
          price: 150,
          image: 'https://images.unsplash.com/photo-1617634667039-44e6a1004b2d?ixlib=rb-4.0.3&auto=format&fit=crop&w=300&h=200&q=80',
          category: 'Desserts',
          is_popular: false
        },
        {
          name: 'Paneer Tikka',
          description: 'Grilled paneer with spices',
          price: 280,
          image: 'https://images.unsplash.com/photo-1596797038530-2c107229654b?ixlib=rb-4.0.3&auto=format&fit=crop&w=300&h=200&q=80',
          category: 'Vegetarian',
          is_popular: false
        }
      ];
      for (const item of defaultMenu) {
        await pool.query(`
          INSERT INTO menu_items (name, description, price, image, category, is_popular)
          VALUES ($1, $2, $3, $4, $5, $6)
        `, [item.name, item.description, item.price, item.image, item.category, item.is_popular]);
      }
    }

    // Seed default promotion
    const promoCount = await pool.query('SELECT COUNT(*) FROM promotions');
    if (promoCount.rows[0].count == 0) {
      await pool.query(`
        INSERT INTO promotions (title, description, code, discount, image)
        VALUES ($1, $2, $3, $4, $5)
      `, [
        '20% Off First Order',
        'Use code FIRST20 for 20% off',
        'FIRST20',
        20,
        'https://images.unsplash.com/photo-1546069901-ba9599a7e63c?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&h=300&q=80'
      ]);
    }

    // Seed default FAQs
    const faqCount = await pool.query('SELECT COUNT(*) FROM faqs');
    if (faqCount.rows[0].count == 0) {
      const defaultFaqs = [
        { question: 'What are your delivery hours?', answer: 'We deliver from 10 AM to 10 PM daily.' },
        { question: 'Can I cancel my order?', answer: 'Yes, within 10 minutes of placing the order.' }
      ];
      for (const faq of defaultFaqs) {
        await pool.query(`
          INSERT INTO faqs (question, answer)
          VALUES ($1, $2)
        `, [faq.question, faq.answer]);
      }
    }

    logger.info('Database initialized successfully');
  } catch (err) {
    logger.error('Error initializing database', { error: err });
    throw err;
  }
}

// ... (OTP Generation, Authentication Middleware, Routes unchanged except for the Update Address route) ...

// Update Address
app.post('/api/addresses/update', authenticateToken, async (req, res) => {
  const { id, name, street, city, state, zip, mobile, isDefault } = req.body;
  const userId = req.user.id;
  if (!id || !name || !street || !city || !state || !zip || !mobile) {
    return res.status(400).json({ message: 'All address fields are required' });
  }
  try {
    if (isDefault) {
      await pool.query('UPDATE addresses SET is_default = FALSE WHERE user_id = $1', [userId]);
    }
    await pool.query(`
      UPDATE addresses
      SET name = $1, street = $2, city = $3, state = $4, zip = $5, mobile = $6, is_default = $7
      WHERE id = $8 AND user_id = $9
    `, [name, street, city, state, zip, mobile, isDefault || false, id, userId]);
    res.json({ success: true });
  } catch (err) {
    logger.error('Update address error', { error: err });
    res.status(500).json({ message: 'Server error' });
  }
});

// ... (Remaining routes unchanged) ...

// Start Server
async function startServer() {
  try {
    await initDb();
    app.listen(port, () => {
      logger.info(`Server running at http://localhost:${port}`);
    });
  } catch (err) {
    logger.error('Failed to start server', { error: err });
    process.exit(1);
  }
}

startServer();