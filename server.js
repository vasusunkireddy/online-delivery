const express = require('express');
   const mysql = require('mysql2/promise');
   const jwt = require('jsonwebtoken');
   const bcrypt = require('bcryptjs');
   const { OAuth2Client } = require('google-auth-library');
   const nodemailer = require('nodemailer');
   const cors = require('cors');
   const dotenv = require('dotenv');
   const path = require('path');
   const session = require('express-session');
   const MySQLStore = require('express-mysql-session')(session);
   const multer = require('multer');

   // Load environment variables
   dotenv.config();

   const app = express();

   // Middleware
   app.use(cors({
     origin: process.env.CLIENT_URL,
     credentials: true
   }));
   app.use(express.json());
   app.use(express.static(path.join(__dirname, 'public')));
   app.use(session({
     secret: process.env.SESSION_SECRET,
     resave: false,
     saveUninitialized: false,
     store: new MySQLStore({
       host: process.env.DB_HOST,
       port: process.env.DB_PORT,
       user: process.env.DB_USER,
       password: process.env.DB_PASSWORD,
       database: process.env.DB_NAME
     }),
     cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
   }));

   // Database connection
   async function initializeDatabase() {
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

     try {
       const connection = await pool.getConnection();
       console.log('Database connected successfully');
       connection.release();
       return pool;
     } catch (error) {
       console.error('Database connection failed:', error);
       throw error;
     }
   }

   // Google OAuth2 Client
   const googleClient = new OAuth2Client({
     clientId: process.env.GOOGLE_CLIENT_ID,
     clientSecret: process.env.GOOGLE_CLIENT_SECRET,
     redirectUri: 'postmessage'
   });

   // Email transporter setup
   const transporter = nodemailer.createTransport({
     service: 'gmail',
     auth: {
       user: process.env.EMAIL_USER,
       pass: process.env.EMAIL_PASS
     }
   });

   // Routes
   const indexRoutes = require('./routes/index');
   const adminRoutes = require('./routes/admin');
   const adminDashboardRoutes = require('./routes/admindashboard');
   const userDashboardRoutes = require('./routes/userdashboard');
   app.use('/api', indexRoutes);
   app.use('/api/admin', adminRoutes);
   app.use('/api/admin', adminDashboardRoutes);
   app.use('/api', userDashboardRoutes);

   // Error handling middleware
   app.use((err, req, res, next) => {
     console.error(err.stack);
     if (err instanceof multer.MulterError) {
       if (err.code === 'LIMIT_FILE_SIZE') {
         return res.status(413).json({ error: 'File too large. Maximum size is 2MB.' });
       }
       return res.status(400).json({ error: 'File upload error' });
     }
     if (err.message === 'Only JPEG and PNG images are allowed') {
       return res.status(400).json({ error: err.message });
     }
     res.status(500).json({ error: 'Internal server error' });
   });

   // Start server
   const PORT = process.env.PORT || 3000;
   async function startServer() {
     try {
       await initializeDatabase();
       app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
     } catch (error) {
       console.error('Failed to start server:', error);
       process.exit(1);
     }
   }

   startServer();