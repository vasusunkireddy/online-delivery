const express = require('express');
const Sequelize = require('sequelize');
const dotenv = require('dotenv');
const cors = require('cors');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const path = require('path');
const fs = require('fs');

// Load .env file
const envPath = path.resolve(__dirname, '.env');
if (!fs.existsSync(envPath)) {
  console.error('Error: .env file not found at:', envPath);
  process.exit(1);
}
dotenv.config({ path: envPath });

// Validate required environment variables
const requiredEnv = ['DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_PORT', 'JWT_SECRET', 'SESSION_SECRET'];
const missingEnv = requiredEnv.filter(key => !process.env[key]);
if (missingEnv.length > 0) {
  console.error('Error: Missing required environment variables:', missingEnv.join(', '));
  process.exit(1);
}

// Create public/Uploads directory
const uploadDir = path.join(__dirname, 'public/Uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log('Created public/Uploads directory');
}

// Sequelize instance
const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT) || 3306,
    dialect: 'mysql',
    dialectOptions: {
      ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
    },
    logging: process.env.NODE_ENV === 'development' ? console.log : false,
  }
);

// Models
const User = sequelize.define('User', {
  id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
  name: { type: Sequelize.STRING, allowNull: false },
  email: { type: Sequelize.STRING, unique: true, allowNull: false },
  phone: { type: Sequelize.STRING, unique: true, allowNull: true },
  password: { type: Sequelize.STRING, allowNull: true },
  googleId: { type: Sequelize.STRING, unique: true, allowNull: true },
  image: { type: Sequelize.STRING, defaultValue: '/Uploads/default-profile.png' },
  resetPasswordToken: { type: Sequelize.STRING },
  resetPasswordExpires: { type: Sequelize.DATE },
});

const Cart = sequelize.define('Cart', {
  id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
  userId: {
    type: Sequelize.INTEGER,
    references: { model: 'Users', key: 'id' },
    allowNull: false,
  },
  itemId: { type: Sequelize.INTEGER, allowNull: false },
  name: { type: Sequelize.STRING, allowNull: false },
  price: { type: Sequelize.FLOAT, allowNull: false },
  image: { type: Sequelize.STRING, defaultValue: '/Uploads/default-menu.png' },
  quantity: { type: Sequelize.INTEGER, defaultValue: 1, allowNull: false },
});

const MenuItem = sequelize.define('MenuItem', {
  id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
  name: { type: Sequelize.STRING, allowNull: false },
  price: { type: Sequelize.FLOAT, allowNull: false },
  image: { type: Sequelize.STRING, defaultValue: '/Uploads/default-menu.png' },
  description: { type: Sequelize.TEXT },
  category: { type: Sequelize.STRING, allowNull: false, defaultValue: 'general' },
});

const RestaurantStatus = sequelize.define('RestaurantStatus', {
  id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
  status: {
    type: Sequelize.ENUM('open', 'closed'),
    defaultValue: 'open',
    allowNull: false,
  },
});

const Address = sequelize.define('Address', {
  id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
  userId: {
    type: Sequelize.INTEGER,
    references: { model: 'Users', key: 'id' },
    allowNull: false,
  },
  fullName: { type: Sequelize.STRING, allowNull: false },
  mobile: { type: Sequelize.STRING, allowNull: false },
  houseNo: { type: Sequelize.STRING, allowNull: false },
  location: { type: Sequelize.STRING, allowNull: false },
  landmark: { type: Sequelize.STRING },
});

const Favorite = sequelize.define('Favorite', {
  id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
  userId: {
    type: Sequelize.INTEGER,
    references: { model: 'Users', key: 'id' },
    allowNull: false,
  },
  itemId: { type: Sequelize.INTEGER, allowNull: false },
  name: { type: Sequelize.STRING, allowNull: false },
  image: { type: Sequelize.STRING, defaultValue: '/Uploads/default-menu.png' },
}, {
  indexes: [{ unique: true, fields: ['userId', 'itemId'], name: 'favorite_userId_itemId_idx' }],
});

const Coupon = sequelize.define('Coupon', {
  id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
  code: { type: Sequelize.STRING, unique: true, allowNull: false },
  discount: { type: Sequelize.FLOAT, allowNull: false },
  image: { type: Sequelize.STRING, defaultValue: '/Uploads/default-coupon.png' },
});

const Order = sequelize.define('Order', {
  id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
  userId: {
    type: Sequelize.INTEGER,
    references: { model: 'Users', key: 'id' },
    allowNull: false,
  },
  addressId: {
    type: Sequelize.INTEGER,
    references: { model: 'Addresses', key: 'id' },
    allowNull: false,
  },
  items: { type: Sequelize.JSON, allowNull: false },
  total: { type: Sequelize.FLOAT, allowNull: false },
  couponCode: { type: Sequelize.STRING, allowNull: true },
  paymentMethod: {
    type: Sequelize.ENUM('cod', 'online'),
    allowNull: false,
  },
  deliveryCost: { type: Sequelize.FLOAT, allowNull: false, defaultValue: 0 },
  status: {
    type: Sequelize.ENUM('pending', 'confirmed', 'shipped', 'delivered', 'cancelled'),
    allowNull: false,
    defaultValue: 'pending',
  },
  cancelReason: { type: Sequelize.STRING, allowNull: true },
}, {
  timestamps: true,
});

// Associations
User.hasMany(Cart, { foreignKey: 'userId', onDelete: 'CASCADE' });
Cart.belongsTo(User, { foreignKey: 'userId' });
Cart.belongsTo(MenuItem, { foreignKey: 'itemId' });
User.hasMany(Address, { foreignKey: 'userId', onDelete: 'CASCADE' });
Address.belongsTo(User, { foreignKey: 'userId' });
User.hasMany(Favorite, { foreignKey: 'userId', onDelete: 'CASCADE' });
Favorite.belongsTo(User, { foreignKey: 'userId' });
Favorite.belongsTo(MenuItem, { foreignKey: 'itemId' });
User.hasMany(Order, { foreignKey: 'userId', onDelete: 'CASCADE' });
Order.belongsTo(User, { foreignKey: 'userId' });
Order.belongsTo(Address, { foreignKey: 'addressId' });

// Initialize default data
async function initializeDefaults() {
  try {
    const menuCount = await MenuItem.count();
    if (menuCount === 0) {
      await MenuItem.bulkCreate([
        { name: 'Cloud Soufflé', price: 250, image: '/Uploads/default-menu.png', description: 'A light, fluffy dessert.', category: 'dessert' },
        { name: 'Sky Risotto', price: 350, image: '/Uploads/default-menu.png', description: 'Creamy and flavorful.', category: 'main' },
        { name: 'Star Bruschetta', price: 150, image: '/Uploads/default-menu.png', description: 'Fresh and zesty.', category: 'starter' },
        { name: 'Moonlit Mojito', price: 100, image: '/Uploads/default-menu.png', description: 'Refreshing and cool.', category: 'beverage' },
      ]);
      console.log('Default menu items created');
    }

    const statusCount = await RestaurantStatus.count();
    if (statusCount === 0) {
      await RestaurantStatus.create({ status: 'open' });
      console.log('Default restaurant status created');
    }

    const couponCount = await Coupon.count();
    if (couponCount === 0) {
      await Coupon.bulkCreate([
        { code: 'DELICUTE10', discount: 10, image: '/Uploads/default-coupon.png' },
        { code: 'SAVE20', discount: 20, image: '/Uploads/default-coupon.png' },
      ]);
      console.log('Default coupons created');
    }
  } catch (error) {
    console.error('Error initializing default data:', error.message);
    process.exit(1);
  }
}

// Session store
const sessionStore = new MySQLStore({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
  clearExpired: true,
  checkExpirationInterval: 15 * 60 * 1000, // 15 minutes
  expiration: 24 * 60 * 60 * 1000, // 24 hours
});

const app = express();

// Middleware
const corsOptions = {
  origin: [
    process.env.CLIENT_URL || 'http://localhost:3000',
    'http://localhost:3000',
  ],
  credentials: true,
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: 'Unauthorized: Please log in' });
  }
  next();
};

// Routes
const indexRoutes = require('./routes/index')(User, Cart, MenuItem, RestaurantStatus, Address, Favorite, Coupon, Order);
app.use('/api', indexRoutes);

// Serve frontend files
app.get('*', (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).json({ message: 'Frontend file not found' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(`Server error: ${err.message} | Path: ${req.path} | Method: ${req.method}`);
  if (err.name === 'SequelizeValidationError') {
    return res.status(400).json({ message: err.errors[0].message });
  }
  if (err.message.includes('LIMIT_FILE_SIZE')) {
    return res.status(400).json({ message: 'File size exceeds 2MB limit' });
  }
  if (err.message.includes('Only JPEG, PNG')) {
    return res.status(400).json({ message: err.message });
  }
  res.status(500).json({
    message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error',
  });
});

// Start server
const PORT = process.env.PORT || 3000;
async function startServer() {
  try {
    await sequelize.authenticate();
    console.log('✅ Database connection established');
    await sequelize.sync({ force: false });
    console.log('✅ Database models synced');
    await initializeDefaults();
    console.log('✅ Default data initialized');
    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
      if (!process.env.CLIENT_URL) {
        console.warn('⚠️ CLIENT_URL not set in .env. Using default: http://localhost:3000');
      }
    });
  } catch (error) {
    console.error('Error starting server:', error.message);
    process.exit(1);
  }
}

startServer();