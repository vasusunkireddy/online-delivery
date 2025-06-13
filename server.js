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
    logging: false,
  }
);

// Models
const User = sequelize.define('User', {
  id: {
    type: Sequelize.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  name: { type: Sequelize.STRING, allowNull: false },
  email: { type: Sequelize.STRING, unique: true, allowNull: false },
  phone: { type: Sequelize.STRING, unique: true, allowNull: true },
  password: { type: Sequelize.STRING, allowNull: true },
  googleId: { type: Sequelize.STRING, unique: true, allowNull: true },
  image: { type: Sequelize.STRING, allowNull: true },
  resetPasswordToken: { type: Sequelize.STRING },
  resetPasswordExpires: { type: Sequelize.DATE },
});

const Cart = sequelize.define('Cart', {
  id: {
    type: Sequelize.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  userId: {
    type: Sequelize.INTEGER,
    references: { model: 'Users', key: 'id' },
    allowNull: false,
  },
  itemId: { type: Sequelize.STRING, allowNull: false },
  name: { type: Sequelize.STRING, allowNull: false },
  price: { type: Sequelize.FLOAT, allowNull: false },
  image: { type: Sequelize.STRING },
  quantity: { type: Sequelize.INTEGER, defaultValue: 1, allowNull: false },
}, {
  indexes: [{ unique: false, fields: ['userId'], name: 'cart_userId_idx' }],
});

const MenuItem = sequelize.define('MenuItem', {
  id: {
    type: Sequelize.STRING,
    primaryKey: true,
  },
  name: { type: Sequelize.STRING, allowNull: false },
  price: { type: Sequelize.FLOAT, allowNull: false },
  image: { type: Sequelize.STRING },
  description: { type: Sequelize.TEXT },
  category: { type: Sequelize.STRING, allowNull: false, defaultValue: 'general' },
});

const RestaurantStatus = sequelize.define('RestaurantStatus', {
  id: {
    type: Sequelize.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  status: {
    type: Sequelize.ENUM('open', 'closed'),
    defaultValue: 'open',
    allowNull: false,
  },
});

const Address = sequelize.define('Address', {
  id: {
    type: Sequelize.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
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
}, {
  indexes: [{ unique: false, fields: ['userId'], name: 'address_userId_idx' }],
});

const Favorite = sequelize.define('Favorite', {
  id: {
    type: Sequelize.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  userId: {
    type: Sequelize.INTEGER,
    references: { model: 'Users', key: 'id' },
    allowNull: false,
  },
  itemId: { type: Sequelize.STRING, allowNull: false },
  name: { type: Sequelize.STRING, allowNull: false },
  image: { type: Sequelize.STRING },
}, {
  indexes: [{ unique: true, fields: ['userId', 'itemId'], name: 'favorite_userId_itemId_idx' }],
});

const Coupon = sequelize.define('Coupon', {
  id: {
    type: Sequelize.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  code: { type: Sequelize.STRING, unique: true, allowNull: false },
  discount: { type: Sequelize.FLOAT, allowNull: false },
  image: { type: Sequelize.STRING },
});

const Order = sequelize.define('Order', {
  id: {
    type: Sequelize.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
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
  couponCode: { type: Sequelize.STRING },
  paymentMethod: { type: Sequelize.STRING, allowNull: false },
  deliveryCost: { type: Sequelize.FLOAT, defaultValue: 0 },
  status: {
    type: Sequelize.ENUM('pending', 'confirmed', 'shipped', 'delivered', 'cancelled'),
    defaultValue: 'pending',
    allowNull: false,
  },
}, {
  indexes: [
    { unique: false, fields: ['userId'], name: 'order_userId_idx' },
    { unique: false, fields: ['addressId'], name: 'order_addressId_idx' },
  ],
});

// Associations
User.hasMany(Cart, { foreignKey: 'userId', onDelete: 'CASCADE' });
Cart.belongsTo(User, { foreignKey: 'userId' });
User.hasMany(Address, { foreignKey: 'userId', onDelete: 'CASCADE' });
Address.belongsTo(User, { foreignKey: 'userId' });
User.hasMany(Favorite, { foreignKey: 'userId', onDelete: 'CASCADE' });
Favorite.belongsTo(User, { foreignKey: 'userId' });
User.hasMany(Order, { foreignKey: 'userId', onDelete: 'CASCADE' });
Order.belongsTo(User, { foreignKey: 'userId' });
Order.belongsTo(Address, { foreignKey: 'addressId' });

// Sync database
async function syncDatabase() {
  try {
    await sequelize.sync({ alter: true });
    await initializeDefaults();
  } catch (err) {
    console.error('Error syncing database:', err.message);
    process.exit(1);
  }
}

// Initialize default data
async function initializeDefaults() {
  try {
    const menuCount = await MenuItem.count();
    if (menuCount === 0) {
      await MenuItem.bulkCreate([
        { id: 'cloud-souffle', name: 'Cloud Soufflé', price: 250, image: 'https://images.unsplash.com/photo-1563805042-7684c019e1cb', description: 'A light, fluffy dessert.', category: 'dessert' },
        { id: 'sky-risotto', name: 'Sky Risotto', price: 350, image: 'https://images.unsplash.com/photo-1476124369491-e7addf5db371', description: 'Creamy and flavorful.', category: 'main' },
        { id: 'star-bruschetta', name: 'Star Bruschetta', price: 150, image: 'https://images.unsplash.com/photo-1594041680534-e8c8cdebd659', description: 'Fresh and zesty.', category: 'starter' },
        { id: 'moonlit-mojito', name: 'Moonlit Mojito', price: 100, image: 'https://images.unsplash.com/photo-1569058242253-92a9c755a0ec', description: 'Refreshing and cool.', category: 'beverage' },
      ]);
    }

    const statusCount = await RestaurantStatus.count();
    if (statusCount === 0) {
      await RestaurantStatus.create({ status: 'open' });
    }

    const couponCount = await Coupon.count();
    if (couponCount === 0) {
      await Coupon.bulkCreate([
        { code: 'DELICUTE10', discount: 10, image: 'https://via.placeholder.com/150' },
        { code: 'SAVE20', discount: 20, image: 'https://via.placeholder.com/150' },
      ]);
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
});

const app = express();

// Middleware
app.use(cors({ origin: [process.env.CLIENT_URL, 'http://localhost:3000'], credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(
  session({
    secret: process.env.JWT_SECRET || 'fallback-secret',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
  })
);

// Routes
const indexRoutes = require('./routes/index')(User, Cart, MenuItem, RestaurantStatus, Address, Favorite, Coupon, Order);
app.use('/api', indexRoutes);

// Serve frontend files
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
const PORT = process.env.PORT || 3000;
async function startServer() {
  try {
    await sequelize.authenticate();
    console.log('Database connected successfully');
    await syncDatabase();
    app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
  } catch (error) {
    console.error('Error starting server:', error.message);
    process.exit(1);
  }
}

startServer();