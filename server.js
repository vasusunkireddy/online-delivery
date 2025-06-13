const express = require('express');
const Sequelize = require('sequelize');
const dotenv = require('dotenv');
const cors = require('cors');
const passport = require('passport');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');

// Load .env file
const envPath = path.resolve(__dirname, '.env');
console.log('Attempting to load .env from:', envPath);

if (fs.existsSync(envPath)) {
  console.log('.env file found');
} else {
  console.error('.env file not found at:', envPath);
  process.exit(1);
}

const result = dotenv.config({ path: envPath });
if (result.error) {
  console.error('Error loading .env file:', result.error);
  process.exit(1);
}
console.log('Environment variables loaded successfully');

// Debug environment variables
console.log('GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID || 'Not set');
console.log('GOOGLE_CLIENT_SECRET:', process.env.GOOGLE_CLIENT_SECRET ? 'Loaded' : 'Not set');
console.log('DB_HOST:', process.env.DB_HOST || 'Not set');
console.log('DB_PORT:', process.env.DB_PORT || 'Not set');
console.log('DB_USER:', process.env.DB_USER || 'Not set');
console.log('DB_PASSWORD:', process.env.DB_PASSWORD ? 'Loaded' : 'Not set');
console.log('DB_NAME:', process.env.DB_NAME || 'Not set');
console.log('JWT_SECRET:', process.env.JWT_SECRET ? 'Loaded' : 'Not set');
console.log('CLIENT_URL:', process.env.CLIENT_URL || 'Not set');
console.log('SERVER_URL:', process.env.SERVER_URL || 'Not set');

// Sequelize instance
const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT),
    dialect: 'mysql',
    dialectOptions: {
      ssl: {
        require: true,
        rejectUnauthorized: false,
      },
    },
    logging: process.env.NODE_ENV === 'development' ? console.log : false,
  }
);

// Models
const User = sequelize.define('User', {
  id: {
    type: Sequelize.DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  name: { type: Sequelize.DataTypes.STRING, allowNull: false },
  email: { type: Sequelize.DataTypes.STRING, unique: true, allowNull: false },
  phone: { type: Sequelize.DataTypes.STRING },
  password: { type: Sequelize.DataTypes.STRING },
  googleId: { type: Sequelize.DataTypes.STRING },
  resetPasswordToken: { type: Sequelize.DataTypes.STRING },
  resetPasswordExpires: { type: Sequelize.DataTypes.DATE },
});

const Cart = sequelize.define('Cart', {
  id: {
    type: Sequelize.DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  userId: {
    type: Sequelize.DataTypes.INTEGER,
    references: { model: 'Users', key: 'id' },
    allowNull: false,
  },
  itemId: { type: Sequelize.DataTypes.STRING, allowNull: false },
  name: { type: Sequelize.DataTypes.STRING, allowNull: false },
  price: { type: Sequelize.DataTypes.FLOAT, allowNull: false },
  image: { type: Sequelize.DataTypes.STRING },
  quantity: { type: Sequelize.DataTypes.INTEGER, defaultValue: 1, allowNull: false },
}, {
  indexes: [{ unique: false, fields: ['userId'], name: 'cart_userId_fk' }],
});

const MenuItem = sequelize.define('MenuItem', {
  id: {
    type: Sequelize.DataTypes.STRING,
    primaryKey: true,
  },
  name: { type: Sequelize.DataTypes.STRING, allowNull: false },
  price: { type: Sequelize.DataTypes.FLOAT, allowNull: false },
  image: { type: Sequelize.DataTypes.STRING },
  description: { type: Sequelize.DataTypes.TEXT },
  category: { type: Sequelize.DataTypes.STRING, allowNull: false, defaultValue: 'general' },
});

const RestaurantStatus = sequelize.define('RestaurantStatus', {
  id: {
    type: Sequelize.DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  status: {
    type: Sequelize.DataTypes.ENUM('open', 'closed'),
    defaultValue: 'open',
    allowNull: false,
  },
});

const Address = sequelize.define('Address', {
  id: {
    type: Sequelize.DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  userId: {
    type: Sequelize.DataTypes.INTEGER,
    references: { model: 'Users', key: 'id' },
    allowNull: false,
  },
  fullName: { type: Sequelize.DataTypes.STRING, allowNull: false },
  mobile: { type: Sequelize.DataTypes.STRING, allowNull: false },
  houseNo: { type: Sequelize.DataTypes.STRING, allowNull: false },
  location: { type: Sequelize.DataTypes.STRING, allowNull: false },
  landmark: { type: Sequelize.DataTypes.STRING },
}, {
  indexes: [{ unique: false, fields: ['userId'], name: 'address_userId_fk' }],
});

const Favorite = sequelize.define('Favorite', {
  id: {
    type: Sequelize.DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  userId: {
    type: Sequelize.DataTypes.INTEGER,
    references: { model: 'Users', key: 'id' },
    allowNull: false,
  },
  itemId: { type: Sequelize.DataTypes.STRING, allowNull: false },
  name: { type: Sequelize.DataTypes.STRING, allowNull: false },
  image: { type: Sequelize.DataTypes.STRING },
}, {
  indexes: [{ unique: false, fields: ['userId'], name: 'favorite_userId_fk' }],
});

const Coupon = sequelize.define('Coupon', {
  id: {
    type: Sequelize.DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  code: { type: Sequelize.DataTypes.STRING, unique: true, allowNull: false },
  discount: { type: Sequelize.DataTypes.FLOAT, allowNull: false },
  image: { type: Sequelize.DataTypes.STRING },
});

const Order = sequelize.define('Order', {
  id: {
    type: Sequelize.DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  userId: {
    type: Sequelize.DataTypes.INTEGER,
    references: { model: 'Users', key: 'id' },
    allowNull: false,
  },
  addressId: {
    type: Sequelize.DataTypes.INTEGER,
    references: { model: 'Addresses', key: 'id' },
    allowNull: false,
  },
  items: { type: Sequelize.DataTypes.JSON, allowNull: false },
  total: { type: Sequelize.DataTypes.FLOAT, allowNull: false },
  couponCode: { type: Sequelize.DataTypes.STRING },
  paymentMethod: { type: Sequelize.DataTypes.STRING, allowNull: false },
  deliveryCost: { type: Sequelize.DataTypes.FLOAT, defaultValue: 0 },
  status: {
    type: Sequelize.DataTypes.ENUM('pending', 'confirmed', 'shipped', 'delivered', 'cancelled'),
    defaultValue: 'pending',
    allowNull: false,
  },
  date: { type: Sequelize.DataTypes.DATE, defaultValue: Sequelize.NOW },
}, {
  indexes: [
    { unique: false, fields: ['userId'], name: 'order_userId_fk' },
    { unique: false, fields: ['addressId'], name: 'order_addressId_fk' },
  ],
});

// Associations
User.hasMany(Cart, { foreignKey: 'userId', onDelete: 'CASCADE', onUpdate: 'CASCADE' });
Cart.belongsTo(User, { foreignKey: 'userId' });
User.hasMany(Address, { foreignKey: 'userId', onDelete: 'CASCADE', onUpdate: 'CASCADE' });
Address.belongsTo(User, { foreignKey: 'userId' });
User.hasMany(Favorite, { foreignKey: 'userId', onDelete: 'CASCADE', onUpdate: 'CASCADE' });
Favorite.belongsTo(User, { foreignKey: 'userId' });
User.hasMany(Order, { foreignKey: 'userId', onDelete: 'CASCADE', onUpdate: 'CASCADE' });
Order.belongsTo(User, { foreignKey: 'userId' });
Order.belongsTo(Address, { foreignKey: 'addressId' });

// Sync database with migration handling
async function syncDatabase() {
  try {
    // Check if category column exists in MenuItems
    const [results] = await sequelize.query("SHOW COLUMNS FROM `MenuItems` LIKE 'category'");
    if (results.length === 0) {
      console.log('Adding category column to MenuItems');
      await sequelize.query("ALTER TABLE `MenuItems` ADD `category` VARCHAR(255) NOT NULL DEFAULT 'general'");
      console.log('Category column added successfully');
    }

    // Remove all foreign key constraints for Carts.userId
    const [fkResultsCarts] = await sequelize.query(
      "SELECT CONSTRAINT_NAME FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE WHERE TABLE_NAME = 'Carts' AND COLUMN_NAME = 'userId' AND CONSTRAINT_NAME != 'PRIMARY'"
    );
    for (const fk of fkResultsCarts) {
      console.log(`Removing foreign key ${fk.CONSTRAINT_NAME} from Carts`);
      await sequelize.query(`ALTER TABLE \`Carts\` DROP FOREIGN KEY \`${fk.CONSTRAINT_NAME}\``);
    }

    // Remove all foreign key constraints for Addresses.userId
    const [fkResultsAddresses] = await sequelize.query(
      "SELECT CONSTRAINT_NAME FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE WHERE TABLE_NAME = 'Addresses' AND COLUMN_NAME = 'userId' AND CONSTRAINT_NAME != 'PRIMARY'"
    );
    for (const fk of fkResultsAddresses) {
      console.log(`Removing foreign key ${fk.CONSTRAINT_NAME} from Addresses`);
      await sequelize.query(`ALTER TABLE \`Addresses\` DROP FOREIGN KEY \`${fk.CONSTRAINT_NAME}\``);
    }

    // Remove all foreign key constraints for Orders.userId and Orders.addressId
    const [fkResultsOrders] = await sequelize.query(
      "SELECT CONSTRAINT_NAME FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE WHERE TABLE_NAME = 'Orders' AND COLUMN_NAME IN ('userId', 'addressId') AND CONSTRAINT_NAME != 'PRIMARY'"
    );
    for (const fk of fkResultsOrders) {
      console.log(`Removing foreign key ${fk.CONSTRAINT_NAME} from Orders`);
      await sequelize.query(`ALTER TABLE \`Orders\` DROP FOREIGN KEY \`${fk.CONSTRAINT_NAME}\``);
    }

    // Remove all foreign key constraints for Favorites.userId
    const [fkResultsFavorites] = await sequelize.query(
      "SELECT CONSTRAINT_NAME FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE WHERE TABLE_NAME = 'Favorites' AND COLUMN_NAME = 'userId' AND CONSTRAINT_NAME != 'PRIMARY'"
    );
    for (const fk of fkResultsFavorites) {
      console.log(`Removing foreign key ${fk.CONSTRAINT_NAME} from Favorites`);
      await sequelize.query(`ALTER TABLE \`Favorites\` DROP FOREIGN KEY \`${fk.CONSTRAINT_NAME}\``);
    }

    // Sync models
    await sequelize.sync({ alter: true });
    console.log('Database synced successfully');
    await initializeDefaults();
  } catch (err) {
    console.error('Database sync error:', err.message);
    if (err.message.includes('ER_FK_DUP_NAME') || err.message.includes('Unknown column')) {
      console.log('Continuing server startup despite schema issue. Some features may not work.');
      await initializeDefaults();
    } else {
      console.error('Fatal sync error. Exiting...');
      process.exit(1);
    }
  }
}

// Initialize default menu, status, and coupons
async function initializeDefaults() {
  try {
    const menuCount = await MenuItem.count();
    if (menuCount === 0) {
      await MenuItem.bulkCreate([
        {
          id: 'signature-salad',
          name: 'Signature Salad',
          price: 800,
          image: 'https://images.unsplash.com/photo-1512621776951-a57141f2eefd?auto=format&fit=crop&w=300&q=80',
          description: 'Fresh greens with a zesty lemon vinaigrette.',
          category: 'starter',
        },
        {
          id: 'truffle-pasta',
          name: 'Truffle Pasta',
          price: 1200,
          image: 'https://images.unsplash.com/photo-1621996650001-9b1d3c5a560e?auto=format&fit=crop&w=300&q=80',
          description: 'Creamy truffle-infused pasta with mushrooms.',
          category: 'main',
        },
        {
          id: 'berry-parfait',
          name: 'Berry Parfait',
          price: 650,
          image: 'https://images.unsplash.com/photo-1565182999561-18d7dc61c393?auto=format&fit=crop&w=300&q=80',
          description: 'Layered yogurt with fresh berries and granola.',
          category: 'dessert',
        },
        {
          id: 'moonlit-mocktail',
          name: 'Moonlit Mocktail',
          price: 300,
          image: 'https://images.unsplash.com/photo-1609951651556-5334e270bb3d?auto=format&fit=crop&w=300&q=80',
          description: 'Refreshing beverage with a fruity twist.',
          category: 'beverage',
        },
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
        { code: 'DELICUTE10', discount: 10, image: 'https://via.placeholder.com/150' },
        { code: 'SAVE20', discount: 20, image: 'https://via.placeholder.com/150' },
      ]);
      console.log('Default coupons created');
    }
  } catch (error) {
    console.error('Failed to initialize defaults:', error.message);
  }
}

// Session store
const sessionStore = new MySQLStore({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false },
});

const app = express();

// Middleware
app.use(cors({ origin: process.env.CLIENT_URL, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session setup
app.use(
  session({
    secret: process.env.JWT_SECRET || 'fallback-secret',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
  })
);

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// Routes
const indexRoutes = require('./routes/index')(sequelize, User, Cart, MenuItem, RestaurantStatus);
const userDashboardRoutes = require('./routes/userdashboard')(sequelize, User, Cart, MenuItem, Address, Favorite, Coupon, Order);
app.use('/api', indexRoutes);
app.use('/', userDashboardRoutes);

// Start server
const PORT = process.env.PORT || 3000;
async function startServer() {
  try {
    await sequelize.authenticate();
    console.log('MySQL connected successfully');
    await syncDatabase();
    app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
  } catch (error) {
    console.error('Server startup error:', error.message);
    process.exit(1);
  }
}

startServer();