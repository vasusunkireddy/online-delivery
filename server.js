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
const bcrypt = require('bcryptjs');

const envPath = path.resolve(__dirname, '.env');
if (!fs.existsSync(envPath)) {
  console.error('.env file not found at:', envPath);
  process.exit(1);
}
dotenv.config({ path: envPath });

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

const User = sequelize.define('User', {
  id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
  name: { type: Sequelize.STRING, allowNull: false },
  email: { type: Sequelize.STRING, unique: true, allowNull: false },
  phone: { type: Sequelize.STRING },
  password: { type: Sequelize.STRING },
  googleId: { type: Sequelize.STRING },
  image: { type: Sequelize.STRING },
  resetPasswordToken: { type: Sequelize.STRING },
  resetPasswordExpires: { type: Sequelize.BIGINT },
});

const Cart = sequelize.define('Cart', {
  id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
  userId: { type: Sequelize.INTEGER, allowNull: false, references: { model: 'Users', key: 'id' } },
  itemId: { type: Sequelize.STRING, allowNull: false },
  name: { type: Sequelize.STRING, allowNull: false },
  price: { type: Sequelize.FLOAT, allowNull: false },
  image: { type: Sequelize.STRING },
  quantity: { type: Sequelize.INTEGER, defaultValue: 1, allowNull: false },
}, { indexes: [{ unique: false, fields: ['userId'], name: 'cart_userId_fk' }] });

const MenuItem = sequelize.define('MenuItem', {
  id: { type: Sequelize.STRING, primaryKey: true },
  name: { type: Sequelize.STRING, allowNull: false },
  price: { type: Sequelize.FLOAT, allowNull: false },
  image: { type: Sequelize.STRING },
  description: { type: Sequelize.TEXT },
  category: { type: Sequelize.STRING, allowNull: false, defaultValue: 'general' },
});

const RestaurantStatus = sequelize.define('RestaurantStatus', {
  id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
  status: { type: Sequelize.ENUM('open', 'closed'), defaultValue: 'open', allowNull: false },
});

const Address = sequelize.define('Address', {
  id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
  userId: { type: Sequelize.INTEGER, allowNull: false, references: { model: 'Users', key: 'id' } },
  fullName: { type: Sequelize.STRING, allowNull: false },
  mobile: { type: Sequelize.STRING, allowNull: false },
  houseNo: { type: Sequelize.STRING, allowNull: false },
  location: { type: Sequelize.STRING, allowNull: false },
  landmark: { type: Sequelize.STRING },
}, { indexes: [{ unique: false, fields: ['userId'], name: 'address_userId_fk' }] });

const Favorite = sequelize.define('Favorite', {
  id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
  userId: { type: Sequelize.INTEGER, allowNull: false, references: { model: 'Users', key: 'id' } },
  itemId: { type: Sequelize.STRING, allowNull: false },
  name: { type: Sequelize.STRING, allowNull: false },
  image: { type: Sequelize.STRING },
}, { indexes: [{ unique: false, fields: ['userId'], name: 'favorite_userId_fk' }] });

const Coupon = sequelize.define('Coupon', {
  id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
  code: { type: Sequelize.STRING, unique: true, allowNull: false },
  discount: { type: Sequelize.FLOAT, allowNull: false },
  image: { type: Sequelize.STRING },
});

const Order = sequelize.define('Order', {
  id: { type: Sequelize.INTEGER, autoIncrement: true, primaryKey: true },
  userId: { type: Sequelize.INTEGER, allowNull: false, references: { model: 'Users', key: 'id' } },
  addressId: { type: Sequelize.INTEGER, allowNull: false, references: { model: 'Addresses', key: 'id' } },
  items: { type: Sequelize.JSON, allowNull: false },
  total: { type: Sequelize.FLOAT, allowNull: false },
  couponCode: { type: Sequelize.STRING },
  paymentMethod: { type: Sequelize.STRING, allowNull: false },
  deliveryCost: { type: Sequelize.FLOAT, defaultValue: 0 },
  status: { type: Sequelize.ENUM('pending', 'confirmed', 'shipped', 'delivered', 'cancelled'), defaultValue: 'pending', allowNull: false },
  date: { type: Sequelize.DATE, defaultValue: Sequelize.NOW },
}, { indexes: [
  { unique: false, fields: ['userId'], name: 'order_userId_fk' },
  { unique: false, fields: ['addressId'], name: 'order_addressId_fk' },
] });

User.hasMany(Cart, { foreignKey: 'userId', onDelete: 'CASCADE', onUpdate: 'CASCADE' });
Cart.belongsTo(User, { foreignKey: 'userId' });
User.hasMany(Address, { foreignKey: 'userId', onDelete: 'CASCADE', onUpdate: 'CASCADE' });
Address.belongsTo(User, { foreignKey: 'userId' });
User.hasMany(Favorite, { foreignKey: 'userId', onDelete: 'CASCADE', onUpdate: 'CASCADE' });
Favorite.belongsTo(User, { foreignKey: 'userId' });
User.hasMany(Order, { foreignKey: 'userId', onDelete: 'CASCADE', onUpdate: 'CASCADE' });
Order.belongsTo(User, { foreignKey: 'userId' });
Order.belongsTo(Address, { foreignKey: 'addressId' });

async function syncDatabase() {
  try {
    const [results] = await sequelize.query("SHOW COLUMNS FROM `MenuItems` LIKE 'category'");
    if (results.length === 0) {
      console.log('Adding category column to MenuItems');
      await sequelize.query("ALTER TABLE `MenuItems` ADD `category` VARCHAR(255) NOT NULL DEFAULT 'general'");
    }

    const tables = ['Carts', 'Addresses', 'Favorites', 'Orders'];
    const columns = { Carts: ['userId'], Addresses: ['userId'], Favorites: ['userId'], Orders: ['userId', 'addressId'] };
    for (const table of tables) {
      for (const column of columns[table]) {
        const [fkResults] = await sequelize.query(
          `SELECT CONSTRAINT_NAME FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE WHERE TABLE_NAME = '${table}' AND COLUMN_NAME = '${column}' AND CONSTRAINT_NAME != 'PRIMARY'`
        );
        for (const fk of fkResults) {
          console.log(`Removing foreign key ${fk.CONSTRAINT_NAME} from ${table}`);
          await sequelize.query(`ALTER TABLE \`${table}\` DROP FOREIGN KEY \`${fk.CONSTRAINT_NAME}\``);
        }
      }
    }

    await sequelize.sync({ alter: true });
    console.log('Database synced successfully');
    await initializeDefaults();
  } catch (err) {
    console.error('Database sync error:', err.message);
    if (err.message.includes('ER_FK_DUP_NAME') || err.message.includes('Unknown column')) {
      console.log('Continuing server startup despite schema issue.');
      await initializeDefaults();
    } else {
      console.error('Fatal sync error. Exiting...');
      process.exit(1);
    }
  }
}

async function initializeDefaults() {
  try {
    if (await MenuItem.count() === 0) {
      await MenuItem.bulkCreate([
        { id: 'signature-salad', name: 'Signature Salad', price: 800, image: 'https://images.unsplash.com/photo-1512621776951-a57141f2eefd', description: 'Fresh greens with a zesty lemon vinaigrette.', category: 'starter' },
        { id: 'truffle-pasta', name: 'Truffle Pasta', price: 1200, image: 'https://images.unsplash.com/photo-1621996650001-9b1d3c5a560e', description: 'Creamy truffle-infused pasta with mushrooms.', category: 'main' },
        { id: 'berry-parfait', name: 'Berry Parfait', price: 650, image: 'https://images.unsplash.com/photo-1565182999561-18d7dc61c393', description: 'Layered yogurt with fresh berries and granola.', category: 'dessert' },
        { id: 'moonlit-mocktail', name: 'Moonlit Mocktail', price: 300, image: 'https://images.unsplash.com/photo-1609951651556-5334e270bb3d', description: 'Refreshing beverage with a fruity twist.', category: 'beverage' },
      ]);
      console.log('Default menu items created');
    }

    if (await RestaurantStatus.count() === 0) {
      await RestaurantStatus.create({ status: 'open' });
      console.log('Default restaurant status created');
    }

    if (await Coupon.count() === 0) {
      await Coupon.bulkCreate([
        { code: 'DELICUTE10', discount: 10, image: 'https://via.placeholder.com/150' },
        { code: 'SAVE20', discount: 20, image: 'https://via.placeholder.com/150' },
      ]);
      console.log('Default coupons created');
    }

    if (await User.count() === 0) {
      await User.create({
        name: 'Test User',
        email: 'test@example.com',
        password: await bcrypt.hash('password123', 10),
        phone: '1234567890',
      });
      console.log('Default user created');
    }
  } catch (error) {
    console.error('Failed to initialize defaults:', error.message);
  }
}

const sessionStore = new MySQLStore({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false },
  clearExpired: true,
  checkExpirationInterval: 15 * 60 * 1000, // 15 minutes
  expiration: 24 * 60 * 60 * 1000, // 24 hours
});

const app = express();
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || process.env.JWT_SECRET,
  resave: false,
  saveUninitialized: false,
  store: sessionStore,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  },
}));
app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
  console.log(`Session ID: ${req.sessionID}, User: ${req.user ? req.user.id : 'None'}`);
  next();
});

const indexRoutes = require('./routes/index')(sequelize, User, Cart, MenuItem, RestaurantStatus);
const userDashboardRoutes = require('./routes/userdashboard')(sequelize, User, Cart, MenuItem, Address, Favorite, Coupon, Order);
app.use('/api', indexRoutes);
app.use('/', userDashboardRoutes);

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