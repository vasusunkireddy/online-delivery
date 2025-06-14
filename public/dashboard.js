-- Creating the database
CREATE DATABASE IF NOT EXISTS defaultdb;
USE defaultdb;

-- Users table for storing user information
CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(15) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Menu items table for storing restaurant menu
CREATE TABLE IF NOT EXISTS menu_items (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2) NOT NULL,
    category ENUM('starter', 'main', 'dessert', 'beverage', 'general') DEFAULT 'general',
    image VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Cart table for storing user cart items
CREATE TABLE IF NOT EXISTS cart (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    item_id BIGINT UNSIGNED NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES menu_items(id) ON DELETE CASCADE
);

-- Password reset tokens table for handling password resets
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
);

-- Restaurant status table (single row to track open/closed status)
CREATE TABLE IF NOT EXISTS restaurant_status (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    status ENUM('open', 'closed') DEFAULT 'open',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert default restaurant status
INSERT INTO restaurant_status (status) VALUES ('open');

-- Create indexes for faster queries
CREATE INDEX idx_user_email ON users(email);
CREATE INDEX idx_menu_category ON menu_items(category);
CREATE INDEX idx_cart_user_id ON cart(user_id);
CREATE INDEX idx_reset_email ON password_reset_tokens(email);