const state = {
    cart: [],
    addresses: [],
    favorites: [],
    menuItems: [],
    coupons: [],
    orders: [],
    user: null,
    appliedCoupon: null,
    API_BASE_URL: window.location.hostname.includes('localhost') ? 'http://localhost:3000' : 'https://delicute.onrender.com',
    token: localStorage.getItem('token'),
};

const utils = {
    debounce: (func, delay) => {
        let timeout;
        return (...args) => {
            clearTimeout(timeout);
            timeout = setTimeout(() => func(...args), delay);
        };
    },

    showToast: (message, type = 'success') => {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `<span>${message}</span>`;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3500);
    },

    scrollToSection: (sectionId) => {
        const section = document.getElementById(sectionId);
        section?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    },

    fetchWithAuth: async (url, options = {}) => {
        try {
            if (!state.token) throw new Error('No token found');
            const headers = {
                'Authorization': `Bearer ${state.token}`,
                ...options.headers,
            };
            if (options.body instanceof FormData) {
                delete headers['Content-Type'];
            } else {
                headers['Content-Type'] = 'application/json';
            }
            const response = await fetch(`${state.API_BASE_URL}${url}`, { ...options, headers });
            if (response.status === 401) {
                utils.showToast('Session expired. Please log in.', 'error');
                localStorage.removeItem('token');
                state.token = null;
                setTimeout(() => window.location.href = '/index.html', 2000);
                throw new Error('Unauthorized');
            }
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || `HTTP ${response.status}`);
            }
            return await response.json().catch(() => ({}));
        } catch (error) {
            console.error('Fetch error:', error);
            throw error;
        }
    },

    validateMobile: (mobile) => {
        return /^\d{10}$/.test(mobile);
    },

    validateEmail: (email) => {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    },

    validateImage: (file) => {
        if (!file) return false;
        const validTypes = ['image/jpeg', 'image/png'];
        const maxSize = 2 * 1024 * 1024; // 2MB
        return validTypes.includes(file.type) && file.size <= maxSize;
    },

    uploadImage: async (file) => {
        if (!utils.validateImage(file)) {
            throw new Error('Please upload a valid JPEG or PNG image (max 2MB)');
        }
        const formData = new FormData();
        formData.append('image', file);
        const response = await utils.fetchWithAuth('/api/upload', {
            method: 'POST',
            body: formData,
        });
        return response.url;
    },
};

const ui = {
    toggleNav: () => {
        const navLinks = document.getElementById('navLinks');
        const hamburger = document.getElementById('hamburger');
        navLinks.classList.toggle('active');
        hamburger.classList.toggle('active');
    },

    toggleDropdown: () => {
        document.getElementById('profileDropdown').classList.toggle('show');
    },

    openModal: (modalId) => {
        document.getElementById(modalId).style.display = 'flex';
        if (modalId === 'favoritesModal') data.loadFavorites();
        else if (modalId === 'cartModal') {
            data.loadCart();
            data.loadAddresses();
        }
        ui.toggleDropdown();
    },

    closeModal: (modalId) => {
        document.getElementById(modalId).style.display = 'none';
    },

    toggleDarkMode: () => {
        document.body.classList.toggle('dark-mode');
        localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
        utils.showToast(`Switched to ${document.body.classList.contains('dark-mode') ? 'Dark' : 'Light'} Mode`, 'success');
    },

    loadDarkMode: () => {
        if (localStorage.getItem('darkMode') === 'true') document.body.classList.add('dark-mode');
    },

    populateAddressForm: (address = {}) => {
        document.getElementById('addressId').value = address.id || '';
        document.getElementById('addressFullName').value = address.fullName || '';
        document.getElementById('addressMobile').value = address.mobile || '';
        document.getElementById('addressHouseNo').value = address.houseNo || '';
        document.getElementById('addressLocation').value = address.location || '';
        document.getElementById('addressLandmark').value = address.landmark || '';
        document.getElementById('addressFormTitle').textContent = address.id ? 'Edit Address' : 'Add New Address';
        document.getElementById('addressSubmitBtn').textContent = address.id ? 'Update Address' : 'Add Address';
    },
};

const data = {
    checkAuth: () => {
        if (!state.token) {
            utils.showToast('Please log in to access the dashboard', 'error');
            setTimeout(() => window.location.href = '/index.html', 2000);
            return false;
        }
        return true;
    },

    loadProfile: async () => {
        if (!data.checkAuth()) return;
        try {
            state.user = await utils.fetchWithAuth('/api/profile');
            document.getElementById('userName').textContent = state.user.name || 'User';
            document.getElementById('profileName').value = state.user.name || '';
            document.getElementById('profileEmail').value = state.user.email || '';
            document.getElementById('profileMobile').value = state.user.phone || '';
            document.getElementById('profileImg').src = state.user.image || '/Uploads/default-profile.png';
        } catch (error) {
            utils.showToast(error.message || 'Failed to load profile', 'error');
        }
    },

    updateProfile: async () => {
        const name = document.getElementById('profileName').value.trim();
        const email = document.getElementById('profileEmail').value.trim();
        const imageInput = document.getElementById('profileImage').files[0];
        if (!name || !email) return utils.showToast('Name and Email are required', 'error');
        if (!utils.validateEmail(email)) return utils.showToast('Invalid email format', 'error');
        try {
            const body = { name, email };
            if (imageInput) {
                body.image = await utils.uploadImage(imageInput);
            }
            state.user = await utils.fetchWithAuth('/api/profile', {
                method: 'PUT',
                body: JSON.stringify(body),
            });
            document.getElementById('userName').textContent = state.user.name;
            document.getElementById('profileImg').src = state.user.image || '/Uploads/default-profile.png';
            document.getElementById('profileImage').value = ''; // Clear file input
            utils.showToast('Profile updated!', 'success');
            ui.closeModal('profileModal');
        } catch (error) {
            utils.showToast(error.message || 'Failed to update profile', 'error');
        }
    },

    loadAddresses: async () => {
        if (!data.checkAuth()) return;
        try {
            state.addresses = await utils.fetchWithAuth('/api/addresses');
            const addressSelect = document.getElementById('cartAddressSelect');
            const addressList = document.getElementById('addressList');
            addressSelect.innerHTML = '<option value="">Select Address</option>';
            addressList.innerHTML = '';
            state.addresses.forEach(addr => {
                const addressString = `${addr.fullName}, ${addr.houseNo}, ${addr.location}${addr.landmark ? `, ${addr.landmark}` : ''}, Mobile: ${addr.mobile}`;
                addressSelect.innerHTML += `<option value="${addr.id}">${addressString}</option>`;
                addressList.innerHTML += `
                    <div class="order-card flex justify-between items-center">
                        <p class="text-gray-600 text-sm">${addressString}</p>
                        <div class="flex gap-2">
                            <button class="btn-primary text-sm py-1 px-3" onclick="data.editAddress('${addr.id}')">Edit</button>
                            <button class="btn-secondary text-sm py-1 px-3" onclick="data.deleteAddress('${addr.id}')">Delete</button>
                        </div>
                    </div>
                `;
            });
        } catch (error) {
            utils.showToast(error.message || 'Failed to load addresses', 'error');
        }
    },

    addOrUpdateAddress: async (e) => {
        e.preventDefault();
        const id = document.getElementById('addressId').value;
        const fullName = document.getElementById('addressFullName').value.trim();
        const mobile = document.getElementById('addressMobile').value.trim();
        const houseNo = document.getElementById('addressHouseNo').value.trim();
        const location = document.getElementById('addressLocation').value.trim();
        const landmark = document.getElementById('addressLandmark').value.trim();
        if (!fullName || !mobile || !houseNo || !location) {
            return utils.showToast('Please fill all required fields', 'error');
        }
        if (!utils.validateMobile(mobile)) {
            return utils.showToast('Valid mobile number is required', 'error');
        }
        try {
            const method = id ? 'PUT' : 'POST';
            const url = id ? `/api/addresses/${id}` : '/api/addresses';
            await utils.fetchWithAuth(url, {
                method,
                body: JSON.stringify({ fullName, mobile, houseNo, location, landmark }),
            });
            utils.showToast(id ? 'Address updated!' : 'Address added!', 'success');
            document.getElementById('addressForm').reset();
            ui.populateAddressForm();
            data.loadAddresses();
        } catch (error) {
            utils.showToast(error.message || `Failed to ${id ? 'update' : 'add'} address`, 'error');
        }
    },

    editAddress: async (id) => {
        try {
            const address = await utils.fetchWithAuth(`/api/addresses/${id}`);
            ui.populateAddressForm(address);
        } catch (error) {
            utils.showToast(error.message || 'Failed to load address', 'error');
        }
    },

    deleteAddress: async (id) => {
        try {
            await utils.fetchWithAuth(`/api/addresses/${id}`, { method: 'DELETE' });
            utils.showToast('Address deleted!', 'success');
            data.loadAddresses();
        } catch (error) {
            utils.showToast(error.message || 'Failed to delete address', 'error');
        }
    },

    loadMenu: async () => {
        if (!data.checkAuth()) return;
        try {
            state.menuItems = await utils.fetchWithAuth('/api/menu');
            data.renderMenu();
        } catch (error) {
            utils.showToast(error.message || 'Failed to load menu', 'error');
        }
    },

    renderMenu: (items = state.menuItems) => {
        const menuContainer = document.getElementById('menuItems');
        menuContainer.innerHTML = '';
        items.forEach(item => {
            const isFavorite = state.favorites.some(fav => fav.itemId === item.id);
            menuContainer.innerHTML += `
                <div class="menu-card">
                    <img src="${item.image || '/Uploads/default-menu.png'}" alt="${item.name}" class="w-full h-48 object-cover rounded-lg mb-2">
                    <h3 class="text-base font-semibold text-gray-800" style="font-family: 'Playfair Display', serif;">${item.name}</h3>
                    <p class="text-gray-600 text-sm mb-1">${item.description || 'No description'}</p>
                    <p class="text-gray-500 text-sm mb-1">Category: ${item.category || 'N/A'}</p>
                    <p class="text-purple-600 font-bold text-base mb-2">₹${item.price}</p>
                    <div class="flex justify-between items-center gap-2">
                        <button class="btn-primary text-sm py-1 px-3" onclick="data.addToCart('${item.id}', '${item.name}', ${item.price}, '${item.image || '/Uploads/default-menu.png'}')">Add to Cart</button>
                        <button class="btn-secondary text-sm py-1 px-3" onclick="${isFavorite ? `data.removeFromFavorites('${item.id}')` : `data.addToFavorites('${item.id}', '${item.name}', '${item.image || '/Uploads/default-menu.png'}')`}">${isFavorite ? 'Remove' : 'Favorite'}</button>
                    </div>
                </div>
            `;
        });
        if (items.length === 0) {
            menuContainer.innerHTML = '<p class="text-center text-gray-600 text-sm">No items found.</p>';
        }
    },

    searchMenu: () => {
        const query = document.getElementById('menuSearch').value.toLowerCase();
        const filteredItems = state.menuItems.filter(item => item.name.toLowerCase().includes(query));
        data.renderMenu(filteredItems);
    },

    filterCategory: () => {
        const category = document.getElementById('categoryFilter').value;
        const filteredItems = category ? state.menuItems.filter(item => item.category === category) : state.menuItems;
        data.renderMenu(filteredItems);
    },

    loadCoupons: async () => {
        if (!data.checkAuth()) return;
        try {
            state.coupons = await utils.fetchWithAuth('/api/coupons');
            const couponsList = document.getElementById('couponsList');
            couponsList.innerHTML = '';
            state.coupons.forEach(coupon => {
                couponsList.innerHTML += `
                    <div class="coupon-card">
                        <img src="${coupon.image || '/Uploads/default-coupon.png'}" alt="${coupon.code}" class="w-full h-24 object-cover rounded-lg mb-2">
                        <h3 class="text-base font-semibold text-gray-800">${coupon.code}</h3>
                        <p class="text-gray-600 text-sm mb-2">${coupon.discount}% OFF</p>
                        <button class="btn-primary w-full text-sm py-1 px-3" onclick="data.applyCouponFromList('${coupon.code}', ${coupon.discount})">Apply Coupon</button>
                    </div>
                `;
            });
        } catch (error) {
            utils.showToast(error.message || 'Failed to load coupons', 'error');
        }
    },

    loadFavorites: async () => {
        if (!data.checkAuth()) return;
        try {
            state.favorites = await utils.fetchWithAuth('/api/favorites');
            data.renderFavorites();
            data.renderMenu();
        } catch (error) {
            utils.showToast(error.message || 'Failed to load favorites', 'error');
        }
    },

    renderFavorites: () => {
        const favoritesList = document.getElementById('favoritesList');
        const favoritesModalList = document.getElementById('favoritesModalList');
        favoritesList.innerHTML = '';
        favoritesModalList.innerHTML = '';
        state.favorites.forEach(item => {
            const cardHTML = `
                <div class="favorite-card flex items-center gap-2">
                    <img src="${item.image || '/Uploads/default-menu.png'}" alt="${item.name}" class="w-16 h-16 object-cover rounded-lg">
                    <div class="flex-1">
                        <h3 class="text-base font-semibold text-gray-800">${item.name}</h3>
                    </div>
                    <div class="flex gap-2">
                        <button class="btn-primary text-sm py-1 px-3" onclick="data.addToCart('${item.itemId}', '${item.name}', ${item.price || 0}, '${item.image || '/Uploads/default-menu.png'}')">Add to Cart</button>
                        <button class="btn-secondary text-sm py-1 px-3" onclick="data.removeFromFavorites('${item.itemId}')">Remove</button>
                    </div>
                </div>
            `;
            favoritesList.innerHTML += cardHTML;
            favoritesModalList.innerHTML += cardHTML;
        });
        if (state.favorites.length === 0) {
            favoritesList.innerHTML = '<p class="text-center text-gray-600 text-sm">No favorites yet.</p>';
            favoritesModalList.innerHTML = '<p class="text-center text-gray-600 text-sm">No favorites yet.</p>';
        }
    },

    addToFavorites: async (id, name, image) => {
        try {
            await utils.fetchWithAuth('/api/favorites', {
                method: 'POST',
                body: JSON.stringify({ itemId: id, name, image }),
            });
            utils.showToast(`${name} added to favorites!`, 'success');
            data.loadFavorites();
        } catch (error) {
            utils.showToast(error.message || 'Failed to add favorite', 'error');
        }
    },

    removeFromFavorites: async (id) => {
        try {
            await utils.fetchWithAuth(`/api/favorites/${id}`, { method: 'DELETE' });
            utils.showToast('Removed from favorites!', 'success');
            data.loadFavorites();
        } catch (error) {
            utils.showToast(error.message || 'Failed to remove favorite', 'error');
        }
    },

    loadCart: async () => {
        if (!data.checkAuth()) return;
        try {
            state.cart = await utils.fetchWithAuth('/api/cart');
            data.renderCart();
        } catch (error) {
            utils.showToast(error.message || 'Failed to load cart', 'error');
        }
    },

    renderCart: () => {
        const cartItems = document.getElementById('cartItems');
        cartItems.innerHTML = '';
        let originalTotal = 0;
        state.cart.forEach(item => {
            originalTotal += item.price * item.quantity;
            cartItems.innerHTML += `
                <div class="order-card flex items-center gap-2 mb-2">
                    <img src="${item.image || '/Uploads/default-menu.png'}" alt="${item.name}" class="w-16 h-16 object-cover rounded-lg">
                    <div class="flex-1">
                        <h3 class="text-base font-semibold text-gray-800">${item.name}</h3>
                        <p class="text-gray-600 text-sm">₹${item.price} x ${item.quantity}</p>
                        <div class="flex items-center gap-2 mt-2">
                            <button class="btn-quantity" onclick="data.updateQuantity('${item.itemId}', -1)">-</button>
                            <span class="text-sm">${item.quantity}</span>
                            <button class="btn-quantity" onclick="data.updateQuantity('${item.itemId}', 1)">+</button>
                        </div>
                    </div>
                    <button class="btn-secondary text-sm py-1 px-3" onclick="data.removeFromCart('${item.itemId}')">Remove</button>
                </div>
            `;
        });
        const discount = state.appliedCoupon ? (originalTotal * state.appliedCoupon.discount) / 100 : 0;
        const finalTotal = originalTotal - discount;
        document.getElementById('cartOriginalTotal').textContent = originalTotal.toFixed(2);
        document.getElementById('cartDiscount').textContent = discount.toFixed(2);
        document.getElementById('cartDelivery').textContent = '0.00';
        document.getElementById('cartFinalTotal').textContent = finalTotal.toFixed(2);
        if (state.cart.length === 0) {
            cartItems.innerHTML = '<p class="text-center text-gray-600 text-sm">Your cart is empty.</p>';
        }
    },

    addToCart: async (id, name, price, image) => {
        try {
            const cartItem = {
                itemId: id,
                name,
                price: parseFloat(price),
                image,
                quantity: 1
            };
            await utils.fetchWithAuth('/api/cart', {
                method: 'POST',
                body: JSON.stringify(cartItem),
            });
            utils.showToast(`${name} added to cart!`, 'success');
            data.loadCart();
        } catch (error) {
            utils.showToast(error.message || 'Failed to add to cart', 'error');
        }
    },

    updateQuantity: async (itemId, change) => {
        const item = state.cart.find(item => item.itemId === itemId);
        if (item && item.quantity + change >= 1) {
            try {
                await utils.fetchWithAuth(`/api/cart/${itemId}`, {
                    method: 'PUT',
                    body: JSON.stringify({ quantity: item.quantity + change }),
                });
                utils.showToast('Quantity updated!', 'success');
                data.loadCart();
            } catch (error) {
                utils.showToast(error.message || 'Failed to update quantity', 'error');
            }
        }
    },

    removeFromCart: async (itemId) => {
        try {
            await utils.fetchWithAuth(`/api/cart/${itemId}`, { method: 'DELETE' });
            utils.showToast('Item removed from cart!', 'success');
            data.loadCart();
        } catch (error) {
            utils.showToast(error.message || 'Failed to remove item', 'error');
        }
    },

    applyCoupon: async () => {
        const code = document.getElementById('couponCode').value.trim();
        if (!code) return utils.showToast('Enter a coupon code', 'error');
        try {
            const coupon = await utils.fetchWithAuth(`/api/coupons/validate?code=${encodeURIComponent(code)}`);
            state.appliedCoupon = { code: coupon.code, discount: coupon.discount };
            document.getElementById('couponCode').value = coupon.code;
            utils.showToast(`Coupon ${coupon.code} applied!`, 'success');
            data.renderCart();
        } catch (error) {
            utils.showToast(error.message || 'Failed to validate coupon', 'error');
        }
    },

    applyCouponFromList: async (code, discount) => {
        try {
            state.appliedCoupon = { code, discount };
            document.getElementById('couponCode').value = code;
            utils.showToast(`Coupon ${code} applied!`, 'success');
            data.renderCart();
        } catch (error) {
            utils.showToast(error.message || 'Failed to apply coupon', 'error');
        }
    },

    placeOrder: async (method) => {
        const selectedAddress = document.getElementById('cartAddressSelect').value;
        if (!selectedAddress) return utils.showToast('Select an address', 'error');
        if (state.cart.length === 0) return utils.showToast('Cart is empty', 'error');
        try {
            const orderData = {
                addressId: parseInt(selectedAddress),
                items: state.cart.map(item => ({
                    itemId: item.itemId,
                    name: item.name,
                    price: item.price,
                    quantity: item.quantity,
                    image: item.image
                })),
                couponCode: state.appliedCoupon ? state.appliedCoupon.code : null,
                paymentMethod: method,
                deliveryCost: 0,
            };
            await utils.fetchWithAuth('/api/orders', {
                method: 'POST',
                body: JSON.stringify(orderData),
            });
            utils.showToast('Order placed successfully!', 'success');
            state.cart = [];
            state.appliedCoupon = null;
            document.getElementById('couponCode').value = '';
            data.renderCart();
            data.loadOrderHistory();
            ui.closeModal('cartModal');
        } catch (error) {
            utils.showToast(error.message || 'Failed to place order', 'error');
        }
    },

    loadOrderHistory: async () => {
        if (!data.checkAuth()) return;
        try {
            state.orders = await utils.fetchWithAuth('/api/orders');
            data.renderOrderHistory();
        } catch (error) {
            utils.showToast(error.message || 'Failed to load order history', 'error');
        }
    },

    renderOrderHistory: () => {
        const orderHistory = document.getElementById('orderHistory');
        orderHistory.innerHTML = '';
        state.orders.forEach(order => {
            const canCancel = ['pending', 'confirmed'].includes(order.status.toLowerCase());
            orderHistory.innerHTML += `
                <div class="order-card">
                    <h3 class="text-base font-semibold text-gray-800">Order #${order.id}</h3>
                    <p class="text-gray-600 text-sm">Date: ${order.date}</p>
                    <p class="text-gray-600 text-sm">Items: ${order.items.join(', ')}</p>
                    <p class="text-gray-600 text-sm">Total: ₹${order.total}</p>
                    <p class="text-gray-600 text-sm">Delivery: ${order.delivery}</p>
                    <p class="text-gray-600 text-sm">Status: ${order.status}</p>
                    <div class="flex gap-2 mt-2">
                        <button class="btn-primary text-sm py-1 px-3" onclick="data.trackOrder('${order.id}')">Track Order</button>
                        ${canCancel ? `<button class="btn-secondary text-sm py-1 px-3" onclick="data.openCancelOrderModal('${order.id}')">Cancel Order</button>` : ''}
                    </div>
                </div>
            `;
        });
        document.getElementById('totalOrders').textContent = state.orders.length;
        if (state.orders.length === 0) {
            orderHistory.innerHTML = '<p class="text-center text-gray-600 text-sm">No orders found.</p>';
        }
    },

    clearOrderHistory: async () => {
        if (!data.checkAuth()) return;
        if (!confirm('Are you sure you want to clear your order history? This action cannot be undone.')) return;
        try {
            await utils.fetchWithAuth('/api/orders/clear', { method: 'DELETE' });
            state.orders = [];
            data.renderOrderHistory();
            utils.showToast('Order history cleared!', 'success');
        } catch (error) {
            utils.showToast(error.message || 'Failed to clear order history', 'error');
        }
    },

    openCancelOrderModal: (orderId) => {
        document.getElementById('cancelOrderId').value = orderId;
        document.getElementById('cancelReason').value = '';
        ui.openModal('cancelOrderModal');
    },

    cancelOrder: async (e) => {
        e.preventDefault();
        const orderId = document.getElementById('cancelOrderId').value;
        const reason = document.getElementById('cancelReason').value.trim();
        if (!reason) return utils.showToast('Please provide a reason', 'error');
        try {
            await utils.fetchWithAuth(`/api/orders/${orderId}/cancel`, {
                method: 'PUT',
                body: JSON.stringify({ reason }),
            });
            utils.showToast('Order cancelled successfully!', 'success');
            document.getElementById('cancelOrderForm').reset();
            ui.closeModal('cancelOrderModal');
            data.loadOrderHistory();
        } catch (error) {
            utils.showToast(error.message || 'Failed to cancel order', 'error');
        }
    },

    trackOrder: async (id) => {
        try {
            const updatedOrder = await utils.fetchWithAuth(`/api/orders/${id}/track`, { method: 'PUT' });
            utils.showToast(`Order #${id} status: ${updatedOrder.status}`, 'success');
            data.loadOrderHistory();
        } catch (error) {
            utils.showToast(error.message || 'Failed to track order', 'error');
        }
    },

    logout: () => {
        localStorage.removeItem('token');
        state.token = null;
        utils.showToast('Logged out!', 'success');
        setTimeout(() => window.location.href = '/index.html', 1000);
    },
};

const eventListeners = {
    setup: () => {
        window.onclick = (event) => {
            if (!event.target.matches('.profile-img') && !event.target.closest('.dropdown-menu')) {
                document.querySelectorAll('.dropdown-menu.show').forEach(dropdown => dropdown.classList.remove('show'));
            }
            if (event.target.classList.contains('modal')) {
                ['profileModal', 'addressModal', 'favoritesModal', 'cartModal', 'cancelOrderModal'].forEach(ui.closeModal);
            }
        };
        document.getElementById('addressForm').addEventListener('submit', data.addOrUpdateAddress);
        document.getElementById('cancelOrderForm').addEventListener('submit', data.cancelOrder);
        document.getElementById('profileImage').addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file && !utils.validateImage(file)) {
                utils.showToast('Please select a valid JPEG or PNG image (max 2MB)', 'error');
                e.target.value = '';
            }
        });
    },
};

const debounceSearch = utils.debounce(data.searchMenu, 300);

window.onload = () => {
    data.checkAuth();
    ui.loadDarkMode();
    if (state.token) {
        data.loadProfile();
        data.loadMenu();
        data.loadCoupons();
        data.loadFavorites();
        data.loadCart();
        data.loadAddresses();
        data.loadOrderHistory();
    }
    eventListeners.setup();
};