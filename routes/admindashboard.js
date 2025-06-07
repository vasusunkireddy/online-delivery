const BASE_URL = window.location.hostname === 'localhost' ? 'http://localhost:3000' : 'https://delicute.onrender.com';

// Utility Functions
function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.className = `toast ${type}`;
    toast.style.display = 'flex';
    setTimeout(() => {
        toast.style.display = 'none';
    }, 3000);
}

function toggleDropdown() {
    const dropdown = document.getElementById('profileDropdown');
    if (dropdown) {
        dropdown.classList.toggle('active');
    }
}

function showSection(section) {
    document.querySelectorAll('section').forEach(s => s.classList.add('hidden'));
    const sectionElement = document.getElementById(`${section}Section`);
    if (sectionElement) {
        sectionElement.classList.remove('hidden');
    }
    toggleDropdown();
    const actions = {
        menu: fetchMenuItems,
        orders: fetchOrders,
        offers: fetchOffers,
        coupons: fetchCoupons,
        customers: fetchCustomers,
        contact: fetchContactMessages,
        profile: fetchAdminDetails
    };
    if (actions[section]) {
        actions[section]();
    }
}

function showModal(modalId) {
    closeModalAll();
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'flex';
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
    }
}

function closeModalAll() {
    document.querySelectorAll('.modal').forEach(modal => modal.style.display = 'none');
}

async function uploadImage(file) {
    if (!file) return null;
    const formData = new FormData();
    formData.append('file', file);
    try {
        const response = await fetch(`${BASE_URL}/api/files/upload`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` },
            body: formData
        });
        const data = await response.json();
        if (response.ok) {
            localStorage.setItem('adminProfileImage', data.fileUrl);
            return data.fileUrl;
        }
        showToast(data.error || 'Failed to upload image.', 'error');
        return null;
    } catch (error) {
        console.error('Error uploading image:', error);
        showToast('Failed to upload image.', 'error');
        return null;
    }
}

// Authentication and Profile
async function fetchAdminDetails() {
    try {
        const response = await fetch(`${BASE_URL}/api/auth/admin/me`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const data = await response.json();
        if (response.ok) {
            document.getElementById('welcomeMessage')?.textContent = `Welcome, ${data.name || 'Admin'}`;
            document.getElementById('profileName')?.value = data.name || '';
            document.getElementById('profileEmail')?.value = data.email || '';
            document.getElementById('profilePhone')?.value = data.phone || '';
            document.getElementById('displayProfileName')?.textContent = data.name || '';
            document.getElementById('displayProfileEmail')?.textContent = data.email || '';
            document.getElementById('displayProfilePhone')?.textContent = data.phone || '';
            const savedProfileImage = localStorage.getItem('adminProfileImage') || data.profileImage;
            if (savedProfileImage) {
                document.getElementById('profileImage')?.setAttribute('src', savedProfileImage);
                document.getElementById('modalProfileImage')?.setAttribute('src', savedProfileImage);
                document.getElementById('displayProfileImage')?.setAttribute('src', savedProfileImage);
            }
        } else {
            showToast(data.error || 'Failed to fetch admin details.', 'error');
        }
    } catch (error) {
        console.error('Error fetching admin details:', error);
        showToast('Failed to fetch admin details.', 'error');
    }
}

async function updateProfileImage() {
    const fileInput = document.getElementById('profileImageUpload');
    if (!fileInput?.files[0]) {
        showToast('Please select an image.', 'error');
        return;
    }
    const imageUrl = await uploadImage(fileInput.files[0]);
    if (!imageUrl) return;
    try {
        const response = await fetch(`${BASE_URL}/api/auth/admin/profile`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            },
            body: JSON.stringify({ profileImage: imageUrl })
        });
        const data = await response.json();
        if (response.ok) {
            showToast('Profile image updated successfully!', 'success');
            fetchAdminDetails();
            closeModal('profileModal');
        } else {
            showToast(data.error || 'Failed to update profile image.', 'error');
        }
    } catch (error) {
        console.error('Error updating profile image:', error);
        showToast('Failed to update profile image.', 'error');
    }
}

async function checkAuth() {
    const token = localStorage.getItem('adminToken');
    if (!token) {
        window.location.href = 'admin.html';
        return;
    }
    try {
        const response = await fetch(`${BASE_URL}/api/auth/admin/me`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!response.ok) {
            localStorage.removeItem('adminToken');
            localStorage.removeItem('adminProfileImage');
            window.location.href = 'admin.html';
        } else {
            fetchAdminDetails();
            showSection('home');
            fetchOrders();
            fetchMenuItems();
            fetchRestaurantStatus();
        }
    } catch (error) {
        console.error('Error checking auth:', error);
        localStorage.removeItem('adminToken');
        localStorage.removeItem('adminProfileImage');
        window.location.href = 'admin.html';
    }
}

// Menu Management
async function fetchMenuItems() {
    try {
        const response = await fetch(`${BASE_URL}/api/menu`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const items = await response.json();
        displayMenuItems(items);
        document.getElementById('totalMenuItems')?.textContent = items.length;
    } catch (error) {
        console.error('Error fetching menu items:', error);
        showToast('Failed to load menu items.', 'error');
    }
}

function displayMenuItems(items) {
    const menuTableBody = document.getElementById('menuTableBody');
    if (!menuTableBody) return;
    menuTableBody.innerHTML = items.map(item => `
        <tr class="border-b hover:bg-gray-50">
            <td class="py-3 px-3">${item.image ? `<img src="${item.image}" alt="${item.name}" class="menu-img">` : 'No Image'}</td>
            <td class="py-3 px-3">${item.name || 'N/A'}</td>
            <td class="py-3 px-3">${item.category || 'N/A'}</td>
            <td class="py-3 px-3 text-right">${item.price ? `₹${item.price.toFixed(2)}` : 'N/A'}</td>
            <td class="py-3 px-3">${item.description || 'N/A'}</td>
            <td class="py-3 px-3 flex space-x-2">
                <button onclick="editMenuItem('${item._id}')" class="auth-btn bg-blue-600 hover:bg-blue-700 text-xs px-3 py-1.5">Edit</button>
                <button onclick="deleteMenuItem('${item._id}')" class="auth-btn bg-red-600 hover:bg-red-700 text-xs px-3 py-1.5">Delete</button>
            </td>
        </tr>
    `).join('');
}

async function addMenuItem() {
    const item = {
        name: document.getElementById('itemName')?.value.trim() || '',
        price: parseFloat(document.getElementById('itemPrice')?.value) || null,
        category: document.getElementById('itemCategory')?.value.trim() || '',
        imageUrl: document.getElementById('itemImage')?.value.trim() || '',
        file: document.getElementById('itemImageUpload')?.files[0] || null,
        description: document.getElementById('itemDescription')?.value.trim() || ''
    };

    if (!item.name || !item.category || !item.price) {
        showToast('Item name, category, and price are required.', 'error');
        return;
    }

    const uploadedImageUrl = item.file ? await uploadImage(item.file) : item.imageUrl || null;

    try {
        const response = await fetch(`${BASE_URL}/api/menu`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            },
            body: JSON.stringify({
                name: item.name,
                price: item.price,
                category: item.category,
                image: uploadedImageUrl,
                description: item.description
            })
        });
        const data = await response.json();
        if (response.ok) {
            showToast('Menu item added successfully!', 'success');
            ['itemName', 'itemPrice', 'itemCategory', 'itemImage', 'itemImageUpload', 'itemDescription'].forEach(id => {
                const element = document.getElementById(id);
                if (element) element.value = '';
            });
            fetchMenuItems();
        } else {
            showToast(data.error || 'Failed to add menu item.', 'error');
        }
    } catch (error) {
        console.error('Error adding menu item:', error);
        showToast('Failed to add menu item.', 'error');
    }
}

async function editMenuItem(itemId) {
    try {
        const response = await fetch(`${BASE_URL}/api/menu/${itemId}`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const item = await response.json();
        if (response.ok) {
            document.getElementById('editItemId')?.value = item._id || '';
            document.getElementById('editItemName')?.value = item.name || '';
            document.getElementById('editItemPrice')?.value = item.price || '';
            document.getElementById('editItemCategory')?.value = item.category || '';
            document.getElementById('editItemImage')?.value = item.image || '';
            document.getElementById('editItemDescription')?.value = item.description || '';
            showModal('editMenuModal');
        } else {
            showToast(item.error || 'Failed to load menu item.', 'error');
        }
    } catch (error) {
        console.error('Error fetching menu item:', error);
        showToast('Failed to load menu item.', 'error');
    }
}

async function updateMenuItem() {
    const item = {
        id: document.getElementById('editItemId')?.value || '',
        name: document.getElementById('editItemName')?.value.trim() || '',
        price: parseFloat(document.getElementById('editItemPrice')?.value) || null,
        category: document.getElementById('editItemCategory')?.value.trim() || '',
        imageUrl: document.getElementById('editItemImage')?.value.trim() || '',
        file: document.getElementById('editItemImageUpload')?.files[0] || null,
        description: document.getElementById('editItemDescription')?.value.trim() || ''
    };

    if (!item.name || !item.category || !item.price) {
        showToast('Item name, category, and price are required.', 'error');
        return;
    }

    const uploadedImageUrl = item.file ? await uploadImage(item.file) : item.imageUrl || null;

    try {
        const response = await fetch(`${BASE_URL}/api/menu/${item.id}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            },
            body: JSON.stringify({
                name: item.name,
                price: item.price,
                category: item.category,
                image: uploadedImageUrl,
                description: item.description
            })
        });
        const data = await response.json();
        if (response.ok) {
            showToast('Menu item updated successfully!', 'success');
            closeModal('editMenuModal');
            fetchMenuItems();
        } else {
            showToast(data.error || 'Failed to update menu item.', 'error');
        }
    } catch (error) {
        console.error('Error updating menu item:', error);
        showToast('Failed to update menu item.', 'error');
    }
}

async function deleteMenuItem(itemId) {
    if (!confirm('Are you sure you want to delete this menu item?')) return;
    try {
        const response = await fetch(`${BASE_URL}/api/menu/${itemId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const data = await response.json();
        if (response.ok) {
            showToast('Menu item deleted successfully!', 'success');
            fetchMenuItems();
        } else {
            showToast(data.error || 'Failed to delete menu item.', 'error');
        }
    } catch (error) {
        console.error('Error deleting menu item:', error);
        showToast('Failed to delete menu item.', 'error');
    }
}

// Order Management
async function fetchOrders() {
    try {
        const response = await fetch(`${BASE_URL}/api/orders`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const orders = await response.json();
        displayOrders(orders);
        document.getElementById('totalOrders')?.textContent = orders.length;
        document.getElementById('pendingOrders')?.textContent = orders.filter(order => order.status === 'Pending').length;
    } catch (error) {
        console.error('Error fetching orders:', error);
        showToast('Failed to load orders.', 'error');
    }
}

function displayOrders(orders) {
    const orderTableBody = document.getElementById('orderTableBody');
    if (!orderTableBody) return;
    orderTableBody.innerHTML = orders.map(order => `
        <tr class="border-b hover:bg-gray-50">
            <td class="py-3 px-3">${order._id || 'N/A'}</td>
            <td class="py-3 px-3">${order.customerName || 'N/A'}</td>
            <td class="py-3 px-3">${order.address || 'N/A'}</td>
            <td class="py-3 px-3 text-right">₹${order.total?.toFixed(2) || '0.00'}</td>
            <td class="py-3 px-3 text-center">${order.status || 'Pending'}</td>
            <td class="py-3 px-3 text-center">${order.paymentStatus || 'Pending'}</td>
            <td class="py-3 px-3 flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-2">
                <button onclick="viewOrderDetails('${order._id}')" class="auth-btn bg-blue-600 hover:bg-blue-700 text-xs px-3 py-1.5">View</button>
            </td>
        </tr>
    `).join('');
}

async function viewOrderDetails(orderId) {
    try {
        const response = await fetch(`${BASE_URL}/api/orders/${orderId}`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const order = await response.json();
        if (response.ok) {
            document.getElementById('orderId')?.textContent = order._id || 'N/A';
            document.getElementById('orderCustomerName')?.textContent = order.customerName || 'N/A';
            document.getElementById('orderAddress')?.textContent = order.address || 'N/A';
            document.getElementById('orderTotal')?.textContent = `₹${order.total?.toFixed(2) || '0.00'}`;
            document.getElementById('orderStatus')?.textContent = order.status || 'Pending';
            document.getElementById('orderPaymentStatus')?.textContent = order.paymentStatus || 'Pending';
            document.getElementById('orderStatusSelect')?.value = order.status || 'Pending';
            document.getElementById('updateOrderStatusBtn')?.onclick = () => updateOrderStatus(orderId, document.getElementById('orderStatusSelect')?.value);
            const refundOrderBtn = document.getElementById('refundOrderBtn');
            if (refundOrderBtn) {
                refundOrderBtn.style.display = order.paymentStatus === 'Paid' ? 'block' : 'none';
                refundOrderBtn.onclick = () => refundOrder(orderId);
            }

            const orderItems = document.getElementById('orderItems');
            if (orderItems) {
                orderItems.innerHTML = order.items?.map(item => `
                    <div class="text-sm mb-2">
                        <p><strong>Item:</strong> ${item.name || 'N/A'}</p>
                        <p><strong>Quantity:</strong> ${item.quantity || 1}</p>
                        <p><strong>Price:</strong> ₹${item.price?.toFixed(2) || '0.00'}</p>
                    </div>
                `).join('') || 'No items';
            }

            const orderReview = document.getElementById('orderReview');
            if (orderReview) {
                if (order.review) {
                    const stars = '★'.repeat(order.review.rating) + '☆'.repeat(5 - order.review.rating);
                    orderReview.innerHTML = `
                        <p><strong>Rating:</strong> <span class="rating-stars">${stars}</span> (${order.review.rating}/5)</p>
                        <p><strong>Comment:</strong> ${order.review.comment || 'No comment'}</p>
                    `;
                } else {
                    orderReview.innerHTML = 'No review provided';
                }
            }

            showModal('orderDetailsModal');
        } else {
            showToast(order.error || 'Failed to load order details.', 'error');
        }
    } catch (error) {
        console.error('Error fetching order details:', error);
        showToast('Failed to load order details.', 'error');
    }
}

async function updateOrderStatus(orderId, status) {
    try {
        const response = await fetch(`${BASE_URL}/api/orders/${orderId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            },
            body: JSON.stringify({ status })
        });
        const data = await response.json();
        if (response.ok) {
            showToast(`Order status updated to ${status}!`, 'success');
            closeModal('orderDetailsModal');
            fetchOrders();
        } else {
            showToast(data.error || 'Failed to update order status.', 'error');
        }
    } catch (error) {
        console.error('Error updating order status:', error);
        showToast('Failed to update order status.', 'error');
    }
}

async function refundOrder(orderId) {
    if (!confirm('Are you sure you want to refund this order?')) return;
    try {
        const response = await fetch(`${BASE_URL}/api/orders/${orderId}/refund`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const data = await response.json();
        if (response.ok) {
            showToast('Order refunded successfully!', 'success');
            closeModal('orderDetailsModal');
            fetchOrders();
        } else {
            showToast(data.error || 'Failed to process refund.', 'error');
        }
    } catch (error) {
        console.error('Error processing refund:', error);
        showToast('Failed to process refund.', 'error');
    }
}

// Special Offers
async function fetchOffers() {
    try {
        const response = await fetch(`${BASE_URL}/api/offers`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const offers = await response.json();
        displayOffers(offers);
    } catch (error) {
        console.error('Error fetching offers:', error);
        showToast('Failed to load offers.', 'error');
    }
}

function displayOffers(offers) {
    const offerTableBody = document.getElementById('offerTableBody');
    if (!offerTableBody) return;
    offerTableBody.innerHTML = offers.map(offer => `
        <tr class="border-b hover:bg-gray-50">
            <td class="py-3 px-3">${offer.image ? `<img src="${offer.image}" alt="${offer.name}" class="menu-img">` : 'No Image'}</td>
            <td class="py-3 px-3">${offer.name || 'N/A'}</td>
            <td class="py-3 px-3 text-right">₹${offer.price?.toFixed(2) || '0.00'}</td>
            <td class="py-3 px-3 flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-2">
                <button onclick="editOffer('${offer._id}')" class="auth-btn bg-blue-600 hover:bg-blue-700 text-xs px-3 py-1.5">Edit</button>
                <button onclick="deleteOffer('${offer._id}')" class="auth-btn bg-red-600 hover:bg-red-700 text-xs px-3 py-1.5">Delete</button>
            </td>
        </tr>
    `).join('');
}

async function addOffer() {
    const offer = {
        name: document.getElementById('offerName')?.value.trim() || '',
        price: parseFloat(document.getElementById('offerPrice')?.value) || null,
        imageUrl: document.getElementById('offerImage')?.value.trim() || '',
        file: document.getElementById('offerImageUpload')?.files[0] || null,
        description: document.getElementById('offerDescription')?.value.trim() || ''
    };

    if (!offer.name || !offer.price) {
        showToast('Offer name and price are required.', 'error');
        return;
    }

    const uploadedImageUrl = offer.file ? await uploadImage(offer.file) : offer.imageUrl || null;

    try {
        const response = await fetch(`${BASE_URL}/api/offers`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            },
            body: JSON.stringify({
                name: offer.name,
                price: offer.price,
                image: uploadedImageUrl,
                description: offer.description
            })
        });
        const data = await response.json();
        if (response.ok) {
            showToast('Offer added successfully!', 'success');
            ['offerName', 'offerPrice', 'offerImage', 'offerImageUpload', 'offerDescription'].forEach(id => {
                document.getElementById(id)?.value = '';
            });
            fetchOffers();
        } else {
            showToast(data.error || 'Failed to add offer.', 'error');
        }
    } catch (error) {
        console.error('Error adding offer:', error);
        showToast('Failed to add offer.', 'error');
    }
}

async function editOffer(id) {
    try {
        const response = await fetch(`${BASE_URL}/api/offers/${id}`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const offer = await response.json();
        if (response.ok) {
            document.getElementById('editOfferId')?.value = offer._id || '';
            document.getElementById('editOfferName')?.value = offer.name || '';
            document.getElementById('editOfferPrice')?.value = offer.price || '';
            document.getElementById('editOfferImage')?.value = offer.image || '';
            document.getElementById('editOfferDescription')?.value = offer.description || '';
            showModal('editOfferModal');
        } else {
            showToast(offer.error || 'Failed to load offer.', 'error');
        }
    } catch (error) {
        console.error('Error fetching offer:', error);
        showToast('Failed to load offer.', 'error');
    }
}

async function updateOffer() {
    const offer = {
        id: document.getElementById('editOfferId')?.value || '',
        name: document.getElementById('editOfferName')?.value.trim() || '',
        price: parseFloat(document.getElementById('editOfferPrice')?.value) || null,
        imageUrl: document.getElementById('editOfferImage')?.value.trim() || '',
        file: document.getElementById('editOfferImageUpload')?.files[0] || null,
        description: document.getElementById('editOfferDescription')?.value.trim() || ''
    };

    if (!offer.name || !offer.price) {
        showToast('Offer name and price are required.', 'error');
        return;
    }

    const uploadedImageUrl = offer.file ? await uploadImage(offer.file) : offer.imageUrl || null;

    try {
        const response = await fetch(`${BASE_URL}/api/offers/${offer.id}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            },
            body: JSON.stringify({
                name: offer.name,
                price: offer.price,
                image: uploadedImageUrl,
                description: offer.description
            })
        });
        const data = await response.json();
        if (response.ok) {
            showToast('Offer updated successfully!', 'success');
            closeModal('editOfferModal');
            fetchOffers();
        } else {
            showToast(data.error || 'Failed to update offer.', 'error');
        }
    } catch (error) {
        console.error('Error updating offer:', error);
        showToast('Failed to update offer.', 'error');
    }
}

async function deleteOffer(id) {
    if (!confirm('Are you sure you want to delete this offer?')) return;
    try {
        const response = await fetch(`${BASE_URL}/api/offers/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const data = await response.json();
        if (response.ok) {
            showToast('Offer deleted successfully!', 'success');
            fetchOffers();
        } else {
            showToast(data.error || 'Failed to delete offer.', 'error');
        }
    } catch (error) {
        console.error('Error deleting offer:', error);
        showToast('Failed to delete offer.', 'error');
    }
}

// Coupons Management
async function fetchCoupons() {
    try {
        const response = await fetch(`${BASE_URL}/api/coupons`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const coupons = await response.json();
        displayCoupons(coupons);
    } catch (error) {
        console.error('Error fetching coupons:', error);
        showToast('Failed to load coupons.', 'error');
    }
}

function displayCoupons(coupons) {
    const couponTableBody = document.getElementById('couponTableBody');
    if (!couponTableBody) return;
    couponTableBody.innerHTML = coupons.map(coupon => `
        <tr class="border-b hover:bg-gray-50">
            <td class="py-3 px-3">${coupon.image ? `<img src="${coupon.image}" alt="${coupon.code}" class="menu-img">` : 'No Image'}</td>
            <td class="py-3 px-3">${coupon.code || 'N/A'}</td>
            <td class="py-3 px-3 text-right">${coupon.discount || 0}%</td>
            <td class="py-3 px-3 flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-2">
                <button onclick="editCoupon('${coupon._id}')" class="auth-btn bg-blue-600 hover:bg-blue-700 text-xs px-3 py-1.5">Edit</button>
                <button onclick="deleteCoupon('${coupon._id}')" class="auth-btn bg-red-600 hover:bg-red-700 text-xs px-3 py-1.5">Delete</button>
            </td>
        </tr>
    `).join('');
}

async function addCoupon() {
    const coupon = {
        code: document.getElementById('couponCode')?.value.trim().toUpperCase() || '',
        discount: parseInt(document.getElementById('couponDiscount')?.value) || null,
        imageUrl: document.getElementById('couponImage')?.value.trim() || '',
        file: document.getElementById('couponImageUpload')?.files[0] || null,
        description: document.getElementById('couponDescription')?.value.trim() || ''
    };

    if (!coupon.code || !coupon.discount) {
        showToast('Coupon code and discount are required.', 'error');
        return;
    }

    const uploadedImageUrl = coupon.file ? await uploadImage(coupon.file) : coupon.imageUrl || null;

    try {
        const response = await fetch(`${BASE_URL}/api/coupons`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            },
            body: JSON.stringify({
                code: coupon.code,
                discount: coupon.discount,
                image: uploadedImageUrl,
                description: coupon.description
            })
        });
        const data = await response.json();
        if (response.ok) {
            showToast('Coupon added successfully!', 'success');
            ['couponCode', 'couponDiscount', 'couponImage', 'couponImageUpload', 'couponDescription'].forEach(id => {
                document.getElementById(id)?.value = '';
            });
            fetchCoupons();
        } else {
            showToast(data.error || 'Failed to add coupon.', 'error');
        }
    } catch (error) {
        console.error('Error adding coupon:', error);
        showToast('Failed to add coupon.', 'error');
    }
}

async function editCoupon(id) {
    try {
        const response = await fetch(`${BASE_URL}/api/coupons/${id}`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const coupon = await response.json();
        if (response.ok) {
            document.getElementById('editCouponId')?.value = coupon._id || '';
            document.getElementById('editCouponCode')?.value = coupon.code || '';
            document.getElementById('editCouponDiscount')?.value = coupon.discount || '';
            document.getElementById('editCouponImage')?.value = coupon.image || '';
            document.getElementById('editCouponDescription')?.value = coupon.description || '';
            showModal('editCouponModal');
        } else {
            showToast(coupon.error || 'Failed to load coupon.', 'error');
        }
    } catch (error) {
        console.error('Error fetching coupon:', error);
        showToast('Failed to load coupon.', 'error');
    }
}

async function updateCoupon() {
    const coupon = {
        id: document.getElementById('editCouponId')?.value || '',
        code: document.getElementById('editCouponCode')?.value.trim().toUpperCase() || '',
        discount: parseInt(document.getElementById('editCouponDiscount')?.value) || null,
        imageUrl: document.getElementById('editCouponImage')?.value.trim() || '',
        file: document.getElementById('editCouponImageUpload')?.files[0] || null,
        description: document.getElementById('editCouponDescription')?.value.trim() || ''
    };

    if (!coupon.code || !coupon.discount) {
        showToast('Coupon code and discount are required.', 'error');
        return;
    }

    const uploadedImageUrl = coupon.file ? await uploadImage(coupon.file) : coupon.imageUrl || null;

    try {
        const response = await fetch(`${BASE_URL}/api/coupons/${coupon.id}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            },
            body: JSON.stringify({
                code: coupon.code,
                discount: coupon.discount,
                image: uploadedImageUrl,
                description: coupon.description
            })
        });
        const data = await response.json();
        if (response.ok) {
            showToast('Coupon updated successfully!', 'success');
            closeModal('editCouponModal');
            fetchCoupons();
        } else {
            showToast(data.error || 'Failed to update coupon.', 'error');
        }
    } catch (error) {
        console.error('Error updating coupon:', error);
        showToast('Failed to update coupon.', 'error');
    }
}

async function deleteCoupon(id) {
    if (!confirm('Are you sure you want to delete this coupon?')) return;
    try {
        const response = await fetch(`${BASE_URL}/api/coupons/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const data = await response.json();
        if (response.ok) {
            showToast('Coupon deleted successfully!', 'success');
            fetchCoupons();
        } else {
            showToast(data.error || 'Failed to delete coupon.', 'error');
        }
    } catch (error) {
        console.error('Error deleting coupon:', error);
        showToast('Failed to delete coupon.', 'error');
    }
}

// Customer Management
async function fetchCustomers() {
    try {
        const response = await fetch(`${BASE_URL}/api/users`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const customers = await response.json();
        displayCustomers(customers);
    } catch (error) {
        console.error('Error fetching customers:', error);
        showToast('Failed to load customers.', 'error');
    }
}

function displayCustomers(customers) {
    const customerTableBody = document.getElementById('customerTableBody');
    if (!customerTableBody) return;
    customerTableBody.innerHTML = customers.map(customer => `
        <tr class="border-b hover:bg-gray-50">
            <td class="py-3 px-3">${customer.name || 'N/A'}</td>
            <td class="py-3 px-3">${customer.email || 'N/A'}</td>
            <td class="py-3 px-3">${customer.phone || 'N/A'}</td>
            <td class="py-3 px-3 text-center">${customer.isBlocked ? 'Blocked' : 'Active'}</td>
            <td class="py-3 px-3 flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-2">
                <button onclick="viewCustomerDetails('${customer._id}')" class="auth-btn bg-blue-600 hover:bg-blue-700 text-xs px-3 py-1.5">View</button>
            </td>
        </tr>
    `).join('');
}

async function viewCustomerDetails(customerId) {
    try {
        const response = await fetch(`${BASE_URL}/api/users/${customerId}`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const customer = await response.json();
        if (response.ok) {
            document.getElementById('customerName')?.textContent = customer.name || 'N/A';
            document.getElementById('customerEmail')?.textContent = customer.email || 'N/A';
            document.getElementById('customerPhone')?.textContent = customer.phone || 'N/A';
            document.getElementById('customerStatus')?.textContent = customer.isBlocked ? 'Blocked' : 'Active';
            const blockUnblockBtn = document.getElementById('blockUnblockBtn');
            if (blockUnblockBtn) {
                blockUnblockBtn.textContent = customer.isBlocked ? 'Unblock' : 'Block';
                blockUnblockBtn.className = `auth-btn px-4 py-2 ${customer.isBlocked ? 'bg-green-600 hover:bg-green-700' : 'bg-red-600 hover:bg-red-700'}`;
                blockUnblockBtn.onclick = () => toggleCustomerBlock(customerId, customer.isBlocked);
            }

            const orderHistory = document.getElementById('customerOrderHistory');
            if (orderHistory) {
                orderHistory.innerHTML = customer.orders?.length ? `
                    <table class="w-full text-sm">
                        <thead>
                            <tr>
                                <th>Order ID</th>
                                <th>Total</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${customer.orders.map(order => `
                                <tr class="border-b">
                                    <td class="py-2 px-3">${order._id || 'N/A'}</td>
                                    <td class="py-2 px-3 text-right">₹${order.total?.toFixed(2) || '0.00'}</td>
                                    <td class="py-2 px-3 text-center">${order.status || 'Pending'}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                ` : 'No order history';
            }

            showModal('customerDetailsModal');
        } else {
            showToast(customer.error || 'Failed to load customer details.', 'error');
        }
    } catch (error) {
        console.error('Error fetching customer details:', error);
        showToast('Failed to load customer details.', 'error');
    }
}

async function toggleCustomerBlock(customerId, isBlocked) {
    try {
        const response = await fetch(`${BASE_URL}/api/users/${customerId}/block`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            },
            body: JSON.stringify({ isBlocked: !isBlocked })
        });
        const data = await response.json();
        if (response.ok) {
            showToast(`Customer ${!isBlocked ? 'blocked' : 'unblocked'} successfully!`, 'success');
            closeModal('customerDetailsModal');
            fetchCustomers();
        } else {
            showToast(data.error || 'Failed to update customer status.', 'error');
        }
    } catch (error) {
        console.error('Error toggling customer block:', error);
        showToast('Failed to update customer status.', 'error');
    }
}

// Contact Messages
async function fetchContactMessages() {
    try {
        const response = await fetch(`${BASE_URL}/api/contact`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const messages = await response.json();
        displayContactMessages(messages);
    } catch (error) {
        console.error('Error fetching contact messages:', error);
        showToast('Failed to load contact messages.', 'error');
    }
}

function displayContactMessages(messages) {
    const contactTableBody = document.getElementById('contactTableBody');
    if (!contactTableBody) return;
    contactTableBody.innerHTML = messages.map(message => `
        <tr class="border-b hover:bg-gray-50">
            <td class="py-3 px-3">${message.name || 'N/A'}</td>
            <td class="py-3 px-3">${message.email || 'N/A'}</td>
            <td class="py-3 px-3">${message.subject || 'N/A'}</td>
            <td class="py-3 px-3"><div class="contact-message">${message.message || 'N/A'}</div></td>
            <td class="py-3 px-3 text-center">${message.status || 'Pending'}</td>
            <td class="py-3 px-3 flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-2">
                <button onclick="replyToMessage('${message._id}')" class="auth-btn bg-blue-600 hover:bg-blue-700 text-xs px-3 py-1.5">Reply</button>
                <button onclick="markAsResolved('${message._id}')" class="auth-btn bg-green-600 hover:bg-green-700 text-xs px-3 py-1.5">Resolve</button>
            </td>
        </tr>
    `).join('');
}

function replyToMessage(messageId) {
    document.getElementById('contactMessageId')?.value = messageId;
    showModal('replyContactModal');
}

async function sendReply() {
    const messageId = document.getElementById('contactMessageId')?.value || '';
    const subject = document.getElementById('contactReplySubject')?.value.trim() || '';
    const message = document.getElementById('contactReplyMessage')?.value.trim() || '';

    if (!subject || !message) {
        showToast('Subject and message are required.', 'error');
        return;
    }

    try {
        const response = await fetch(`${BASE_URL}/api/contact/${messageId}/reply`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            },
            body: JSON.stringify({ subject, message })
        });
        const data = await response.json();
        if (response.ok) {
            showToast('Reply sent successfully!', 'success');
            closeModal('replyContactModal');
            fetchContactMessages();
        } else {
            showToast(data.error || 'Failed to send reply.', 'error');
        }
    } catch (error) {
        console.error('Error sending reply:', error);
        showToast('Failed to send reply.', 'error');
    }
}

async function markAsResolved(messageId) {
    try {
        const response = await fetch(`${BASE_URL}/api/contact/${messageId}/resolve`, {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const data = await response.json();
        if (response.ok) {
            showToast('Message marked as resolved!', 'success');
            fetchContactMessages();
        } else {
            showToast(data.error || 'Failed to resolve message.', 'error');
        }
    } catch (error) {
        console.error('Error resolving message:', error);
        showToast('Failed to resolve message.', 'error');
    }
}

// Restaurant Status
async function fetchRestaurantStatus() {
    try {
        const response = await fetch(`${BASE_URL}/api/restaurant/status`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('adminToken')}` }
        });
        const data = await response.json();
        if (response.ok) {
            document.getElementById('restaurantStatus')?.textContent = data.isOpen ? 'Open' : 'Closed';
            document.getElementById('statusToggleBtn')?.textContent = data.isOpen ? 'Close Restaurant' : 'Open Restaurant';
        } else {
            showToast(data.error || 'Failed to fetch restaurant status.', 'error');
        }
    } catch (error) {
        console.error('Error fetching restaurant status:', error);
        showToast('Failed to fetch restaurant status.', 'error');
    }
}

async function toggleRestaurantStatus() {
    try {
        const response = await fetch(`${BASE_URL}/api/restaurant/status`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('adminToken')}`
            }
        });
        const data = await response.json();
        if (response.ok) {
            showToast(`Restaurant ${data.isOpen ? 'opened' : 'closed'} successfully!`, 'success');
            fetchRestaurantStatus();
        } else {
            showToast(data.error || 'Failed to toggle restaurant status.', 'error');
        }
    } catch (error) {
        console.error('Error toggling restaurant status:', error);
        showToast('Failed to toggle restaurant status.', 'error');
    }
}

// Logout
function logout() {
    localStorage.removeItem('adminToken');
    localStorage.removeItem('adminProfileImage');
    window.location.href = 'admin.html';
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    document.addEventListener('click', (e) => {
        const profileDropdown = document.getElementById('profileDropdown');
        const profileImage = document.getElementById('profileImage');
        if (profileDropdown && profileImage && !profileImage.contains(e.target) && !profileDropdown.contains(e.target)) {
            profileDropdown.classList.remove('active');
        }
    });
});