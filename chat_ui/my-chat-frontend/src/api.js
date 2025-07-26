const API_BASE_URL = 'http://127.0.0.1:5000/api'; // Your Flask API base URL

// Helper to get authentication headers
export const getAuthHeaders = () => {
    const token = localStorage.getItem('token');
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
    };
};

// --- Authentication API Calls ---
export const registerUser = async (username, password) => {
    const response = await fetch(`${API_BASE_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
    });
    return response.json();
};

export const loginUser = async (username, password) => {
    const response = await fetch(`${API_BASE_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
    });
    const data = await response.json();
    if (response.ok) {
        localStorage.setItem('token', data.access_token);
        localStorage.setItem('user_id', data.user_id);
        localStorage.setItem('username', data.username);
    }
    return { ok: response.ok, data };
};

// --- User & Friend API Calls ---
export const getFriends = async () => {
    const response = await fetch(`${API_BASE_URL}/friends`, {
        method: 'GET',
        headers: getAuthHeaders(),
    });
    return response.json();
};

export const getPendingFriendRequests = async () => {
    const response = await fetch(`${API_BASE_URL}/friend_requests/pending`, {
        method: 'GET',
        headers: getAuthHeaders(),
    });
    return response.json();
};

export const sendFriendRequest = async (recipientUsername) => {
    const response = await fetch(`${API_BASE_URL}/friend_requests/send`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ recipient_username: recipientUsername }),
    });
    return response.json();
};

export const acceptFriendRequest = async (requesterId) => {
    const response = await fetch(`${API_BASE_URL}/friend_requests/accept`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ requester_id: requesterId }),
    });
    return response.json();
};

export const searchUsers = async (query) => {
    const response = await fetch(`${API_BASE_URL}/users/search?q=${query}`, {
        method: 'GET',
        headers: getAuthHeaders(),
    });
    return response.json();
};

export const getMessages = async (friendId) => {
    const response = await fetch(`${API_BASE_URL}/messages/${friendId}`, {
        method: 'GET',
        headers: getAuthHeaders(),
    });
    // Check if the response is OK before parsing JSON
    if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.msg || 'Failed to fetch messages');
    }
    return response.json();
};

// --- Steganography API Calls ---
export const embedImage = async (file, message, algorithm = 'aes') => {
    const formData = new FormData();
    formData.append('image', file);
    formData.append('message', message);
    formData.append('algorithm', algorithm);

    const token = localStorage.getItem('token');
    const response = await fetch('http://127.0.0.1:5000/embed', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`
        },
        body: formData,
    });
    return response.json();
};

export const extractImage = async (file, keyHex, algorithm = 'aes') => {
    const formData = new FormData();
    formData.append('image', file);
    formData.append('key', keyHex);
    formData.append('algorithm', algorithm);

    const token = localStorage.getItem('token');
    const response = await fetch('http://127.0.0.1:5000/extract', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`
        },
        body: formData,
    });
    return response.json();
};