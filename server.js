const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const db = require('./database.js'); // Assumes database.js is in the same folder

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

const PORT = process.env.PORT || 3000;
const BCRYPT_SALT_ROUNDS = 12;

// --- Session Configuration ---
const sessionParser = session({
    store: new FileStore({ path: './sessions', logFn: function(){} }),
    secret: 'a_very_secret_key_change_this_later',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 // 1 day
    }
});

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(sessionParser);
// Serve the 'public' folder (which will just contain index.html)
app.use(express.static('public')); 

// --- Main App Route ---
// Serves your single-page app
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- API ROUTES (for Login/Register/Logout) ---

// API: Check if user is already logged in
app.get('/api/me', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    res.json({ username: req.session.username });
});

// API: Handle login logic
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        // BETTER LOGGING
        if (err) {
            console.error("!!! LOGIN DB (SELECT) ERROR: ", err.message);
            return res.status(500).json({ success: false, message: 'Server error. Check logs.' });
        }
        
        if (!user) {
            console.log(`Login failed: User ${username} not found.`);
            return res.status(401).json({ success: false, message: 'Invalid username or password.' });
        }
        
        if (user.expires_at && new Date(user.expires_at) < new Date()) {
            console.log(`Login failed: Temporary user ${username} has expired.`);
            return res.status(401).json({ success: false, message: 'This temporary account has expired.' });
        }
        
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            console.log(`Login failed: Incorrect password for ${username}.`);
            return res.status(401).json({ success: false, message: 'Invalid username or password.' });
        }

        // Success! Create session
        console.log(`Login successful for ${username}. Creating session.`);
        req.session.userId = user.id;
        req.session.username = user.username;
        res.json({ success: true, username: user.username });
    });
});

// API: Handle register logic
app.post('/api/register', (req, res) => {
    const { username, password, is_temporary } = req.body;

    // 1. Check: Does user already exist?
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, existingUser) => {
        // NEW: Check for database errors first!
        if (err) {
            console.error("!!! REGISTER DB (SELECT) ERROR: ", err.message);
            return res.status(500).json({ success: false, message: 'Server error. Check logs.' });
        }
        
        if (existingUser) {
            console.log(`Registration blocked: ${username} already exists.`);
            return res.status(400).json({ success: false, message: 'Username already exists.' });
        }

        // 2. Create: Hash password and set expiration
        console.log(`Registering new user: ${username}`);
        const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
        
        let expirationDate = null;
        if (is_temporary === 'true') {
            const now = new Date();
            now.setHours(now.getHours() + 1); // Expires in 1 hour
            expirationDate = now.toISOString();
            console.log(`User ${username} is temporary.`);
        }

        // 3. Save: Add to database
        db.run(
            "INSERT INTO users (username, password_hash, expires_at) VALUES (?, ?, ?)",
            [username, passwordHash, expirationDate],
            (err) => {
                // NEW: Check for database errors on INSERT!
                if (err) {
                    console.error("!!! REGISTER DB (INSERT) ERROR: ", err.message);
                    return res.status(500).json({ success: false, message: 'Could not create account. Check logs.' });
                }
                
                // Success!
                console.log(`Successfully created user: ${username}`);
                res.json({ success: true, message: 'Account created! Please log in.' });
            }
        );
    });
});

// API: Handle logout
app.post('/api/logout', (req, res) => {
    console.log(`Logging out user: ${req.session.username}`);
    req.session.destroy((err) => {
        if (err) {
            console.error("!!! LOGOUT ERROR: ", err.message);
            return res.status(500).json({ success: false, message: 'Could not log out.' });
        }
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});


// --- Secure WebSocket Handshake ---
server.on('upgrade', (request, socket, head) => {
    console.log('Parsing session from upgrade request...');
    sessionParser(request, {}, () => {
        if (!request.session.userId) {
            console.log('WebSocket upgrade rejected: No session/unauthorized');
            socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
            socket.destroy();
            return;
        }

        console.log(`WebSocket upgrade accepted for user: ${request.session.username}`);
        wss.handleUpgrade(request, socket, head, (ws) => {
            ws.userId = request.session.userId;
            ws.username = request.session.username;
            wss.emit('connection', ws, request);
        });
    });
});

// --- WebSocket Connection Handler ---
wss.on('connection', (ws) => {
    console.log(`New client connected: ${ws.username} (ID: ${ws.userId})`);
    
    // Send immediate confirmation
    ws.send(JSON.stringify({
        type: 'connected',
        message: 'Connected to server',
        username: ws.username // Send the user their *real* username
    }));
    
    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data.toString());
            handleMessage(ws, message); 
        } catch (error) {
            console.error('Error parsing message:', error);
        }
    });

    ws.on('close', () => {
        const user = users.get(ws);
        if (user) {
            console.log(`User ${user.username} disconnected`);
            users.delete(ws);
            broadcastUserList();
        }
    });

    ws.on('error', (console.error));
});

// --- (Chat logic) ---
const users = new Map(); // WebSocket -> user info
const channels = {
    general: [],
    random: [],
    gaming: []
};

function handleMessage(ws, message) {
    const user = { username: ws.username, id: ws.userId };
    switch (message.type) {
        case 'join':
            handleJoin(ws, user);
            break;
        case 'message':
            handleChatMessage(ws, user, message);
            break;
        case 'getHistory':
            handleGetHistory(ws, message);
            break;
        case 'typing':
            handleTyping(ws, user, message);
            break;
    }
}

function handleJoin(ws, user) {
    console.log(`User ${user.username} is joining the chat room.`);
    users.set(ws, { username: user.username, id: user.id });
    ws.send(JSON.stringify({ type: 'joined', username: user.username, channels: Object.keys(channels) }));
    broadcastUserList();
}

function handleChatMessage(ws, user, message) {
    const { channel, text } = message;
    const chatMessage = {
        id: generateId(),
        author: user.username,
        text,
        channel,
        timestamp: new Date().toISOString()
    };
    if (channels[channel]) {
        channels[channel].push(chatMessage);
        if (channels[channel].length > 100) channels[channel].shift();
    }
    broadcast({ type: 'message', message: chatMessage });
}

function handleGetHistory(ws, message) {
    const { channel } = message;
    if (channels[channel]) {
        ws.send(JSON.stringify({ type: 'history', channel, messages: channels[channel] }));
    }
}

function handleTyping(ws, user, message) {
    const { channel, isTyping } = message;
    broadcast({ type: 'typing', username: user.username, channel, isTyping }, ws);
}

function broadcastUserList() {
    const userList = Array.from(users.values()).map(u => u.username);
    console.log(`Broadcasting user list: ${userList.join(', ')}`);
    broadcast({ type: 'userList', users: userList });
}

function broadcast(message, excludeWs = null) {
    const data = JSON.stringify(message);
    wss.clients.forEach((client) => {
        if (client !== excludeWs && client.readyState === WebSocket.OPEN) {
            client.send(data);
        }
    });
}

function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

// --- Start Server ---
server.listen(PORT, () => {
    console.log(`=================================`);
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`=================================`);
});
