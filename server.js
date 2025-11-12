const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const bcrypt = require('bcrypt'); // --- NEW ---
const session = require('express-session'); // --- NEW ---
const FileStore = require('session-file-store')(session); // --- NEW ---
const db = require('./database.js'); // --- NEW ---

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true }); // --- MODIFIED ---

const PORT = process.env.PORT || 3000;
const BCRYPT_SALT_ROUNDS = 12;

// --- NEW --- (Session Configuration)
const sessionParser = session({
    store: new FileStore({ path: './sessions' }),
    secret: 'a_very_secret_key_change_this_later',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 // 1 day
    }
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // --- NEW --- (For HTML forms)
app.use(sessionParser); // --- NEW --- (Use sessions)
app.use(express.static('public'));

// In-memory storage
const channels = {
    general: [],
    random: [],
    gaming: []
};

const users = new Map(); // WebSocket -> user info

// --- NEW --- (Authentication Middleware)
// This function checks if a user is logged in before letting them see a page
function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/login'); // Not logged in, send to login
    }
    next(); // Logged in, continue
}

// --- NEW --- (Auth Routes: Login, Register, Logout)

// Serve the chat app (protected)
app.get('/', requireLogin, (req, res) => {
    // req.session.username is available because of requireLogin
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve the login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Handle login logic
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) {
            return res.status(500).send("Server error");
        }
        
        // 1. Check: User exists
        if (!user) {
            return res.status(401).send('Invalid username or password. <a href="/login">Try again</a>');
        }

        // 2. Check: Account hasn't expired (if temporary)
        if (user.expires_at && new Date(user.expires_at) < new Date()) {
            return res.status(401).send('This temporary account has expired. <a href="/login">Try again</a>');
        }

        // 3. Check: Password is correct
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            return res.status(401).send('Invalid username or password. <a href="/login">Try again</a>');
        }

        // 4. Success! Create session
        req.session.userId = user.id;
        req.session.username = user.username;
        res.redirect('/'); // Redirect to the chat app
    });
});

// Serve the register page
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Handle register logic
app.post('/register', async (req, res) => {
    const { username, password, is_temporary } = req.body;

    // 1. Check: Does user already exist?
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, existingUser) => {
        if (err) {
            return res.status(500).send("Server error");
        }
        if (existingUser) {
            return res.status(400).send('Username already exists. <a href="/register">Try again</a>');
        }

        // 2. Create: Hash password and set expiration
        const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
        
        let expirationDate = null;
        if (is_temporary === 'true') {
            const now = new Date();
            now.setHours(now.getHours() + 1); // Expires in 1 hour
            expirationDate = now.toISOString();
        }

        // 3. Save: Add to database
        db.run(
            "INSERT INTO users (username, password_hash, expires_at) VALUES (?, ?, ?)",
            [username, passwordHash, expirationDate],
            (err) => {
                if (err) {
                    return res.status(500).send("Error creating account");
                }
                res.redirect('/login'); // Registration successful, redirect to login
            }
        );
    });
});

// Handle logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.redirect('/');
        }
        res.clearCookie('connect.sid'); // Clear the session cookie
        res.redirect('/login');
    });
});

// --- NEW --- (Secure WebSocket Handshake)
// This logic runs *before* the 'connection' event
// It checks the session to see if the user is logged in
server.on('upgrade', (request, socket, head) => {
    console.log('Parsing session from upgrade request...');
    
    // Pass the request to the session parser
    sessionParser(request, {}, () => {
        // 1. Check if the user is logged in
        if (!request.session.userId) {
            console.log('WebSocket upgrade rejected: No session');
            socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
            socket.destroy();
            return;
        }

        console.log(`WebSocket upgrade accepted for user: ${request.session.username}`);

        // 2. User is logged in, complete the WebSocket handshake
        wss.handleUpgrade(request, socket, head, (ws) => {
            // Attach the user info *to* the WebSocket object
            ws.userId = request.session.userId;
            ws.username = request.session.username;
            
            // Now, emit the 'connection' event
            wss.emit('connection', ws, request);
        });
    });
});

// WebSocket connection handler
wss.on('connection', (ws) => {
    // --- MODIFIED ---
    // We already know who the user is, thanks to the 'upgrade' logic!
    console.log(`New client connected: ${ws.username}`);
    
    // Send immediate confirmation
    ws.send(JSON.stringify({
        type: 'connected',
        message: 'Connected to server',
        username: ws.username // --- NEW --- Send the user their *real* username
    }));
    
    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data.toString());
            // --- MODIFIED --- Pass 'ws' so we know the user
            handleMessage(ws, message); 
        } catch (error) {
            console.error('Error parsing message:', error);
        }
    });

    ws.on('close', () => {
        const user = users.get(ws); // Get user from our *chat* map
        if (user) {
            console.log(`User ${user.username} disconnected`);
            users.delete(ws);
            broadcastUserList();
        }
    });

    ws.on('error', (console.error));
});

// Handle different message types
function handleMessage(ws, message) {
    // --- MODIFIED --- We get the user from 'ws', not the message
    const user = {
        username: ws.username,
        id: ws.userId
    };

    switch (message.type) {
        case 'join':
            handleJoin(ws, user); // --- MODIFIED ---
            break;
        case 'message':
            handleChatMessage(ws, user, message); // --- MODIFIED ---
            break;
        case 'getHistory':
            handleGetHistory(ws, message);
            break;
        case 'typing':
            handleTyping(ws, user, message); // --- MODIFIED ---
            break;
    }
}

// User joins
function handleJoin(ws, user) { // --- MODIFIED ---
    // We no longer need the 'username' from the message
    console.log(`User joining: ${user.username}`);
    
    users.set(ws, {
        username: user.username,
        id: user.id
    });

    // Send welcome message
    ws.send(JSON.stringify({
        type: 'joined',
        username: user.username,
        channels: Object.keys(channels)
    }));

    broadcastUserList();
}

// Handle chat messages
function handleChatMessage(ws, user, message) { // --- MODIFIED ---
    const { channel, text } = message;
    console.log(`Message from ${user.username} in #${channel}: ${text}`);
    
    const chatMessage = {
        id: generateId(),
        author: user.username, // --- SECURE ---
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

// Get channel history (no change)
function handleGetHistory(ws, message) {
    const { channel } = message;
    if (channels[channel]) {
        ws.send(JSON.stringify({
            type: 'history',
            channel,
            messages: channels[channel]
        }));
    }
}

// Handle typing indicator
function handleTyping(ws, user, message) { // --- MODIFIED ---
    const { channel, isTyping } = message;
    
    broadcast({
        type: 'typing',
        username: user.username, // --- SECURE ---
        channel,
        isTyping
    }, ws);
}

// (Rest of your functions: broadcastUserList, broadcast, generateId, API routes, health check)
// ... (They can stay mostly the same) ...

// Broadcast user list
function broadcastUserList() {
    const userList = Array.from(users.values()).map(u => u.username);
    broadcast({
        type: 'userList',
        users: userList
    });
}

// Broadcast to all clients (except sender if specified)
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

// (Your API and health routes - unchanged)
// ...

// Start server
server.listen(PORT, () => {
    console.log(`=================================`);
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`=================================`);
});
