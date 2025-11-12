// (The first two lines are the same)
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        // This will now shout the error if it can't even open the file
        console.error("!!! DATABASE OPEN ERROR: ", err.message);
    } else {
        console.log('Database connection opened successfully.');
    }
});

db.serialize(() => {
    console.log('Initializing database schema...');
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            expires_at DATETIME
        )
    `, (err) => {
        if (err) {
            // This will shout the error if the table can't be created
            console.error("!!! TABLE CREATION ERROR: ", err.message);
        } else {
            console.log("Users table is ready.");
        }
    });
});

module.exports = db;
