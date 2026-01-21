const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const fs = require('fs');
const rateLimit = require('express-rate-limit');

const app = express();

// Rate limiter for database query endpoints - stricter limits
const dbQueryLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// Rate limiter for command execution endpoints - very strict limits
const commandLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // limit each IP to 10 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// Rate limiter for file download endpoints
const downloadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // limit each IP to 50 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// SQL Injection vulnerability
app.get('/user/:id', dbQueryLimiter, (req, res) => {
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'mydb'
    });
    
    // Vulnerable: unsanitized user input in SQL query
    const query = "SELECT * FROM users WHERE id = " + req.params.id;
    connection.query(query, (error, results) => {
        res.send(results);
    });
});

// Command Injection vulnerability
app.get('/ping', commandLimiter, (req, res) => {
    const host = req.query.host;
    // Vulnerable: user input directly in shell command
    exec('ping -c 4 ' + host, (error, stdout) => {
        res.send(stdout);
    });
});

// Path Traversal vulnerability
app.get('/download', downloadLimiter, (req, res) => {
    const filename = req.query.file;
    // Vulnerable: no path validation
    const filepath = '/var/www/uploads/' + filename;
    res.sendFile(filepath);
});

// XSS vulnerability
app.get('/search', (req, res) => {
    const searchTerm = req.query.q;
    // Vulnerable: reflecting user input without sanitization
    res.send('<h1>Results for: ' + searchTerm + '</h1>');
});

// eval() on user input
app.post('/calculate', (req, res) => {
    const expression = req.body.expr;
    // Vulnerable: eval on user-controlled input
    const result = eval(expression);
    res.json({ result: result });
});

// Hard-coded credentials
const API_KEY = 'sk-1234567890abcdef';
const DB_PASSWORD = 'MySecretPassword123!';

// Prototype pollution vulnerability
app.post('/update-config', (req, res) => {
    const userConfig = req.body;
    const config = {};
    // Vulnerable: no protection against __proto__
    for (let key in userConfig) {
        config[key] = userConfig[key];
    }
    res.json(config);
});

// Insecure randomness
function generateToken() {
    // Vulnerable: Math.random() is not cryptographically secure
    return Math.random().toString(36).substring(7);
}

// Regular expression denial of service (ReDoS)
app.get('/validate', (req, res) => {
    const input = req.query.input;
    // Vulnerable: catastrophic backtracking
    const pattern = /^(a+)+$/;
    const isValid = pattern.test(input);
    res.json({ valid: isValid });
});

app.listen(3000);
