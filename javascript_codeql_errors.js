const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const fs = require('fs');

const app = express();

// SQL Injection vulnerability
app.get('/user/:id', (req, res) => {
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'mydb'
    });
    
    // Fixed: using parameterized query to prevent SQL injection
    const query = "SELECT * FROM users WHERE id = ?";
    connection.query(query, [req.params.id], (error, results) => {
        res.send(results);
    });
});

// Command Injection vulnerability
app.get('/ping', (req, res) => {
    const host = req.query.host;
    // Vulnerable: user input directly in shell command
    exec('ping -c 4 ' + host, (error, stdout) => {
        res.send(stdout);
    });
});

// Path Traversal vulnerability
app.get('/download', (req, res) => {
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
