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
    
    // Vulnerable: unsanitized user input in SQL query
    const query = "SELECT * FROM users WHERE id = " + req.params.id;
    connection.query(query, (error, results) => {
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

// Safe mathematical expression parser (no eval/Function)
function safeEvaluate(expression) {
    if (typeof expression !== 'string') {
        throw new Error('Expression must be a string');
    }
    
    const tokens = tokenize(expression);
    const result = parseExpression(tokens);
    
    if (tokens.length > 0) {
        throw new Error('Unexpected token: ' + tokens[0]);
    }
    
    return result;
}

function tokenize(expr) {
    const tokens = [];
    const regex = /(\d+\.?\d*|\+|\-|\*|\/|\(|\))/g;
    let match;
    
    // Remove whitespace
    expr = expr.replace(/\s+/g, '');
    
    // Validate that expression only contains allowed characters
    if (!/^[\d+\-*/().]+$/.test(expr)) {
        throw new Error('Invalid characters in expression');
    }
    
    while ((match = regex.exec(expr)) !== null) {
        tokens.push(match[0]);
    }
    
    return tokens;
}

function parseExpression(tokens) {
    let result = parseTerm(tokens);
    
    while (tokens.length > 0 && (tokens[0] === '+' || tokens[0] === '-')) {
        const op = tokens.shift();
        const term = parseTerm(tokens);
        result = op === '+' ? result + term : result - term;
    }
    
    return result;
}

function parseTerm(tokens) {
    let result = parseFactor(tokens);
    
    while (tokens.length > 0 && (tokens[0] === '*' || tokens[0] === '/')) {
        const op = tokens.shift();
        const factor = parseFactor(tokens);
        result = op === '*' ? result * factor : result / factor;
    }
    
    return result;
}

function parseFactor(tokens) {
    if (tokens.length === 0) {
        throw new Error('Unexpected end of expression');
    }
    
    const token = tokens.shift();
    
    // Handle negative numbers
    if (token === '-') {
        return -parseFactor(tokens);
    }
    
    // Handle positive sign
    if (token === '+') {
        return parseFactor(tokens);
    }
    
    // Handle parentheses
    if (token === '(') {
        const result = parseExpression(tokens);
        if (tokens.length === 0 || tokens.shift() !== ')') {
            throw new Error('Missing closing parenthesis');
        }
        return result;
    }
    
    // Handle numbers
    const num = parseFloat(token);
    if (isNaN(num)) {
        throw new Error('Invalid number: ' + token);
    }
    
    return num;
}

app.post('/calculate', (req, res) => {
    const expression = req.body.expr;
    try {
        const result = safeEvaluate(expression);
        if (!isFinite(result)) {
            return res.status(400).json({ error: 'Result is not a finite number' });
        }
        res.json({ result: result });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
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
