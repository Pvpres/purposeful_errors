import pickle
import sqlite3
import os
import subprocess

# SQL Injection vulnerability
def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable: direct string concatenation in SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

# Command Injection vulnerability
def ping_host(hostname):
    # Vulnerable: unsanitized user input in shell command
    command = "ping -c 4 " + hostname
    result = subprocess.call(command, shell=True)
    return result

# Path Traversal vulnerability
def read_file(filename):
    # Vulnerable: no path sanitization
    with open("/var/www/files/" + filename, 'r') as f:
        return f.read()

# Pickle Deserialization vulnerability
def load_user_data(serialized_data):
    # Vulnerable: pickle.loads on untrusted data
    user_data = pickle.loads(serialized_data)
    return user_data

# Hard-coded credentials
def connect_to_database():
    # Vulnerable: hard-coded password
    db_password = "SuperSecret123!"
    conn = sqlite3.connect('app.db')
    return conn

# Secure password hashing using PBKDF2
def hash_password(password):
    import hashlib
    import secrets
    # Secure: using PBKDF2 with SHA-256, random salt, and sufficient iterations
    salt = secrets.token_bytes(32)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + ':' + password_hash.hex()

# Use of eval on user input
def calculate(expression):
    # Vulnerable: eval on user-controlled input
    result = eval(expression)
    return result
