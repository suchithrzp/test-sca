"""
Vulnerable Authentication Module
Contains various authentication vulnerabilities for SCA testing
"""

import hashlib
import sqlite3
import os
from cryptography.fernet import Fernet  # Vulnerable version 2.3
from Crypto.Cipher import AES  # pycrypto 2.6.1 - deprecated and vulnerable
import jwt  # Not imported in requirements but shows pattern
from flask import jsonify

# Hardcoded secrets (vulnerability)
SECRET_KEY = "hardcoded-secret-key"
ENCRYPTION_KEY = b'twelve_byte_key!'  # Weak key

# Simulated database
users_db = [
    {"id": 1, "username": "admin", "password": "21232f297a57a5a743894a0e4a801fc3", "role": "admin"},  # MD5 hash of 'admin'
    {"id": 2, "username": "user", "password": "ee11cbb19052e40b07aac0ca060c23ee", "role": "user"}     # MD5 hash of 'user'
]

def authenticate_user(data):
    """
    Vulnerable authentication function
    REACHABLE: This function is called from the main app
    """
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    username = data.get('username', '')
    password = data.get('password', '')
    
    # Vulnerability 1: SQL Injection pattern (even though using list)
    # This simulates what would be a SQL injection if using real database
    query = f"SELECT * FROM users WHERE username = '{username}'"  # Dangerous pattern
    print(f"Simulated query: {query}")  # Information disclosure
    
    # Vulnerability 2: Using weak MD5 hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    # Find user
    user = None
    for u in users_db:
        if u['username'] == username and u['password'] == password_hash:
            user = u
            break
    
    if not user:
        # Vulnerability 3: Information disclosure in error messages
        return jsonify({
            "error": "Authentication failed",
            "debug_info": f"User '{username}' not found or password mismatch",
            "attempted_hash": password_hash
        }), 401
    
    # Vulnerability 4: Using deprecated pycrypto
    try:
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)  # Weak ECB mode
        # This would be vulnerable if actually used
    except Exception as e:
        print(f"Crypto error: {e}")
    
    return jsonify({
        "message": "Authentication successful",
        "user": user,  # Information disclosure - returning full user object
        "token": generate_token(user)
    })

def generate_token(user):
    """
    Generate authentication token using vulnerable methods
    """
    # Vulnerability: Weak token generation
    token_data = f"{user['id']}:{user['username']}:{SECRET_KEY}"
    token = hashlib.md5(token_data.encode()).hexdigest()  # Weak hashing
    return token

def validate_password_strength(password):
    """
    Weak password validation
    """
    # Very weak validation - should be much stronger
    if len(password) < 4:  # Too short minimum
        return False
    return True

def get_user_by_id(user_id):
    """
    Vulnerable user retrieval function
    """
    # Vulnerability: No input validation/sanitization
    for user in users_db:
        if str(user['id']) == str(user_id):  # Loose comparison
            return user
    return None

def hash_password_insecure(password):
    """
    Insecure password hashing using deprecated methods
    """
    # Vulnerability: Using MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()

def encrypt_sensitive_data(data):
    """
    Vulnerable encryption implementation
    """
    try:
        # Using vulnerable cryptography version
        key = Fernet.generate_key()  # Key not properly stored
        cipher = Fernet(key)
        encrypted = cipher.encrypt(data.encode())
        return encrypted, key
    except Exception as e:
        # Information disclosure in exception handling
        print(f"Encryption failed: {e}")
        return None, None 