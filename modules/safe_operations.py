"""
Safe Operations Module
Contains secure implementations for comparison with vulnerable modules
This demonstrates proper security practices
"""

import hashlib
import secrets
import hmac
import json
from datetime import datetime, timedelta
from flask import jsonify
import yaml
import sqlite3
import logging

# Configure secure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Safe configuration
SAFE_SECRET_KEY = secrets.token_urlsafe(32)  # Cryptographically secure random key
MAX_LOGIN_ATTEMPTS = 3
RATE_LIMIT_WINDOW = timedelta(minutes=15)

# Secure user data (passwords properly hashed)
safe_users = [
    {
        "id": 1, 
        "username": "admin", 
        "password_hash": "scrypt:32768:8:1$salt$hash",  # Properly hashed with salt
        "role": "admin",
        "login_attempts": 0,
        "last_attempt": None
    },
    {
        "id": 2, 
        "username": "user", 
        "password_hash": "scrypt:32768:8:1$salt2$hash2", 
        "role": "user",
        "login_attempts": 0,
        "last_attempt": None
    }
]

def get_safe_data():
    """
    REACHABLE: Safe data retrieval function
    This function is called from the main app and demonstrates secure practices
    """
    try:
        # Safe data structure without sensitive information
        safe_response = {
            "message": "Safe operation completed successfully",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "users_count": len(safe_users),
            "security_features": [
                "Input validation",
                "Secure password hashing", 
                "Rate limiting",
                "Proper error handling",
                "No information disclosure"
            ]
        }
        
        logger.info("Safe data operation completed")
        return jsonify(safe_response)
    
    except Exception as e:
        # Secure error handling - no sensitive information disclosed
        logger.error(f"Safe operation failed: {str(e)}")
        return jsonify({"error": "Operation failed"}), 500

def safe_login(credentials):
    """
    Secure authentication implementation
    """
    try:
        if not credentials or not isinstance(credentials, dict):
            return jsonify({"error": "Invalid credentials format"}), 400
        
        username = credentials.get('username', '').strip()
        password = credentials.get('password', '')
        
        # Input validation
        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400
        
        if len(username) > 50 or len(password) > 100:  # Reasonable limits
            return jsonify({"error": "Input too long"}), 400
        
        # Find user safely
        user = None
        for u in safe_users:
            if u['username'] == username:
                user = u
                break
        
        if not user:
            # Generic error message - no information disclosure
            logger.warning(f"Login attempt for non-existent user: {username}")
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Check rate limiting
        if user['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
            if user['last_attempt'] and datetime.now() - user['last_attempt'] < RATE_LIMIT_WINDOW:
                logger.warning(f"Rate limit exceeded for user: {username}")
                return jsonify({"error": "Too many failed attempts. Try again later."}), 429
            else:
                # Reset attempts after rate limit window
                user['login_attempts'] = 0
        
        # Verify password (in real implementation, use proper password hashing)
        # This is simplified for demonstration
        password_valid = verify_password_safe(password, user['password_hash'])
        
        if not password_valid:
            user['login_attempts'] += 1
            user['last_attempt'] = datetime.now()
            logger.warning(f"Failed login attempt for user: {username}")
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Successful login
        user['login_attempts'] = 0  # Reset on successful login
        logger.info(f"Successful login for user: {username}")
        
        # Generate secure session token
        session_token = generate_secure_token(user['id'])
        
        return jsonify({
            "message": "Authentication successful",
            "token": session_token,
            "user": {
                "id": user['id'],
                "username": user['username'],
                "role": user['role']
                # No sensitive information included
            }
        })
    
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"error": "Authentication failed"}), 500

def verify_password_safe(password, password_hash):
    """
    Secure password verification
    In a real implementation, this would use bcrypt, scrypt, or Argon2
    """
    # Simplified implementation for demonstration
    # In production, use: bcrypt.checkpw(password.encode('utf-8'), password_hash)
    return hmac.compare_digest(
        hashlib.pbkdf2_hmac('sha256', password.encode(), b'safe_salt', 100000).hex(),
        password_hash.split('$')[-1] if '$' in password_hash else password_hash
    )

def generate_secure_token(user_id):
    """
    Generate cryptographically secure token
    """
    # Use cryptographically secure random number generator
    token_data = {
        "user_id": user_id,
        "issued_at": datetime.utcnow().isoformat(),
        "expires": (datetime.utcnow() + timedelta(hours=1)).isoformat()
    }
    
    # In real implementation, use JWT with proper signing
    token = secrets.token_urlsafe(32)
    return token

def safe_database_query(search_term):
    """
    Secure database query with parameterization
    """
    try:
        # Input validation
        if not search_term or len(search_term) > 100:
            return {"error": "Invalid search term"}
        
        # Sanitize input
        safe_search_term = search_term.strip()
        
        # Use parameterized query (safe from SQL injection)
        query = "SELECT id, username, role FROM users WHERE username LIKE ? OR role LIKE ?"
        params = (f"%{safe_search_term}%", f"%{safe_search_term}%")
        
        # Simulate safe database operation
        results = []
        for user in safe_users:
            if (safe_search_term.lower() in user['username'].lower() or 
                safe_search_term.lower() in user['role'].lower()):
                results.append({
                    "id": user['id'],
                    "username": user['username'],
                    "role": user['role']
                    # No sensitive data included
                })
        
        logger.info(f"Safe database search completed for term: {safe_search_term}")
        return {
            "results": results,
            "count": len(results),
            "search_term": safe_search_term
            # No internal query details exposed
        }
    
    except Exception as e:
        logger.error(f"Database query error: {str(e)}")
        return {"error": "Search failed"}

def safe_file_operations(filename):
    """
    Secure file operations with proper validation
    """
    try:
        # Input validation and sanitization
        if not filename or not isinstance(filename, str):
            return {"error": "Invalid filename"}
        
        # Remove dangerous characters and prevent path traversal
        safe_filename = "".join(c for c in filename if c.isalnum() or c in ('-', '_', '.'))
        
        # Prevent path traversal
        if '..' in safe_filename or '/' in safe_filename or '\\' in safe_filename:
            logger.warning(f"Path traversal attempt detected: {filename}")
            return {"error": "Invalid filename"}
        
        # Whitelist allowed extensions
        allowed_extensions = ['.txt', '.json', '.csv']
        if not any(safe_filename.endswith(ext) for ext in allowed_extensions):
            return {"error": "File type not allowed"}
        
        # Safe file path construction
        safe_directory = "/tmp/safe_uploads"
        safe_filepath = f"{safe_directory}/{safe_filename}"
        
        return {
            "original_filename": filename,
            "safe_filename": safe_filename,
            "safe_path": safe_filepath,
            "validation_passed": True
        }
    
    except Exception as e:
        logger.error(f"File operation error: {str(e)}")
        return {"error": "File operation failed"}

def safe_yaml_processing(yaml_string):
    """
    Safe YAML processing using yaml.safe_load
    """
    try:
        # Input validation
        if not yaml_string or len(yaml_string) > 10000:  # Size limit
            return {"error": "Invalid YAML input"}
        
        # Use safe YAML loading (prevents code execution)
        data = yaml.safe_load(yaml_string)  # SECURE - only loads basic Python objects
        
        # Additional validation
        if data is None:
            return {"error": "Empty YAML data"}
        
        return {
            "yaml_processed": True,
            "data_type": str(type(data)),
            "keys": list(data.keys()) if isinstance(data, dict) else None,
            "size": len(str(data))
        }
    
    except yaml.YAMLError as e:
        logger.warning(f"YAML parsing error: {str(e)}")
        return {"error": "Invalid YAML format"}
    except Exception as e:
        logger.error(f"YAML processing error: {str(e)}")
        return {"error": "YAML processing failed"}

def secure_session_management():
    """
    Demonstrates secure session management practices
    """
    session_config = {
        "secure_random_token": secrets.token_urlsafe(32),
        "expiration": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
        "security_features": [
            "Cryptographically secure random tokens",
            "Proper expiration handling",
            "No sensitive data in tokens",
            "Secure token storage recommendations"
        ],
        "recommendations": [
            "Use HTTPOnly cookies",
            "Enable Secure flag for HTTPS",
            "Implement proper CSRF protection",
            "Regular token rotation"
        ]
    }
    
    return session_config

def input_validation_examples():
    """
    Examples of proper input validation
    """
    validation_patterns = {
        "email": r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
        "phone": r'^\+?1?[0-9]{10,15}$',
        "username": r'^[a-zA-Z0-9_]{3,20}$',
        "safe_filename": r'^[a-zA-Z0-9._-]{1,255}$'
    }
    
    return {
        "validation_patterns": validation_patterns,
        "best_practices": [
            "Always validate input length",
            "Use whitelist validation when possible",
            "Sanitize input before processing",
            "Implement proper error handling",
            "Log security events appropriately"
        ]
    } 