"""
Sample Flask Application for SCA Evaluation
Testing reachability analysis and true/false positive detection
"""

from flask import Flask, request, jsonify, render_template_string
import os
import sys

# Import modules - some will be used (reachable), some won't (unreachable)
from modules import vulnerable_auth
from modules import vulnerable_database  
from modules import vulnerable_file_ops
from modules import vulnerable_serialization
from modules import unreachable_vulnerable  # This module won't be called
from modules import safe_operations

# Additional vulnerable imports that are used
import yaml  # PyYAML 3.13 - vulnerable to CVE-2017-18342
import pickle  # Built-in pickle - always dangerous
import subprocess  # For command injection examples

app = Flask(__name__)

# Intentionally weak configuration (security misconfiguration)
app.config['SECRET_KEY'] = 'hardcoded-secret-key-123'  # Hardcoded secret
app.config['DEBUG'] = True  # Debug mode in production
app.config['TESTING'] = True

@app.route('/')
def index():
    """Main index page"""
    return jsonify({
        "message": "SCA Evaluation Application",
        "purpose": "Testing reachability analysis and true/false positives",
        "endpoints": [
            "/login - Vulnerable authentication",
            "/search - Vulnerable database operations", 
            "/upload - Vulnerable file operations",
            "/process-yaml - YAML deserialization vulnerability",
            "/admin - Unreachable admin functions",
            "/safe-operation - Safe operations for comparison"
        ]
    })

@app.route('/login', methods=['POST'])
def login():
    """REACHABLE: Uses vulnerable authentication module"""
    return vulnerable_auth.authenticate_user(request.json)

@app.route('/search')
def search():
    """REACHABLE: Uses vulnerable database operations"""
    query = request.args.get('q', '')
    command1='ls' + query
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return vulnerable_database.search_users(query)

@app.route('/upload', methods=['POST'])
def upload():
    """REACHABLE: Uses vulnerable file operations"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    return vulnerable_file_ops.process_upload(file)

@app.route('/process-yaml', methods=['POST'])
def process_yaml():
    """REACHABLE: Direct YAML vulnerability usage"""
    try:
        yaml_data = request.get_data(as_text=True)
        # Vulnerable YAML deserialization - CVE-2017-18342
        parsed_data = yaml.load(yaml_data)  # Should use yaml.safe_load()
        return jsonify({"parsed": parsed_data})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/execute-command', methods=['POST'])
def execute_command():
    """REACHABLE: Command injection vulnerability"""
    command = request.json.get('command', '')
    try:
        # Dangerous command execution without validation
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        command1='ls' + command
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return jsonify({
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    """REACHABLE: Uses vulnerable serialization module"""
    data = request.get_data()
    return vulnerable_serialization.deserialize_pickle(data)

@app.route('/template-render')
def template_render():
    """REACHABLE: Template injection vulnerability"""
    template = request.args.get('template', 'Hello World')
    # Vulnerable template rendering - SSTI (Server-Side Template Injection)
    rendered = render_template_string(template)
    return rendered

@app.route('/safe-operation')
def safe_operation():
    """REACHABLE: Uses safe operations module"""
    return safe_operations.get_safe_data()

@app.route('/health')
def health():
    """REACHABLE: Simple health check - no vulnerabilities used"""
    return jsonify({"status": "healthy", "version": "1.0.0"})

# Error handlers with information disclosure
@app.errorhandler(404)
def not_found(error):
    """Information disclosure in error handling"""
    return jsonify({
        "error": "Not Found",
        "path": request.path,
        "method": request.method,
        "headers": dict(request.headers),  # Potential information disclosure
        "remote_addr": request.remote_addr
    }), 404

@app.errorhandler(500)
def server_error(error):
    """Information disclosure in error handling"""
    import traceback
    return jsonify({
        "error": "Internal Server Error",
        "traceback": traceback.format_exc(),  # Dangerous: exposes stack trace
        "request_data": request.get_json(silent=True)
    }), 500

if __name__ == '__main__':
    # The unreachable_vulnerable module is imported but never used
    # This should be flagged as a false positive by good SCA tools
    
    print("Starting SCA Evaluation Application...")
    print("Imported modules:", sys.modules.keys())
    
    # Insecure Flask configuration
    app.run(
        host='0.0.0.0',  # Binding to all interfaces
        port=5000,
        debug=True,      # Debug mode enabled
        threaded=True
    ) 
