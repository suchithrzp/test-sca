#!/usr/bin/env python3
"""
SCA Evaluation Test Script
Helps evaluate SCA tools by testing endpoints and generating evaluation data
"""

import requests
import json
import time
import base64
import pickle
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:5000"
TEST_RESULTS = []

def log_test(test_name, description, endpoint, should_be_vulnerable=True):
    """Log test execution for evaluation"""
    test_info = {
        "test_name": test_name,
        "description": description,
        "endpoint": endpoint,
        "should_be_vulnerable": should_be_vulnerable,
        "timestamp": datetime.now().isoformat()
    }
    TEST_RESULTS.append(test_info)
    print(f"[TEST] {test_name}: {description}")

def test_reachable_vulnerabilities():
    """Test all reachable vulnerability endpoints"""
    print("=" * 60)
    print("TESTING REACHABLE VULNERABILITIES (True Positives)")
    print("=" * 60)
    
    # Test 1: SQL Injection via search
    log_test(
        "SQL_INJECTION_SEARCH", 
        "SQL injection in search endpoint", 
        "/search",
        True
    )
    try:
        response = requests.get(f"{BASE_URL}/search?q=' OR 1=1 --")
        print(f"Search endpoint status: {response.status_code}")
    except Exception as e:
        print(f"Search test failed: {e}")
    
    # Test 2: Vulnerable authentication
    log_test(
        "VULNERABLE_AUTH",
        "Weak authentication with MD5 hashing",
        "/login", 
        True
    )
    try:
        response = requests.post(f"{BASE_URL}/login", json={
            "username": "admin",
            "password": "admin"
        })
        print(f"Login endpoint status: {response.status_code}")
    except Exception as e:
        print(f"Login test failed: {e}")
    
    # Test 3: YAML Deserialization
    log_test(
        "YAML_DESERIALIZATION",
        "Unsafe YAML deserialization vulnerability",
        "/process-yaml",
        True
    )
    try:
        yaml_payload = """
        test: value
        list: [1, 2, 3]
        """
        response = requests.post(f"{BASE_URL}/process-yaml", data=yaml_payload)
        print(f"YAML processing status: {response.status_code}")
    except Exception as e:
        print(f"YAML test failed: {e}")
    
    # Test 4: Command Injection
    log_test(
        "COMMAND_INJECTION",
        "Command injection vulnerability",
        "/execute-command",
        True
    )
    try:
        response = requests.post(f"{BASE_URL}/execute-command", json={
            "command": "echo 'test command injection'"
        })
        print(f"Command execution status: {response.status_code}")
    except Exception as e:
        print(f"Command injection test failed: {e}")
    
    # Test 5: Pickle Deserialization
    log_test(
        "PICKLE_DESERIALIZATION",
        "Dangerous pickle deserialization",
        "/deserialize",
        True
    )
    try:
        # Create a safe pickle payload for testing
        safe_data = {"test": "data", "number": 42}
        pickled_data = pickle.dumps(safe_data)
        encoded_data = base64.b64encode(pickled_data).decode()
        
        response = requests.post(f"{BASE_URL}/deserialize", data=encoded_data)
        print(f"Pickle deserialization status: {response.status_code}")
    except Exception as e:
        print(f"Pickle test failed: {e}")
    
    # Test 6: Server-Side Template Injection
    log_test(
        "SSTI_VULNERABILITY",
        "Server-side template injection",
        "/template-render",
        True
    )
    try:
        response = requests.get(f"{BASE_URL}/template-render?template=Hello {{7*7}}")
        print(f"Template injection status: {response.status_code}")
    except Exception as e:
        print(f"SSTI test failed: {e}")

def test_safe_endpoints():
    """Test safe endpoints that should not be flagged"""
    print("\n" + "=" * 60)
    print("TESTING SAFE ENDPOINTS (Should not be flagged)")
    print("=" * 60)
    
    # Test 1: Safe operation
    log_test(
        "SAFE_OPERATION",
        "Secure implementation example",
        "/safe-operation",
        False
    )
    try:
        response = requests.get(f"{BASE_URL}/safe-operation")
        print(f"Safe operation status: {response.status_code}")
    except Exception as e:
        print(f"Safe operation test failed: {e}")
    
    # Test 2: Health check
    log_test(
        "HEALTH_CHECK",
        "Simple health check endpoint",
        "/health",
        False
    )
    try:
        response = requests.get(f"{BASE_URL}/health")
        print(f"Health check status: {response.status_code}")
    except Exception as e:
        print(f"Health check test failed: {e}")
    
    # Test 3: Application info
    log_test(
        "APP_INFO",
        "Application information endpoint",
        "/",
        False
    )
    try:
        response = requests.get(f"{BASE_URL}/")
        print(f"App info status: {response.status_code}")
    except Exception as e:
        print(f"App info test failed: {e}")

def generate_vulnerability_report():
    """Generate a report of expected vulnerabilities for SCA comparison"""
    
    expected_vulnerabilities = {
        "reachable_code_vulnerabilities": [
            {
                "type": "SQL Injection",
                "location": "modules/vulnerable_database.py:search_users()",
                "severity": "HIGH",
                "reachable": True,
                "endpoint": "/search"
            },
            {
                "type": "Command Injection", 
                "location": "app.py:execute_command()",
                "severity": "HIGH",
                "reachable": True,
                "endpoint": "/execute-command"
            },
            {
                "type": "Path Traversal",
                "location": "modules/vulnerable_file_ops.py:process_upload()",
                "severity": "HIGH", 
                "reachable": True,
                "endpoint": "/upload"
            },
            {
                "type": "YAML Deserialization",
                "location": "app.py:process_yaml()",
                "severity": "HIGH",
                "reachable": True,
                "endpoint": "/process-yaml"
            },
            {
                "type": "Pickle Deserialization",
                "location": "modules/vulnerable_serialization.py:deserialize_pickle()",
                "severity": "CRITICAL",
                "reachable": True,
                "endpoint": "/deserialize"
            },
            {
                "type": "Server-Side Template Injection",
                "location": "app.py:template_render()",
                "severity": "HIGH",
                "reachable": True,
                "endpoint": "/template-render"
            },
            {
                "type": "Information Disclosure",
                "location": "app.py:server_error()",
                "severity": "MEDIUM",
                "reachable": True,
                "endpoint": "Error handlers"
            },
            {
                "type": "XXE Vulnerability",
                "location": "modules/vulnerable_file_ops.py:process_xml_unsafe()",
                "severity": "HIGH",
                "reachable": True,
                "endpoint": "/upload (XML files)"
            }
        ],
        
        "unreachable_code_vulnerabilities": [
            {
                "type": "SQL Injection",
                "location": "modules/unreachable_vulnerable.py:unreachable_sql_injection()",
                "severity": "Should be LOW/INFO",
                "reachable": False,
                "note": "Function never called"
            },
            {
                "type": "Command Injection",
                "location": "modules/unreachable_vulnerable.py:unreachable_command_injection()",
                "severity": "Should be LOW/INFO",
                "reachable": False,
                "note": "Function never called"
            },
            {
                "type": "Pickle Deserialization",
                "location": "modules/unreachable_vulnerable.py:unreachable_pickle_vulnerability()",
                "severity": "Should be LOW/INFO",
                "reachable": False,
                "note": "Function never called"
            },
            {
                "type": "YAML Deserialization",
                "location": "modules/unreachable_vulnerable.py:unreachable_yaml_vulnerability()",
                "severity": "Should be LOW/INFO",
                "reachable": False,
                "note": "Function never called"
            }
        ],
        
        "vulnerable_dependencies": [
            {
                "package": "Django",
                "version": "2.2.0",
                "cves": ["CVE-2019-14232", "CVE-2019-14233", "CVE-2019-14234", "CVE-2019-14235"],
                "used": False,
                "note": "Installed but not imported"
            },
            {
                "package": "Flask",
                "version": "1.0.0",
                "cves": ["CVE-2018-1000656"],
                "used": True,
                "note": "Used in main application"
            },
            {
                "package": "PyYAML",
                "version": "3.13",
                "cves": ["CVE-2017-18342"],
                "used": True,
                "note": "Used in vulnerable deserialization"
            },
            {
                "package": "Pillow",
                "version": "6.2.0",
                "cves": ["CVE-2019-16865", "CVE-2020-5312"],
                "used": True,
                "note": "Used in file processing"
            },
            {
                "package": "requests",
                "version": "2.19.1",
                "cves": ["CVE-2018-18074"],
                "used": True,
                "note": "Used in unreachable module only"
            }
        ]
    }
    
    return expected_vulnerabilities

def save_evaluation_report():
    """Save evaluation data to file"""
    
    report = {
        "evaluation_metadata": {
            "timestamp": datetime.now().isoformat(),
            "application": "SCA Evaluation Test App",
            "purpose": "Testing reachability analysis and true/false positives"
        },
        "test_execution": TEST_RESULTS,
        "expected_vulnerabilities": generate_vulnerability_report(),
        "evaluation_criteria": {
            "reachability_analysis": {
                "excellent": "Distinguishes reachable vs unreachable vulnerabilities with different priorities",
                "good": "Flags reachable vulnerabilities as high priority",
                "poor": "Treats all vulnerabilities equally regardless of reachability"
            },
            "dependency_analysis": {
                "excellent": "Distinguishes between used and unused dependencies",
                "good": "Identifies vulnerable dependencies with usage context",
                "poor": "Lists all vulnerable dependencies without context"
            },
            "false_positive_management": {
                "excellent": "Minimal false positives, clear risk prioritization",
                "good": "Some false positives but good overall accuracy",
                "poor": "Many false positives, unclear prioritization"
            }
        }
    }
    
    filename = f"sca_evaluation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nEvaluation report saved to: {filename}")
    return filename

def main():
    """Main evaluation function"""
    print("SCA Tool Evaluation Test Script")
    print("=" * 60)
    print("This script tests various endpoints to help evaluate SCA tool capabilities")
    print("Make sure the Flask application is running on http://localhost:5000")
    print()
    
    # Test if application is running
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        print("✅ Application is running and accessible")
    except Exception as e:
        print(f"❌ Cannot connect to application: {e}")
        print("Please start the Flask application first: python app.py")
        return
    
    # Run tests
    test_reachable_vulnerabilities()
    test_safe_endpoints()
    
    # Generate and save report
    print("\n" + "=" * 60)
    print("GENERATING EVALUATION REPORT")
    print("=" * 60)
    
    report_file = save_evaluation_report()
    
    print("\n" + "=" * 60)
    print("EVALUATION COMPLETE")
    print("=" * 60)
    print("Next steps:")
    print("1. Run your SCA tools (Semgrep, Dependabot, etc.) on this codebase")
    print("2. Compare results with the expected vulnerabilities in the report")
    print("3. Evaluate reachability analysis accuracy")
    print("4. Assess false positive rates")
    print(f"5. Reference the evaluation report: {report_file}")

if __name__ == "__main__":
    main() 