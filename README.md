# SCA Evaluation Application

A comprehensive Python Flask application designed to evaluate Static Code Analysis (SCA) tools like **Semgrep** and **Dependabot**, with a focus on testing **reachability analysis** and **true positive vs false positive** detection.

## Overview

This application contains intentionally vulnerable code patterns and dependencies to test how well SCA tools can:

1. **Reachability Analysis**: Distinguish between vulnerable code that is actually executed vs. code that is imported but never called
2. **True/False Positives**: Accurately identify real security issues while minimizing false alarms

## Application Structure

```
├── app.py                              # Main Flask application
├── requirements.txt                    # Dependencies (mix of vulnerable and safe)
├── modules/
│   ├── vulnerable_auth.py             # REACHABLE: Authentication vulnerabilities
│   ├── vulnerable_database.py         # REACHABLE: SQL injection patterns
│   ├── vulnerable_file_ops.py         # REACHABLE: File handling vulnerabilities
│   ├── vulnerable_serialization.py    # REACHABLE: Deserialization vulnerabilities
│   ├── unreachable_vulnerable.py      # UNREACHABLE: Never called vulnerabilities
│   └── safe_operations.py             # REACHABLE: Secure implementations
├── test_scenarios/                     # Test cases for SCA evaluation
└── docs/                              # Evaluation documentation
```

## Vulnerability Categories

### 1. REACHABLE Vulnerabilities (True Positives)
These vulnerabilities exist in code paths that are actually executed:

- **SQL Injection** (`/search` endpoint)
- **Command Injection** (`/execute-command` endpoint)
- **Path Traversal** (`/upload` endpoint)
- **YAML Deserialization** (`/process-yaml` endpoint)
- **Pickle Deserialization** (`/deserialize` endpoint)
- **Server-Side Template Injection** (`/template-render` endpoint)
- **Information Disclosure** (Error handlers)
- **XXE Vulnerabilities** (File upload processing)

### 2. UNREACHABLE Vulnerabilities (False Positives)
These vulnerabilities exist in imported modules but are never called:

- Multiple SQL injection functions in `unreachable_vulnerable.py`
- Command injection functions that are never executed
- Unsafe deserialization methods that are never called
- Cryptographic vulnerabilities in unused code paths

### 3. Vulnerable Dependencies
The application uses intentionally old versions of libraries with known CVEs:

- **Django 2.2.0** - CVE-2019-14232, CVE-2019-14233, CVE-2019-14234, CVE-2019-14235
- **Flask 1.0.0** - CVE-2018-1000656
- **requests 2.19.1** - CVE-2018-18074
- **Pillow 6.2.0** - CVE-2019-16865, CVE-2020-5312
- **PyYAML 3.13** - CVE-2017-18342
- **lxml 4.2.0** - CVE-2018-19787, CVE-2020-27783
- **pycrypto 2.6.1** - CVE-2018-6594 (deprecated)

## Installation and Setup

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd sample-sca
   ```

2. **Create virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**:
   ```bash
   python app.py
   ```

The application will start on `http://localhost:5000`

## API Endpoints for Testing

### REACHABLE Endpoints (Should be flagged as True Positives)

1. **POST /login** - Vulnerable authentication
2. **GET /search?q=<query>** - SQL injection vulnerability
3. **POST /upload** - File upload with path traversal
4. **POST /process-yaml** - YAML deserialization vulnerability
5. **POST /execute-command** - Command injection
6. **POST /deserialize** - Pickle deserialization
7. **GET /template-render?template=<template>** - SSTI vulnerability

### SAFE Endpoints (Should not be flagged)

1. **GET /safe-operation** - Uses secure implementations
2. **GET /health** - Simple health check
3. **GET /** - Application info

## SCA Tool Evaluation

### Testing Reachability Analysis

**Good SCA tools should:**
- ✅ Flag vulnerabilities in reachable code paths (app.py routes and called modules)
- ✅ Identify vulnerable dependencies that are actually used
- ❌ **NOT** flag vulnerabilities in `unreachable_vulnerable.py` as high priority
- ❌ **NOT** flag unused vulnerable dependencies as critical

**Poor SCA tools will:**
- ❌ Flag all vulnerabilities equally regardless of reachability
- ❌ Generate many false positives from unused code
- ❌ Not distinguish between code paths

### Testing True vs False Positives

1. **Run SCA scan**: 
   ```bash
   # Semgrep example
   semgrep --config=auto .
   
   # Dependabot will scan requirements.txt automatically
   ```

2. **Analyze results**:
   - Count vulnerabilities in reachable vs unreachable modules
   - Check if tools provide reachability information
   - Evaluate priority/severity assignments

3. **Expected Results**:
   - **High Priority**: Vulnerabilities in reachable code paths
   - **Medium Priority**: Vulnerable dependencies that are used
   - **Low Priority/Info**: Vulnerabilities in unreachable code
   - **Suppressed**: Dependencies that are installed but not imported

## Evaluation Metrics

### Reachability Analysis Quality
- **True Positive Rate**: % of reachable vulnerabilities correctly identified as high risk
- **False Positive Rate**: % of unreachable vulnerabilities incorrectly flagged as high risk
- **Precision**: Accuracy of reachability determination

### Dependency Analysis Quality
- **Used vs Unused**: Can the tool distinguish between imported and non-imported dependencies?
- **Call Graph Analysis**: Does the tool trace actual usage of vulnerable functions?
- **Contextual Risk**: Does risk assessment consider actual usage patterns?

## Testing Scenarios

### Scenario 1: Basic Vulnerability Detection
- Run SCA tools on the codebase
- Count total vulnerabilities found
- Compare against known vulnerability list

### Scenario 2: Reachability Analysis
- Compare flagged vulnerabilities in reachable vs unreachable modules
- Check if tools provide call graph or usage analysis
- Evaluate priority/severity differences

### Scenario 3: Dependency Management
- Test with different dependency configurations
- Add/remove dependencies and test detection
- Evaluate dependency tree analysis

### Scenario 4: False Positive Management
- Add more unreachable vulnerable code
- Test suppression and filtering capabilities
- Evaluate noise reduction features

## Security Note

⚠️ **WARNING**: This application contains real security vulnerabilities and should only be used in isolated testing environments. Do not deploy to production or expose to public networks.

## Contributing

When adding new test cases:
1. Clearly mark functions as REACHABLE or UNREACHABLE
2. Document the vulnerability type and CVE if applicable
3. Update this README with new test scenarios
4. Follow the security best practices in `safe_operations.py` for comparison

## License

This project is for educational and testing purposes only. 