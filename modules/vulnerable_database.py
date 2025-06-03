"""
Vulnerable Database Operations Module
Contains SQL injection and other database vulnerabilities for SCA testing
"""

import sqlite3
import psycopg2  # Vulnerable version 2.7.5
from sqlalchemy import create_engine, text  # Vulnerable SQLAlchemy 1.2.0
from flask import jsonify
import os

# Database connection configurations (insecure)
DATABASE_URL = "sqlite:///app.db"  # Default database
POSTGRES_URL = "postgresql://user:password@localhost/testdb"  # Hardcoded credentials

# Sample data
sample_users = [
    {"id": 1, "name": "Alice Johnson", "email": "alice@example.com", "role": "admin"},
    {"id": 2, "name": "Bob Smith", "email": "bob@example.com", "role": "user"},
    {"id": 3, "name": "Charlie Brown", "email": "charlie@example.com", "role": "user"},
    {"id": 4, "name": "Diana Prince", "email": "diana@example.com", "role": "moderator"}
]

def search_users(query):
    """
    REACHABLE: Vulnerable user search function with SQL injection
    This function is called from the main app
    """
    try:
        # Vulnerability 1: SQL Injection - direct string concatenation
        sql_query = f"SELECT * FROM users WHERE name LIKE '%{query}%' OR email LIKE '%{query}%'"
        print(f"Executing SQL: {sql_query}")  # Information disclosure
        
        # Simulate database search (in real app, this would execute the vulnerable query)
        results = []
        for user in sample_users:
            if query.lower() in user['name'].lower() or query.lower() in user['email'].lower():
                results.append(user)
        
        return jsonify({
            "query": query,
            "sql_executed": sql_query,  # Information disclosure
            "results": results,
            "count": len(results)
        })
    
    except Exception as e:
        # Vulnerability 2: Information disclosure in error handling
        return jsonify({
            "error": "Database search failed",
            "details": str(e),
            "query": query,
            "sql_query": sql_query if 'sql_query' in locals() else None
        }), 500

def get_user_profile(user_id):
    """
    REACHABLE: Another vulnerable database function
    """
    # Vulnerability: SQL injection through parameter
    query = f"SELECT * FROM users WHERE id = {user_id}"  # No parameterization
    
    try:
        # Simulate database execution
        for user in sample_users:
            if user['id'] == int(user_id):
                return jsonify({
                    "user": user,
                    "sql_query": query,  # Information disclosure
                    "success": True
                })
        
        return jsonify({"error": "User not found", "sql_query": query}), 404
    
    except ValueError:
        return jsonify({
            "error": "Invalid user ID",
            "provided_id": user_id,
            "sql_query": query
        }), 400

def create_sqlite_connection():
    """
    Vulnerable SQLite connection setup
    """
    try:
        # Vulnerability: Using vulnerable SQLAlchemy version
        engine = create_engine(DATABASE_URL, echo=True)  # Echo=True exposes SQL in logs
        connection = engine.connect()
        return connection
    except Exception as e:
        print(f"Database connection failed: {e}")
        return None

def execute_raw_query(query_string):
    """
    DANGEROUS: Direct query execution without validation
    This function demonstrates SQL injection vulnerability
    """
    try:
        connection = create_sqlite_connection()
        if connection:
            # Vulnerability: Direct execution of user-provided SQL
            result = connection.execute(text(query_string))  # Dangerous!
            return result.fetchall()
    except Exception as e:
        print(f"Query execution failed: {e}")
        return None

def get_user_data_postgresql(user_id):
    """
    Vulnerable PostgreSQL operations using psycopg2
    """
    try:
        # Vulnerability: Using vulnerable psycopg2 version
        conn = psycopg2.connect(POSTGRES_URL)  # Hardcoded connection string
        cursor = conn.cursor()
        
        # Vulnerability: SQL injection
        query = f"SELECT * FROM users WHERE id = {user_id}"  # No parameterization
        cursor.execute(query)
        
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        return result
    
    except Exception as e:
        print(f"PostgreSQL operation failed: {e}")
        return None

def bulk_update_users(updates):
    """
    Vulnerable bulk update function
    """
    results = []
    
    for update in updates:
        user_id = update.get('id')
        new_data = update.get('data', {})
        
        # Vulnerability: Building dynamic SQL with user input
        set_clauses = []
        for key, value in new_data.items():
            set_clauses.append(f"{key} = '{value}'")  # No escaping
        
        sql = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = {user_id}"
        
        # Log the vulnerable SQL (information disclosure)
        print(f"Bulk update SQL: {sql}")
        results.append({"sql": sql, "user_id": user_id})
    
    return results

def search_with_filters(filters):
    """
    Complex search function with multiple SQL injection points
    """
    base_query = "SELECT * FROM users WHERE 1=1"
    
    # Build dynamic WHERE clauses (vulnerable)
    for field, value in filters.items():
        if field in ['name', 'email', 'role']:
            # Vulnerability: No input validation or parameterization
            base_query += f" AND {field} LIKE '%{value}%'"
    
    # Add ordering (another injection point)
    if 'order_by' in filters:
        base_query += f" ORDER BY {filters['order_by']}"  # Vulnerable
    
    print(f"Complex search SQL: {base_query}")
    return base_query

def get_database_schema():
    """
    Function that exposes database schema (information disclosure)
    """
    schema_info = {
        "tables": ["users", "sessions", "logs", "admin_settings"],
        "users_columns": ["id", "name", "email", "password_hash", "role", "created_at"],
        "sensitive_tables": ["admin_settings", "audit_logs"],
        "database_version": "SQLite 3.31.1",
        "connection_string": DATABASE_URL  # Information disclosure
    }
    
    return schema_info 