"""
Vulnerable Serialization Module
Contains deserialization vulnerabilities for SCA testing
"""

import pickle
import json
import base64
import yaml  # PyYAML 3.13 - vulnerable
from flask import jsonify
import redis  # redis 3.2.0 - vulnerable version
import marshal

# Redis connection (insecure configuration)
redis_client = None
try:
    redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
except:
    pass

def deserialize_pickle(data):
    """
    REACHABLE: Dangerous pickle deserialization
    This function is called from the main app
    """
    try:
        # Vulnerability 1: Unsafe pickle deserialization
        # This is extremely dangerous as pickle can execute arbitrary code
        if isinstance(data, bytes):
            deserialized_obj = pickle.loads(data)  # DANGEROUS!
        else:
            # Try to decode base64 first
            try:
                decoded_data = base64.b64decode(data)
                deserialized_obj = pickle.loads(decoded_data)  # DANGEROUS!
            except:
                return jsonify({"error": "Invalid pickle data"}), 400
        
        return jsonify({
            "message": "Deserialization successful",
            "type": str(type(deserialized_obj)),
            "data": str(deserialized_obj)[:500]  # Truncated for safety
        })
    
    except Exception as e:
        return jsonify({
            "error": "Deserialization failed",
            "details": str(e),
            "data_preview": str(data)[:100] if data else None
        }), 500

def serialize_and_store(obj, key):
    """
    Store serialized object using vulnerable methods
    """
    try:
        # Vulnerability: Using pickle for serialization
        pickled_data = pickle.dumps(obj)
        
        # Store in Redis (if available) using vulnerable version
        if redis_client:
            redis_client.set(key, base64.b64encode(pickled_data).decode())
        
        return {
            "serialized": True,
            "key": key,
            "size": len(pickled_data),
            "redis_stored": redis_client is not None
        }
    
    except Exception as e:
        return {"error": str(e)}

def deserialize_from_store(key):
    """
    Retrieve and deserialize from storage
    """
    try:
        if not redis_client:
            return {"error": "Redis not available"}
        
        # Get data from Redis
        stored_data = redis_client.get(key)
        if not stored_data:
            return {"error": "Key not found"}
        
        # Vulnerability: Deserialize without validation
        pickled_data = base64.b64decode(stored_data)
        obj = pickle.loads(pickled_data)  # DANGEROUS!
        
        return {
            "key": key,
            "deserialized": True,
            "type": str(type(obj)),
            "data": str(obj)[:500]
        }
    
    except Exception as e:
        return {"error": str(e)}

def process_yaml_data(yaml_string):
    """
    Process YAML data using vulnerable yaml.load
    """
    try:
        # Vulnerability: Using yaml.load instead of yaml.safe_load
        data = yaml.load(yaml_string)  # Dangerous - can execute code
        
        return {
            "yaml_processed": True,
            "type": str(type(data)),
            "data": data
        }
    
    except Exception as e:
        return {"error": str(e)}

def marshal_operations(data):
    """
    Using marshal module unsafely
    """
    try:
        # Vulnerability: Marshal can also be dangerous with untrusted data
        if isinstance(data, str):
            # Try to interpret as base64 encoded marshal data
            try:
                decoded = base64.b64decode(data)
                unmarshaled = marshal.loads(decoded)  # Potentially dangerous
                return {"unmarshaled": str(unmarshaled)}
            except:
                # Marshal the string itself
                marshaled = marshal.dumps(data)
                return {"marshaled": base64.b64encode(marshaled).decode()}
        else:
            marshaled = marshal.dumps(data)
            return {"marshaled": base64.b64encode(marshaled).decode()}
    
    except Exception as e:
        return {"error": str(e)}

def create_malicious_pickle():
    """
    Create a malicious pickle payload for testing (demonstration only)
    WARNING: This creates dangerous payloads for educational purposes
    """
    
    class MaliciousPayload:
        def __reduce__(self):
            # This would execute when unpickled
            import os
            return (os.system, ('echo "Pickle executed arbitrary code!"',))
    
    payload = MaliciousPayload()
    pickled = pickle.dumps(payload)
    
    return {
        "warning": "This is a malicious pickle payload - DO NOT DESERIALIZE",
        "payload_b64": base64.b64encode(pickled).decode(),
        "size": len(pickled)
    }

def json_deserialization_issues(json_string):
    """
    JSON deserialization with potential issues
    """
    try:
        # While JSON is generally safer, improper handling can still cause issues
        data = json.loads(json_string)
        
        # Vulnerability: Processing JSON without size limits
        if isinstance(data, dict) and len(str(data)) > 1000000:  # 1MB limit
            return {"error": "JSON too large", "size": len(str(data))}
        
        # Vulnerability: Recursively processing nested structures without depth limits
        def process_recursive(obj, depth=0):
            if depth > 100:  # Prevent infinite recursion
                return "MAX_DEPTH_REACHED"
            
            if isinstance(obj, dict):
                return {k: process_recursive(v, depth + 1) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [process_recursive(item, depth + 1) for item in obj]
            else:
                return obj
        
        processed = process_recursive(data)
        
        return {
            "json_processed": True,
            "original_size": len(json_string),
            "processed_data": processed
        }
    
    except Exception as e:
        return {"error": str(e)}

def unsafe_eval_operations(code_string):
    """
    Dangerous eval operations (for demonstration)
    """
    try:
        # Vulnerability: Using eval with user input
        # This is included to test if SCA tools detect eval usage
        result = eval(code_string)  # EXTREMELY DANGEROUS!
        
        return {
            "eval_result": str(result),
            "code_executed": code_string,
            "warning": "eval() executed user input"
        }
    
    except Exception as e:
        return {
            "error": str(e),
            "code_attempted": code_string
        }

def redis_operations_unsafe():
    """
    Unsafe Redis operations using vulnerable version
    """
    if not redis_client:
        return {"error": "Redis not available"}
    
    try:
        # Vulnerability: Using vulnerable Redis version
        info = redis_client.info()
        
        # Store some test data
        redis_client.set("test_key", "test_value")
        
        # Vulnerability: Executing Redis commands without validation
        # In vulnerable versions, certain operations could be exploited
        
        return {
            "redis_version": info.get('redis_version', 'unknown'),
            "server_info": dict(list(info.items())[:10]),  # Limited info
            "operations": "basic_set_get_completed"
        }
    
    except Exception as e:
        return {"error": str(e)} 