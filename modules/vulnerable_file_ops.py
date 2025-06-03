"""
Vulnerable File Operations Module
Contains file handling vulnerabilities for SCA testing
"""

import os
import shutil
import tarfile
import zipfile
from PIL import Image  # Pillow 6.2.0 - vulnerable version
import xml.etree.ElementTree as ET  # For XXE vulnerabilities
from lxml import etree  # lxml 4.2.0 - vulnerable version
from flask import jsonify, request
import subprocess

UPLOAD_FOLDER = '/tmp/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'xml'}

def process_upload(file):
    """
    REACHABLE: Vulnerable file upload processing
    This function is called from the main app
    """
    try:
        filename = file.filename
        
        # Vulnerability 1: No filename validation - path traversal possible
        filepath = os.path.join(UPLOAD_FOLDER, filename)  # Dangerous - no validation
        
        # Create upload directory if it doesn't exist
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        
        # Vulnerability 2: No file size limits
        file.save(filepath)  # Could lead to DoS through large files
        
        # Vulnerability 3: Process different file types unsafely
        file_ext = filename.split('.')[-1].lower() if '.' in filename else ''
        
        result = {
            "filename": filename,
            "filepath": filepath,  # Information disclosure
            "size": os.path.getsize(filepath),
            "extension": file_ext
        }
        
        # Process based on file type
        if file_ext in ['jpg', 'jpeg', 'png', 'gif']:
            result.update(process_image_unsafe(filepath))
        elif file_ext == 'xml':
            result.update(process_xml_unsafe(filepath))
        elif file_ext in ['zip', 'tar', 'gz']:
            result.update(process_archive_unsafe(filepath))
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            "error": "File processing failed",
            "details": str(e),
            "filepath": filepath if 'filepath' in locals() else None
        }), 500

def process_image_unsafe(filepath):
    """
    Unsafe image processing using vulnerable Pillow
    """
    try:
        # Vulnerability: Using vulnerable Pillow version
        with Image.open(filepath) as img:
            # No validation of image content
            info = {
                "image_format": img.format,
                "image_size": img.size,
                "image_mode": img.mode,
                "image_info": img.info  # Could contain sensitive metadata
            }
            
            # Vulnerability: Automatic processing without validation
            if img.size[0] > 1000 or img.size[1] > 1000:
                # Resize without proper validation
                img.thumbnail((800, 800))
                img.save(filepath.replace('.', '_resized.'))
            
            return info
    
    except Exception as e:
        return {"image_error": str(e)}

def process_xml_unsafe(filepath):
    """
    REACHABLE: Unsafe XML processing - XXE vulnerability
    """
    try:
        # Vulnerability 1: XXE with xml.etree.ElementTree
        tree = ET.parse(filepath)  # Vulnerable to XXE
        root = tree.getroot()
        
        # Vulnerability 2: XXE with lxml (more dangerous)
        parser = etree.XMLParser(resolve_entities=True)  # Dangerous!
        doc = etree.parse(filepath, parser)
        
        return {
            "xml_root": root.tag,
            "xml_children": len(root),
            "xml_content": etree.tostring(doc, encoding='unicode')[:500]  # Truncated
        }
    
    except Exception as e:
        return {"xml_error": str(e)}

def process_archive_unsafe(filepath):
    """
    Unsafe archive processing - Zip slip vulnerability
    """
    try:
        results = {"extracted_files": []}
        
        if filepath.endswith('.zip'):
            with zipfile.ZipFile(filepath, 'r') as zip_file:
                # Vulnerability: Zip slip attack - no path validation
                for member in zip_file.namelist():
                    # Dangerous extraction without validation
                    extract_path = os.path.join(UPLOAD_FOLDER, member)
                    zip_file.extract(member, UPLOAD_FOLDER)  # No path validation!
                    results["extracted_files"].append(extract_path)
        
        elif filepath.endswith(('.tar', '.tar.gz')):
            with tarfile.open(filepath, 'r') as tar_file:
                # Vulnerability: Tar slip attack
                for member in tar_file.getmembers():
                    tar_file.extract(member, UPLOAD_FOLDER)  # Dangerous!
                    results["extracted_files"].append(member.name)
        
        return results
    
    except Exception as e:
        return {"archive_error": str(e)}

def read_file_unsafe(filename):
    """
    Unsafe file reading - path traversal vulnerability
    """
    try:
        # Vulnerability: No path validation - allows directory traversal
        filepath = os.path.join(UPLOAD_FOLDER, filename)  # ../../../etc/passwd possible
        
        with open(filepath, 'r') as f:
            content = f.read()
        
        return {
            "filename": filename,
            "filepath": filepath,  # Information disclosure
            "content": content[:1000],  # Truncated content
            "size": len(content)
        }
    
    except Exception as e:
        return {"error": str(e), "attempted_path": filepath}

def delete_file_unsafe(filename):
    """
    Unsafe file deletion
    """
    try:
        # Vulnerability: No path validation
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        
        # Vulnerability: Using shell command instead of os.remove
        result = subprocess.run(f'rm -f "{filepath}"', shell=True, capture_output=True, text=True)
        
        return {
            "deleted": filename,
            "filepath": filepath,
            "command_output": result.stdout,
            "command_error": result.stderr
        }
    
    except Exception as e:
        return {"error": str(e)}

def get_file_info(filename):
    """
    Get file information - potential information disclosure
    """
    try:
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        stat = os.stat(filepath)
        
        return {
            "filename": filename,
            "full_path": os.path.abspath(filepath),  # Information disclosure
            "size": stat.st_size,
            "permissions": oct(stat.st_mode),
            "owner": stat.st_uid,
            "group": stat.st_gid,
            "modified": stat.st_mtime,
            "created": stat.st_ctime
        }
    
    except Exception as e:
        return {"error": str(e)}

def process_batch_files(file_list):
    """
    Process multiple files - amplifies vulnerabilities
    """
    results = []
    
    for filename in file_list:
        try:
            # Vulnerability: No rate limiting or validation
            result = read_file_unsafe(filename)
            results.append(result)
        except Exception as e:
            results.append({"filename": filename, "error": str(e)})
    
    return results

def backup_files():
    """
    Backup functionality with command injection risk
    """
    try:
        backup_name = f"backup_{os.getpid()}.tar.gz"
        
        # Vulnerability: Command injection possible if UPLOAD_FOLDER contains special chars
        command = f"tar -czf /tmp/{backup_name} {UPLOAD_FOLDER}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        return {
            "backup_created": backup_name,
            "command": command,  # Information disclosure
            "output": result.stdout,
            "errors": result.stderr
        }
    
    except Exception as e:
        return {"error": str(e)} 