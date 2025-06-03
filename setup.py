#!/usr/bin/env python3
"""
Setup script for SCA Evaluation Application
"""

import os
import sys
import subprocess
import venv
from pathlib import Path

def create_virtual_environment():
    """Create a virtual environment for the project"""
    venv_path = Path("venv")
    
    if venv_path.exists():
        print("✅ Virtual environment already exists")
        return True
    
    try:
        print("📦 Creating virtual environment...")
        venv.create(venv_path, with_pip=True)
        print("✅ Virtual environment created successfully")
        return True
    except Exception as e:
        print(f"❌ Failed to create virtual environment: {e}")
        return False

def install_dependencies():
    """Install dependencies in the virtual environment"""
    try:
        # Determine the correct pip path based on OS
        if os.name == 'nt':  # Windows
            pip_path = Path("venv/Scripts/pip")
        else:  # Unix/Linux/MacOS
            pip_path = Path("venv/bin/pip")
        
        print("📦 Installing dependencies...")
        result = subprocess.run([
            str(pip_path), "install", "-r", "requirements.txt"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Dependencies installed successfully")
            return True
        else:
            print(f"❌ Failed to install dependencies: {result.stderr}")
            return False
    
    except Exception as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def run_application():
    """Run the Flask application"""
    try:
        # Determine the correct python path based on OS
        if os.name == 'nt':  # Windows
            python_path = Path("venv/Scripts/python")
        else:  # Unix/Linux/MacOS
            python_path = Path("venv/bin/python")
        
        print("🚀 Starting Flask application...")
        print("Application will be available at http://localhost:5000")
        print("Press Ctrl+C to stop the application")
        
        subprocess.run([str(python_path), "app.py"])
    
    except KeyboardInterrupt:
        print("\n🛑 Application stopped")
    except Exception as e:
        print(f"❌ Error running application: {e}")

def run_tests():
    """Run the SCA evaluation tests"""
    try:
        # Determine the correct python path based on OS
        if os.name == 'nt':  # Windows
            python_path = Path("venv/Scripts/python")
        else:  # Unix/Linux/MacOS
            python_path = Path("venv/bin/python")
        
        print("🧪 Running SCA evaluation tests...")
        subprocess.run([str(python_path), "test_sca_evaluation.py"])
    
    except Exception as e:
        print(f"❌ Error running tests: {e}")

def run_semgrep_scan():
    """Run Semgrep scan if available"""
    try:
        print("🔍 Running Semgrep scan...")
        result = subprocess.run([
            "semgrep", "--config=auto", "--json", "--output=semgrep_results.json", "."
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Semgrep scan completed - results saved to semgrep_results.json")
        else:
            print("ℹ️ Semgrep not available or scan failed")
            print("Install Semgrep: pip install semgrep")
    
    except FileNotFoundError:
        print("ℹ️ Semgrep not found. Install with: pip install semgrep")
    except Exception as e:
        print(f"❌ Error running Semgrep: {e}")

def main():
    """Main setup function"""
    print("🔧 SCA Evaluation Application Setup")
    print("=" * 50)
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "install":
            print("📦 Setting up environment and installing dependencies...")
            if create_virtual_environment() and install_dependencies():
                print("\n✅ Setup complete!")
                print("Next steps:")
                print("  python setup.py run    - Start the application")
                print("  python setup.py test   - Run evaluation tests")
                print("  python setup.py scan   - Run Semgrep scan")
        
        elif command == "run":
            run_application()
        
        elif command == "test":
            run_tests()
        
        elif command == "scan":
            run_semgrep_scan()
        
        elif command == "all":
            print("🚀 Running complete SCA evaluation...")
            run_application()  # This will block, so we'll need to run separately
        
        else:
            print("❌ Unknown command. Available commands:")
            print("  install - Set up environment and install dependencies")
            print("  run     - Start the Flask application")
            print("  test    - Run SCA evaluation tests") 
            print("  scan    - Run Semgrep security scan")
    
    else:
        print("Available commands:")
        print("  python setup.py install - Set up environment and install dependencies")
        print("  python setup.py run     - Start the Flask application")
        print("  python setup.py test    - Run SCA evaluation tests")
        print("  python setup.py scan    - Run Semgrep security scan")
        print("\nFor first time setup, run: python setup.py install")

if __name__ == "__main__":
    main() 