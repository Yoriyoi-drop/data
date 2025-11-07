#!/usr/bin/env python3
"""
Quality Check Script - Run all quality checks
"""
import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, description):
    """Run command dan report hasil"""
    print(f"\n[CHECK] {description}...")
    print(f"Command: {cmd}")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[PASS] {description} passed")
            if result.stdout.strip():
                print(f"Output: {result.stdout.strip()}")
        else:
            print(f"[FAIL] {description} failed")
            if result.stderr.strip():
                print(f"Error: {result.stderr.strip()}")
            if result.stdout.strip():
                print(f"Output: {result.stdout.strip()}")
                
        return result.returncode == 0
        
    except Exception as e:
        print(f"[ERROR] {description} error: {e}")
        return False

def main():
    """Run all quality checks"""
    root_dir = Path(__file__).parent.parent
    os.chdir(root_dir)
    
    print("Running Quality Checks for Infinite AI Security")
    print("=" * 60)
    
    checks = [
        # Install dev dependencies
        ("pip install -e .[dev]", "Installing dev dependencies"),
        
        # Code formatting
        ("black --check .", "Code formatting check (Black)"),
        
        # Linting
        ("flake8 .", "Code linting (Flake8)"),
        
        # Security scan
        ("bandit -r . -f json -o bandit_report.json", "Security scan (Bandit)"),
        
        # Dependency vulnerabilities
        ("pip-audit --format=json --output=pip_audit_report.json", "Dependency vulnerability scan"),
        
        # Unit tests
        ("pytest tests/ -v --tb=short", "Unit tests (Pytest)"),
        
        # Type checking (if mypy installed)
        ("python -c \"import mypy; print('MyPy available')\"", "MyPy availability check"),
    ]
    
    results = []
    
    for cmd, desc in checks:
        success = run_command(cmd, desc)
        results.append((desc, success))
    
    # Summary
    print("\n" + "=" * 60)
    print("Quality Check Summary:")
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for desc, success in results:
        status = "[PASS]" if success else "[FAIL]"
        print(f"  {status} {desc}")
    
    print(f"\nOverall: {passed}/{total} checks passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("All quality checks passed! Ready for production.")
        return 0
    else:
        print("Some checks failed. Please review and fix issues.")
        return 1

if __name__ == "__main__":
    sys.exit(main())