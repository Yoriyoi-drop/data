#!/usr/bin/env python3
"""
Project cleanup script - Remove empty folders and redundant files
"""
import os
import shutil
from pathlib import Path

def remove_empty_dirs(path):
    """Remove empty directories recursively"""
    removed = []
    for root, dirs, files in os.walk(path, topdown=False):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            try:
                if not os.listdir(dir_path):  # Empty directory
                    os.rmdir(dir_path)
                    removed.append(dir_path)
                    print(f"Removed empty: {dir_path}")
            except OSError:
                pass
    return removed

def remove_redundant_folders():
    """Remove redundant and duplicate folders"""
    redundant_folders = [
        "ai-python",
        "phase2", 
        "telemetry",
        "web3/rust_solana/src",
        "web3/solidity",
        "ai_hub/config",
        "api/models",
        "api/routes", 
        "dashboard/src/api",
        "dashboard/src/utils",
        "dashboard/src/views",
        "data/decoy",
        "data/samples", 
        "data/traps",
        "deployment/k8s",
        "src/engines/cpp_detector",
        "src/engines/go_scanner",
        "src/engines/rust_labyrinth",
        "src/tests",
        "-p"
    ]
    
    removed = []
    for folder in redundant_folders:
        folder_path = Path(folder)
        if folder_path.exists():
            try:
                if folder_path.is_dir():
                    shutil.rmtree(folder_path)
                    removed.append(str(folder_path))
                    print(f"Removed redundant: {folder}")
            except Exception as e:
                print(f"Failed to remove {folder}: {e}")
    
    return removed

def consolidate_duplicate_files():
    """Remove duplicate files and keep only the best version"""
    duplicates = [
        # Keep main_v2.py, remove main.py
        ("main.py", "main_v2.py"),
        # Keep agents/ folder, remove duplicate in ai_agents/
        ("ai_agents/base_agent.py", "agents/base_agent.py"),
        ("ai_agents/gpt5_agent.py", "agents/gpt5_agent.py"),
        # Keep requirements_fixed.txt, remove old requirements.txt
        ("requirements.txt", "requirements_fixed.txt"),
        # Remove duplicate environment files
        (".env.sample", ".env.example"),
        (".env.secure", ".env.example"),
        # Remove duplicate pyproject files
        ("pyproject.toml", "pyproject_v2.toml"),
    ]
    
    removed = []
    for old_file, keep_file in duplicates:
        old_path = Path(old_file)
        keep_path = Path(keep_file)
        
        if old_path.exists() and keep_path.exists():
            try:
                old_path.unlink()
                removed.append(str(old_path))
                print(f"Removed duplicate: {old_file} (keeping {keep_file})")
            except Exception as e:
                print(f"Failed to remove {old_file}: {e}")
    
    return removed

def main():
    print("\n" + "="*60)
    print("PROJECT CLEANUP - REMOVING REDUNDANT STRUCTURE")
    print("="*60)
    
    # Change to project directory
    os.chdir(Path(__file__).parent)
    print(f"Working in: {os.getcwd()}")
    
    # Remove redundant folders
    print("\nRemoving redundant folders...")
    redundant_removed = remove_redundant_folders()
    
    # Remove duplicate files
    print("\nRemoving duplicate files...")
    duplicate_removed = consolidate_duplicate_files()
    
    # Remove empty directories
    print("\nRemoving empty directories...")
    empty_removed = remove_empty_dirs(".")
    
    # Summary
    print("\n" + "="*60)
    print("CLEANUP COMPLETE")
    print("="*60)
    print(f"Redundant folders removed: {len(redundant_removed)}")
    print(f"Duplicate files removed: {len(duplicate_removed)}")
    print(f"Empty directories removed: {len(empty_removed)}")
    
    total_removed = len(redundant_removed) + len(duplicate_removed) + len(empty_removed)
    print(f"Total items cleaned: {total_removed}")
    
    if total_removed > 0:
        print("\nProject structure is now cleaner and more efficient!")
    else:
        print("\nProject structure was already clean!")
    
    print("="*60 + "\n")

if __name__ == "__main__":
    main()