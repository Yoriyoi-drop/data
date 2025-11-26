#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cleanup Duplicate Files and Empty Folders
Infinite AI Security Platform
"""
import os
import hashlib
import shutil
from pathlib import Path
from collections import defaultdict

def get_file_hash(file_path):
    """Calculate MD5 hash of file content"""
    try:
        with open(file_path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except:
        return None

def find_duplicates(root_dir):
    """Find duplicate files by content hash"""
    file_hashes = defaultdict(list)
    
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = get_file_hash(file_path)
            if file_hash:
                file_hashes[file_hash].append(file_path)
    
    # Return only duplicates (hash with multiple files)
    return {h: paths for h, paths in file_hashes.items() if len(paths) > 1}

def find_empty_folders(root_dir):
    """Find empty folders"""
    empty_folders = []
    
    for root, dirs, files in os.walk(root_dir, topdown=False):
        if not dirs and not files:
            empty_folders.append(root)
        elif not files and all(os.path.join(root, d) in empty_folders for d in dirs):
            empty_folders.append(root)
    
    return empty_folders

def cleanup_project():
    """Main cleanup function"""
    project_root = Path(__file__).parent
    print(f"Cleaning up project: {project_root}")
    
    # Skip these directories
    skip_dirs = {'.git', '__pycache__', '.pytest_cache', 'node_modules', '.venv', 'venv'}
    
    # Find duplicates
    print("\nFinding duplicate files...")
    duplicates = find_duplicates(project_root)
    
    removed_count = 0
    for file_hash, file_paths in duplicates.items():
        if len(file_paths) > 1:
            # Keep the first file, remove others
            keep_file = file_paths[0]
            for duplicate_file in file_paths[1:]:
                # Skip if in protected directories
                if any(skip_dir in duplicate_file for skip_dir in skip_dirs):
                    continue
                
                try:
                    os.remove(duplicate_file)
                    print(f"Removed duplicate: {duplicate_file}")
                    removed_count += 1
                except Exception as e:
                    print(f"Could not remove {duplicate_file}: {e}")
    
    # Find and remove empty folders
    print("\nFinding empty folders...")
    empty_folders = find_empty_folders(project_root)
    
    removed_folders = 0
    for folder in empty_folders:
        # Skip protected directories
        if any(skip_dir in folder for skip_dir in skip_dirs):
            continue
        
        try:
            os.rmdir(folder)
            print(f"Removed empty folder: {folder}")
            removed_folders += 1
        except Exception as e:
            print(f"Could not remove {folder}: {e}")
    
    # Create essential empty folders if needed
    essential_folders = [
        'logs',
        'temp',
        'uploads',
        'app/services',
        'app/utils'
    ]
    
    created_folders = 0
    for folder in essential_folders:
        folder_path = project_root / folder
        if not folder_path.exists():
            folder_path.mkdir(parents=True, exist_ok=True)
            # Create __init__.py for Python packages
            if folder.startswith('app/'):
                (folder_path / '__init__.py').touch()
            print(f"Created essential folder: {folder}")
            created_folders += 1
    
    print(f"\nCleanup Summary:")
    print(f"   Duplicate files removed: {removed_count}")
    print(f"   Empty folders removed: {removed_folders}")
    print(f"   Essential folders created: {created_folders}")
    print(f"   Project cleaned successfully!")

if __name__ == "__main__":
    cleanup_project()