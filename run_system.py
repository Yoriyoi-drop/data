"""
Auto Port Finder & System Runner
Otomatis cari port kosong dan jalankan sistem
"""
import socket
import subprocess
import sys
import time

def find_free_port(start_port=8000, max_port=9999):
    """Cari port yang kosong"""
    for port in range(start_port, max_port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    return None

def update_port_in_file(filename, old_port_pattern, new_port):
    """Update port di file"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Replace various port patterns
        patterns = [
            f'port={old_port_pattern}',
            f'port={old_port_pattern}',
            f':{old_port_pattern}/',
            f':{old_port_pattern}"',
            f':{old_port_pattern}\'',
            f'localhost:{old_port_pattern}',
            f'127.0.0.1:{old_port_pattern}'
        ]
        
        for pattern in patterns:
            if old_port_pattern in pattern:
                new_pattern = pattern.replace(str(old_port_pattern), str(new_port))
                content = content.replace(pattern, new_pattern)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return True
    except Exception as e:
        print(f"Error updating {filename}: {e}")
        return False

def main():
    print("[AUTO] Finding free port...")
    
    # Find free port
    free_port = find_free_port(8000, 9999)
    if not free_port:
        print("[ERROR] No free ports available!")
        return
    
    print(f"[OK] Found free port: {free_port}")
    
    # Update main.py
    print("[UPDATE] Updating main.py...")
    with open('main.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace all port references
    content = content.replace('port=9001', f'port={free_port}')
    content = content.replace('port=9000', f'port={free_port}')
    content = content.replace('port=8008', f'port={free_port}')
    content = content.replace('localhost:9001', f'localhost:{free_port}')
    content = content.replace('localhost:9000', f'localhost:{free_port}')
    content = content.replace('localhost:8008', f'localhost:{free_port}')
    content = content.replace('127.0.0.1:9001', f'127.0.0.1:{free_port}')
    content = content.replace('127.0.0.1:9000', f'127.0.0.1:{free_port}')
    content = content.replace('127.0.0.1:8008', f'127.0.0.1:{free_port}')
    
    with open('main.py', 'w', encoding='utf-8') as f:
        f.write(content)
    
    # Update attack test
    print("[UPDATE] Updating attack test...")
    try:
        with open('simple_attack_test.py', 'r', encoding='utf-8') as f:
            attack_content = f.read()
        
        attack_content = attack_content.replace('127.0.0.1:9001', f'127.0.0.1:{free_port}')
        attack_content = attack_content.replace('127.0.0.1:9000', f'127.0.0.1:{free_port}')
        attack_content = attack_content.replace('127.0.0.1:8008', f'127.0.0.1:{free_port}')
        
        with open('simple_attack_test.py', 'w', encoding='utf-8') as f:
            f.write(attack_content)
    except:
        pass
    
    print(f"[READY] System configured for port {free_port}")
    print(f"[URL] http://127.0.0.1:{free_port}")
    print("[START] Starting system...")
    
    # Start system
    try:
        subprocess.run([sys.executable, 'main.py'], check=True)
    except KeyboardInterrupt:
        print("\n[STOP] System stopped by user")
    except Exception as e:
        print(f"[ERROR] System error: {e}")

if __name__ == "__main__":
    main()