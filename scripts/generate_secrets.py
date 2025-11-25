#!/usr/bin/env python3
"""
Generate Secure Secrets for Infinite AI Security Platform
This script generates cryptographically secure random secrets for production use.
"""
import secrets
import string
import sys
from pathlib import Path

def generate_secret(length=64):
    """Generate URL-safe secret token"""
    return secrets.token_urlsafe(length)

def generate_password(length=32):
    """Generate strong password with mixed characters"""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    
    # Ensure password meets complexity requirements
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    if not (has_upper and has_lower and has_digit and has_special):
        # Regenerate if doesn't meet requirements
        return generate_password(length)
    
    return password

def generate_env_file():
    """Generate .env file with secure secrets"""
    
    print("=" * 70)
    print("🔐 GENERATING SECURE SECRETS FOR INFINITE AI SECURITY PLATFORM")
    print("=" * 70)
    print()
    
    secrets_config = {
        "JWT_SECRET_KEY": generate_secret(64),
        "JWT_REFRESH_SECRET": generate_secret(64),
        "API_SECRET_KEY": generate_secret(64),
        "SESSION_SECRET": generate_secret(64),
        "PG_PASSWORD": generate_password(32),
        "BACKUP_ENCRYPTION_KEY": generate_secret(64),
    }
    
    # Display generated secrets
    print("✅ Generated Secrets:")
    print("-" * 70)
    for key, value in secrets_config.items():
        # Show first and last 8 characters only for security
        masked_value = f"{value[:8]}...{value[-8:]}"
        print(f"{key:30} = {masked_value}")
    print()
    
    # Ask if user wants to save to .env file
    print("⚠️  SECURITY WARNINGS:")
    print("   1. These secrets are shown ONCE. Save them securely!")
    print("   2. NEVER commit .env file to version control")
    print("   3. Use a password manager or secret management service")
    print("   4. Rotate secrets every 90 days minimum")
    print()
    
    response = input("Do you want to create .env file with these secrets? (yes/no): ")
    
    if response.lower() in ['yes', 'y']:
        env_path = Path(__file__).parent.parent / '.env'
        
        if env_path.exists():
            backup_response = input(f".env file already exists. Create backup? (yes/no): ")
            if backup_response.lower() in ['yes', 'y']:
                backup_path = env_path.with_suffix('.env.backup')
                env_path.rename(backup_path)
                print(f"✅ Backed up existing .env to {backup_path}")
        
        # Read template
        template_path = Path(__file__).parent.parent / '.env.example'
        if not template_path.exists():
            print("❌ .env.example template not found!")
            return
        
        with open(template_path, 'r') as f:
            template_content = f.read()
        
        # Replace placeholders
        env_content = template_content
        for key, value in secrets_config.items():
            env_content = env_content.replace(f"{key}=CHANGE_ME_GENERATE_RANDOM_SECRET_64_BYTES", f"{key}={value}")
            env_content = env_content.replace(f"{key}=CHANGE_ME_GENERATE_DIFFERENT_RANDOM_SECRET_64_BYTES", f"{key}={value}")
            env_content = env_content.replace(f"{key}=CHANGE_ME_USE_STRONG_PASSWORD", f"{key}={value}")
        
        # Write to .env
        with open(env_path, 'w') as f:
            f.write(env_content)
        
        print(f"✅ Created .env file at {env_path}")
        print()
        print("🔒 NEXT STEPS:")
        print("   1. Review and customize other settings in .env")
        print("   2. Add .env to .gitignore (if not already)")
        print("   3. Set appropriate file permissions: chmod 600 .env")
        print("   4. Store secrets in password manager")
        print("   5. Setup secret rotation schedule")
        print()
        
        # Set file permissions (Unix-like systems only)
        try:
            import os
            os.chmod(env_path, 0o600)
            print("✅ Set .env file permissions to 600 (owner read/write only)")
        except:
            print("⚠️  Could not set file permissions. Please run: chmod 600 .env")
    else:
        print()
        print("📋 COPY THESE SECRETS TO YOUR .ENV FILE:")
        print("=" * 70)
        for key, value in secrets_config.items():
            print(f"{key}={value}")
        print("=" * 70)
        print()
        print("⚠️  These secrets will not be shown again!")

def main():
    """Main function"""
    if len(sys.argv) > 1:
        if sys.argv[1] == '--secret':
            # Generate single secret
            print(generate_secret(64))
        elif sys.argv[1] == '--password':
            # Generate single password
            print(generate_password(32))
        elif sys.argv[1] == '--help':
            print("Usage:")
            print("  python generate_secrets.py           # Interactive mode")
            print("  python generate_secrets.py --secret  # Generate single secret")
            print("  python generate_secrets.py --password # Generate single password")
        else:
            print("Unknown option. Use --help for usage information.")
    else:
        # Interactive mode
        generate_env_file()

if __name__ == "__main__":
    main()
