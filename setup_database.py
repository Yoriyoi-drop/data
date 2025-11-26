"""
Database Setup Script for Infinite AI Security Platform

This script helps set up the PostgreSQL database for the application.
Run this after setting the correct PostgreSQL credentials in your .env file.
"""
import os
import pg8000
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def setup_database():
    """Set up the PostgreSQL database and apply schema"""
    
    # Get database connection parameters from environment
    db_host = os.getenv("PG_HOST", "127.0.0.1")
    db_port = int(os.getenv("PG_PORT", 5432))
    db_user = os.getenv("PG_USER", "postgres")
    db_password = os.getenv("PG_PASSWORD", "postgres")
    db_name = os.getenv("PG_DATABASE", "infinite_ai")
    
    print(f"Attempting to connect to PostgreSQL at {db_host}:{db_port}")
    print(f"Using user: {db_user}, database: postgres (to create {db_name})")
    
    try:
        # Connect to PostgreSQL server (using 'postgres' database to create new database)
        conn = pg8000.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            database='postgres'  # Connect to default postgres database first
        )
        
        print("Successfully connected to PostgreSQL server")
        
        # Create cursor
        cur = conn.cursor()
        
        # Check if database already exists
        cur.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (db_name,))
        exists = cur.fetchone()
        
        if not exists:
            # Create the database
            # Note: Can't use parameters for database names, so we'll format the string
            # In production, ensure db_name is properly validated to prevent injection
            cur.execute(f"CREATE DATABASE {db_name}")
            print(f"Database '{db_name}' created successfully")
        else:
            print(f"Info: Database '{db_name}' already exists")
        
        # Close the connection
        cur.close()
        conn.close()
        
        print(f"Database '{db_name}' is ready for use")
        
        # Now apply the schema to the created database
        apply_schema(db_host, db_port, db_user, db_password, db_name)
        
    except Exception as e:
        print(f"Error connecting to PostgreSQL: {str(e)}")
        print("\nTroubleshooting tips:")
        print("  - Make sure PostgreSQL is running")
        print("  - Verify your PG_USER and PG_PASSWORD in the .env file")
        print("  - Ensure the PostgreSQL service is accessible on the configured host/port")
        return False
    
    return True

def apply_schema(db_host, db_port, db_user, db_password, db_name):
    """Apply the database schema to the specified database"""
    
    try:
        # Connect to the target database
        conn = pg8000.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            database=db_name
        )
        
        print(f"Connected to database '{db_name}'")
        
        # Read the schema file
        schema_file = os.path.join(os.path.dirname(__file__), 'sql', '00_schema_setup.sql')
        if not os.path.exists(schema_file):
            print(f"✗ Schema file not found: {schema_file}")
            return False
        
        with open(schema_file, 'r', encoding='utf-8') as f:
            schema_sql = f.read()
        
        # Execute the schema
        cur = conn.cursor()
        cur.execute(schema_sql)
        conn.commit()
        
        print("Schema applied successfully")
        
        # Close the connection
        cur.close()
        conn.close()
        
    except Exception as e:
        print(f"Error applying schema: {str(e)}")
        return False
    
    return True

if __name__ == "__main__":
    print("Setting up PostgreSQL database for Infinite AI Security Platform")
    print("="*60)
    
    success = setup_database()
    
    if success:
        print("\nDatabase setup completed successfully!")
        print("\nNext steps:")
        print("  1. Verify your .env file has the correct PostgreSQL credentials")
        print("  2. Run the main application: python main_v2.py")
    else:
        print("\nDatabase setup failed. Please check the error messages above.")
        print("\nMake sure to:")
        print("  - Check PostgreSQL is running")
        print("  - Verify your credentials in the .env file")
        print("  - Ensure the user has necessary permissions")