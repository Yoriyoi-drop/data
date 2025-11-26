# PostgreSQL Setup Guide for Infinite AI Security Platform

## Issue: "password authentication failed for user 'postgres'"

This error occurs when the PostgreSQL password in your `.env` file doesn't match the password configured in your PostgreSQL installation.

## Finding Your PostgreSQL Password

### Option 1: Check Your PostgreSQL Installation Records
- If you installed PostgreSQL yourself, recall the password you set during installation
- Check any installation documentation or notes you may have created

### Option 2: Check PostgreSQL Configuration Files
1. Look for `pg_hba.conf` file in your PostgreSQL installation directory (typically in `C:\Program Files\PostgreSQL\[VERSION]\data\`)
2. Look for authentication settings in this file
3. Check for any stored passwords in `pgpass.conf` if it exists

### Option 3: Use pgAdmin (if installed)
1. Open pgAdmin
2. Connect to your PostgreSQL server
3. Look at user accounts and their passwords if configured

## Resetting Your PostgreSQL Password

### Method 1: Using psql Command Line (Recommended)
1. Open Command Prompt as Administrator
2. Navigate to your PostgreSQL bin directory:
   ```cmd
   cd "C:\Program Files\PostgreSQL\[VERSION]\bin"
   ```
   (Replace [VERSION] with your PostgreSQL version number)

3. Connect to PostgreSQL as superuser:
   ```cmd
   psql -U postgres -d postgres
   ```
   When prompted for password, if you don't know it, try leaving it blank or try common defaults like 'postgres'

4. If connected successfully, run:
   ```sql
   ALTER USER postgres PASSWORD 'newpassword';
   ```
   Replace 'newpassword' with your desired password.

5. Exit psql:
   ```sql
   \q
   ```

### Method 2: Using pgAdmin
1. Open pgAdmin
2. Navigate to your server and expand "Login/Group Roles"
3. Right-click on "postgres" user → Properties
4. Go to "Definition" tab
5. Enter a new password in the "Password" field
6. Click "Save"

### Method 3: Reset via Configuration (if authentication is set to 'trust')
1. Open `pg_hba.conf` file in your PostgreSQL data directory
2. Look for lines with 'peer', 'trust' or 'local' authentication for the local connection
3. If available, temporarily change the authentication method to 'trust' for localhost connections
4. Restart PostgreSQL service
5. Connect without password and reset the password as shown in Method 1
6. Restore the original authentication method and restart PostgreSQL service again

## Updating Your .env File

Once you know the correct password:

1. Open the `.env` file in your `infinite_ai_security` directory
2. Update the `PG_PASSWORD` line:
   ```
   PG_PASSWORD=your_actual_password_here
   ```
3. Save the file

## Testing the Connection

After updating your password:

1. Test with the setup script:
   ```cmd
   cd C:\ai-p\infinite_ai_security
   python setup_database.py
   ```

2. If successful, run the main application:
   ```cmd
   python main_v2.py
   ```

## Common Default Passwords for Windows PostgreSQL Installations
- Empty (just press Enter when prompted)
- `postgres`
- `root`
- `admin`
- The same as your Windows username

## Troubleshooting Tips

- Ensure PostgreSQL service is running (check Windows Services)
- Make sure your firewall is not blocking port 5432
- Verify PostgreSQL is properly installed and in your system PATH
- If using a non-standard port, update `PG_PORT` in your `.env` file

## Security Best Practices
- Use a strong, unique password for your PostgreSQL user
- Do not commit your `.env` file to version control
- Change default passwords in production environments
- Regularly update and rotate database passwords