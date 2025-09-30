# Indy Nexus Authentication System Documentation

## Overview

The Indy Nexus authentication system provides secure user registration and login functionality with industry-standard security practices.

## Security Features

### Password Requirements
- **Minimum Length**: 20 characters
- **Maximum Length**: 84 characters
- **Required Elements**:
  - At least one uppercase letter (A-Z)
  - At least one lowercase letter (a-z)
  - At least one number (0-9)
  - At least one special character (!@#$%^&*()_+-=[]{}|;':",./<>?)

### Password Hashing
- **Algorithm**: bcrypt
- **Salt Rounds**: 12 (industry standard)
- **Why bcrypt?**:
  - Resistant to brute-force attacks
  - Automatically handles salt generation
  - Configurable work factor (salt rounds)
  - Time-tested and widely adopted

### Database Storage
- **Database**: SQLite3
- **Location**: `/opt/indy-nexus/users.db` (on Debian container)
- **Tables**:
  - `users`: Stores user accounts
  - `sessions`: Tracks active login sessions

### Security Measures
1. **Rate Limiting**: Maximum 5 authentication attempts per 15 minutes per IP
2. **Account Lockout**: After 5 failed attempts, account locked for 30 minutes
3. **JWT Tokens**: 24-hour expiry for session management
4. **HTTPS Headers**: Security headers (X-Frame-Options, X-Content-Type-Options, etc.)
5. **Input Validation**: Server-side validation for all inputs
6. **SQL Injection Protection**: Parameterized queries

## Architecture

```
┌─────────────────┐
│   Web Browser   │
│  (Client-side)  │
└────────┬────────┘
         │
    HTTP/HTTPS
         │
┌────────▼────────┐
│     Nginx       │ Port 46228
│ (Reverse Proxy) │
└────────┬────────┘
         │
    localhost:3000
         │
┌────────▼────────┐
│   Node.js/Express│
│   Backend API    │
└────────┬────────┘
         │
┌────────▼────────┐
│   SQLite DB     │
│   users.db      │
└─────────────────┘
```

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    failed_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    is_active BOOLEAN DEFAULT 1
);
```

### Sessions Table
```sql
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## API Endpoints

### POST /api/register
Register a new user account
```json
Request:
{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "MySecurePassword123!@#WithMinimum20Chars"
}

Response (Success):
{
    "message": "Registration successful",
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "userId": 1,
    "username": "john_doe"
}
```

### POST /api/login
Login with existing account
```json
Request:
{
    "username": "john_doe",
    "password": "MySecurePassword123!@#WithMinimum20Chars"
}

Response (Success):
{
    "message": "Login successful",
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "userId": 1,
    "username": "john_doe"
}
```

### GET /api/profile
Get user profile (requires authentication)
```json
Headers:
{
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIs..."
}

Response:
{
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "created_at": "2024-01-01T00:00:00.000Z",
    "last_login": "2024-01-02T00:00:00.000Z"
}
```

### POST /api/logout
Logout current session
```json
Headers:
{
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIs..."
}

Response:
{
    "message": "Logout successful"
}
```

## Deployment Instructions

### On Windows (Development)

1. **Install Node.js** (if not already installed)
   ```powershell
   # Download from https://nodejs.org/
   ```

2. **Install Dependencies**
   ```powershell
   cd C:\1A\warp\indy.nexus
   npm install
   ```

3. **Start the Backend Server**
   ```powershell
   npm start
   ```

4. **Access the Site**
   - Open browser to: http://127.0.0.1:3000

### On Debian Container (Production)

1. **Transfer Files**
   ```bash
   # From Windows (PowerShell)
   scp -r C:\1A\warp\indy.nexus\* root@<CONTAINER_IP>:/root/indy-nexus/
   ```

2. **SSH into Container**
   ```bash
   ssh root@<CONTAINER_IP>
   ```

3. **Run Deployment Script**
   ```bash
   cd /root/indy-nexus
   chmod +x deploy-with-auth.sh
   ./deploy-with-auth.sh
   ```

4. **Configure JWT Secret**
   ```bash
   # Generate a secure secret
   openssl rand -hex 32
   
   # Edit the service file
   nano /etc/systemd/system/indy-nexus-backend.service
   # Replace JWT_SECRET value with generated secret
   
   # Restart service
   systemctl daemon-reload
   systemctl restart indy-nexus-backend
   ```

## Security Best Practices

### 1. Environment Variables
Always use environment variables for sensitive data:
```bash
JWT_SECRET=your-secret-key-here
NODE_ENV=production
```

### 2. Database Backup
Regular backups of the SQLite database:
```bash
# Backup
sqlite3 /opt/indy-nexus/users.db ".backup /backup/users_backup.db"

# Restore
cp /backup/users_backup.db /opt/indy-nexus/users.db
chown www-data:www-data /opt/indy-nexus/users.db
```

### 3. Monitor Failed Login Attempts
```sql
-- Check failed login attempts
SELECT username, failed_attempts, locked_until 
FROM users 
WHERE failed_attempts > 0;
```

### 4. Regular Security Updates
```bash
# Update Node.js packages
cd /opt/indy-nexus
npm audit
npm audit fix

# Update system packages
apt-get update
apt-get upgrade
```

## Troubleshooting

### Common Issues

1. **Backend not starting**
   ```bash
   # Check logs
   journalctl -u indy-nexus-backend -n 50
   
   # Check if port is in use
   netstat -tlnp | grep 3000
   ```

2. **Database locked**
   ```bash
   # Check permissions
   ls -la /opt/indy-nexus/users.db
   
   # Fix permissions
   chown www-data:www-data /opt/indy-nexus/users.db
   ```

3. **Authentication failing**
   ```bash
   # Check JWT secret is set
   systemctl show indy-nexus-backend | grep Environment
   
   # Test API directly
   curl -X GET http://127.0.0.1:3000/api/health
   ```

## Testing

### Manual Testing

1. **Test Registration**
   ```bash
   curl -X POST http://127.0.0.1:3000/api/register \
     -H "Content-Type: application/json" \
     -d '{
       "username": "testuser",
       "email": "test@example.com",
       "password": "TestPassword123!@#$%WithMin20Chars"
     }'
   ```

2. **Test Login**
   ```bash
   curl -X POST http://127.0.0.1:3000/api/login \
     -H "Content-Type: application/json" \
     -d '{
       "username": "testuser",
       "password": "TestPassword123!@#$%WithMin20Chars"
     }'
   ```

3. **Test Protected Route**
   ```bash
   # Use token from login response
   curl -X GET http://127.0.0.1:3000/api/profile \
     -H "Authorization: Bearer YOUR_TOKEN_HERE"
   ```

## Maintenance

### Daily Tasks
- Monitor error logs: `journalctl -u indy-nexus-backend -p err`
- Check disk space for database: `df -h /opt/indy-nexus`

### Weekly Tasks
- Backup database
- Review failed login attempts
- Check for security updates

### Monthly Tasks
- Rotate logs
- Review and update JWT secret
- Performance monitoring

## File Structure

```
/opt/indy-nexus/
├── index.html          # Main landing page
├── login.html          # Login page
├── register.html       # Registration page
├── dashboard.html      # Protected dashboard (create as needed)
├── styles.css          # Main styles
├── auth-styles.css     # Authentication styles
├── auth.js             # Client-side authentication logic
├── server.js           # Node.js backend server
├── package.json        # Node.js dependencies
├── package-lock.json   # Dependency lock file
└── users.db           # SQLite database (created on first run)
```

## Support and Maintenance Commands

```bash
# Service Management
systemctl start indy-nexus-backend
systemctl stop indy-nexus-backend
systemctl restart indy-nexus-backend
systemctl status indy-nexus-backend

# View Logs
journalctl -u indy-nexus-backend -f          # Follow logs
journalctl -u indy-nexus-backend --since today # Today's logs
journalctl -u indy-nexus-backend -p err      # Error logs only

# Database Management
sqlite3 /opt/indy-nexus/users.db             # Open database console
sqlite3 /opt/indy-nexus/users.db ".tables"   # List tables
sqlite3 /opt/indy-nexus/users.db ".schema"   # Show schema

# Check Running Processes
ps aux | grep node
netstat -tlnp | grep -E "3000|46228"
```

## Security Considerations

⚠️ **Important Security Notes:**

1. **Change Default JWT Secret**: The default secret in the code MUST be changed in production
2. **Use HTTPS in Production**: Consider setting up SSL/TLS certificates
3. **Regular Updates**: Keep Node.js, npm packages, and system packages updated
4. **Firewall Rules**: Ensure only localhost can access port 3000
5. **Database Encryption**: Consider encrypting the SQLite database file at rest
6. **Audit Logging**: Implement comprehensive audit logging for security events

## License

This authentication system is provided as-is for the Indy Nexus project.