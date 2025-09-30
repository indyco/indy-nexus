# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Quick Reference

### Essential Commands

```bash
# Development
npm install                    # Install dependencies
npm run dev                    # Start with nodemon (auto-restart)
npm start                      # Production start

# Admin Operations  
node admin.js                  # Interactive admin console
node admin.js approve <id>     # Quick approve user
node admin.js list-pending     # Show users awaiting approval

# Database Operations
sqlite3 users.db ".backup backup.db"     # Backup database
sqlite3 users.db < schema.sql            # Reset database
sqlite3 users.db "SELECT * FROM users;"  # Query users

# Testing & Security
npm audit                      # Check for vulnerabilities
npm audit fix                  # Auto-fix vulnerabilities
curl http://localhost:3000/api/health    # Health check

# Deployment
docker build -t indy-nexus .              # Build Docker image
docker run -p 3000:3000 --env-file .env indy-nexus  # Run container
systemctl status indy-nexus               # Check systemd service
```

### Environment Setup

```bash
# Create .env from template
cp .env.example .env

# Generate secure JWT_SECRET (required)
openssl rand -hex 64  # Linux/Mac
[System.Convert]::ToHexString((1..64 | ForEach {Get-Random -Maximum 256}))  # Windows PowerShell
```

## Architecture Overview

### System Components

The Indy Nexus authentication system is built with a layered security architecture:

1. **Web Layer** (`index.html`, `login.html`, `register.html`)
   - Static HTML/CSS/JS frontend
   - Green-themed UI with black background
   - Client-side validation with real-time feedback
   - JWT token management in localStorage

2. **API Layer** (`server.js` / `server-enhanced.js`)
   - Express.js REST API
   - Two server variants:
     - `server.js`: Standard security implementation
     - `server-enhanced.js`: Advanced security with 2FA, audit logging, enhanced monitoring
   - Endpoints: `/api/register`, `/api/login`, `/api/logout`, `/api/profile`, `/api/verify`

3. **Security Middleware Stack** (order matters)
   - Helmet.js: Security headers (CSP, HSTS, X-Frame-Options)
   - CORS: Controlled cross-origin access
   - Express Rate Limit: 5 auth attempts per 15 minutes
   - Body size limits: 10kb max payload
   - Mongo-sanitize: NoSQL injection prevention
   - HPP: HTTP parameter pollution prevention
   - XSS: Cross-site scripting protection

4. **Authentication Layer**
   - Argon2id password hashing (PHC winner, more secure than bcrypt)
     - Memory: 128MB (enhanced) / 64MB (standard)
     - Iterations: 4 (enhanced) / 3 (standard)  
     - Salt: 32 bytes (enhanced) / 16 bytes (standard)
   - JWT tokens with 24-hour expiry
   - Session tracking with IP/User-Agent logging
   - Account lockout after 5 failed attempts (30-minute lock)

5. **Data Layer** (`better-sqlite3`)
   - SQLite database with security pragmas
   - Tables: `users`, `sessions`, `audit_log` (enhanced only)
   - Prepared statements for SQL injection prevention
   - Foreign key constraints enabled
   - WAL mode for better concurrency

6. **Admin Tools** (`admin.js`)
   - Interactive CLI for user management
   - Approval workflow for new registrations
   - User listing, approval, rejection, deactivation
   - Direct database manipulation capabilities

### Authentication Flow

```
1. Registration
   Client → POST /api/register → Validate inputs → Check English-only
   → Hash password (Argon2) → Insert user (is_approved=0) → Return success

2. Admin Approval (if REQUIRE_USER_APPROVAL=true)
   Admin → node admin.js → List pending → Approve user → Set is_approved=1

3. Login
   Client → POST /api/login → Validate → Check approval status
   → Verify password → Reset failed attempts → Generate JWT → Store session → Return token

4. Protected Requests
   Client → Add "Authorization: Bearer <token>" → Verify JWT → Process request

5. Lockout Flow
   Failed login → Increment failed_attempts → If >= 5, set locked_until (+30 min)
   → Return 423 status → Auto-unlock after timeout
```

## Security Implementation Details

### Input Validation

- **English-only enforcement**: All usernames/passwords restricted to ASCII
  - Prevents Unicode attacks, homograph attacks, encoding issues
  - Silent rejection with generic errors to confuse attackers
  - Logged as security events for monitoring

- **Username**: `/^[a-zA-Z0-9_]{3,30}$/`
- **Password**: 20-84 chars, must include uppercase, lowercase, number, special char
- **Email**: Standard email regex with additional sanitization

### Rate Limiting Strategy

```javascript
// Authentication endpoints: Strict
authLimiter: 5 requests per 15 minutes per IP

// API endpoints: Moderate  
apiLimiter: 100 requests per minute per IP

// Bypass for successful requests: No
// Distributed tracking: Database-backed (planned)
```

### Security Headers (Helmet.js)

- CSP: Default-src 'self', inline styles allowed for theme
- HSTS: 1 year max-age with preload
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: no-referrer

### Account Security

- Lockout: 5 failed attempts = 30-minute lock
- Session expiry: 24 hours (configurable)
- Password history: Not implemented (consider for enhanced)
- 2FA: Available in `server-enhanced.js` only

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL, 
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    failed_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    is_active BOOLEAN DEFAULT 1,
    is_approved BOOLEAN DEFAULT 0,  -- Approval workflow
    approved_at DATETIME,
    approved_by TEXT,
    approval_notes TEXT
)
```

### Sessions Table
```sql
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
```

### Database Maintenance

```bash
# Backup
sqlite3 users.db ".backup backup_$(date +%Y%m%d).db"

# Restore
sqlite3 users.db < backup.sql

# Clean expired sessions
sqlite3 users.db "DELETE FROM sessions WHERE expires_at < datetime('now');"

# Check database integrity
sqlite3 users.db "PRAGMA integrity_check;"

# Vacuum (defragment)
sqlite3 users.db "VACUUM;"
```

## Deployment Configurations

### Docker Deployment
```bash
# Build and run
docker build -t indy-nexus .
docker run -d \
  -p 3000:3000 \
  --env-file .env \
  -v $(pwd)/users.db:/app/users.db \
  --restart unless-stopped \
  --name indy-nexus \
  indy-nexus
```

### Systemd Service
Service file at `indy-nexus.service`:
- Auto-restart on failure
- Environment file: `/etc/indy-nexus/.env`
- User: `indy-nexus` (non-root)
- Working directory: `/opt/indy-nexus`

### Production Checklist
- [ ] Set NODE_ENV=production
- [ ] Use strong JWT_SECRET (min 64 chars)
- [ ] Enable REQUIRE_USER_APPROVAL=true
- [ ] Configure HTTPS/TLS termination
- [ ] Set up database backups
- [ ] Configure log rotation
- [ ] Monitor failed login attempts
- [ ] Review rate limit settings

## Common Development Tasks

### Add New API Endpoint
1. Define route in `server.js`
2. Add authentication middleware if protected
3. Implement input validation
4. Add rate limiting if needed
5. Update API documentation

### Modify Database Schema
1. Create migration SQL file
2. Test on development database
3. Backup production database
4. Apply migration
5. Update prepared statements in server

### Debug Authentication Issues
1. Check `/api/health` endpoint
2. Review failed_attempts in users table
3. Check locked_until timestamps
4. Verify JWT_SECRET matches
5. Review audit_log (enhanced server)

### Update Security Settings
1. Argon2 config: `ARGON2_CONFIG` object
2. Rate limits: `authLimiter`, `apiLimiter`
3. JWT expiry: `expiresIn` parameter
4. Lockout duration: Line ~316 in server.js

## Testing Guidelines

### Manual Testing Checklist
- [ ] Registration with valid/invalid inputs
- [ ] Login with correct/incorrect credentials
- [ ] Account lockout after 5 failures
- [ ] JWT token expiry handling
- [ ] Admin approval workflow
- [ ] Protected endpoint access
- [ ] Rate limit enforcement
- [ ] Non-English character rejection

### Security Testing
```bash
# Test rate limiting
for i in {1..10}; do curl -X POST http://localhost:3000/api/login -H "Content-Type: application/json" -d '{"username":"test","password":"test"}'; done

# Test large payload rejection
curl -X POST http://localhost:3000/api/register -H "Content-Type: application/json" -d @large_payload.json

# Check security headers
curl -I http://localhost:3000
```

## Performance Optimization

### Database
- Indexes on username, email, is_active
- WAL mode for concurrent reads
- Prepared statements cached
- Connection pooling not needed (SQLite)

### Server
- Compression middleware enabled
- Static file caching (1 hour)
- JWT verification cached (planned)
- Session cleanup cron (implement)

## Troubleshooting

### Common Issues

1. **"JWT_SECRET not defined"**
   - Create `.env` file from `.env.example`
   - Set JWT_SECRET to secure random string

2. **"Account temporarily locked"**
   - Wait 30 minutes or manually unlock:
   ```sql
   UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE username = 'user';
   ```

3. **"Awaiting approval"** 
   - Run `node admin.js` and approve user
   - Or set `REQUIRE_USER_APPROVAL=false` in `.env`

4. **Database locked errors**
   - Check for multiple server instances
   - Ensure WAL mode is enabled
   - Close SQLite CLI connections

5. **CORS errors**
   - Update `ALLOWED_ORIGINS` in `.env`
   - Check Origin header in request

## Important Files Reference

- **Configuration**: `.env`, `config.js`
- **Main Server**: `server.js` (standard), `server-enhanced.js` (advanced)
- **Admin Tools**: `admin.js`
- **Frontend**: `index.html`, `login.html`, `register.html`, `auth.js`
- **Styles**: `styles.css`, `auth-styles.css`
- **Security Docs**: `SECURITY-CONFIG.md`, `SECURITY-OPS-GUIDE.md`
- **Deployment**: `deploy.sh`, `Dockerfile`, `indy-nexus.service`
- **Database**: `users.db` (auto-created)

## Development Best Practices

1. **Never expose secrets**: Use environment variables
2. **Validate all inputs**: Both client and server side
3. **Log security events**: Failed logins, lockouts, non-English attempts
4. **Test edge cases**: Unicode inputs, large payloads, rapid requests
5. **Keep dependencies updated**: Run `npm audit` weekly
6. **Review PR changes**: Especially authentication/security code
7. **Document API changes**: Update this file and API docs
8. **Backup before migrations**: Always backup production database