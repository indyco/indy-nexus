# WARP.md - Indy Nexus Technical Architecture

> **For Day-to-Day Operations**: See [README.md](./README.md) for:
> - Server management commands
> - Admin operations (user approval, etc.)
> - Database backup/maintenance
> - Health checks and monitoring
> - Troubleshooting guide
> - Windows PowerShell equivalents

This document covers advanced architecture and configuration details for developers modifying the system.

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

### Database Notes

> See README.md for backup, maintenance, and session cleanup commands

# Restore
sqlite3 users.db < backup.sql

# Clean expired sessions
sqlite3 users.db "DELETE FROM sessions WHERE expires_at < datetime('now');"

# Check database integrity
sqlite3 users.db "PRAGMA integrity_check;"

# Vacuum (defragment)
sqlite3 users.db "VACUUM;"
```

## Deployment Notes

> See README.md for Docker and systemd deployment instructions

### Production Checklist
- NODE_ENV=production
- Strong JWT_SECRET (64+ chars)
- REQUIRE_USER_APPROVAL=true
- HTTPS/TLS termination
- Backup automation
- Log rotation
- Failed login monitoring

## Development Configuration

### Key Config Objects
- **Argon2**: `ARGON2_CONFIG` object  
- **Rate Limits**: `authLimiter`, `apiLimiter`
- **JWT Expiry**: `expiresIn` parameter
- **Lockout Duration**: ~Line 316 in server.js

### Adding New Features
- New API: Route → Auth middleware → Validation → Rate limit
- Schema changes: Migration SQL → Test → Backup → Apply → Update statements

## Performance Notes

### Database Optimization
- Indexes on username, email, is_active
- WAL mode for concurrent reads  
- Prepared statements cached

### Server Optimization  
- Compression middleware enabled
- Static file caching (1 hour)
- JWT verification caching (planned)

> **Troubleshooting**: See README.md §Troubleshooting for common issues and solutions

## File Structure

- **Servers**: `server.js` (standard), `server-enhanced.js` (2FA/audit)
- **Admin**: `admin.js` CLI tool
- **Frontend**: `index.html`, `login.html`, `register.html`
- **Config**: `.env`, `config.js`
- **Database**: `users.db` (auto-created)
