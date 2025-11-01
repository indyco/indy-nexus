# WARP.md - Indy Nexus AI Agent Guide

> **Operations & Commands**: See [README.md](./README.md)

This guide helps AI agents understand and modify the codebase efficiently.

## Quick Architecture

**Stack**: Node.js/Express + SQLite + Argon2 + JWT  
**Frontend**: Static HTML/CSS/JS (green theme) - `index.html`, `login.html`, `register.html`  
**Backend**: Two variants - `server.js` (standard) or `server-enhanced.js` (with 2FA)  
**Database**: SQLite with tables: `users`, `sessions`, `audit_log` (enhanced only)  
**Security**: Helmet.js, rate limiting (5 auth/15min), Argon2id hashing, 30min lockout  
**Admin**: `admin.js` CLI for user management

## Key Dependencies

- `express` - Web framework
- `better-sqlite3` - SQLite driver  
- `argon2` - Password hashing
- `jsonwebtoken` - JWT tokens
- `helmet` - Security headers
- `express-rate-limit` - Rate limiting
- `dotenv` - Environment variables
- `cors` - CORS handling

## API Endpoints

- `POST /api/register` - New user registration (creates with is_approved=0)
- `POST /api/login` - User login (returns JWT token)
- `POST /api/logout` - Logout user
- `GET /api/verify` - Verify JWT token
- `GET /api/profile` - Get user profile (protected)
- `GET /api/health` - Health check endpoint

## Key Validation Rules

- **Username**: `/^[a-zA-Z0-9_]{3,30}$/` (English only)
- **Password**: 20-84 chars, must have: uppercase, lowercase, number, special char
- **Email**: Standard email validation
- **Rate limits**: Auth: 5/15min, API: 100/min
- **Lockout**: 5 failed attempts = 30min lock

## Database Schema

**users table**: id, username, email, password_hash, created_at, last_login, failed_attempts, locked_until, is_active, is_approved, approved_at, approved_by, approval_notes

**sessions table**: id, user_id, token_hash, ip_address, user_agent, created_at, expires_at

**audit_log table** (enhanced only): id, user_id, action, ip_address, user_agent, created_at

## Environment Variables

**Required**: `JWT_SECRET` (64+ chars)  
**Important**: `PORT` (default: 3000/46228), `NODE_ENV`, `DATABASE_PATH`, `REQUIRE_USER_APPROVAL`  
**Security**: `MAX_LOGIN_ATTEMPTS=5`, `LOCKOUT_DURATION_MINUTES=30`, `SESSION_DURATION_HOURS=24`

## Code Locations

- **Config objects**: `ARGON2_CONFIG`, `authLimiter`, `apiLimiter` in server files
- **Auth middleware**: Look for `authenticateToken` function
- **Validation**: Input validation in route handlers
- **Database queries**: Prepared statements in `statements` object

## Development Workflow

1. **Local dev**: Run `./serve.ps1` (Windows) or `npm run dev` (cross-platform)
2. **Test auth**: Use provided admin credentials or create new user
3. **Add features**: New routes go in server.js, follow existing patterns
4. **Database changes**: Update schema, then prepared statements

## Testing Strategy

- **No test framework installed** - Consider adding Jest or Mocha
- **Manual testing**: Use curl/Postman for API endpoints
- **Security**: Run `npm audit` regularly
- **Linting**: No linter configured - consider ESLint

## Common Tasks for AI Agents

### Adding a New API Endpoint
```javascript
// In server.js, add after existing routes:
app.post('/api/your-endpoint', authenticateToken, async (req, res) => {
    // Validation
    // Business logic  
    // Database operations using prepared statements
    // Return JSON response
});
```

### Modifying Frontend
- Files: `index.html`, `login.html`, `register.html`
- Styles: `styles.css` (main), `auth-styles.css` (auth pages)
- JS: `auth.js` handles authentication logic
- Theme: Green text (#00ff00) on black background

### Database Migrations
- No migration tool - manually update schema
- After schema changes, update prepared statements in server files
- Test locally before deploying
