# Indy Nexus Unified Server Documentation

## Overview

The Indy Nexus application now uses a **unified server architecture** that adapts to different environments through configuration rather than separate server files. This eliminates the need for maintaining multiple server versions and provides consistent behavior across development and production.

## Architecture

### Core Components

1. **`server.js`** - Single server implementation with feature toggles
2. **`config/index.js`** - Configuration module that manages environment settings
3. **Security Presets** - Two pre-configured security levels: `basic` (dev) and `enhanced` (production)

### Security Presets

#### Basic Preset (Development)
- Helmet enabled (without CSP for convenience)
- CORS with wildcard origin
- No rate limiting
- No HTTPS enforcement
- Minimal logging
- Fast Argon2 settings (64MB memory)

#### Enhanced Preset (Production)
- Full Helmet with CSP and HSTS
- Strict CORS with specific origins
- Rate limiting enabled
- HTTPS enforcement
- Audit logging
- Session cleanup
- Strong Argon2 settings (128MB memory)
- XSS protection
- NoSQL injection prevention

## Quick Start

### Windows Development

```powershell
# Option 1: Use the PowerShell wrapper
.\serve.ps1 -OpenBrowser

# Option 2: Use npm scripts
npm install
npm run dev

# For enhanced security in dev:
.\serve.ps1 -SecurityPreset enhanced
```

### Linux/macOS Development

```bash
# Install dependencies
npm install

# Run with basic security (development)
npm run dev

# Run with enhanced security
npm run dev:enhanced
```

### Production Deployment (Linux)

```bash
# Run the deployment script
sudo ./deploy.sh

# Or deploy with specific preset
sudo ./deploy.sh enhanced true  # enhanced preset, install nginx
```

## Configuration

### Environment Variables

Create a `.env` file from `.env.example`:

```bash
cp .env.example .env
```

Key configuration options:

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment mode | `development` |
| `SECURITY_PRESET` | Security level (`basic` or `enhanced`) | `basic` |
| `PORT` | Server port | `3000` |
| `JWT_SECRET` | **Required** - JWT signing secret | None |
| `TRUST_PROXY` | Trust proxy headers | `false` |
| `FORCE_HTTPS` | Force HTTPS redirect | `false` |

### Overriding Presets

You can override specific security features while using a preset:

```bash
# Use enhanced preset but disable rate limiting
SECURITY_PRESET=enhanced ENABLE_RATE_LIMIT=false npm start
```

## Scripts

### Package.json Scripts

| Script | Description |
|--------|-------------|
| `npm start` | Start server with current .env settings |
| `npm run dev` | Development mode with basic security |
| `npm run dev:enhanced` | Development with enhanced security |
| `npm run start:basic` | Production with basic security |
| `npm run start:enhanced` | Production with enhanced security |

### Helper Scripts

| Script | Platform | Description |
|--------|----------|-------------|
| `serve.ps1` | Windows | PowerShell wrapper for development |
| `deploy.sh` | Linux | Production deployment script |

## Migration from Old System

### Mapping Old to New

| Old File | New Equivalent | Notes |
|----------|----------------|-------|
| Old `server.js` | New `server.js` with `SECURITY_PRESET=basic` | Basic auth features |
| `server-enhanced.js` | `server.js` with `SECURITY_PRESET=enhanced` | Full security stack |
| Old `deploy.sh` | New `deploy.sh` | Unified deployment |
| `deploy-with-auth.sh` | `deploy.sh` | Auth handled by server |
| Old `serve.ps1` | New `serve.ps1` | Simplified wrapper |

### Migration Steps

1. **Backup existing data:**
   ```bash
   cp users.db users.db.backup
   ```

2. **Install new dependencies:**
   ```bash
   npm install
   ```

3. **Create .env file:**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

4. **Test locally:**
   ```bash
   npm run dev
   ```

5. **Deploy to production:**
   ```bash
   sudo ./deploy.sh enhanced
   ```

## Production Deployment

### System Requirements

- Ubuntu/Debian Linux (20.04+ recommended)
- Node.js 20 LTS
- 1GB RAM minimum
- nginx (optional, for reverse proxy)

### Deployment Process

1. **Run deployment script:**
   ```bash
   sudo ./deploy.sh enhanced true
   ```

2. **Configure domain and SSL:**
   - Edit `/etc/indy-nexus.env` to set `CORS_ORIGIN`
   - Install SSL certificates:
     ```bash
     sudo certbot --nginx -d yourdomain.com
     ```

3. **Monitor service:**
   ```bash
   # View logs
   journalctl -u indy-nexus -f
   
   # Check status
   systemctl status indy-nexus
   
   # Restart if needed
   sudo systemctl restart indy-nexus
   ```

### Security Hardening

The unified server includes these security features in production:

- **Non-root user** - Runs as `indy` user
- **systemd security** - PrivateTmp, ProtectHome, ReadOnlyPaths
- **Resource limits** - File and process limits
- **Audit logging** - Security events logged to database
- **Session management** - Automatic cleanup of expired sessions
- **Password security** - Argon2id with strong settings
- **Rate limiting** - Prevents brute force attacks

## API Endpoints

### Public Endpoints

- `GET /api/health` - Health check
- `POST /api/register` - User registration  
- `POST /api/login` - User login

### Protected Endpoints

- `GET /api/profile` - User profile (requires auth)
- `POST /api/logout` - Logout (requires auth)

## Troubleshooting

### Common Issues

**Port already in use:**
```bash
# Find process using port 3000
lsof -i :3000
# Or on Windows:
netstat -ano | findstr :3000
```

**Database locked:**
```bash
# Stop the service first
sudo systemctl stop indy-nexus
# Then restart
sudo systemctl start indy-nexus
```

**SSL certificate issues:**
```bash
# Renew certificates
sudo certbot renew
# Restart nginx
sudo systemctl restart nginx
```

### Debug Mode

Enable verbose logging:
```bash
NODE_ENV=development LOG_LEVEL=debug npm start
```

## Performance Tuning

### Development Settings
- Fast Argon2 (64MB memory)
- No rate limiting
- No static caching
- Minimal logging

### Production Settings
- Strong Argon2 (128MB memory)
- Rate limiting (5 requests/15 min for auth)
- 1-year static cache
- Compression enabled
- Audit logging

### Database Optimization

The enhanced preset enables:
- WAL mode for better concurrency
- Full synchronous for durability
- Auto vacuum for space management
- Secure delete for data privacy

## Monitoring

### Health Checks

```bash
# Local health check
curl http://localhost:3000/api/health

# Production health check
curl https://yourdomain.com/api/health
```

### Metrics to Monitor

- Response times
- Error rates  
- Failed login attempts
- Memory usage
- Database size

### Log Analysis

```bash
# View all logs
journalctl -u indy-nexus

# Filter by date
journalctl -u indy-nexus --since "2024-01-01"

# Export logs
journalctl -u indy-nexus > app.log
```

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review logs with `journalctl -u indy-nexus`
3. Verify environment configuration in `/etc/indy-nexus.env`
4. Test health endpoint at `/api/health`

## Version History

- **2.0.0** - Unified server architecture
- **1.1.0** - Enhanced security features
- **1.0.0** - Initial release with separate servers