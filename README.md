# Indy Nexus - Secure Authentication System

[![Node.js](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen)](https://nodejs.org)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Security](https://img.shields.io/badge/security-argon2-orange)](https://github.com/P-H-C/phc-winner-argon2)

A modern, secure authentication system built with Node.js, Express, and SQLite, featuring advanced security practices and a beautiful green-themed UI.

## 🌟 Features

### Security First
- **Argon2id** password hashing (winner of PHC competition)
- **JWT** token-based authentication with secure storage
- **Rate limiting** on authentication endpoints
- **Account lockout** after failed attempts
- **User approval system** for new registrations
- **Session management** with automatic expiration
- **SQL injection prevention** with parameterized queries
- **XSS protection** with input sanitization
- **CSRF protection** ready
- **Security headers** with Helmet.js

### Modern Stack
- Node.js + Express backend
- SQLite database with better-sqlite3
- Responsive HTML/CSS/JavaScript frontend
- RESTful API architecture
- Environment-based configuration

## 📋 Prerequisites

- **Node.js**: Version 14.0.0 or higher
- **npm**: Version 6.0.0 or higher
- **SQLite3**: Installed on your system (optional, for CLI access)

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/indy-nexus.git
cd indy-nexus
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment Variables
```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your favorite editor
# At minimum, you MUST set JWT_SECRET to a secure random value
```

**Important**: Generate a secure JWT_SECRET:
```bash
# On Linux/Mac:
openssl rand -hex 64

# On Windows (PowerShell):
[System.Convert]::ToHexString((1..64 | ForEach {Get-Random -Maximum 256}))
```

### 4. Initialize the Database
The database will be created automatically when you first run the server. The file will be created at the path specified in `DATABASE_PATH` (default: `./users.db`).

### 5. Start the Server
```bash
# Development mode with auto-restart
npm run dev

# Production mode
npm start
```

The server will start on `http://localhost:3000` (or the port specified in your `.env` file).

## 📁 Project Structure

```
indy-nexus/
├── .env.example           # Environment variables template
├── .gitignore            # Git ignore rules
├── package.json          # Node.js dependencies
├── server.js             # Main server file
├── server-enhanced.js    # Enhanced security server (optional)
├── admin.js              # CLI tool for user management
├── config.js             # Frontend configuration
├── auth.js               # Frontend authentication logic
├── index.html            # Landing page
├── login.html            # Login page
├── register.html         # Registration page
├── auth-styles.css       # Authentication pages styling
├── styles.css            # General styling
└── *.md                  # Documentation files
```

## 🔧 Configuration

All configuration is done through environment variables. See `.env.example` for all available options.

### Key Configuration Options

| Variable | Description | Required |
|----------|-------------|----------|
| `JWT_SECRET` | Secret key for JWT signing (min 64 chars) | ✅ Yes |
| `PORT` | Server port (default: 3000) | No |
| `NODE_ENV` | Environment (development/production) | No |
| `DATABASE_PATH` | Path to SQLite database | No |
| `REQUIRE_USER_APPROVAL` | Enable admin approval for new users | No |

## 👤 User Management

### Admin CLI Tool
Use the included admin tool to manage users:

```bash
# Run the admin CLI
node admin.js

# Available commands:
# - List pending users
# - Approve users
# - Reject users
# - View user details
# - Create admin account
```

### Default Flow
1. Users register through `/register.html`
2. If approval is enabled, admin must approve via CLI
3. Users can login through `/login.html`
4. JWT tokens are stored in localStorage
5. Sessions expire after 24 hours (configurable)

## 🔒 Security Best Practices

### For Development
1. **Never commit `.env` files** - Use `.env.example` as template
2. **Never commit database files** - They contain user data
3. **Use strong JWT secrets** - At least 64 random characters
4. **Keep dependencies updated** - Run `npm audit` regularly

### For Production
1. **Use HTTPS only** - Never run authentication over HTTP
2. **Set secure headers** - Already configured with Helmet.js
3. **Enable rate limiting** - Already configured, adjust as needed
4. **Rotate JWT secrets** - Change periodically
5. **Backup database regularly** - Automate backups
6. **Monitor failed logins** - Check audit logs
7. **Use environment variables** - Never hardcode secrets
8. **Run behind reverse proxy** - nginx/Apache recommended

### Database Security
- Database files are automatically excluded from git
- Use file system permissions to protect database
- Consider encryption at rest for production
- Regular backups are essential

## 🚢 Deployment

### Using Docker
```bash
docker build -t indy-nexus .
docker run -p 3000:3000 --env-file .env indy-nexus
```

### Using PM2
```bash
npm install -g pm2
pm2 start server.js --name indy-nexus
pm2 save
pm2 startup
```

### Using systemd (Linux)
See `indy-nexus.service` for a complete systemd service file.

### Behind nginx
```nginx
location / {
    proxy_pass http://localhost:3000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host $host;
    proxy_cache_bypass $http_upgrade;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

## 🧪 Testing

```bash
# Run tests (if available)
npm test

# Check for vulnerabilities
npm audit

# Lint code (if configured)
npm run lint
```

## 📊 API Endpoints

### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - Login user
- `POST /api/logout` - Logout user
- `GET /api/verify` - Verify JWT token

### User Management (Protected)
- `GET /api/profile` - Get user profile
- `PUT /api/profile` - Update user profile
- `DELETE /api/account` - Delete account

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines
- Follow existing code style
- Add tests for new features
- Update documentation
- Check security implications
- Run `npm audit` before submitting

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Argon2](https://github.com/P-H-C/phc-winner-argon2) - Password hashing
- [Express.js](https://expressjs.com/) - Web framework
- [better-sqlite3](https://github.com/JoshuaWise/better-sqlite3) - SQLite driver
- [Helmet.js](https://helmetjs.github.io/) - Security headers
- [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) - JWT implementation

## ⚠️ Disclaimer

This is a demonstration/educational project. While it implements many security best practices, always conduct a thorough security audit before using in production environments.

## 📞 Support

For issues, questions, or suggestions:
1. Check the [documentation](./SECURITY-CONFIG.md)
2. Search [existing issues](https://github.com/yourusername/indy-nexus/issues)
3. Create a new issue with detailed information

---

**Remember**: Security is not a feature, it's a process. Stay updated, stay secure! 🔐