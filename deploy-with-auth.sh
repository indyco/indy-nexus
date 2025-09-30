#!/bin/bash

# Enhanced deployment script for indy.nexus with authentication
# This script sets up the website with Node.js backend and SQLite database

set -e

echo "==========================================="
echo "Indy Nexus Enhanced Deployment Script"
echo "With Authentication System"
echo "==========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Update system
echo "[1/10] Updating system packages..."
apt-get update
apt-get upgrade -y

# Install Node.js and npm (v20 LTS)
echo "[2/10] Installing Node.js v20 LTS and npm..."
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs build-essential python3

# Install nginx
echo "[3/10] Installing nginx..."
apt-get install -y nginx

# Install SQLite
echo "[4/10] Installing SQLite..."
apt-get install -y sqlite3

# Create application directory
echo "[5/10] Creating application directory..."
mkdir -p /opt/indy-nexus
mkdir -p /var/www/indy.nexus

# Copy all files
echo "[6/10] Copying application files..."
cp -r *.html *.css *.js *.json *.md server*.js admin.js /opt/indy-nexus/ 2>/dev/null || true
cp .env.example /opt/indy-nexus/.env.example 2>/dev/null || true

# Install Node.js dependencies and setup environment
echo "[7/10] Installing Node.js dependencies..."
cd /opt/indy-nexus

# Create .env file with secure JWT secret
if [ ! -f .env ]; then
    JWT_SECRET=$(openssl rand -hex 64)
    cat > .env << EOL
# Server Configuration
PORT=3000
NODE_ENV=production

# Security
JWT_SECRET=$JWT_SECRET

# Database
DATABASE_PATH=./users.db

# Authentication Settings  
REQUIRE_USER_APPROVAL=false
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=30
SESSION_DURATION_HOURS=24

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=5
EOL
    echo "Created .env file with secure JWT_SECRET"
fi

npm install --production

# Create systemd service for Node.js backend
echo "[8/10] Creating systemd service for backend..."
cat > /etc/systemd/system/indy-nexus-backend.service << 'EOF'
[Unit]
Description=Indy Nexus Backend API
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/indy-nexus
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=10
Environment=NODE_ENV=production
EnvironmentFile=/opt/indy-nexus/.env

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/opt/indy-nexus

[Install]
WantedBy=multi-user.target
EOF

# Configure nginx as reverse proxy
echo "[9/10] Configuring nginx..."
cat > /etc/nginx/sites-available/indy.nexus << 'EOF'
server {
    listen 127.0.0.1:46228;
    server_name localhost;
    
    root /opt/indy-nexus;
    index index.html;
    
    # Serve static files
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    # Proxy API requests to Node.js backend
    location /api/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
    }
    
    # Security for hidden files
    location ~ /\. {
        deny all;
    }
    
    # Prevent access to database files
    location ~ \.(db|sqlite|sqlite3)$ {
        deny all;
    }
}
EOF

# Enable the site
ln -sf /etc/nginx/sites-available/indy.nexus /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Set proper permissions
chown -R www-data:www-data /opt/indy-nexus
chmod 750 /opt/indy-nexus
chmod 640 /opt/indy-nexus/*.js /opt/indy-nexus/*.json
chmod 644 /opt/indy-nexus/*.html /opt/indy-nexus/*.css

# Test nginx configuration
nginx -t

# Start services
echo "[10/10] Starting services..."
systemctl daemon-reload
systemctl enable indy-nexus-backend
systemctl start indy-nexus-backend
systemctl restart nginx
systemctl enable nginx

# Wait for backend to start
sleep 5

# Create initial admin user (optional)
echo ""
echo "Creating initial admin user (optional)..."
cat > /opt/indy-nexus/create-admin.js << 'EOFADMIN'
require('dotenv').config();
const Database = require('better-sqlite3');
const argon2 = require('argon2');

const db = new Database('./users.db');

async function createAdmin() {
    try {
        // Check if any users exist
        const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
        if (userCount.count > 0) {
            console.log('Users already exist, skipping admin creation');
            return;
        }
        
        const username = 'admin';
        const email = 'admin@localhost';
        const password = 'AdminPass2024!@#$';
        
        const passwordHash = await argon2.hash(password, {
            type: argon2.argon2id,
            memoryCost: 65536,
            timeCost: 3,
            parallelism: 4
        });
        
        db.prepare(`
            INSERT INTO users (username, email, password_hash, is_approved)
            VALUES (?, ?, ?, 1)
        `).run(username, email, passwordHash);
        
        console.log('\n✅ Initial admin user created:');
        console.log('   Username: admin');
        console.log('   Password: AdminPass2024!@#$');
        console.log('   ⚠️  CHANGE THIS PASSWORD IMMEDIATELY!');
    } catch (err) {
        console.log('Admin user creation skipped:', err.message);
    }
}

createAdmin().then(() => process.exit(0));
EOFADMIN

cd /opt/indy-nexus
node create-admin.js || true
rm -f create-admin.js

# Check service status
echo ""
echo "==========================================="
echo "Checking service status..."
echo "==========================================="
systemctl status indy-nexus-backend --no-pager
systemctl status nginx --no-pager

echo ""
echo "==========================================="
echo "✅ Deployment Complete!"
echo "==========================================="
echo ""
echo "📍 Access Points:"
echo "   Main Site:    http://127.0.0.1:46228"
echo "   Login Page:   http://127.0.0.1:46228/login.html"
echo "   Register:     http://127.0.0.1:46228/register.html"
echo "   API Backend:  http://127.0.0.1:3000"
echo ""
echo "🔐 Admin Access:"
if [ -f /opt/indy-nexus/users.db ]; then
    echo "   Admin panel:  node /opt/indy-nexus/admin.js"
fi
echo ""
echo "📁 Important Locations:"
echo "   App Directory:  /opt/indy-nexus/"
echo "   Database:       /opt/indy-nexus/users.db"
echo "   Config:         /opt/indy-nexus/.env"
echo "   Logs:           journalctl -u indy-nexus-backend -f"
echo ""
echo "🧪 Test Commands:"
echo "   Health check:   curl http://127.0.0.1:3000/api/health"
echo "   Service status: systemctl status indy-nexus-backend"
echo ""
echo "⚠️  Next Steps:"
echo "   1. If admin user was created, login and change the password"
echo "   2. Configure firewall rules if needed"
echo "   3. Setup SSL/TLS for production use"
echo "   4. Configure backup for database"
echo ""
