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

# Install Node.js and npm
echo "[2/10] Installing Node.js and npm..."
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs build-essential

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
cp -r *.html *.css *.js package.json server.js /opt/indy-nexus/

# Install Node.js dependencies
echo "[7/10] Installing Node.js dependencies..."
cd /opt/indy-nexus
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
Environment=JWT_SECRET=CHANGE_THIS_SECRET_KEY_IN_PRODUCTION_$(openssl rand -hex 32)

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

# Check service status
echo ""
echo "==========================================="
echo "Checking service status..."
echo "==========================================="
systemctl status indy-nexus-backend --no-pager
systemctl status nginx --no-pager

echo ""
echo "==========================================="
echo "Deployment Complete!"
echo "==========================================="
echo "Website: http://127.0.0.1:46228"
echo "API Backend: http://127.0.0.1:3000"
echo ""
echo "Security Notes:"
echo "1. Change JWT_SECRET in /etc/systemd/system/indy-nexus-backend.service"
echo "2. Database is stored at /opt/indy-nexus/users.db"
echo "3. Logs: journalctl -u indy-nexus-backend -f"
echo ""
echo "Test the authentication:"
echo "curl -X GET http://127.0.0.1:3000/api/health"
echo ""