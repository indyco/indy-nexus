#!/bin/bash

# Unified deployment script for Indy Nexus
# Works with the environment-based configuration system

set -euo pipefail

# Configuration
APP_NAME="indy-nexus"
APP_DIR="/var/www/indy.nexus"
SERVICE_NAME="indy-nexus"
NODE_VERSION="20"  # Node.js LTS version

echo "==========================================="
echo "Indy Nexus Unified Deployment Script"
echo "==========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Parse arguments
SECURITY_PRESET="${1:-enhanced}"
INSTALL_NGINX="${2:-true}"

echo "Configuration:"
echo "  Security Preset: $SECURITY_PRESET"
echo "  Install Nginx: $INSTALL_NGINX"
echo ""

# Update system
echo "[1/8] Updating system packages..."
apt-get update
apt-get upgrade -y

# Install Node.js if not present
echo "[2/8] Checking Node.js installation..."
if ! command -v node &> /dev/null; then
    echo "Installing Node.js v${NODE_VERSION}..."
    curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash -
    apt-get install -y nodejs build-essential
else
    echo "Node.js already installed: $(node --version)"
fi

# Install nginx if requested
if [ "$INSTALL_NGINX" = "true" ]; then
    echo "[3/8] Installing nginx..."
    apt-get install -y nginx
else
    echo "[3/8] Skipping nginx installation"
fi

# Create application user if not exists
echo "[4/8] Setting up application user..."
if ! id -u indy &>/dev/null; then
    useradd -r -m -d /home/indy -s /bin/bash indy
    echo "Created user 'indy'"
else
    echo "User 'indy' already exists"
fi

# Create application directory
echo "[5/8] Setting up application directory..."
mkdir -p $APP_DIR
chown -R indy:indy $APP_DIR

# Copy application files
echo "[6/8] Copying application files..."
cp -r *.js *.json *.html *.css *.md $APP_DIR/ 2>/dev/null || true
if [ -d "config" ]; then
    cp -r config $APP_DIR/
fi

# Setup environment file
cd $APP_DIR

if [ ! -f "/etc/${APP_NAME}.env" ]; then
    echo "Creating environment configuration..."
    
    # Generate secure JWT secret
    JWT_SECRET=$(openssl rand -hex 64)
    
    cat > /etc/${APP_NAME}.env << EOF
# Indy Nexus Production Configuration
NODE_ENV=production
SECURITY_PRESET=$SECURITY_PRESET
PORT=3000
HOST=127.0.0.1

# Security
JWT_SECRET=$JWT_SECRET
DATABASE_PATH=/var/www/indy.nexus/users.db

# Production settings
TRUST_PROXY=true
FORCE_HTTPS=true
ENABLE_HELMET=true
ENABLE_CSP=true
ENABLE_HSTS=true
ENABLE_RATE_LIMIT=true
ENABLE_CORS=true
ENABLE_COMPRESSION=true
ENABLE_AUDIT_LOG=true
ENABLE_SESSION_CLEANUP=true

# CORS (update with your domain)
CORS_ORIGIN=https://yourdomain.com

# Rate limiting (production values)
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=5

# Static caching
STATIC_MAX_AGE=31536000
STATIC_IMMUTABLE=true
EOF
    
    chmod 600 /etc/${APP_NAME}.env
    chown indy:indy /etc/${APP_NAME}.env
    echo "Created /etc/${APP_NAME}.env with secure defaults"
else
    echo "Using existing /etc/${APP_NAME}.env"
fi

# Install Node.js dependencies
echo "[7/8] Installing Node.js dependencies..."
sudo -u indy npm ci --omit=dev

# Create systemd service
echo "[8/8] Setting up systemd service..."
cat > /etc/systemd/system/${SERVICE_NAME}.service << 'EOF'
[Unit]
Description=Indy Nexus Web Application
After=network.target

[Service]
Type=simple
User=indy
Group=indy
WorkingDirectory=/var/www/indy.nexus
EnvironmentFile=/etc/indy-nexus.env
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=indy-nexus

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/www/indy.nexus

# Resource limits
LimitNOFILE=65536
LimitNPROC=512

[Install]
WantedBy=multi-user.target
EOF

# Setup nginx if installed
if [ "$INSTALL_NGINX" = "true" ]; then
    echo "Configuring nginx reverse proxy..."
    cat > /etc/nginx/sites-available/${APP_NAME} << 'EOF'
server {
    listen 80;
    server_name _;
    
    # Redirect HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name _;
    
    # SSL configuration (update with your certificates)
    # ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Proxy to Node.js application
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Static file caching (optional)
    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        proxy_pass http://127.0.0.1:3000;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOF
    
    # Enable site
    ln -sf /etc/nginx/sites-available/${APP_NAME} /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Test nginx configuration
    nginx -t
    systemctl restart nginx
    systemctl enable nginx
fi

# Set proper permissions
chown -R indy:indy $APP_DIR
chmod 750 $APP_DIR
chmod 640 $APP_DIR/*.js $APP_DIR/*.json 2>/dev/null || true
chmod 644 $APP_DIR/*.html $APP_DIR/*.css 2>/dev/null || true

# Start and enable service
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
systemctl restart ${SERVICE_NAME}

# Wait for service to start
sleep 3

# Check service status
echo ""
echo "==========================================="
echo "Checking service status..."
echo "==========================================="
systemctl status ${SERVICE_NAME} --no-pager || true

# Test health endpoint
echo ""
echo "Testing health endpoint..."
if curl -s http://127.0.0.1:3000/api/health | grep -q "OK"; then
    echo "✅ Health check passed!"
else
    echo "⚠️  Health check failed - check logs with: journalctl -u ${SERVICE_NAME} -f"
fi

echo ""
echo "==========================================="
echo "✅ Deployment Complete!"
echo "==========================================="
echo ""
echo "📍 Access Points:"
if [ "$INSTALL_NGINX" = "true" ]; then
    echo "   Web Interface: https://your-domain.com"
    echo "   (Configure SSL certificates in /etc/nginx/sites-available/${APP_NAME})"
fi
echo "   Direct Node.js: http://127.0.0.1:3000"
echo "   Health Check: http://127.0.0.1:3000/api/health"
echo ""
echo "🔧 Management Commands:"
echo "   View logs: journalctl -u ${SERVICE_NAME} -f"
echo "   Restart: systemctl restart ${SERVICE_NAME}"
echo "   Status: systemctl status ${SERVICE_NAME}"
echo "   Edit config: nano /etc/${APP_NAME}.env"
echo ""
echo "⚠️  Next Steps:"
echo "   1. Configure your domain in /etc/${APP_NAME}.env (CORS_ORIGIN)"
echo "   2. Set up SSL certificates (use certbot for Let's Encrypt)"
echo "   3. Update firewall rules if needed"
echo "   4. Set up database backups"
echo ""