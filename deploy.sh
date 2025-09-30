#!/bin/bash

# Deployment script for indy.nexus on Debian-based LXC container
# This script sets up the website to run on localhost:46228

set -e

echo "==================================="
echo "Indy Nexus Deployment Script"
echo "==================================="

# Update system
echo "[1/7] Updating system packages..."
apt-get update
apt-get upgrade -y

# Install nginx
echo "[2/7] Installing nginx..."
apt-get install -y nginx

# Create web directory if it doesn't exist
echo "[3/7] Creating web directory..."
mkdir -p /var/www/indy.nexus

# Copy website files
echo "[4/7] Copying website files..."
cp index.html /var/www/indy.nexus/
cp styles.css /var/www/indy.nexus/

# Create nginx site configuration
echo "[5/7] Configuring nginx..."
cat > /etc/nginx/sites-available/indy.nexus << 'EOF'
server {
    # Listen only on localhost
    listen 127.0.0.1:46228;
    server_name localhost;
    
    root /var/www/indy.nexus;
    index index.html;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
}
EOF

# Enable the site
ln -sf /etc/nginx/sites-available/indy.nexus /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test nginx configuration
echo "[6/7] Testing nginx configuration..."
nginx -t

# Restart nginx
echo "[7/7] Starting nginx service..."
systemctl restart nginx
systemctl enable nginx

echo ""
echo "==================================="
echo "Deployment Complete!"
echo "==================================="
echo "Website is now running on: http://127.0.0.1:46228"
echo ""
echo "To check status: systemctl status nginx"
echo "To view logs: journalctl -u nginx -f"
echo ""