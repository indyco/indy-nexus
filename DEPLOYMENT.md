# Indy Nexus - Debian LXC Deployment Guide

## Overview
This guide explains how to deploy the indy.nexus website on a fresh Debian-based LXC container running on Proxmox. The website will be served locally on port 46228 (localhost only).

## Prerequisites
- Fresh Debian-based LXC container on Proxmox (Debian 11/12 or Ubuntu 20.04/22.04)
- Root or sudo access to the container
- Basic network connectivity for package installation

## Files Included
- `index.html` - Main website file
- `styles.css` - Website styling (black background, green fonts)
- `deploy.sh` - Automated deployment script
- `nginx.conf` - Nginx configuration (optional, for Docker deployment)
- `Dockerfile` - Docker configuration (alternative deployment method)
- `indy-nexus.service` - Systemd service file (optional)

## Quick Deployment (Recommended)

### Step 1: Transfer Files to LXC Container
From your Windows machine, transfer the files to the LXC container. You can use SCP, SFTP, or Proxmox's file upload feature.

```bash
# Example using SCP from Windows (requires SSH access)
scp -r C:\1A\warp\indy.nexus\* root@<LXC_IP>:/root/indy.nexus/
```

### Step 2: Connect to the LXC Container
```bash
# From Proxmox web interface or SSH
ssh root@<LXC_IP>
```

### Step 3: Run the Deployment Script
```bash
cd /root/indy.nexus
chmod +x deploy.sh
./deploy.sh
```

The script will:
1. Update system packages
2. Install nginx
3. Copy website files to `/var/www/indy.nexus/`
4. Configure nginx to serve on localhost:46228
5. Enable and start the nginx service

## Manual Deployment (Alternative)

If you prefer to deploy manually:

### 1. Update and Install Nginx
```bash
apt-get update
apt-get upgrade -y
apt-get install -y nginx
```

### 2. Create Website Directory
```bash
mkdir -p /var/www/indy.nexus
```

### 3. Copy Website Files
```bash
cp index.html /var/www/indy.nexus/
cp styles.css /var/www/indy.nexus/
```

### 4. Configure Nginx
Create the site configuration:
```bash
nano /etc/nginx/sites-available/indy.nexus
```

Add the following content:
```nginx
server {
    listen 127.0.0.1:46228;
    server_name localhost;
    
    root /var/www/indy.nexus;
    index index.html;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

### 5. Enable the Site
```bash
ln -s /etc/nginx/sites-available/indy.nexus /etc/nginx/sites-enabled/
rm /etc/nginx/sites-enabled/default
nginx -t
systemctl restart nginx
systemctl enable nginx
```

## Docker Deployment (Alternative)

If you prefer using Docker:

### 1. Install Docker
```bash
apt-get update
apt-get install -y docker.io
systemctl start docker
systemctl enable docker
```

### 2. Build and Run
```bash
cd /root/indy.nexus
docker build -t indy-nexus .
docker run -d -p 127.0.0.1:46228:46228 --name indy-nexus --restart unless-stopped indy-nexus
```

## Verification

### Check if the service is running:
```bash
# For nginx deployment
systemctl status nginx
curl http://127.0.0.1:46228

# For Docker deployment
docker ps
docker logs indy-nexus
```

### Test the website:
```bash
# From within the LXC container
curl -I http://127.0.0.1:46228
wget -O- http://127.0.0.1:46228 | head -20
```

## Troubleshooting

### Port Already in Use
If port 46228 is already in use:
```bash
# Check what's using the port
netstat -tlnp | grep 46228
# Kill the process or change the port in the nginx configuration
```

### Nginx Configuration Errors
```bash
# Test nginx configuration
nginx -t
# Check error logs
tail -f /var/log/nginx/error.log
```

### Permission Issues
```bash
# Fix ownership
chown -R www-data:www-data /var/www/indy.nexus
# Fix permissions
chmod -R 755 /var/www/indy.nexus
```

## Security Notes
- The website is configured to listen only on localhost (127.0.0.1:46228)
- No external access is configured by default
- To allow external access, modify the nginx configuration to listen on 0.0.0.0:46228 (not recommended without proper security measures)

## Maintenance

### Update Website Content
```bash
# Edit files directly
nano /var/www/indy.nexus/index.html
nano /var/www/indy.nexus/styles.css
# Reload nginx to apply changes
systemctl reload nginx
```

### View Logs
```bash
# Access logs
tail -f /var/log/nginx/access.log
# Error logs
tail -f /var/log/nginx/error.log
```

### Start/Stop/Restart Service
```bash
systemctl start nginx
systemctl stop nginx
systemctl restart nginx
systemctl reload nginx
```

## Additional Configuration

### Auto-start on Boot
The deployment script already enables nginx to start on boot. To verify:
```bash
systemctl is-enabled nginx
```

### Backup
To backup the website:
```bash
tar -czf indy-nexus-backup.tar.gz /var/www/indy.nexus/
```

### Restore from Backup
```bash
tar -xzf indy-nexus-backup.tar.gz -C /
systemctl restart nginx
```

## Support
For issues or questions, check:
- Nginx error logs: `/var/log/nginx/error.log`
- System logs: `journalctl -u nginx -n 50`
- Configuration syntax: `nginx -t`