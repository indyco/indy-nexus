# Dockerfile for indy.nexus static website
FROM nginx:alpine

# Remove default nginx config
RUN rm -rf /usr/share/nginx/html/*

# Copy website files
COPY index.html /usr/share/nginx/html/
COPY styles.css /usr/share/nginx/html/

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Expose port 46228
EXPOSE 46228

# Start nginx
CMD ["nginx", "-g", "daemon off;"]