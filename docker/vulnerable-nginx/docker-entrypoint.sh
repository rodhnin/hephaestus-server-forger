#!/bin/sh
set -e

echo "🔨 Setting up vulnerable Nginx server..."

# Install openssl
apk add --no-cache openssl

# Generate SSL certificate
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/nginx.key \
  -out /etc/nginx/ssl/nginx.crt \
  -subj "/C=US/ST=Test/L=Test/O=Test/OU=Test/CN=localhost" 2>/dev/null

# Create vulnerable nginx.conf
cat > /etc/nginx/nginx.conf << 'NGINXCONF'
user nginx;
worker_processes 1;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # VULNERABLE: Show server version
    server_tokens on;
    
    access_log /var/log/nginx/access.log;
    sendfile on;
    keepalive_timeout 65;

    # HTTP Server
    server {
        listen 80;
        server_name localhost;
        root /usr/share/nginx/html;
        
        # VULNERABLE: Directory listing enabled
        autoindex on;
        
        location / {
            index index.html;
        }
        
        # VULNERABLE: Expose .git
        location /.git {
            autoindex on;
        }
        
        # VULNERABLE: Expose .env
        location /.env {
            default_type text/plain;
        }
        
        # Allow .well-known for consent tokens
        location /.well-known {
            autoindex on;
        }
    }
    
    # HTTPS Server with weak TLS
    server {
        listen 443 ssl;
        server_name localhost;
        root /usr/share/nginx/html;
        
        # VULNERABLE: Weak SSL protocols
        ssl_certificate /etc/nginx/ssl/nginx.crt;
        ssl_certificate_key /etc/nginx/ssl/nginx.key;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_ciphers ALL:!aNULL:!eNULL;
        
        autoindex on;
        
        location / {
            index index.html;
        }
    }
}
NGINXCONF

# Create .env file (CRITICAL vulnerability)
cat > /usr/share/nginx/html/.env << 'ENVFILE'
APP_NAME=VulnerableNginxApp
APP_ENV=production
APP_KEY=base64:NginxSecretKeyHere987654321==
APP_DEBUG=true

DB_CONNECTION=postgresql
DB_HOST=127.0.0.1
DB_PORT=5432
DB_DATABASE=nginx_prod_db
DB_USERNAME=postgres
DB_PASSWORD=NginxSecretPass456!

API_SECRET=nginx_api_secret_key_123
JWT_SECRET=NginxJWTSecret987654321
ENVFILE

# Create index.html
cat > /usr/share/nginx/html/index.html << 'INDEXHTML'
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Nginx Server</title>
</head>
<body>
    <h1>🔨 Hephaestus Test Lab - Nginx</h1>
    <p>Intentionally vulnerable Nginx server for testing</p>
    <ul>
        <li>Server version disclosed in headers</li>
        <li>.env file exposed at /.env</li>
        <li>.git directory exposed</li>
        <li>Directory listing enabled</li>
        <li>Weak TLS protocols (TLS 1.0, 1.1)</li>
        <li>Missing security headers</li>
    </ul>
</body>
</html>
INDEXHTML

# Create uploads directory with files
mkdir -p /usr/share/nginx/html/uploads
echo "Upload 1" > /usr/share/nginx/html/uploads/file1.txt
echo "Upload 2" > /usr/share/nginx/html/uploads/file2.txt
echo "Secret document" > /usr/share/nginx/html/uploads/secret.pdf

# Create fake .git directory (CRITICAL vulnerability)
mkdir -p /usr/share/nginx/html/.git
echo "ref: refs/heads/main" > /usr/share/nginx/html/.git/HEAD

cat > /usr/share/nginx/html/.git/config << 'GITCONFIG'
[core]
    repositoryformatversion = 0
[remote "origin"]
    url = https://github.com/company/nginx-prod.git
GITCONFIG

# Create .well-known directory for consent tokens
mkdir -p /usr/share/nginx/html/.well-known

echo "✅ Vulnerable Nginx server configured successfully!"
echo "🔓 Vulnerabilities ready for testing:"
echo "   - .env file at /.env"
echo "   - .git directory at /.git/"
echo "   - Directory listing at /uploads/"
echo "   - Server version in headers"
echo "   - Weak TLS configuration"

# Start Nginx
exec nginx -g 'daemon off;'