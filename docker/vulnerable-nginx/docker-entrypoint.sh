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

        # VULNERABLE: CORS wildcard on all responses
        add_header Access-Control-Allow-Origin "*" always;

        # VULNERABLE: No security headers

        location / {
            index index.html;
            # VULNERABLE: Set session cookie without security flags
            add_header Set-Cookie "session_id=nginx_sess_abc123; Path=/" always;
            add_header Set-Cookie "user_pref=dark_mode; Path=/" always;
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

        # API endpoint (unauthenticated JSON)
        location /api/ {
            default_type application/json;
            add_header Access-Control-Allow-Origin "*" always;
        }

        # Swagger spec exposed
        location /openapi.json {
            default_type application/json;
        }

        # /admin/ blocked (for robots.txt testing)
        location /admin/ {
            return 403;
        }

        # /backup/ accessible (despite robots.txt)
        location /backup/ {
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
    <h1>Hephaestus Test Lab - Nginx</h1>
    <p>Intentionally vulnerable Nginx server for testing</p>
    <ul>
        <li>Server version disclosed in headers</li>
        <li>.env file exposed at /.env</li>
        <li>.git directory exposed</li>
        <li>Directory listing enabled</li>
        <li>Weak TLS protocols (TLS 1.0, 1.1)</li>
        <li>Missing security headers</li>
        <li>CORS wildcard on all responses</li>
        <li>Session cookies without security flags</li>
        <li>robots.txt with sensitive paths</li>
        <li>/openapi.json exposed</li>
        <li>/api/ directory accessible</li>
        <li>/backup/ accessible despite robots.txt</li>
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

# VULNERABLE: robots.txt with sensitive disallowed paths
cat > /usr/share/nginx/html/robots.txt << 'ROBOTSTXT'
User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /api/
Disallow: /config/
Disallow: /internal/
Disallow: /.git/
Disallow: /private/
Disallow: /database/
ROBOTSTXT

# Create /backup/ accessible despite robots.txt
mkdir -p /usr/share/nginx/html/backup
echo '{"db_pass": "NginxSecret123", "db_user": "postgres"}' > /usr/share/nginx/html/backup/config.json

# Create /api/ with JSON response
mkdir -p /usr/share/nginx/html/api/v1
cat > /usr/share/nginx/html/api/v1/info.json << 'APIINFO'
{"api": "v1", "endpoints": ["/users", "/products", "/config"], "auth": "none"}
APIINFO

# Create /openapi.json (exposed spec)
cat > /usr/share/nginx/html/openapi.json << 'OPENAPISPEC'
{
  "openapi": "3.0.0",
  "info": {"title": "Nginx VulnApp API", "version": "1.0.0"},
  "paths": {
    "/api/v1/users": {"get": {"summary": "List all users"}},
    "/api/v1/config": {"get": {"summary": "Application config"}},
    "/api/v1/admin": {"get": {"summary": "Admin operations"}}
  }
}
OPENAPISPEC

# Create /admin/ directory (will return 403 via nginx config)
mkdir -p /usr/share/nginx/html/admin
echo "Admin panel" > /usr/share/nginx/html/admin/index.html

echo "Vulnerable Nginx server configured successfully!"
echo "Vulnerabilities ready for testing:"
echo "   - .env file at /.env"
echo "   - .git directory at /.git/"
echo "   - Directory listing at /uploads/"
echo "   - Server version in headers"
echo "   - Weak TLS configuration"
echo "   - CORS wildcard header on all responses"
echo "   - Session cookies without security flags"
echo "   - robots.txt with 8 sensitive Disallow paths"
echo "   - /backup/ accessible (despite robots.txt)"
echo "   - /admin/ blocked (403)"
echo "   - /openapi.json exposed"
echo "   - /api/v1/ returning JSON"

# Start Nginx
exec nginx -g 'daemon off;'