#!/bin/bash
set -e

echo "🔨 Setting up vulnerable Apache server..."

# Enable Apache modules
a2enmod ssl headers rewrite status

# Configure vulnerable Apache settings
cat >> /etc/apache2/apache2.conf << 'APACHECONF'

# VULNERABLE: Show full server version
ServerTokens Full
ServerSignature On

# VULNERABLE: Enable TRACE method
TraceEnable On

# VULNERABLE: Public server-status
<Location /server-status>
    SetHandler server-status
    Require all granted
</Location>

# VULNERABLE: Directory listing in uploads
<Directory /var/www/html/uploads>
    Options +Indexes
    Require all granted
</Directory>

# VULNERABLE: CORS wildcard with credentials (for CORS testing)
<Location /api>
    Header always set Access-Control-Allow-Origin "*"
    Header always set Access-Control-Allow-Credentials "true"
    Header always set Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS"
</Location>

# WAF SIMULATION: Cloudflare headers (for WAF detection testing — Phase 10)
Header always set CF-Ray "7a8b9c0d1e2f3-IAD"
Header always set CF-Cache-Status "DYNAMIC"
APACHECONF

# Configure vulnerable PHP
cat >> /usr/local/etc/php/php.ini << 'PHPCONF'
expose_php = On
display_errors = On
allow_url_fopen = On
allow_url_include = On
disable_functions =
session.cookie_secure = Off
session.cookie_httponly = Off
upload_max_filesize = 200M
PHPCONF

# Generate SSL certificate
mkdir -p /etc/ssl/certs/apache /etc/ssl/private
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/apache.key \
  -out /etc/ssl/certs/apache/apache.crt \
  -subj "/C=US/ST=Test/L=Test/O=Test/OU=Test/CN=localhost" 2>/dev/null

# Enable SSL site
cat > /etc/apache2/sites-available/default-ssl.conf << 'SSLCONF'
<VirtualHost *:443>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/apache/apache.crt
    SSLCertificateKeyFile /etc/ssl/private/apache.key
    
    # VULNERABLE: Weak SSL protocols
    SSLProtocol all -SSLv2 -SSLv3
</VirtualHost>
SSLCONF

a2ensite default-ssl

# Create .env file (CRITICAL vulnerability)
cat > /var/www/html/.env << 'ENVFILE'
APP_NAME=VulnerableApp
APP_ENV=production
APP_KEY=base64:YourSuperSecretKeyHere123456789==
APP_DEBUG=true
APP_URL=http://localhost

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=production_db
DB_USERNAME=root
DB_PASSWORD=SuperSecretPassword123!

REDIS_PASSWORD=AnotherSecretPassword456!

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_USERNAME=your-username
MAIL_PASSWORD=your-mail-password

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

STRIPE_SECRET=sk_test_51234567890abcdef
JWT_SECRET=YourJWTSecretKeyHere123456789
ENVFILE

# Create phpinfo.php (CRITICAL vulnerability)
cat > /var/www/html/phpinfo.php << 'PHPINFO'
<?php
phpinfo();
?>
PHPINFO

# Create test PHP files
cat > /var/www/html/test.php << 'TESTPHP'
<?php
echo 'Test file - vulnerable server';
?>
TESTPHP

cat > /var/www/html/info.php << 'INFOPHP'
<?php
echo 'Info page - should not be public';
?>
INFOPHP

# Create index.php with CORS header + insecure cookie (for header/cookie testing)
cat > /var/www/html/index.php << 'INDEXPHP'
<?php
// VULNERABLE: CORS wildcard on all pages
header('Access-Control-Allow-Origin: *');
// VULNERABLE: Session cookie without security flags
setcookie('session_id', 'abc123def456', 0, '/', '', false, false);
setcookie('user_token', 'tok_xyz789', 0, '/', '', false, false);
setcookie('laravel_session', 'eyJpdiI6InRlc3QifQ', 0, '/', '', false, false);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Apache Server</title>
</head>
<body>
    <h1>&#128296; Hephaestus Test Lab - Apache</h1>
    <p>Intentionally vulnerable server for testing Hephaestus scanner</p>
    <ul>
        <li>Server version disclosed in headers</li>
        <li>PHP version disclosed in headers</li>
        <li>.env file exposed at /.env</li>
        <li>phpinfo.php accessible with dangerous settings</li>
        <li>.git directory exposed</li>
        <li>Directory listing enabled in /uploads/</li>
        <li>Weak TLS configuration</li>
        <li>Missing security headers</li>
        <li>CORS wildcard header set</li>
        <li>Session cookies without security flags</li>
        <li>robots.txt exposes sensitive paths</li>
        <li>/api/v1/ and /swagger.json accessible</li>
    </ul>
</body>
</html>
INDEXPHP

# Remove old index.html if it exists
rm -f /var/www/html/index.html

# Create uploads directory with files
mkdir -p /var/www/html/uploads
echo "Sensitive upload file 1" > /var/www/html/uploads/file1.txt
echo "Sensitive upload file 2" > /var/www/html/uploads/file2.txt
echo "Confidential document" > /var/www/html/uploads/confidential.pdf

# Create fake .git directory (CRITICAL vulnerability)
mkdir -p /var/www/html/.git
echo "ref: refs/heads/master" > /var/www/html/.git/HEAD

cat > /var/www/html/.git/config << 'GITCONFIG'
[core]
    repositoryformatversion = 0
    filemode = true
[remote "origin"]
    url = https://github.com/company/production-code.git
    fetch = +refs/heads/*:refs/remotes/origin/*
GITCONFIG

# Create .well-known directory for consent tokens
mkdir -p /var/www/html/.well-known

# VULNERABLE: robots.txt with sensitive disallowed paths
cat > /var/www/html/robots.txt << 'ROBOTSTXT'
User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /config/
Disallow: /api/
Disallow: /internal/
Disallow: /database/
Disallow: /.git/
Disallow: /phpmyadmin/
Disallow: /staging/
Disallow: /private/
ROBOTSTXT

# Create /backup/ directory that is ACCESSIBLE (robots.txt says disallow but no auth)
mkdir -p /var/www/html/backup
echo "DB_PASS=SuperSecret123" > /var/www/html/backup/db.conf
echo "backup_2024.sql dump here" > /var/www/html/backup/database_dump.sql

# Create /api/v1/ endpoint (JSON)
mkdir -p /var/www/html/api/v1
cat > /var/www/html/api/v1/users.json << 'APIUSERS'
{"users": [{"id": 1, "name": "admin", "email": "admin@example.com", "role": "administrator"}]}
APIUSERS

cat > /var/www/html/api/v1/index.php << 'APIINDEX'
<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
echo json_encode(["version" => "1.0", "endpoints" => ["/users", "/products", "/orders"]]);
APIINDEX

# Create /swagger.json (exposed API spec)
cat > /var/www/html/swagger.json << 'SWAGGERJSON'
{
  "openapi": "3.0.0",
  "info": {"title": "VulnerableApp API", "version": "1.0.0"},
  "paths": {
    "/api/v1/users": {"get": {"summary": "List users", "responses": {"200": {"description": "OK"}}}},
    "/api/v1/admin": {"get": {"summary": "Admin endpoint", "responses": {"200": {"description": "OK"}}}},
    "/api/v1/config": {"get": {"summary": "Config dump", "responses": {"200": {"description": "OK"}}}}
  }
}
SWAGGERJSON

# Create /admin/ directory (blocked 403 — robots says disallow and access IS blocked)
mkdir -p /var/www/html/admin
cat >> /etc/apache2/apache2.conf << 'ADMINCONF'
<Directory /var/www/html/admin>
    Require all denied
</Directory>
ADMINCONF

echo "✅ Vulnerable Apache server configured successfully!"
echo "Vulnerabilities ready for testing:"
echo "   - .env file at /.env"
echo "   - phpinfo.php at /phpinfo.php (with display_errors=On, allow_url_fopen=On)"
echo "   - .git directory at /.git/"
echo "   - Directory listing at /uploads/"
echo "   - Server version in headers"
echo "   - Weak TLS configuration"
echo "   - CORS wildcard + credentials at /api/"
echo "   - WAF simulation: Cloudflare CF-Ray + CF-Cache-Status headers"
echo "   - Session cookies without Secure/HttpOnly flags"
echo "   - robots.txt with 10 sensitive Disallow paths"
echo "   - /backup/ accessible (despite robots.txt)"
echo "   - /admin/ blocked (403)"
echo "   - /swagger.json exposed"
echo "   - /api/v1/ returning JSON"

# Start Apache
exec apache2-foreground