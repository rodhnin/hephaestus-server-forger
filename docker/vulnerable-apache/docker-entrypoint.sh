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
APACHECONF

# Configure vulnerable PHP
cat >> /usr/local/etc/php/php.ini << 'PHPCONF'
expose_php = On
display_errors = On
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

# Create index.html
cat > /var/www/html/index.html << 'INDEXHTML'
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Apache Server</title>
</head>
<body>
    <h1>🔨 Hephaestus Test Lab - Apache</h1>
    <p>Intentionally vulnerable server for testing Hephaestus scanner</p>
    <ul>
        <li>Server version disclosed in headers</li>
        <li>PHP version disclosed in headers</li>
        <li>.env file exposed at /.env</li>
        <li>phpinfo.php accessible</li>
        <li>.git directory exposed</li>
        <li>Directory listing enabled in /uploads/</li>
        <li>Weak TLS configuration</li>
        <li>Missing security headers</li>
    </ul>
</body>
</html>
INDEXHTML

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

echo "✅ Vulnerable Apache server configured successfully!"
echo "🔓 Vulnerabilities ready for testing:"
echo "   - .env file at /.env"
echo "   - phpinfo.php at /phpinfo.php"
echo "   - .git directory at /.git/"
echo "   - Directory listing at /uploads/"
echo "   - Server version in headers"
echo "   - Weak TLS configuration"

# Start Apache
exec apache2-foreground