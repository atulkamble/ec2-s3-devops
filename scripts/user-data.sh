#!/usr/bin/env bash
set -euxo pipefail

# System
dnf -y update
dnf -y install httpd git

# Web root
install -d -m 0755 /var/www/html
cat >/var/www/html/index.html <<'HTML'
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>My Static Website</title></head>
  <body>
    <h1 style="text-align:center">Welcome to My Static Website!</h1>
    <p style="text-align:center">Assets are served via CloudFront from S3.</p>
    <div style="text-align:center">
      <img src="__CLOUDFRONT_URL__/assets/coffee.png" alt="Coffee Image" width="420">
    </div>
  </body>
</html>
HTML

# Apache
systemctl enable --now httpd

# Insert CloudFront URL at first boot using instance metadata tag (optional)
CF_URL="$(/usr/bin/curl -s http://169.254.169.254/latest/meta-data/tags/instance/CLOUDFRONT_URL || true)"
if [[ -n "${CF_URL}" ]]; then
  sed -i "s|__CLOUDFRONT_URL__|${CF_URL}|g" /var/www/html/index.html
else
  sed -i "s|__CLOUDFRONT_URL__|#-set-cloudfront-url-|g" /var/www/html/index.html
fi
