#!/usr/bin/env python3
"""Render the canonical Privora Panel dual-surface Nginx control-panel vhost."""
from __future__ import annotations
import argparse, re, sys

p=argparse.ArgumentParser()
p.add_argument('--admin-port', type=int, required=True)
p.add_argument('--hosting-port', type=int, required=True)
p.add_argument('--server-name', default='_')
p.add_argument('--fpm-socket', required=True)
p.add_argument('--phpmyadmin-fpm-socket', default='/run/php/php8.4-fpm-privora-phpmyadmin.sock')
p.add_argument('--webmail-fpm-socket', default='/run/php/php8.4-fpm-privora-webmail.sock')
p.add_argument('--panel-root', default='/opt/privora-panel')
a=p.parse_args()
for name,port in [('PCC',a.admin_port),('PPanel',a.hosting_port)]:
    if not 1 <= port <= 65535:
        raise SystemExit(f'invalid {name} port: {port}')
if a.admin_port == a.hosting_port:
    raise SystemExit('PCC and PPanel ports must differ')
server_name=a.server_name.strip() or '_'
if server_name != '_' and not re.fullmatch(r'[A-Za-z0-9.-]+', server_name):
    raise SystemExit('unsafe server_name')
if not re.fullmatch(r'/[A-Za-z0-9_./-]+\.sock', a.fpm_socket):
    raise SystemExit('unsafe FPM socket path')
if not re.fullmatch(r'/[A-Za-z0-9_./-]+\.sock', a.phpmyadmin_fpm_socket):
    raise SystemExit('unsafe phpMyAdmin FPM socket path')
if not re.fullmatch(r'/[A-Za-z0-9_./-]+\.sock', a.webmail_fpm_socket):
    raise SystemExit('unsafe webmail FPM socket path')
if not re.fullmatch(r'/[A-Za-z0-9_./-]+', a.panel_root):
    raise SystemExit('unsafe panel root')

def block(port:int,surface:str,title:str,own_path:str,other_path:str,other_port:int)->str:
    return fr'''# Privora {title} listener
server {{
 listen {port} ssl http2;
 listen [::]:{port} ssl http2;
 server_name {server_name};
 root {a.panel_root}/panel/public;
 index index.php;
 ssl_certificate /etc/privora-panel/tls/panel.crt;
 ssl_certificate_key /etc/privora-panel/tls/panel.key;
 client_max_body_size 520m;
 error_page 404 500 502 503 504 =503 /_privora_recovery.html;
 location = /_privora_recovery.html {{ internal; root /usr/share/privora-panel/recovery; }}
 location = /admin.php {{ return 404; }}
 location = /customer.php {{ return 404; }}
 location = /{own_path} {{ return 302 /; }}
 location = /{own_path}/ {{ return 302 /; }}
 location = /{other_path} {{ return 302 https://$host:{other_port}/; }}
 location = /{other_path}/ {{ return 302 https://$host:{other_port}/; }}
 location = /phpmyadmin {{ return 302 /phpmyadmin/; }}
 location = /_privora_phpmyadmin_auth {{
  internal;
  include fastcgi_params;
  fastcgi_param SCRIPT_FILENAME $document_root/api.php;
  fastcgi_param QUERY_STRING route=phpmyadmin-auth;
  fastcgi_param REQUEST_METHOD GET;
  fastcgi_param HTTP_COOKIE $http_cookie;
  fastcgi_param PRIVORA_PANEL_SURFACE {surface};
  fastcgi_intercept_errors off;
  fastcgi_read_timeout 600s;
  fastcgi_send_timeout 600s;
  fastcgi_pass unix:{a.fpm_socket};
 }}
 location /phpmyadmin/ {{
  auth_request /_privora_phpmyadmin_auth;
  root /usr/share;
  index index.php;
  try_files $uri $uri/ /phpmyadmin/index.php?$query_string;
 }}
 location ~ ^/phpmyadmin/(.+\.php)$ {{
  auth_request /_privora_phpmyadmin_auth;
  root /usr/share;
  try_files $uri =404;
  include fastcgi_params;
  fastcgi_param SCRIPT_FILENAME /usr/share$fastcgi_script_name;
  fastcgi_param DOCUMENT_ROOT /usr/share;
  fastcgi_param HTTPS on;
  fastcgi_param HTTP_COOKIE $http_cookie;
  fastcgi_intercept_errors off;
  fastcgi_read_timeout 600s;
  fastcgi_send_timeout 600s;
  fastcgi_pass unix:{a.phpmyadmin_fpm_socket};
 }}
 location = /webmail {{ return 302 /webmail/; }}
 location = /_privora_webmail_auth {{
  internal;
  include fastcgi_params;
  fastcgi_param SCRIPT_FILENAME $document_root/api.php;
  fastcgi_param QUERY_STRING route=webmail-auth;
  fastcgi_param REQUEST_METHOD GET;
  fastcgi_param HTTP_COOKIE $http_cookie;
  fastcgi_param PRIVORA_PANEL_SURFACE {surface};
  fastcgi_intercept_errors off;
  fastcgi_read_timeout 600s;
  fastcgi_send_timeout 600s;
  fastcgi_pass unix:{a.fpm_socket};
 }}
 location ~ ^/webmail/installer(?:/|$) {{ deny all; }}
 location /webmail/ {{
  auth_request /_privora_webmail_auth;
  alias /usr/share/roundcube/;
  index index.php;
 }}
 location ~ ^/webmail/(.+\.php)$ {{
  auth_request /_privora_webmail_auth;
  include fastcgi_params;
  fastcgi_param SCRIPT_FILENAME /usr/share/roundcube/$1;
  fastcgi_param SCRIPT_NAME /webmail/$1;
  fastcgi_param DOCUMENT_ROOT /usr/share/roundcube;
  fastcgi_param HTTPS on;
  fastcgi_param HTTP_COOKIE $http_cookie;
  fastcgi_intercept_errors off;
  fastcgi_read_timeout 600s;
  fastcgi_send_timeout 600s;
  fastcgi_pass unix:{a.webmail_fpm_socket};
 }}
 location ~ ^/assets/(?:app\.css|app\.js|components\.js|customer\.js)$ {{
  add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;
  add_header Pragma "no-cache" always;
  add_header Expires "0" always;
  try_files $uri =404;
 }}
 location / {{ try_files $uri $uri/ /index.php?$query_string; }}
 location = /api.php {{
  try_files $fastcgi_script_name =404;
  include fastcgi_params;
  fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  fastcgi_param PRIVORA_PANEL_SURFACE {surface};
  fastcgi_intercept_errors off;
  fastcgi_read_timeout 600s;
  fastcgi_send_timeout 600s;
  error_page 502 504 =503 @privora_api_unavailable_{surface};
  fastcgi_pass unix:{a.fpm_socket};
 }}
 location @privora_api_unavailable_{surface} {{ internal; default_type application/json; return 503 '{{"error":"Privora API temporarily unavailable","recovery":true}}'; }}
 location ~ \.php$ {{
  try_files $fastcgi_script_name =404;
  include fastcgi_params;
  fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  fastcgi_param PRIVORA_PANEL_SURFACE {surface};
  fastcgi_intercept_errors on;
  fastcgi_read_timeout 600s;
  fastcgi_send_timeout 600s;
  fastcgi_pass unix:{a.fpm_socket};
 }}
 location ~ /\. {{ deny all; }}
}}
'''

sys.stdout.write('# Privora Panel dual-surface control plane\n')
sys.stdout.write(block(a.admin_port,'admin','Command Center / PCC','pcc','ppanel',a.hosting_port))
sys.stdout.write('\n')
sys.stdout.write(block(a.hosting_port,'hosting','Panel / PPanel','ppanel','pcc',a.admin_port))
