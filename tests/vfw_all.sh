#/bin/sh
host=${1:-localhost}
# Empty UA
curl -H 'User-Agent:'  "http://$host/politica/1237583227176.html"

# SSI Injection
curl  -X POST -d 'in=<!--#exec' "http://$host/politica/1237583227176.html"

# Stored XSS
curl -X POST -d 'in=<script>javascript.alter('xss');</script>' "http://$host/politica/1237583227176.html"

# Reflected XSS
curl -X GET "http://$host/politica/1237583227176.html?in=<script>javascript.alter('xss');</script>"

# SQL Injection
curl -X GET "http://$host/politica/1237583227176.html?in=SELECT * FROM"
