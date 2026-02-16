#!/bin/bash

# Build SQL Injection Lab
echo "Building SQL Injection Lab..."
docker build -t matrix-sqli-lab:latest -f backend/vulnerable_apps/Dockerfile.sql_injection backend/vulnerable_apps/

# Build XSS Lab
echo "Building XSS Lab..."
docker build -t matrix-xss-lab:latest -f backend/vulnerable_apps/Dockerfile.xss backend/vulnerable_apps/

# Build RCE Lab
echo "Building RCE Lab..."
docker build -t matrix-rce-lab:latest -f backend/vulnerable_apps/Dockerfile.rce backend/vulnerable_apps/

echo "✅ All lab images built successfully!"
