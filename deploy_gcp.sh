#!/bin/bash

# Exit on error
set -e

echo "🚀 Starting Matrix GCP Deployment Setup..."

# 1. Update and install basic dependencies
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common git

# 2. Install Docker if not present
if ! command -v docker &> /dev/null
then
    echo "🐳 Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
fi

# 3. Setup Swap Space (CRITICAL for 1GB RAM building)
if [ ! -f /swapfile ]; then
    echo "🧠 Setting up 2GB Swap Space..."
    sudo fallocate -l 2G /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
fi

echo "✅ Environment prepared. Please ensure you have cloned the repository and are in the project root."
echo "Then run: docker compose up -d --build"
echo ""
echo "Note: If you haven't cloned yet, do:"
echo "git clone https://github.com/Zahid-Ham/Matrix-Cyber.git"
echo "cd Matrix-Cyber"
