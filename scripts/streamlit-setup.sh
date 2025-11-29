#!/bin/bash

# About the script: This script sets up the Streamlit web application for eBPF forensic monitoring.
# It installs system dependencies (Python3, pip, graphviz), Python packages, and ensures config.json is available.

set -e  # Exit on error

echo "Checking Python version..."
if command -v python3.12 &> /dev/null; then
    echo "[+] Python 3.12 is already installed."
else
    echo "Python 3.12 not found. Installing from deadsnakes PPA..."
    sudo apt-get update
    sudo apt-get install -y software-properties-common
    sudo add-apt-repository -y ppa:deadsnakes/ppa
    sudo apt-get update
    echo "Installing Python 3.12..."
    sudo apt-get install -y python3.12 python3.12-venv python3.12-dev
    echo "[+] Python 3.12 installed successfully."
fi

echo "Installing additional system dependencies..."
sudo apt-get install -y python3-pip

echo "Creating Python virtual environment..."
WEBAPP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/web"
cd "$WEBAPP_DIR"

if [ -d "venv" ]; then
    echo "[!] Virtual environment already exists, skipping creation."
else
    python3.12 -m venv venv
    echo "[+] Virtual environment created with Python 3.12."
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing Python requirements..."
pip install --upgrade pip
pip install -r requirements.txt

echo "Setting up config.json..."
CONFIG_PATH="/var/config.json"
if [ -f "$CONFIG_PATH" ]; then
    echo "[+] Config file already exists at $CONFIG_PATH"
else
    echo "Creating config file at $CONFIG_PATH..."
    sudo mkdir -p /var/monitoring/events /var/monitoring/outputs
    sudo cp ../config/config.json "$CONFIG_PATH"
    sudo chmod 644 "$CONFIG_PATH"
fi

echo ""
echo "Setting up systemd service..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Creating environment configuration..."
echo "PROJECT_ROOT=$PROJECT_DIR" | sudo tee /etc/default/streamlit-webapp > /dev/null
echo "[+] Environment file created at /etc/default/streamlit-webapp"

sudo cp "$SCRIPT_DIR/streamlit-webapp.service" /lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable streamlit-webapp.service
echo "[+] Systemd service installed. Start with: sudo systemctl start streamlit-webapp"

echo ""
echo "Access the web interface at: http://0.0.0.0:8501"
echo ""
echo "Important: Update Elasticsearch credentials in /var/config.json before starting."
