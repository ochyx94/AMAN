#!/bin/bash

# AMAN Installer Script
# Install AMAN sebagai systemd service

set -e

echo "=========================================="
echo "AMAN Installer - Service Setup"
echo "=========================================="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: Please run as root (sudo)"
    exit 1
fi

# Variables
INSTALL_DIR="/opt/aman"
DATA_DIR="/opt/aman/data"
USER="aman"
GROUP="aman"
BINARY_NAME="aman"

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[1/6] Creating user 'aman'..."
if id "$USER" &>/dev/null; then
    echo "User '$USER' already exists, skipping..."
else
    useradd -r -s /bin/false -d /opt/aman $USER
    echo "User created."
fi

echo
echo "[2/6] Creating directories..."
mkdir -p $INSTALL_DIR
mkdir -p $DATA_DIR
mkdir -p /etc/aman
echo "Directories created."

echo
echo "[3/6] Copying files..."
if [ -f "$SCRIPT_DIR/aman" ]; then
    cp $SCRIPT_DIR/aman $INSTALL_DIR/$BINARY_NAME
elif [ -f "$SCRIPT_DIR/build/aman" ]; then
    cp $SCRIPT_DIR/build/aman $INSTALL_DIR/$BINARY_NAME
else
    echo "Error: Binary 'aman' not found in $SCRIPT_DIR"
    exit 1
fi
cp $SCRIPT_DIR/deploy/aman.service /etc/systemd/system/
chmod +x $INSTALL_DIR/$BINARY_NAME
echo "Files copied."

echo
echo "[4/6] Setting permissions..."
chown -R $USER:$GROUP $INSTALL_DIR
chown -R $USER:$GROUP $DATA_DIR
echo "Permissions set."

echo
echo "[5/6] Enabling service..."
systemctl daemon-reload
systemctl enable aman
echo "Service enabled."

echo
echo "[6/6] Starting service..."
systemctl start aman
echo "Service started."

echo
echo "=========================================="
echo "Installation complete!"
echo "=========================================="
echo
echo "Commands:"
echo "  systemctl status aman   - Check status"
echo "  systemctl start aman   - Start service"
echo "  systemctl stop aman    - Stop service"
echo "  systemctl restart aman - Restart service"
echo
echo "API Endpoints:"
echo "  GET  http://localhost:8080/health       - Health check"
echo "  POST http://localhost:8080/api/v1/scan  - Scan folder"
echo "  POST http://localhost:8080/api/v1/update - Update database"
echo
echo "Example scan:"
echo "  curl -X POST http://localhost:8080/api/v1/scan \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"path\": \"/app\", \"check_online\": false}'"
echo
