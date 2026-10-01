#!/bin/bash
# AMAN One-Line Installer
# Usage: curl -sSL https://raw.githubusercontent.com/ochyx94/AMAN/main/deploy/install.sh | sudo bash
# Or:    sudo ./install.sh [path-to-local-binary]

set -e

REPO="ochyx94/AMAN"
INSTALL_DIR="/opt/aman"
BINARY_NAME="aman"
SERVICE_FILE="/etc/systemd/system/aman.service"
PORT="8080"

echo "=========================================="
echo " AMAN Installer - Security Scanner"
echo "=========================================="
echo

# --- Check root ---
if [ "$EUID" -ne 0 ]; then
    echo "Error: Jalankan sebagai root (sudo)"
    exit 1
fi

# --- Detect system ---
if command -v systemctl >/dev/null 2>&1; then
    echo "[OK] systemd terdeteksi"
else
    echo "Error: systemd tidak ditemukan. Install manual: cp aman /usr/local/bin/"
    exit 1
fi

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ASSET_ARCH="amd64" ;;
    aarch64|arm64) ASSET_ARCH="arm64" ;;
    *) echo "Error: arsitektur tidak didukung: $ARCH"; exit 1 ;;
esac
echo "[OK] Arsitektur: $ARCH"

# --- [1/5] Get binary ---
echo
echo "[1/5] Menyiapkan binary AMAN..."
TMP_BIN=$(mktemp)
LOCAL_BIN=""
# Prefer local binary if provided as argument or exists next to script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
for cand in "$1" "$SCRIPT_DIR/aman" "$SCRIPT_DIR/aman-linux-${ASSET_ARCH}"; do
    if [ -n "$cand" ] && [ -f "$cand" ] && [ -x "$cand" ]; then
        LOCAL_BIN="$cand"
        break
    fi
done

if [ -n "$LOCAL_BIN" ]; then
    echo "  Menggunakan binary lokal: $LOCAL_BIN"
    cp "$LOCAL_BIN" "$TMP_BIN"
else
    echo "  Mengunduh dari GitHub Releases..."
    DL_URL="https://github.com/${REPO}/releases/latest/download/aman-linux-${ASSET_ARCH}"
    if command -v curl >/dev/null 2>&1; then
        curl -sSLf -o "$TMP_BIN" "$DL_URL" || { echo "Error: gagal download dari $DL_URL"; rm -f "$TMP_BIN"; exit 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$TMP_BIN" "$DL_URL" || { echo "Error: gagal download dari $DL_URL"; rm -f "$TMP_BIN"; exit 1; }
    else
        echo "Error: curl atau wget dibutuhkan"
        exit 1
    fi
fi
chmod +x "$TMP_BIN"
echo "  Binary siap."

# --- [2/5] Directories ---
echo
echo "[2/5] Membuat direktori..."
mkdir -p "$INSTALL_DIR/data"
echo "  $INSTALL_DIR siap."

# --- [3/5] Install binary + service ---
echo
echo "[3/5] Install binary + systemd service..."
# Stop service first to avoid 'Text file busy' on upgrade
systemctl stop aman 2>/dev/null || true
cp "$TMP_BIN" "$INSTALL_DIR/$BINARY_NAME"
chmod +x "$INSTALL_DIR/$BINARY_NAME"
rm -f "$TMP_BIN"

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=AMAN - Alat Deteksi Kelemahan Software
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$BINARY_NAME serve --port $PORT
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment=AMAN_HOME=$INSTALL_DIR
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
echo "  Terinstall: $INSTALL_DIR/$BINARY_NAME"

# --- [4/5] Enable + start ---
echo
echo "[4/5] Mengaktifkan service..."
systemctl daemon-reload
systemctl enable aman -q 2>/dev/null || systemctl enable aman
systemctl restart aman
echo "  Service aktif."

# --- [5/5] Verify ---
echo
echo "[5/5] Verifikasi..."
sleep 2
if curl -sf "http://localhost:${PORT}/health" >/dev/null 2>&1; then
    HEALTH=$(curl -s "http://localhost:${PORT}/health")
    echo "  $HEALTH"
    echo
    echo "=========================================="
    echo " ✓ AMAN terinstall & berjalan!"
    echo "=========================================="
    echo
    echo " Service : systemctl status aman"
    echo " CLI     : $INSTALL_DIR/$BINARY_NAME --help"
    echo " Dashboard: http://$(hostname -I 2>/dev/null | awk '{print $1}'):${PORT}"
    echo
    echo " Contoh:"
    echo "   $INSTALL_DIR/$BINARY_NAME periksa-security"
    echo "   $INSTALL_DIR/$BINARY_NAME periksa --jenis all --format html"
    echo "   $INSTALL_DIR/$BINARY_NAME update --all"
else
    echo "  Warning: health check gagal. Cek log:"
    echo "    journalctl -u aman -n 20"
    exit 1
fi
