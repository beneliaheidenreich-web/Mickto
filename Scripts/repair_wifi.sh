#!/bin/bash
# Run this any time wlan1 gets stuck in monitor mode or NM loses control of it.
set -uo pipefail

IFACE="wlan1"

echo "=== WiFi Repair: restoring $IFACE ==="

echo "Killing capture processes..."
sudo pkill -9 airodump-ng 2>/dev/null || true
sudo pkill -9 aireplay-ng 2>/dev/null || true
sleep 1

echo "Removing monitor interface ${IFACE}mon..."
sudo iw dev "${IFACE}mon" del 2>/dev/null || true

echo "Done. Current state:"
iw dev 2>/dev/null | grep -E "Interface|type"
