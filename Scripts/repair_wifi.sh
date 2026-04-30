#!/bin/bash
# Run this any time wlan1 gets stuck in monitor mode or NM loses control of it.
set -uo pipefail

IFACE="wlan1"

echo "=== WiFi Repair: restoring $IFACE ==="

echo "Killing capture processes..."
sudo pkill -9 airodump-ng 2>/dev/null || true
sudo pkill -9 aireplay-ng 2>/dev/null || true
sleep 1

MON_IFACE=$(iw dev 2>/dev/null | awk '/Interface/{i=$2} /type monitor/{print i; exit}')
if [ -n "$MON_IFACE" ]; then
    echo "Stopping monitor interface $MON_IFACE..."
    sudo airmon-ng stop "$MON_IFACE" 2>/dev/null || true
else
    echo "No monitor interface found."
fi

echo "Restoring hostapd and NetworkManager..."
sudo systemctl start hostapd 2>/dev/null || true
sudo systemctl start NetworkManager 2>/dev/null || true

echo "Done. Current state:"
iw dev 2>/dev/null | grep -E "Interface|type"
