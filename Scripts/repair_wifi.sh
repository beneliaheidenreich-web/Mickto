#!/bin/bash
# Run this any time wlan1 gets stuck in monitor mode or NM loses control of it.
set -uo pipefail

IFACE="wlan1"

echo "=== WiFi Repair: restoring $IFACE ==="

echo "Killing capture processes..."
sudo pkill -9 airodump-ng 2>/dev/null || true
sudo pkill -9 aireplay-ng 2>/dev/null || true
sleep 1

echo "Restoring $IFACE to managed mode..."
sudo ip link set "$IFACE" down 2>/dev/null || true
sudo iw dev "$IFACE" set type managed 2>/dev/null || true
sudo ip link set "$IFACE" up 2>/dev/null || true

echo "Handing $IFACE back to NetworkManager..."
sudo nmcli device set "$IFACE" managed yes 2>/dev/null || true

echo "Done. Current state:"
iw dev "$IFACE" info 2>/dev/null | grep -E "Interface|type|addr" || echo "(interface not found)"
nmcli device status | grep "$IFACE" || true
