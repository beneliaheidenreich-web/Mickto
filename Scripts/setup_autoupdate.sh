#!/bin/bash
# Run once on the Pi (as root) to install the systemd timer.
# Usage: sudo bash Scripts/setup_autoupdate.sh

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SYNC_SCRIPT="$REPO_DIR/Scripts/auto_update.sh"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo bash $0"
    exit 1
fi

chmod +x "$SYNC_SCRIPT"

# ── systemd service ───────────────────────────────────────────────────────────
cat > /etc/systemd/system/mickto-update.service <<EOF
[Unit]
Description=Mickto — pull latest scripts from git

[Service]
Type=oneshot
ExecStart=/bin/bash $SYNC_SCRIPT
WorkingDirectory=$REPO_DIR
StandardOutput=journal
StandardError=journal
EOF

# ── systemd timer (every 2 minutes, starting 30 s after boot) ─────────────────
cat > /etc/systemd/system/mickto-update.timer <<EOF
[Unit]
Description=Mickto update timer

[Timer]
OnBootSec=30s
OnUnitActiveSec=2min
Unit=mickto-update.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now mickto-update.timer

echo ""
echo "Done. Timer enabled — runs every 2 minutes."
echo "Check status : systemctl status mickto-update.timer"
echo "Force a sync : sudo systemctl start mickto-update.service"
echo "View logs    : journalctl -u mickto-update.service -n 20"
