#!/bin/bash
# Polls for git changes, pulls them, and syncs desktop launchers.
# Run by systemd timer — see setup_autoupdate.sh.

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS_DIR="$REPO_DIR/Scripts"
DESKTOP_DIR="/root/Desktop"
PYTHON="/usr/bin/python3"

cd "$REPO_DIR" || exit 1

# ── Pull if there are upstream changes ────────────────────────────────────────
git fetch origin main --quiet 2>/dev/null || exit 0   # no internet — bail silently

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" != "$REMOTE" ]; then
    git pull origin main --quiet
fi

# ── Sync desktop launchers for every .py in Scripts/ ─────────────────────────
mkdir -p "$DESKTOP_DIR"

for script in "$SCRIPTS_DIR"/*.py; do
    [ -f "$script" ] || continue

    filename=$(basename "$script" .py)
    # Prettify: underscores → spaces, title-case each word
    display_name=$(echo "$filename" | sed 's/_/ /g' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2); print}')
    desktop_file="$DESKTOP_DIR/${filename}.desktop"

    cat > "$desktop_file" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=$display_name
Comment=Mickto — $display_name
Exec=sudo $PYTHON $script
Icon=utilities-terminal
Terminal=false
Categories=Application;
EOF
    chmod +x "$desktop_file"
done

# ── Remove launchers whose script no longer exists ────────────────────────────
for desktop_file in "$DESKTOP_DIR"/*.desktop; do
    [ -f "$desktop_file" ] || continue
    exec_line=$(grep "^Exec=" "$desktop_file" | head -1)
    script_path=$(echo "$exec_line" | awk '{print $NF}')
    if [ -n "$script_path" ] && [ ! -f "$script_path" ]; then
        rm "$desktop_file"
    fi
done
