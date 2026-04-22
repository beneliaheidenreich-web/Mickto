# Mickto

**Mini Hacking Tool** — a Raspberry Pi device running Kali Linux.

## Hardware

- **Wi-Fi Adapters**
  - `wlan0` — Access Point for SSH connectivity
  - `wlan1` — Dual-band adapter for wireless attacks
- **GPIO** — LCD touchscreen; tap to launch scripts
- **Power** — Battery connected via bottom GPIO pins

## Setup

### First-time on the Pi

```bash
# Clone the repo
git clone https://github.com/beneliaheidenreich-web/Mickto.git ~/Mickto

# Install the auto-update timer (run once)
cd ~/Mickto
sudo bash Scripts/setup_autoupdate.sh
```

After that, every push to `main` is picked up within 2 minutes. New scripts in `Scripts/` get a desktop launcher automatically; removed scripts lose theirs.

Useful commands on the Pi:
```bash
sudo systemctl start mickto-update.service   # force an immediate sync
journalctl -u mickto-update.service -n 20    # view sync log
```

---

## Scripts

### Aircrack Automation

Automates WPA handshake capture and cracking.

1. Select a target Wi-Fi network
2. Listen for WPA handshakes on the target network
3. Crack captured handshakes using a wordlist

If no handshake is captured, the user can broadcast deauthentication packets to all clients (`FF:FF:FF:FF:FF:FF`) to force reconnections and improve the chance of catching a handshake.

### Recon

Passive area reconnaissance — scans the environment and displays all results in a scrollable GUI.

- **WiFi Access Points** — lists nearby networks via `wlan1`: SSID, signal strength, and security type
- **Bluetooth Classic** — 8-second scan for discoverable classic Bluetooth devices
- **Bluetooth LE** — 6-second BLE scan, deduplicated
- **Network Devices** — ARP scan of the local subnet, listing IP, MAC address, and vendor
