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

Device-centric reconnaissance — discovers, correlates, and grades every device in the area, then performs deep attack-surface analysis on demand.

**Scan phase** (~15 s, tap *Scan All*)

| Source | Tool | Data collected |
| --- | --- | --- |
| WiFi APs | `nmcli` | SSID, BSSID, signal, security type |
| Network hosts | `arp-scan` | IP, MAC, vendor |
| mDNS services | `avahi-browse` | Hostname, IP, service type |
| UPnP devices | SSDP M-SEARCH | Responding IPs |
| Classic BT | `hcitool scan` | MAC, device name (8 s) |
| BLE | `hcitool lescan` | MAC, device name (6 s) |

WiFi, ARP, mDNS, and UPnP scans run in parallel. BT scans run sequentially (shared HCI adapter).

**Correlation**

Records from different sources are merged into a single device entry using MAC OUI matching and the `BT_MAC = WiFi_MAC ± n` heuristic (many manufacturers assign BT and WiFi MACs sequentially). mDNS hostnames are matched by IP and name similarity. A phone with both WiFi and BT visible appears as one row.

**Vulnerability grade**

Each device is scored before you tap it:

| Vector | Score | Quality |
| --- | --- | --- |
| Open WiFi | 40 | CRITICAL |
| WEP WiFi | 35 | CRITICAL |
| BLE / GATT exposed | 25 | HIGH |
| UPnP responding | 25 | HIGH |
| Classic Bluetooth | 15 | MEDIUM |
| WPA/WPA2 WiFi | 10 | MEDIUM |
| mDNS service (per svc) | 10 | MEDIUM |

Grade thresholds: **S** ≥ 100 · **A** ≥ 70 · **B** ≥ 45 · **C** ≥ 20 · **D** < 20

Higher grade = more attack vectors = better target.

**Deep recon** (tap a device)

Runs automatically against the selected device in order:

1. `nmap -sV -O --top-ports 50` — open ports, service versions, OS fingerprint
2. `gatttool --primary` (fallback: `bluetoothctl info`) — GATT service enumeration
3. `nmap --script upnp-info` — UPnP device description (if UPnP detected)
4. NVD CVE API — known CVEs for the detected vendor or SSID keyword

Tap *◀ Back* to return to the device list at any time.
