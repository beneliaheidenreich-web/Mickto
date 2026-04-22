# Mickto

**Mini Hacking Tool** — a Raspberry Pi device running Kali Linux.

## Hardware

- **Wi-Fi Adapters**
  - `wlan0` — Access Point for SSH connectivity
  - `wlan1` — Dual-band adapter for wireless attacks
- **GPIO** — LCD touchscreen; tap to launch scripts
- **Power** — Battery connected via bottom GPIO pins

## Scripts

### Aircrack Automation

Automates WPA handshake capture and cracking.

1. Select a target Wi-Fi network
2. Listen for WPA handshakes on the target network
3. Crack captured handshakes using a wordlist

If no handshake is captured, the user can broadcast deauthentication packets to all clients (`FF:FF:FF:FF:FF:FF`) to force reconnections and improve the chance of catching a handshake.
