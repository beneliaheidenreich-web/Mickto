#!/usr/bin/env python3
"""
Recon — device discovery, correlation, attack-surface grading, deep recon.

Scan phase (parallel):  WiFi APs · ARP hosts · mDNS · UPnP/SSDP
Sequential (one HCI):   Classic BT · BLE

Correlation:  merges records using MAC OUI + ±3 heuristic, name/IP matching.
Grade:        S/A/B/C/D from weighted attack-vector score.
Deep recon:   nmap · GATT · UPnP details · NVD CVE lookup.
"""

import json
import re
import socket
import subprocess
import threading
import time
import tkinter as tk
import urllib.parse
import urllib.request
from tkinter import scrolledtext

# ── Colours (matches wifi_ui.py) ───────────────────────────────────────────────
APP_BG  = "#000000"
CARD_BG = "#0d0d0d"
TEXT    = "#d4d4d4"
MUTED   = "#4a4a4a"
ACCENT  = "#00ff41"
SUCCESS = "#00cc44"
DANGER  = "#cc2200"
WARN    = "#ff9900"
BORDER  = "#1f1f1f"

GRADE_COLOR = {
    "S": "#ff00ff",
    "A": "#ff4444",
    "B": "#ff9900",
    "C": "#ffff00",
    "D": "#00cc44",
}

WIFI_IFACE = "wlan1"

# ── Attack-vector registry ──────────────────────────────────────────────────────
# key: (display label, base score per instance, quality tier)
VECTORS = {
    "wifi_open":  ("Open WiFi",    40, "CRITICAL"),
    "wifi_wep":   ("WEP WiFi",     35, "CRITICAL"),
    "wifi_wpa":   ("WPA WiFi",     10, "MEDIUM"),
    "ble":        ("BLE/GATT",     25, "HIGH"),
    "bt_classic": ("Classic BT",   15, "MEDIUM"),
    "upnp":       ("UPnP",         25, "HIGH"),
    "mdns":       ("mDNS svc",     10, "MEDIUM"),  # × count, capped at 3
}

GRADE_THRESHOLDS = [(100, "S"), (70, "A"), (45, "B"), (20, "C"), (0, "D")]


def _score_to_grade(score: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "D"


# ── Device model ────────────────────────────────────────────────────────────────

class Device:
    def __init__(self):
        self.ip        = None   # from arp-scan or mDNS
        self.wifi_mac  = None   # client MAC (arp-scan)
        self.bssid     = None   # AP BSSID (nmcli)
        self.ssid      = None
        self.signal    = None
        self.security  = None   # "Open", "WPA2", "WEP", …
        self.bt_mac    = None   # Classic BT
        self.ble_mac   = None
        self.name      = None   # BT name or mDNS hostname
        self.vendor    = None   # OUI vendor string (arp-scan)
        self.mdns_svcs = []
        self.upnp      = False
        self.vectors   = {}     # key → True | int(count)
        self.score     = 0
        self.grade     = "D"

    def display_name(self) -> str:
        for v in (self.ssid, self.name, self.vendor,
                  self.ip, self.bssid, self.bt_mac, self.ble_mac):
            if v:
                return str(v)
        return "Unknown"

    def compute_score(self):
        self.vectors = {}

        if self.security:
            sec = self.security.upper()
            if "WEP" in sec:
                self.vectors["wifi_wep"] = True
            elif not self.security.strip() or sec in ("OPEN", "NONE", "--"):
                self.vectors["wifi_open"] = True
            elif "WPA" in sec:
                self.vectors["wifi_wpa"] = True

        if self.bt_mac:
            self.vectors["bt_classic"] = True
        if self.ble_mac:
            self.vectors["ble"] = True
        if self.upnp:
            self.vectors["upnp"] = True
        if self.mdns_svcs:
            self.vectors["mdns"] = len(self.mdns_svcs)

        score = 0
        for key, val in self.vectors.items():
            if key not in VECTORS:
                continue
            _, base, _ = VECTORS[key]
            count = val if isinstance(val, int) else 1
            score += base * min(count, 3)

        self.score = score
        self.grade = _score_to_grade(score)


# ── MAC utilities ───────────────────────────────────────────────────────────────

def _mac_digits(mac: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", mac)

def _mac_oui(mac: str) -> str:
    return _mac_digits(mac).upper()[:6]

def _mac_int(mac: str) -> int:
    d = _mac_digits(mac)
    return int(d, 16) if len(d) == 12 else -1

def macs_likely_same(mac1: str, mac2: str, delta: int = 3) -> bool:
    if not mac1 or not mac2:
        return False
    if _mac_oui(mac1) != _mac_oui(mac2):
        return False
    return abs(_mac_int(mac1) - _mac_int(mac2)) <= delta


# ── Scan functions ──────────────────────────────────────────────────────────────

def _scan_wifi_aps(status_cb) -> list:
    """Returns [(ssid, bssid, signal, security)]."""
    status_cb("Scanning WiFi APs…")
    try:
        subprocess.run(
            ["nmcli", "device", "wifi", "rescan", "ifname", WIFI_IFACE],
            capture_output=True, timeout=8
        )
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["nmcli", "-f", "SSID,BSSID,SIGNAL,SECURITY",
             "device", "wifi", "list", "ifname", WIFI_IFACE],
            capture_output=True, text=True, timeout=15
        )
        bssid_re = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
        results, seen = [], set()
        for line in r.stdout.splitlines()[1:]:   # skip header
            m = bssid_re.search(line)
            if not m:
                continue
            bssid = m.group(1).upper()
            if bssid in seen:
                continue
            seen.add(bssid)
            ssid     = line[:m.start()].strip() or "<hidden>"
            post     = line[m.end():].strip().split()
            signal   = post[0] if post else "0"
            security = post[1] if len(post) > 1 else "Open"
            results.append((ssid, bssid, signal, security))
        return results
    except Exception:
        return []


def _scan_arp_hosts(status_cb) -> list:
    """Returns [(ip, mac, vendor)]."""
    status_cb("ARP-scanning network…")
    try:
        r = subprocess.run(
            ["sudo", "arp-scan", "-l"],
            capture_output=True, text=True, timeout=20
        )
        results = []
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[0] and parts[0][0].isdigit():
                results.append((
                    parts[0].strip(),
                    parts[1].strip().upper(),
                    parts[2].strip() if len(parts) > 2 else "",
                ))
        return results
    except Exception:
        return []


def _scan_bt_classic(status_cb) -> list:
    """Returns [(mac, name)]. Blocks ~8 s."""
    status_cb("Classic BT scan (8 s)…")
    try:
        proc = subprocess.Popen(
            ["sudo", "hcitool", "scan", "--flush"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        time.sleep(8)
        proc.terminate()
        out, _ = proc.communicate(timeout=3)
        results = []
        for line in out.splitlines():
            if not line.strip() or "Scanning" in line:
                continue
            parts = line.strip().split(None, 1)
            if parts:
                results.append((parts[0].upper(), parts[1] if len(parts) > 1 else ""))
        return results
    except Exception:
        return []


def _scan_ble(status_cb) -> list:
    """Returns [(mac, name)]. Blocks ~6 s."""
    status_cb("BLE scan (6 s)…")
    try:
        proc = subprocess.Popen(
            ["sudo", "hcitool", "lescan", "--duplicates"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        time.sleep(6)
        proc.terminate()
        out, _ = proc.communicate(timeout=3)
        seen, results = set(), []
        for line in out.splitlines():
            if not line.strip() or "LE Scan" in line:
                continue
            parts = line.strip().split(None, 1)
            if parts and re.match(r"^[0-9A-Fa-f:]{17}$", parts[0]):
                mac = parts[0].upper()
                if mac not in seen:
                    seen.add(mac)
                    results.append((mac, parts[1] if len(parts) > 1 else ""))
        return results
    except Exception:
        return []


def _scan_mdns(status_cb) -> list:
    """Returns [(hostname, ip, service_type)] via avahi-browse."""
    status_cb("mDNS scan…")
    try:
        r = subprocess.run(
            ["avahi-browse", "-a", "-t", "-r", "-p"],
            capture_output=True, text=True, timeout=12
        )
        seen, results = set(), []
        for line in r.stdout.splitlines():
            if not line.startswith("="):
                continue
            parts = line.split(";")
            if len(parts) < 9:
                continue
            svc_type, hostname, ip = parts[4], parts[6], parts[7]
            key = (hostname, ip)
            if key not in seen and ip:
                seen.add(key)
                results.append((hostname, ip, svc_type))
        return results
    except Exception:
        return []


def _scan_upnp(status_cb) -> set:
    """Returns set of IPs that answered SSDP M-SEARCH."""
    status_cb("UPnP/SSDP discovery…")
    ips = set()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(3)
        msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST:239.255.255.250:1900\r\n"
            "ST:upnp:rootdevice\r\n"
            'MAN:"ssdp:discover"\r\n'
            "MX:2\r\n\r\n"
        ).encode()
        sock.sendto(msg, ("239.255.255.250", 1900))
        deadline = time.time() + 3
        while time.time() < deadline:
            try:
                _, addr = sock.recvfrom(1024)
                ips.add(addr[0])
            except socket.timeout:
                break
        sock.close()
    except Exception:
        pass
    return ips


# ── Correlation ─────────────────────────────────────────────────────────────────

def correlate(wifi_aps, arp_hosts, bt_classic, ble_devices,
              mdns_svcs, upnp_ips) -> list:
    devices: list = []
    by_ip:   dict = {}
    by_mac:  dict = {}

    def _find_by_mac(mac: str):
        key = mac.upper()
        if key in by_mac:
            return by_mac[key]
        for k, d in by_mac.items():
            if macs_likely_same(mac, k):
                return d
        return None

    def _register(dev, ip=None, macs=None):
        devices.append(dev)
        if ip:
            by_ip[ip] = dev
        for m in (macs or []):
            if m:
                by_mac[m.upper()] = dev

    # 1. ARP hosts — carry IP, most actionable
    for ip, mac, vendor in arp_hosts:
        dev = Device()
        dev.ip, dev.wifi_mac, dev.vendor = ip, mac, vendor
        _register(dev, ip=ip, macs=[mac])

    # 2. WiFi APs — try to merge with ARP host at MAC ± 3
    for ssid, bssid, signal, security in wifi_aps:
        dev = _find_by_mac(bssid)
        if dev:
            dev.bssid, dev.ssid, dev.signal, dev.security = bssid, ssid, signal, security
            by_mac[bssid] = dev
        else:
            dev = Device()
            dev.bssid, dev.ssid, dev.signal, dev.security = bssid, ssid, signal, security
            _register(dev, macs=[bssid])

    # 3. Classic BT
    for mac, name in bt_classic:
        dev = _find_by_mac(mac)
        if dev:
            dev.bt_mac = mac
            dev.name = dev.name or name or None
            by_mac[mac] = dev
        else:
            dev = Device()
            dev.bt_mac, dev.name = mac, name or None
            _register(dev, macs=[mac])

    # 4. BLE
    for mac, name in ble_devices:
        dev = _find_by_mac(mac)
        if dev:
            dev.ble_mac = mac
            dev.name = dev.name or name or None
            by_mac[mac] = dev
        else:
            dev = Device()
            dev.ble_mac, dev.name = mac, name or None
            _register(dev, macs=[mac])

    # 5. mDNS — match by IP, then by hostname similarity
    for hostname, ip, svc_type in mdns_svcs:
        if ip in by_ip:
            dev = by_ip[ip]
        else:
            dev = None
            short = hostname.split(".")[0].lower()
            for d in devices:
                if d.name and short in d.name.lower():
                    dev = d
                    break
            if dev is None:
                dev = Device()
                dev.ip, dev.name = ip, hostname
                _register(dev, ip=ip)
            elif ip and not dev.ip:
                dev.ip = ip
                by_ip[ip] = dev
        dev.name = dev.name or hostname
        if svc_type not in dev.mdns_svcs:
            dev.mdns_svcs.append(svc_type)

    # 6. UPnP
    for ip in upnp_ips:
        if ip in by_ip:
            by_ip[ip].upnp = True
        else:
            dev = Device()
            dev.ip, dev.upnp = ip, True
            _register(dev, ip=ip)

    for dev in devices:
        dev.compute_score()
    devices.sort(key=lambda d: d.score, reverse=True)
    return devices


# ── App ──────────────────────────────────────────────────────────────────────────

class ReconApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Recon")
        self.root.configure(bg=APP_BG)
        self.root.attributes("-fullscreen", True)

        self.scanning  = False
        self.devices   = []
        self._deep_gen = 0  # incremented on each deep-recon start to cancel stale threads

        self.list_page = tk.Frame(root, bg=APP_BG)
        self.deep_page = tk.Frame(root, bg=APP_BG)

        self._build_list_page()
        self._build_deep_page()
        self._show_list_page()

    # ── Page switching ─────────────────────────────────────────────────────────

    def _show_list_page(self):
        self._deep_gen += 1          # cancel any running deep-recon thread
        self.deep_page.pack_forget()
        self.list_page.pack(fill="both", expand=True)

    def _show_deep_page(self, device: Device):
        self.list_page.pack_forget()
        self.deep_page.pack(fill="both", expand=True)
        self._start_deep_recon(device)

    # ── List page ──────────────────────────────────────────────────────────────

    def _build_list_page(self):
        self.list_page.grid_rowconfigure(1, weight=1)
        self.list_page.grid_columnconfigure(0, weight=1)

        bar = tk.Frame(self.list_page, bg=APP_BG)
        bar.grid(row=0, column=0, sticky="ew", padx=8, pady=6)
        bar.grid_columnconfigure(0, weight=1)

        tk.Label(bar, text="Recon", font=("Arial", 14, "bold"),
                 bg=APP_BG, fg=TEXT, anchor="w").grid(row=0, column=0, sticky="w")

        self.scan_btn = tk.Button(
            bar, text="Scan All", font=("Arial", 12, "bold"),
            bg=SUCCESS, fg="white", bd=0, padx=12, pady=4,
            command=self._start_scan
        )
        self.scan_btn.grid(row=0, column=1, sticky="e", padx=(0, 6))

        tk.Button(bar, text="✕", font=("Arial", 14, "bold"),
                  bg=DANGER, fg="white", bd=0, padx=10, pady=4,
                  command=self.root.destroy).grid(row=0, column=2, sticky="e")

        cnt = tk.Frame(self.list_page, bg=APP_BG)
        cnt.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)
        cnt.grid_rowconfigure(0, weight=1)
        cnt.grid_columnconfigure(0, weight=1)

        self.list_canvas = tk.Canvas(cnt, bg=APP_BG, highlightthickness=0)
        vsb = tk.Scrollbar(cnt, orient="vertical", command=self.list_canvas.yview)
        self.list_canvas.configure(yscrollcommand=vsb.set)
        self.list_canvas.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        self.dev_frame = tk.Frame(self.list_canvas, bg=APP_BG)
        self._cw = self.list_canvas.create_window((0, 0), window=self.dev_frame, anchor="nw")
        self.dev_frame.bind(
            "<Configure>",
            lambda e: self.list_canvas.configure(
                scrollregion=self.list_canvas.bbox("all"))
        )
        self.list_canvas.bind(
            "<Configure>",
            lambda e: self.list_canvas.itemconfigure(self._cw, width=e.width)
        )
        # Touch/scroll wheel support
        self.list_canvas.bind("<Button-4>",
                              lambda e: self.list_canvas.yview_scroll(-1, "units"))
        self.list_canvas.bind("<Button-5>",
                              lambda e: self.list_canvas.yview_scroll(1, "units"))

        self.status_var = tk.StringVar(value="Press 'Scan All' to begin.")
        tk.Label(self.list_page, textvariable=self.status_var,
                 font=("Arial", 9), bg=APP_BG, fg=MUTED, anchor="w"
                 ).grid(row=2, column=0, sticky="ew", padx=10, pady=(2, 6))

        tk.Label(self.dev_frame, text="No scan yet.",
                 font=("Consolas", 10), bg=APP_BG, fg=MUTED).pack(pady=20)

    def _render_device_list(self):
        for w in self.dev_frame.winfo_children():
            w.destroy()

        if not self.devices:
            tk.Label(self.dev_frame, text="No devices found.",
                     font=("Consolas", 10), bg=APP_BG, fg=MUTED).pack(pady=20)
            return

        for dev in self.devices:
            self._render_device_row(dev)

    def _render_device_row(self, dev: Device):
        gc  = GRADE_COLOR[dev.grade]
        row = tk.Frame(self.dev_frame, bg=CARD_BG,
                       highlightthickness=1, highlightbackground=BORDER)
        row.pack(fill="x", pady=3)
        row.grid_columnconfigure(1, weight=1)

        badge = tk.Label(row, text=f" {dev.grade} ",
                         font=("Arial", 15, "bold"),
                         bg=gc, fg="#000000", width=2)
        badge.grid(row=0, column=0, rowspan=3, padx=(0, 8), sticky="ns", pady=4)

        tk.Label(row, text=dev.display_name()[:30],
                 font=("Consolas", 10, "bold"), bg=CARD_BG, fg=TEXT, anchor="w"
                 ).grid(row=0, column=1, sticky="ew", pady=(4, 0))

        ids = [x for x in [dev.ip, dev.bssid, dev.bt_mac, dev.ble_mac] if x]
        tk.Label(row, text="  ".join(ids)[:50],
                 font=("Consolas", 7), bg=CARD_BG, fg=MUTED, anchor="w"
                 ).grid(row=1, column=1, sticky="ew")

        vec_parts = []
        for key, val in dev.vectors.items():
            if key not in VECTORS:
                continue
            label, _, quality = VECTORS[key]
            prefix = "⚠" if quality == "CRITICAL" else ("●" if quality == "HIGH" else "·")
            count  = val if isinstance(val, int) else 1
            vec_parts.append(f"{prefix}{label}" + (f"×{count}" if count > 1 else ""))
        tk.Label(row, text="  ".join(vec_parts) if vec_parts else "No vectors",
                 font=("Consolas", 7), bg=CARD_BG, fg=gc, anchor="w"
                 ).grid(row=2, column=1, sticky="ew", pady=(0, 4))

        tk.Label(row, text=f"{dev.score}pt",
                 font=("Arial", 8), bg=CARD_BG, fg=MUTED
                 ).grid(row=0, column=2, padx=6, pady=(4, 0))

        def _on_click(e, d=dev):
            self._show_deep_page(d)

        for w in [row, badge] + list(row.winfo_children()):
            w.bind("<Button-1>", _on_click)

    # ── Deep recon page ────────────────────────────────────────────────────────

    def _build_deep_page(self):
        self.deep_page.grid_rowconfigure(1, weight=1)
        self.deep_page.grid_columnconfigure(0, weight=1)

        bar = tk.Frame(self.deep_page, bg=APP_BG)
        bar.grid(row=0, column=0, sticky="ew", padx=8, pady=6)
        bar.grid_columnconfigure(1, weight=1)

        tk.Button(bar, text="◀ Back", font=("Arial", 11, "bold"),
                  bg=CARD_BG, fg=TEXT, bd=0, padx=10, pady=4,
                  command=self._show_list_page).grid(row=0, column=0, sticky="w", padx=(0, 8))

        self.deep_title = tk.Label(bar, text="",
                                   font=("Arial", 12, "bold"),
                                   bg=APP_BG, fg=ACCENT, anchor="w")
        self.deep_title.grid(row=0, column=1, sticky="ew")

        tk.Button(bar, text="✕", font=("Arial", 14, "bold"),
                  bg=DANGER, fg="white", bd=0, padx=10, pady=4,
                  command=self.root.destroy).grid(row=0, column=2, sticky="e")

        self.deep_out = scrolledtext.ScrolledText(
            self.deep_page, font=("Consolas", 8), bg=CARD_BG, fg=TEXT,
            wrap="word", relief="flat", borderwidth=0, state="disabled"
        )
        self.deep_out.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 4))
        self.deep_out.tag_config("h",    foreground=ACCENT,  font=("Consolas", 9, "bold"))
        self.deep_out.tag_config("ok",   foreground=SUCCESS)
        self.deep_out.tag_config("dim",  foreground=MUTED)
        self.deep_out.tag_config("err",  foreground=DANGER)
        self.deep_out.tag_config("warn", foreground=WARN)

        self.deep_status = tk.StringVar(value="")
        tk.Label(self.deep_page, textvariable=self.deep_status,
                 font=("Arial", 9), bg=APP_BG, fg=MUTED, anchor="w"
                 ).grid(row=2, column=0, sticky="ew", padx=10, pady=(2, 6))

    def _dwrite(self, text, tag="", gen=None):
        if gen is not None and gen != self._deep_gen:
            return

        def _do():
            self.deep_out.configure(state="normal")
            self.deep_out.insert(tk.END, text, tag)
            self.deep_out.see(tk.END)
            self.deep_out.configure(state="disabled")
        self.root.after(0, _do)

    def _dstatus(self, text, gen=None):
        if gen is not None and gen != self._deep_gen:
            return
        self.root.after(0, lambda: self.deep_status.set(text))

    def _start_deep_recon(self, dev: Device):
        self._deep_gen += 1
        gen = self._deep_gen

        self.deep_out.configure(state="normal")
        self.deep_out.delete("1.0", tk.END)
        self.deep_out.configure(state="disabled")
        self.deep_title.configure(text=dev.display_name()[:32])

        # Device summary
        self._dwrite(f"\n  {dev.display_name()}\n", "h")
        for label, val in [
            ("IP",    dev.ip),
            ("MAC",   f"{dev.wifi_mac}  ({dev.vendor})" if dev.wifi_mac else None),
            ("BSSID", dev.bssid),
            ("SSID",  f"{dev.ssid}  [{dev.security}]" if dev.ssid else None),
            ("BT",    dev.bt_mac),
            ("BLE",   dev.ble_mac),
            ("mDNS",  ", ".join(dev.mdns_svcs) if dev.mdns_svcs else None),
        ]:
            if val:
                self._dwrite(f"  {label:<6} {val}\n")

        # Grade breakdown
        self._dwrite(f"\n  Grade {dev.grade}  ·  {dev.score} pts\n", "h")
        for key, val in dev.vectors.items():
            if key not in VECTORS:
                continue
            label, base, quality = VECTORS[key]
            count = val if isinstance(val, int) else 1
            pts   = base * min(count, 3)
            self._dwrite(f"  [{quality[:4]}]  {label}  +{pts}\n")

        threading.Thread(target=self._deep_thread, args=(dev, gen), daemon=True).start()

    def _deep_thread(self, dev: Device, gen: int):
        if dev.ip:
            self._dstatus("nmap scanning…", gen)
            self._deep_nmap(dev.ip, gen)

        bt_target = dev.bt_mac or dev.ble_mac
        if bt_target:
            self._dstatus("GATT enumeration…", gen)
            self._deep_gatt(bt_target, gen)

        if dev.upnp and dev.ip:
            self._dstatus("UPnP details…", gen)
            self._deep_upnp(dev.ip, gen)

        vendor_kw = dev.vendor or dev.ssid
        if vendor_kw:
            self._dstatus("CVE lookup…", gen)
            self._deep_cve(vendor_kw, gen)

        self._dstatus("Deep recon complete.", gen)
        self._dwrite("\n  ✓ Done\n", "ok", gen)

    def _deep_nmap(self, ip: str, gen: int):
        self._dwrite(f"\n  Nmap — {ip}\n", "h", gen)
        self._dwrite("  " + "─" * 38 + "\n", "dim", gen)
        try:
            r = subprocess.run(
                ["nmap", "-sV", "-O", "--top-ports", "50", "-T4", ip],
                capture_output=True, text=True, timeout=120
            )
            if gen != self._deep_gen:
                return
            found = False
            for line in r.stdout.splitlines():
                l = line.strip()
                if any(k in l for k in ("PORT", "/tcp", "/udp", "OS:", "Running:", "Service Info")):
                    tag = "ok" if "open" in l else ("dim" if ("closed" in l or "filtered" in l) else "")
                    self._dwrite(f"  {l}\n", tag, gen)
                    found = True
            if not found:
                self._dwrite("  No open ports found\n", "dim", gen)
        except FileNotFoundError:
            self._dwrite("  nmap not installed\n", "err", gen)
        except Exception as e:
            self._dwrite(f"  nmap error: {e}\n", "err", gen)

    def _deep_gatt(self, mac: str, gen: int):
        self._dwrite(f"\n  GATT — {mac}\n", "h", gen)
        self._dwrite("  " + "─" * 38 + "\n", "dim", gen)
        try:
            r = subprocess.run(
                ["gatttool", "-b", mac, "--primary"],
                capture_output=True, text=True, timeout=20
            )
            if gen != self._deep_gen:
                return
            if r.stdout.strip():
                for line in r.stdout.splitlines():
                    self._dwrite(f"  {line.strip()}\n", "ok", gen)
            else:
                self._dwrite("  No services found (may need pairing)\n", "dim", gen)
        except FileNotFoundError:
            try:
                r = subprocess.run(
                    ["bluetoothctl", "info", mac],
                    capture_output=True, text=True, timeout=12
                )
                if gen != self._deep_gen:
                    return
                for line in r.stdout.splitlines():
                    if line.strip():
                        self._dwrite(f"  {line.strip()}\n", gen=gen)
            except Exception as e2:
                self._dwrite(f"  BT tools unavailable: {e2}\n", "err", gen)
        except Exception as e:
            self._dwrite(f"  GATT error: {e}\n", "err", gen)

    def _deep_upnp(self, ip: str, gen: int):
        self._dwrite(f"\n  UPnP — {ip}\n", "h", gen)
        self._dwrite("  " + "─" * 38 + "\n", "dim", gen)
        try:
            r = subprocess.run(
                ["nmap", "-p", "1900,49152-49155", "--script", "upnp-info", ip],
                capture_output=True, text=True, timeout=30
            )
            if gen != self._deep_gen:
                return
            found = False
            for line in r.stdout.splitlines():
                if line.strip().startswith("|"):
                    self._dwrite(f"  {line.strip()}\n", "ok", gen)
                    found = True
            if not found:
                self._dwrite("  No UPnP details retrieved\n", "dim", gen)
        except Exception as e:
            self._dwrite(f"  UPnP error: {e}\n", "err", gen)

    def _deep_cve(self, keyword: str, gen: int):
        kw = keyword.split()[0]
        self._dwrite(f"\n  CVEs — {kw}\n", "h", gen)
        self._dwrite("  " + "─" * 38 + "\n", "dim", gen)
        try:
            q   = urllib.parse.quote(kw)
            url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                   f"?keywordSearch={q}&resultsPerPage=5")
            req = urllib.request.Request(url, headers={"User-Agent": "Mickto/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())

            if gen != self._deep_gen:
                return
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                self._dwrite(f"  No CVEs found for '{kw}'\n", "dim", gen)
                return

            for item in vulns:
                cve   = item.get("cve", {})
                cid   = cve.get("id", "?")
                descs = cve.get("descriptions", [])
                desc  = next((d["value"] for d in descs if d["lang"] == "en"), "")
                metrics = cve.get("metrics", {})
                cvss  = "N/A"
                for ver in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metrics.get(ver):
                        cvss = metrics[ver][0].get("cvssData", {}).get("baseScore", "N/A")
                        break
                self._dwrite(f"  {cid}  CVSS:{cvss}\n", "ok", gen)
                self._dwrite(f"  {desc[:110]}…\n", "dim", gen)
        except Exception as e:
            self._dwrite(f"  CVE lookup failed (no internet?): {e}\n", "err", gen)

    # ── Scan orchestration ─────────────────────────────────────────────────────

    def _start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.scan_btn.configure(state="disabled", text="Scanning…", bg=MUTED)
        for w in self.dev_frame.winfo_children():
            w.destroy()
        tk.Label(self.dev_frame, text="Scanning… (~15 s)",
                 font=("Consolas", 9), bg=APP_BG, fg=MUTED).pack(pady=20)
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _set_status(self, text: str):
        self.root.after(0, lambda: self.status_var.set(text))

    def _scan_thread(self):
        results = {
            "wifi_aps":  [],
            "arp_hosts": [],
            "mdns":      [],
            "upnp_ips":  set(),
        }

        def _run(key, fn):
            results[key] = fn(self._set_status)

        threads = [
            threading.Thread(target=_run, args=("wifi_aps",  _scan_wifi_aps),  daemon=True),
            threading.Thread(target=_run, args=("arp_hosts", _scan_arp_hosts), daemon=True),
            threading.Thread(target=_run, args=("mdns",      _scan_mdns),      daemon=True),
            threading.Thread(target=_run, args=("upnp_ips",  _scan_upnp),      daemon=True),
        ]
        for t in threads:
            t.start()

        bt_classic = _scan_bt_classic(self._set_status)
        ble        = _scan_ble(self._set_status)

        for t in threads:
            t.join()

        self._set_status("Correlating…")
        self.devices = correlate(
            results["wifi_aps"], results["arp_hosts"],
            bt_classic, ble,
            results["mdns"], results["upnp_ips"]
        )
        self.root.after(0, self._scan_done)

    def _scan_done(self):
        self.scanning = False
        self.scan_btn.configure(state="normal", text="Scan All", bg=SUCCESS)
        self._render_device_list()
        n = len(self.devices)
        self.status_var.set(
            f"{n} device{'s' if n != 1 else ''} found.  Tap to deep-recon."
        )


if __name__ == "__main__":
    root = tk.Tk()
    ReconApp(root)
    root.mainloop()
