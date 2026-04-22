#!/usr/bin/env python3
import subprocess
import threading
import time
import tkinter as tk
from tkinter import scrolledtext

# ── Colour scheme (matches wifi_ui.py) ────────────────────────────────────────
APP_BG  = "#0f172a"
CARD_BG = "#1e293b"
TEXT    = "#f8fafc"
MUTED   = "#94a3b8"
ACCENT  = "#38bdf8"
SUCCESS = "#22c55e"
DANGER  = "#ef4444"

WIFI_IFACE = "wlan1"


class ReconUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Recon")
        self.root.configure(bg=APP_BG)
        self.root.attributes("-fullscreen", True)
        self.scanning = False
        self._build_ui()

    # ── Layout ─────────────────────────────────────────────────────────────────

    def _build_ui(self):
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Top bar
        bar = tk.Frame(self.root, bg=APP_BG)
        bar.grid(row=0, column=0, sticky="ew", padx=8, pady=6)
        bar.grid_columnconfigure(0, weight=1)

        tk.Label(
            bar, text="Recon", font=("Arial", 14, "bold"),
            bg=APP_BG, fg=TEXT, anchor="w"
        ).grid(row=0, column=0, sticky="w")

        self.scan_btn = tk.Button(
            bar, text="Scan All", font=("Arial", 12, "bold"),
            bg=SUCCESS, fg="white", bd=0, padx=12, pady=4,
            command=self._start_scan
        )
        self.scan_btn.grid(row=0, column=1, sticky="e", padx=(0, 6))

        tk.Button(
            bar, text="✕", font=("Arial", 14, "bold"),
            bg=DANGER, fg="white", bd=0, padx=10, pady=4,
            command=self.root.destroy
        ).grid(row=0, column=2, sticky="e")

        # Scrollable output
        self.out = scrolledtext.ScrolledText(
            self.root, font=("Consolas", 8), bg=CARD_BG, fg=TEXT,
            wrap="word", relief="flat", borderwidth=0, state="disabled"
        )
        self.out.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 0))

        self.out.tag_config("h",   foreground=ACCENT,   font=("Consolas", 9, "bold"))
        self.out.tag_config("ok",  foreground=SUCCESS)
        self.out.tag_config("dim", foreground=MUTED)
        self.out.tag_config("err", foreground=DANGER)

        # Status bar
        self.status_var = tk.StringVar(value="Press 'Scan All' to begin.")
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("Arial", 9), bg=APP_BG, fg=MUTED, anchor="w"
        ).grid(row=2, column=0, sticky="ew", padx=10, pady=(2, 6))

    # ── Output helpers ─────────────────────────────────────────────────────────

    def _write(self, text, tag=""):
        def _do():
            self.out.configure(state="normal")
            self.out.insert(tk.END, text, tag)
            self.out.see(tk.END)
            self.out.configure(state="disabled")
        self.root.after(0, _do)

    def _clear(self):
        self.out.configure(state="normal")
        self.out.delete("1.0", tk.END)
        self.out.configure(state="disabled")

    def _status(self, text):
        self.root.after(0, lambda: self.status_var.set(text))

    # ── Scan orchestration ─────────────────────────────────────────────────────

    def _start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.scan_btn.config(state="disabled", text="Scanning...", bg=MUTED)
        self._clear()
        threading.Thread(target=self._run_all, daemon=True).start()

    def _run_all(self):
        self._scan_wifi()
        self._scan_bluetooth()
        self._scan_network()
        self.root.after(0, self._done)

    # ── WiFi ───────────────────────────────────────────────────────────────────

    def _scan_wifi(self):
        self._status("Scanning WiFi…")
        self._write("\n  WiFi Access Points\n", "h")
        self._write("  " + "─" * 36 + "\n", "dim")

        try:
            subprocess.run(
                ["nmcli", "device", "wifi", "rescan", "ifname", WIFI_IFACE],
                capture_output=True, timeout=8
            )
        except Exception:
            pass

        try:
            r = subprocess.run(
                ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY",
                 "device", "wifi", "list", "ifname", WIFI_IFACE],
                capture_output=True, text=True, timeout=15
            )
            lines = [l for l in r.stdout.splitlines() if l.strip()]
            if not lines:
                self._write("  No networks found\n", "dim")
                return

            seen = set()
            for line in lines:
                parts = line.split(":", 2)
                ssid = (parts[0] or "<hidden>").strip()
                sig  = parts[1].strip() if len(parts) > 1 else "0"
                sec  = (parts[2] or "Open").strip() if len(parts) > 2 else "Open"
                if ssid in seen:
                    continue
                seen.add(ssid)
                sig_int = int(sig) if sig.isdigit() else 0
                bar = "█" * (sig_int // 10) + "░" * (10 - sig_int // 10)
                self._write(f"  {ssid[:22]:<22} {bar} {sig:>3}%  {sec}\n")

        except Exception as e:
            self._write(f"  Error: {e}\n", "err")

    # ── Bluetooth ──────────────────────────────────────────────────────────────

    def _scan_bluetooth(self):
        # Classic Bluetooth
        self._status("Scanning Bluetooth (Classic, 8 s)…")
        self._write("\n  Bluetooth — Classic\n", "h")
        self._write("  " + "─" * 36 + "\n", "dim")
        try:
            proc = subprocess.Popen(
                ["sudo", "hcitool", "scan", "--flush"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            time.sleep(8)
            proc.terminate()
            out, _ = proc.communicate(timeout=3)
            found = False
            for line in out.splitlines():
                if not line.strip() or "Scanning" in line:
                    continue
                self._write(f"  {line.strip()}\n", "ok")
                found = True
            if not found:
                self._write("  None found\n", "dim")
        except Exception as e:
            self._write(f"  Error: {e}\n", "err")

        # BLE
        self._status("Scanning Bluetooth LE (6 s)…")
        self._write("\n  Bluetooth — BLE\n", "h")
        self._write("  " + "─" * 36 + "\n", "dim")
        try:
            proc = subprocess.Popen(
                ["sudo", "hcitool", "lescan", "--duplicates"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            time.sleep(6)
            proc.terminate()
            out, _ = proc.communicate(timeout=3)
            seen = set()
            found = False
            for line in out.splitlines():
                if not line.strip() or "LE Scan" in line:
                    continue
                if line not in seen:
                    seen.add(line)
                    self._write(f"  {line.strip()}\n", "ok")
                    found = True
            if not found:
                self._write("  None found\n", "dim")
        except Exception as e:
            self._write(f"  Error: {e}\n", "err")

    # ── Network (ARP) ──────────────────────────────────────────────────────────

    def _scan_network(self):
        self._status("ARP-scanning local network…")
        self._write("\n  Network Devices (ARP)\n", "h")
        self._write("  " + "─" * 36 + "\n", "dim")
        try:
            r = subprocess.run(
                ["sudo", "arp-scan", "-l"],
                capture_output=True, text=True, timeout=30
            )
            found = 0
            for line in r.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 2 and parts[0] and parts[0][0].isdigit():
                    ip     = parts[0].strip()
                    mac    = parts[1].strip()
                    vendor = parts[2].strip() if len(parts) > 2 else ""
                    self._write(f"  {ip:<16} {mac}  {vendor}\n", "ok")
                    found += 1
            if found == 0:
                self._write("  No devices found\n", "dim")
        except Exception as e:
            self._write(f"  Error: {e}\n", "err")

    # ── Finish ─────────────────────────────────────────────────────────────────

    def _done(self):
        self.scanning = False
        self.scan_btn.config(state="normal", text="Scan All", bg=SUCCESS)
        self._write("\n  ✓ Scan complete\n", "ok")
        self._status("Scan complete.")


if __name__ == "__main__":
    root = tk.Tk()
    ReconUI(root)
    root.mainloop()
