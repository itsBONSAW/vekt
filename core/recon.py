import subprocess
import threading
import time
import re
import pty
import os
import select
from datetime import datetime

class ReconEngine:
    def __init__(self, interface, on_log_callback, on_update_callback):
        self.interface = interface
        self.on_log = on_log_callback
        self.on_update = on_update_callback
        self.networks_db = {}
        self.running = False
        self.airodump_proc = None
        self.wash_process = None
        self.ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        self.csv_file = "/tmp/vekt_scan-01.csv"

    def setup_interface(self):
        self.on_log(f"[*] Putting {self.interface} in monitor mode...")
        subprocess.run(["systemctl", "stop", "NetworkManager", "wpa_supplicant"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["rfkill", "unblock", "wlan"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", self.interface, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iw", "dev", self.interface, "set", "type", "monitor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", self.interface, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.on_log(f"[+] {self.interface} is in MONITOR Mode.")

    def start(self):
        self.running = True
        self.setup_interface()
        
        # Clean old CSV
        if os.path.exists(self.csv_file): os.remove(self.csv_file)
        
        self.airodump_thread = threading.Thread(target=self._airodump_loop, daemon=True)
        self.wash_thread = threading.Thread(target=self._wash_loop, daemon=True)
        
        self.airodump_thread.start()
        self.wash_thread.start()

    def stop(self):
        self.running = False
        if self.airodump_proc:
            self.airodump_proc.terminate()
            self.airodump_proc.wait()
        if self.wash_process:
            self.wash_process.terminate()
            self.wash_process.wait()
        self.on_log("[!] Recon stopped.")

    def _airodump_loop(self):
        # Run airodump to catch ALL networks, regardless of WPS
        cmd = ["airodump-ng", "-w", "/tmp/vekt_scan", "--output-format", "csv", self.interface]
        self.airodump_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        while self.running:
            time.sleep(1.5)
            if not os.path.exists(self.csv_file): continue
            try:
                with open(self.csv_file, 'r', errors='ignore') as f:
                    lines = f.readlines()
                
                for line in lines:
                    if "Station MAC" in line: break # Reached client section
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 14 and re.match(r'^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:', parts[0]):
                        bssid = parts[0]
                        if bssid == "00:00:00:00:00:00": continue
                        
                        essid = parts[13] if len(parts) > 13 else "Hidden"
                        if not essid: essid = "Hidden"
                        channel = parts[3] if parts[3] else "?"
                        signal = parts[8] if parts[8] else "-100"
                        
                        if bssid not in self.networks_db:
                            self.networks_db[bssid] = {
                                "bssid": bssid,
                                "essid": essid,
                                "channel": channel,
                                "signal_dbm": signal,
                                "wps_status": "Unknown" # Default status until wash sees it
                            }
                            self.on_log(f"[+] New Network: {essid} ({bssid})")
                        else:
                            # Update dynamic info
                            self.networks_db[bssid]["signal_dbm"] = signal
                            self.networks_db[bssid]["essid"] = essid
                            self.networks_db[bssid]["channel"] = channel
                            
                    self.on_update(self.networks_db)
            except Exception:
                pass

    def _wash_loop(self):
        master, slave = pty.openpty()
        cmd = ["wash", "-i", self.interface]
        self.wash_process = subprocess.Popen(cmd, stdout=slave, stderr=slave, text=True)
        os.close(slave)
        
        while self.running:
            rlist, _, _ = select.select([master], [], [], 1.0)
            if rlist:
                try:
                    data = os.read(master, 4096).decode('utf-8', errors='ignore')
                    if not data: continue
                    for line in data.splitlines():
                        self._process_wash_line(line)
                except OSError:
                    break
            if self.wash_process.poll() is not None:
                break

    def _process_wash_line(self, line):
        line = self.ansi_escape.sub('', line).strip()
        if not line or "BSSID" in line or "---" in line: return
            
        parts = re.split(r'\s+', line)
        if len(parts) >= 6 and re.match(r'^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:', parts[0]):
            bssid = parts[0]
            lock_status = parts[4]
            wps_status = "Unlocked" if lock_status == "No" else "Locked"
            
            if bssid in self.networks_db:
                if self.networks_db[bssid]["wps_status"] != wps_status:
                    self.networks_db[bssid]["wps_status"] = wps_status
                    self.on_log(f"[*] WPS detected for {bssid}: {wps_status}")
            else:
                # If wash sees a network airodump hasn't parsed yet, add it
                self.networks_db[bssid] = {
                    "bssid": bssid,
                    "essid": " ".join(parts[6:]) if len(parts) > 6 else "Hidden",
                    "channel": parts[1],
                    "signal_dbm": parts[2],
                    "wps_status": wps_status
                }
            
            self.on_update(self.networks_db)


class TargetScanner:
    def __init__(self, interface, bssid, channel, essid, on_log, on_station):
        self.interface = interface
        self.bssid = bssid
        self.channel = str(channel)
        self.essid = essid
        self.on_log = on_log
        self.on_station = on_station
        self.process = None
        self.running = False
        self.csv_file = "/tmp/vekt_target-01.csv"

    def start(self):
        if os.path.exists(self.csv_file): os.remove(self.csv_file)
        self.running = True
        self.on_log(f"[*] Focusing on {self.essid} (Ch {self.channel})...")
        cmd = ["airodump-ng", "--bssid", self.bssid, "-c", self.channel, "-w", "/tmp/vekt_target", "--output-format", "csv", self.interface]
        self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.thread = threading.Thread(target=self._read_csv, daemon=True)
        self.thread.start()

    def _read_csv(self):
        while self.running:
            time.sleep(1.5)
            if not os.path.exists(self.csv_file): continue
            try:
                with open(self.csv_file, 'r', errors='ignore') as f:
                    lines = f.readlines()
                stations = []
                in_station_section = False
                for line in lines:
                    if "Station MAC" in line:
                        in_station_section = True
                        continue
                    if in_station_section and line.strip():
                        parts = [p.strip() for p in line.split(',')]
                        if len(parts) >= 6:
                            st_mac = parts[0]
                            st_power = parts[3]
                            if st_mac and st_mac != self.bssid:
                                stations.append({"mac": st_mac, "pwr": st_power})
                self.on_station(stations)
            except Exception:
                pass

    def stop(self):
        self.running = False
        if self.process:
            self.process.terminate()
            self.process.wait()
        self.on_log("[*] Target monitoring stopped.")
