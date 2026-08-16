import subprocess
import threading
import re

class NetworkScanner:
    def __init__(self, interface, on_log_callback, on_host_callback):
        self.interface = interface
        self.on_log = on_log_callback
        self.on_host = on_host_callback
        self.stop_event = threading.Event()
        self.thread = None
        self.process = None

    def is_alive(self):
        return self.thread and self.thread.is_alive()

    def start(self, subnet="192.168.1.0/24"):
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._scan_loop, args=(subnet,), daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.process:
            self.process.terminate()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
        self.on_log("[!] Network scan stopped.")

    def _scan_loop(self, subnet):
        self.on_log(f"[*] Running nmap scan on {subnet}...")
        cmd = ["nmap", "-sn", subnet]
        hosts = []
        current_ip = None
        current_mac = None
        current_vendor = None
        current_hostname = None

        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            for line in self.process.stdout:
                if self.stop_event.is_set():
                    break
                    
                line = line.strip()

                if "Nmap scan report for" in line:
                    if current_ip:
                        hosts.append({
                            "ip": current_ip, 
                            "mac": current_mac or "Unknown", 
                            "vendor": current_vendor or "Unknown",
                            "hostname": current_hostname or "Unknown"
                        })
                        current_mac = None
                        current_vendor = None
                        current_hostname = None

                    match = re.search(r"for (?:([^\s]+)\s\()?((?:\d{1,3}\.){3}\d{1,3})\)?", line)
                    if match:
                        current_hostname = match.group(1) if match.group(1) else "Unknown"
                        current_ip = match.group(2)
                        
                elif "MAC Address:" in line:
                    match = re.search(r"MAC Address: ([0-9A-Fa-f:]{17})\s*(?:\((.*)\))?", line)
                    if match:
                        current_mac = match.group(1)
                        current_vendor = match.group(2) if match.group(2) else "Unknown"
                        self.on_log(f"[+] Host found: {current_ip} ({current_mac}) - {current_vendor}")

            if current_ip:
                hosts.append({
                    "ip": current_ip, 
                    "mac": current_mac or "Unknown", 
                    "vendor": current_vendor or "Unknown",
                    "hostname": current_hostname or "Unknown"
                })

            if not self.stop_event.is_set():
                self.on_host(hosts)
                self.on_log(f"[*] Scan complete. Found {len(hosts)} active hosts.")
                
        except Exception as e:
            self.on_log(f"[-] Scan error: {e}")