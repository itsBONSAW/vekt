import subprocess
import threading
import os

class CrackerEngine:
    def __init__(self, cap_file, wordlist, on_log, on_success):
        self.cap_file = cap_file
        self.wordlist = wordlist
        self.on_log = on_log
        self.on_success = on_success
        self.process = None
        self.stop_event = threading.Event()
        self.hash_file = "/tmp/vekt_hash.hc22000"

    def start(self):
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._crack_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.process:
            self.process.terminate()
        self.on_log("[!] Cracking stopped.")

    def _crack_loop(self):
        self.on_log(f"[*] Converting {self.cap_file} to hashcat format...")
        if os.path.exists(self.hash_file):
            os.remove(self.hash_file)
        
        cmd_convert = ["hcxpcapngtool", "-o", self.hash_file, self.cap_file]
        self.process = subprocess.Popen(cmd_convert, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in self.process.stdout:
            if self.stop_event.is_set(): break
            if line.strip(): self.on_log(line.strip())
        self.process.wait()

        if not os.path.exists(self.hash_file) or os.path.getsize(self.hash_file) == 0:
            self.on_log("[-] Conversion failed. Handshake might be incomplete.")
            self.stop_event.set()
            return

        self.on_log(f"[+] Converted successfully. Starting Hashcat...")
        cmd_crack = ["hashcat", "-m", "22000", self.hash_file, self.wordlist, "--force", "--status", "--status-timer=5"]
        self.process = subprocess.Popen(cmd_crack, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        for line in self.process.stdout:
            if self.stop_event.is_set(): break
            if line.strip(): self.on_log(line.strip())
        self.process.wait()

        if self.stop_event.is_set(): return

        cmd_show = ["hashcat", "-m", "22000", self.hash_file, "--show", "--force"]
        result = subprocess.run(cmd_show, capture_output=True, text=True)
        output = result.stdout.strip()

        if ":" in output:
            parts = output.split(":")
            password = parts[-1]
            self.on_success("password", password)
            self.on_log(f"[+] Password Cracked: {password}")
        else:
            self.on_log("[-] Password not found in wordlist.")