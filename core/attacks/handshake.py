from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from core.process import ManagedProcess


class HandshakeError(RuntimeError):
    pass


class HandshakeCaptureEngine:
    def __init__(
        self,
        interface: str,
        bssid: str,
        channel: str,
        essid: str,
        client_mac: str | None,
        on_log,
        on_success,
    ):
        self.interface = interface
        self.bssid = bssid
        self.channel = str(channel)
        self.essid = essid
        self.client_mac = client_mac

        self.on_log = on_log
        self.on_success = on_success

        self.stop_event = threading.Event()
        self.lifecycle_lock = threading.RLock()

        self.capture_process: ManagedProcess | None = None
        self.capture_thread: threading.Thread | None = None

        self.running = False
        self.captured = False

        self.session_dir = Path(
            tempfile.mkdtemp(
                prefix="vekt_handshake_",
            )
        )

        self.capture_base = self.session_dir / "handshake"

        self.capture_file = self.session_dir / "handshake-01.cap"

    def is_alive(self) -> bool:
        with self.lifecycle_lock:
            return self.running

    def start(self) -> None:
        with self.lifecycle_lock:
            if self.running:
                raise HandshakeError("Handshake capture is already running.")

            self._validate_inputs()

            self.stop_event.clear()
            self.captured = False
            self.running = True

            self.capture_thread = threading.Thread(
                target=self._capture_loop,
                name="vekt-handshake-capture",
                daemon=True,
            )

            self.capture_thread.start()

    def stop(self) -> None:
        with self.lifecycle_lock:
            if not self.running:
                return

            self.stop_event.set()

            process = self.capture_process

            if process is not None:
                try:
                    process.cleanup(timeout=2)
                except Exception as exc:
                    self.on_log(f"[-] Capture process cleanup failed: {exc}")
                finally:
                    self.capture_process = None

            thread = self.capture_thread

            if (
                thread is not None
                and thread.is_alive()
                and thread is not threading.current_thread()
            ):
                thread.join(timeout=3)

                if thread.is_alive():
                    self.on_log("[!] Capture worker did not terminate gracefully.")

            self.capture_thread = None
            self.running = False

            if self.captured:
                self.on_log("[*] Handshake capture stopped after successful capture.")
            else:
                self.on_log("[!] Handshake capture stopped.")

            self._cleanup_session()

    def _validate_inputs(self) -> None:
        if not self.interface:
            raise HandshakeError("Wireless interface is required.")

        if not self.bssid:
            raise HandshakeError("Target BSSID is required.")

        if not self.channel:
            raise HandshakeError("Target channel is required.")

    def _capture_loop(self) -> None:
        try:
            self._start_capture_process()

            while not self.stop_event.wait(timeout=1.0):
                process = self.capture_process

                if process is None:
                    raise HandshakeError("Capture process disappeared.")

                if not process.running:
                    if not self.stop_event.is_set():
                        raise HandshakeError("Capture process exited unexpectedly.")

                    return

                if self._capture_appears_complete():
                    if self._validate_capture():
                        self.captured = True

                        self.on_success(
                            "handshake",
                            str(self.capture_file),
                        )

                        self.on_log("[+] Valid capture artifact detected.")

                        self.stop_event.set()
                        return

        except Exception as exc:
            if not self.stop_event.is_set():
                self.on_log(f"[-] Handshake capture failed: {exc}")

        finally:
            process = self.capture_process

            if process is not None:
                try:
                    process.cleanup(timeout=2)
                except Exception as exc:
                    self.on_log(f"[-] Capture process finalization failed: {exc}")

                self.capture_process = None

            with self.lifecycle_lock:
                self.running = False

    def _start_capture_process(self) -> None:
        self.capture_process = ManagedProcess(
            [
                "airodump-ng",
                "--bssid",
                self.bssid,
                "-c",
                self.channel,
                "-w",
                str(self.capture_base),
                self.interface,
            ],
            name="handshake-airodump",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            self.capture_process.start()
        except Exception:
            self.capture_process = None
            raise

        self.on_log(
            f"[*] Capture started for {self.essid} " f"on channel {self.channel}."
        )

    def _capture_appears_complete(self) -> bool:
        candidates = [
            self.capture_file,
            self.session_dir / "handshake-01.cap",
            self.session_dir / "handshake-01.pcap",
            self.session_dir / "handshake-01.pcapng",
        ]

        for path in candidates:
            if path.is_file() and path.stat().st_size > 0:
                return True

        return False

    def _validate_capture(self) -> bool:
        capture = self.capture_file

        if not capture.is_file():
            return False

        if capture.stat().st_size <= 0:
            return False

        try:
            result = subprocess.run(
                [
                    "capinfos",
                    "-c",
                    str(capture),
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (
            OSError,
            subprocess.TimeoutExpired,
        ):
            return self._basic_capture_validation(capture)

        if result.returncode != 0:
            return self._basic_capture_validation(capture)

        return self._basic_capture_validation(capture)

    @staticmethod
    def _basic_capture_validation(
        capture: Path,
    ) -> bool:
        try:
            size = capture.stat().st_size
        except OSError:
            return False

        return size > 0

    def cleanup_artifacts(self) -> None:
        self._cleanup_session()

    def _cleanup_session(self) -> None:
        shutil.rmtree(
            self.session_dir,
            ignore_errors=True,
        )
