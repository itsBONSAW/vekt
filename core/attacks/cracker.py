from __future__ import annotations

import re
import shutil
import threading
import tempfile
from pathlib import Path
from typing import Any

from core.process import ManagedProcess


class CrackerError(RuntimeError):
    pass


class CrackerEngine:
    def __init__(
        self,
        cap_file: str,
        wordlist: str,
        on_log,
        on_success,
    ):
        self.cap_file = Path(cap_file).expanduser()
        self.wordlist = Path(wordlist).expanduser()

        self.on_log = on_log
        self.on_success = on_success

        self.stop_event = threading.Event()
        self.lifecycle_lock = threading.RLock()

        self.process: ManagedProcess | None = None
        self.thread: threading.Thread | None = None

        self.running = False
        self.success = False

        self.session_dir = Path(
            tempfile.mkdtemp(
                prefix="vekt_crack_",
            )
        )

        self.hash_file = self.session_dir / "capture.hc22000"

    def is_alive(self) -> bool:
        with self.lifecycle_lock:
            return self.running

    def start(self) -> None:
        with self.lifecycle_lock:
            if self.running:
                raise CrackerError("Cracker is already running.")

            self._validate_inputs()

            self.stop_event.clear()
            self.success = False
            self.running = True

            self.thread = threading.Thread(
                target=self._run,
                name="vekt-cracker",
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
                    self.on_log(f"[-] Cracker process cleanup failed: {exc}")

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
                    self.on_log("[!] Cracker worker did not terminate gracefully.")

            self.thread = None
            self.running = False

            self.on_log("[!] Cracking stopped.")

            self._cleanup_session()

    def _validate_inputs(self) -> None:
        if not self.cap_file.is_file():
            raise CrackerError(f"Capture file does not exist: {self.cap_file}")

        if not self.wordlist.is_file():
            raise CrackerError(f"Wordlist does not exist: {self.wordlist}")

        if not self.cap_file.stat().st_size:
            raise CrackerError("Capture file is empty.")

        if not self.wordlist.stat().st_size:
            raise CrackerError("Wordlist is empty.")

    def _run(self) -> None:
        try:
            self._convert_capture()

            if self.stop_event.is_set():
                return

            self._run_hashcat()

        except Exception as exc:
            if not self.stop_event.is_set():
                self.on_log(f"[-] Cracking failed: {exc}")

        finally:
            with self.lifecycle_lock:
                self.process = None
                self.running = False

            if not self.stop_event.is_set():
                self._cleanup_session()

    def _convert_capture(self) -> None:
        self.on_log(f"[*] Converting capture: {self.cap_file}")

        self.process = ManagedProcess(
            [
                "hcxpcapngtool",
                "-o",
                str(self.hash_file),
                str(self.cap_file),
            ],
            name="hcxpcapngtool",
            stdout=None,
            stderr=None,
        )

        self.process.start()

        returncode = self.process.wait(timeout=60)

        if self.stop_event.is_set():
            return

        self.process = None

        if returncode != 0:
            raise CrackerError(f"hcxpcapngtool exited with code {returncode}")

        if not self.hash_file.is_file():
            raise CrackerError("Hash conversion did not produce an output file.")

        if self.hash_file.stat().st_size == 0:
            raise CrackerError("No usable hash material was produced.")

        self.on_log("[+] Capture converted successfully.")

    def _run_hashcat(self) -> None:
        self.on_log("[*] Starting Hashcat.")

        self.process = ManagedProcess(
            [
                "hashcat",
                "-m",
                "22000",
                str(self.hash_file),
                str(self.wordlist),
                "--status",
                "--status-timer=5",
            ],
            name="hashcat",
            stdout=None,
            stderr=None,
        )

        self.process.start()

        returncode = self.process.wait(timeout=None)

        if self.stop_event.is_set():
            return

        self.process = None

        if returncode not in (
            0,
            1,
        ):
            raise CrackerError(f"Hashcat exited with code {returncode}")

        password = self._extract_result()

        if password is None:
            self.on_log("[-] No matching key was recovered.")
            return

        self.success = True

        self.on_success(
            "password",
            password,
        )

        self.on_log("[+] Matching key recovered.")

    def _extract_result(
        self,
    ) -> str | None:
        process = ManagedProcess(
            [
                "hashcat",
                "-m",
                "22000",
                str(self.hash_file),
                "--show",
            ],
            name="hashcat-show",
            stdout=None,
            stderr=None,
        )

        process.start()

        result = process.communicate(timeout=30)

        if result.returncode != 0:
            raise CrackerError("Hashcat result query failed.")

        output = result.stdout.strip()

        if not output:
            return None

        for line in output.splitlines():
            value = self._parse_show_line(line)

            if value is not None:
                return value

        return None

    @staticmethod
    def _parse_show_line(
        line: str,
    ) -> str | None:
        clean = line.strip()

        if not clean:
            return None

        parts = clean.split(":")

        if len(parts) < 2:
            return None

        value = parts[-1]

        if not value:
            return None

        return value

    def _cleanup_session(self) -> None:
        shutil.rmtree(
            self.session_dir,
            ignore_errors=True,
        )
