from __future__ import annotations

import subprocess
import tempfile
import threading
from pathlib import Path

from core.network import NetworkManager
from core.process import ManagedProcess


class EvilTwinError(RuntimeError):
    pass


class EvilTwinEngine:
    def __init__(
        self,
        interface: str,
        bssid: str,
        essid: str,
        channel: str,
        on_log,
        on_success,
    ):
        self.interface = interface
        self.bssid = bssid.upper()
        self.essid = essid
        self.channel = str(channel)

        self.on_log = on_log
        self.on_success = on_success

        self.stop_event = threading.Event()
        self.lifecycle_lock = threading.RLock()

        self.hostapd: ManagedProcess | None = None
        self.dnsmasq: ManagedProcess | None = None

        self.worker: threading.Thread | None = None

        self.network = NetworkManager(interface)

        self.running = False
        self.ready = False

        self.session_dir = Path(
            tempfile.mkdtemp(
                prefix="vekt_et_",
            )
        )

        self.hostapd_config = self.session_dir / "hostapd.conf"

        self.dnsmasq_config = self.session_dir / "dnsmasq.conf"

    def is_alive(self) -> bool:
        with self.lifecycle_lock:
            return self.running

    def start(self) -> None:
        with self.lifecycle_lock:
            if self.running:
                raise EvilTwinError("Evil Twin session is already running.")

            self._validate()

            self.stop_event.clear()
            self.ready = False
            self.running = True

            try:
                self.network.prepare_managed("10.20.0.1/24")

                self._write_configs()

                self.worker = threading.Thread(
                    target=self._run,
                    name="vekt-evil-twin",
                    daemon=True,
                )

                self.worker.start()

            except Exception:
                self.running = False

                self._stop_process(
                    self.hostapd,
                    "hostapd",
                )

                self._stop_process(
                    self.dnsmasq,
                    "dnsmasq",
                )

                self.hostapd = None
                self.dnsmasq = None

                self._restore()

                self._cleanup_session()

                raise

    def stop(self) -> None:
        with self.lifecycle_lock:
            if not self.running:
                return

            self.stop_event.set()

            self._stop_process(
                self.hostapd,
                "hostapd",
            )

            self._stop_process(
                self.dnsmasq,
                "dnsmasq",
            )

            self.hostapd = None
            self.dnsmasq = None

            worker = self.worker

            if (
                worker is not None
                and worker.is_alive()
                and worker is not threading.current_thread()
            ):
                worker.join(timeout=4)

                if worker.is_alive():
                    self.on_log("[!] Evil Twin worker did not terminate gracefully.")

            self.worker = None

            restore_errors = self._restore()

            for error in restore_errors:
                self.on_log(f"[-] Restore error: {error}")

            self.running = False
            self.ready = False

            self._cleanup_session()

            self.on_log("[!] Evil Twin session stopped.")

    def _validate(self) -> None:
        if not self.interface:
            raise EvilTwinError("Wireless interface is required.")

        if not self.essid:
            raise EvilTwinError("SSID is required.")

        if len(self.essid) > 32:
            raise EvilTwinError("SSID exceeds 32 characters.")

        if "\r" in self.essid:
            raise EvilTwinError("SSID contains invalid characters.")

        try:
            channel = int(self.channel)
        except ValueError as exc:
            raise EvilTwinError("Channel must be numeric.") from exc

        if not 1 <= channel <= 196:
            raise EvilTwinError("Channel is outside the supported range.")

    def _run(self) -> None:
        try:
            self._start_dnsmasq()
            self._wait_for_process(
                self.dnsmasq,
                "dnsmasq",
            )

            if self.stop_event.is_set():
                return

            self._start_hostapd()
            self._wait_for_process(
                self.hostapd,
                "hostapd",
            )

            if self.stop_event.is_set():
                return

            self.ready = True

            self.on_log(
                f"[+] Lab AP '{self.essid}' is running on channel {self.channel}."
            )

            self.on_success(
                "ap_ready",
                {
                    "ssid": self.essid,
                    "channel": self.channel,
                    "interface": self.interface,
                },
            )

            while not self.stop_event.wait(1.0):
                if self.hostapd is None or not self.hostapd.running:
                    raise EvilTwinError("hostapd exited unexpectedly.")

                if self.dnsmasq is None or not self.dnsmasq.running:
                    raise EvilTwinError("dnsmasq exited unexpectedly.")

        except Exception as exc:
            if not self.stop_event.is_set():
                self.on_log(f"[-] Evil Twin session failed: {exc}")

        finally:
            self._stop_process(
                self.hostapd,
                "hostapd",
            )

            self._stop_process(
                self.dnsmasq,
                "dnsmasq",
            )

            self.hostapd = None
            self.dnsmasq = None
            self.ready = False

            with self.lifecycle_lock:
                self.running = False

    def _write_configs(self) -> None:
        self.hostapd_config.write_text(
            "\n".join(
                [
                    f"interface={self.interface}",
                    f"ssid={self.essid}",
                    f"channel={self.channel}",
                    "driver=nl80211",
                    "hw_mode=g",
                    "auth_algs=1",
                    "ignore_broadcast_ssid=0",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        self.dnsmasq_config.write_text(
            "\n".join(
                [
                    f"interface={self.interface}",
                    "bind-interfaces",
                    "port=0",
                    "dhcp-range=10.20.0.10,10.20.0.100,255.255.255.0,8h",
                    "dhcp-option=3,10.20.0.1",
                    "dhcp-option=6,10.20.0.1",
                    "",
                ]
            ),
            encoding="utf-8",
        )

    def _start_dnsmasq(self) -> None:
        self.dnsmasq = ManagedProcess(
            [
                "dnsmasq",
                "--no-daemon",
                "--conf-file",
                str(self.dnsmasq_config),
            ],
            name="dnsmasq",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        try:
            self.dnsmasq.start()
        except Exception as exc:
            self.dnsmasq = None

            raise EvilTwinError(f"Failed to start dnsmasq: {exc}") from exc

    def _start_hostapd(self) -> None:
        self.hostapd = ManagedProcess(
            [
                "hostapd",
                str(self.hostapd_config),
            ],
            name="hostapd",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        try:
            self.hostapd.start()
        except Exception as exc:
            self.hostapd = None

            raise EvilTwinError(f"Failed to start hostapd: {exc}") from exc

    def _wait_for_process(
        self,
        process: ManagedProcess | None,
        name: str,
    ) -> None:
        if process is None:
            raise EvilTwinError(f"{name} process was not created.")

        for _ in range(20):
            if self.stop_event.is_set():
                raise EvilTwinError("Session stopped during startup.")

            if not process.running:
                raise EvilTwinError(
                    f"{name} exited during startup " f"with code {process.returncode}."
                )

            threading.Event().wait(0.25)

    def _stop_process(
        self,
        process: ManagedProcess | None,
        name: str,
    ) -> None:
        if process is None:
            return

        try:
            process.cleanup(timeout=2)
        except Exception as exc:
            self.on_log(f"[-] {name} cleanup failed: {exc}")

    def _restore(self) -> list[str]:
        try:
            return self.network.restore()
        except Exception as exc:
            return [f"Network restore failed: {exc}"]

    def _cleanup_session(self) -> None:
        try:
            self.hostapd_config.unlink(missing_ok=True)
        except OSError:
            pass

        try:
            self.dnsmasq_config.unlink(missing_ok=True)
        except OSError:
            pass

        try:
            self.session_dir.rmdir()
        except OSError:
            pass
