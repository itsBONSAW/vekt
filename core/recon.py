from __future__ import annotations

import csv
import os
import re
import select
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Any

from core.network import NetworkManager
from core.process import ManagedProcess


class ReconError(RuntimeError):
    pass


class ReconEngine:
    def __init__(
        self,
        interface: str,
        on_log,
        on_update,
    ):
        self.interface = interface
        self.on_log = on_log
        self.on_update = on_update

        self.stop_event = threading.Event()
        self.lifecycle_lock = threading.RLock()

        self.networks_db: dict[str, dict[str, Any]] = {}

        self.network = NetworkManager(interface)

        self.airodump: ManagedProcess | None = None
        self.wash: ManagedProcess | None = None

        self.airodump_thread: threading.Thread | None = None
        self.wash_thread: threading.Thread | None = None

        self.wash_master: int | None = None

        self.running = False

        self.session_dir = Path(
            tempfile.mkdtemp(
                prefix="vekt_recon_",
            )
        )

        self.csv_base = self.session_dir / "scan"

        self.csv_file = self.session_dir / "scan-01.csv"

    def is_alive(self) -> bool:
        with self.lifecycle_lock:
            return self.running

    def start(self) -> None:
        with self.lifecycle_lock:
            if self.running:
                raise ReconError("Recon engine is already running.")

            self.stop_event.clear()
            self.networks_db.clear()

            try:
                self.network.prepare_monitor()

                self._start_processes()

                self.running = True

                self.airodump_thread = threading.Thread(
                    target=self._airodump_loop,
                    name="vekt-recon-airodump",
                    daemon=True,
                )

                self.wash_thread = threading.Thread(
                    target=self._wash_loop,
                    name="vekt-recon-wash",
                    daemon=True,
                )

                self.airodump_thread.start()
                self.wash_thread.start()

                self.on_log(f"[+] Recon started on {self.interface}.")

                self.on_update(self.networks_db)

            except Exception as exc:
                self.stop_event.set()
                self._stop_processes()
                self._close_wash_master()

                restore_errors = self.network.restore()

                for error in restore_errors:
                    self.on_log(f"[-] Restore error: {error}")

                self.running = False
                self._cleanup_session()

                raise ReconError(f"Failed to start recon: {exc}") from exc

    def stop(self) -> None:
        with self.lifecycle_lock:
            if not self.running:
                return

            self.stop_event.set()

            self._stop_processes()

            workers = (
                self.airodump_thread,
                self.wash_thread,
            )

            for worker in workers:
                if worker is not None and worker.is_alive():
                    worker.join(timeout=3)

                    if worker.is_alive():
                        self.on_log("[!] Recon worker did not terminate gracefully.")

            self.airodump_thread = None
            self.wash_thread = None

            self._close_wash_master()

            restore_errors = self.network.restore()

            for error in restore_errors:
                self.on_log(f"[-] Restore error: {error}")

            self.running = False

            self.on_log("[!] Recon stopped.")

            self._cleanup_session()

    def _start_processes(self) -> None:
        self.airodump = ManagedProcess(
            [
                "airodump-ng",
                "-w",
                str(self.csv_base),
                "--output-format",
                "csv",
                self.interface,
            ],
            name="airodump-ng",
            stdout=None,
            stderr=None,
        )

        try:
            self.airodump.start()
        except Exception:
            self.airodump = None
            raise

        master, slave = os.openpty()

        try:
            self.wash = ManagedProcess(
                [
                    "wash",
                    "-i",
                    self.interface,
                ],
                name="wash",
                stdout=slave,
                stderr=slave,
            )

            self.wash.start()

        except Exception:
            try:
                os.close(slave)
            except OSError:
                pass

            try:
                os.close(master)
            except OSError:
                pass

            try:
                self.airodump.cleanup(timeout=2)
            except Exception:
                pass

            self.airodump = None
            self.wash = None

            raise

        os.close(slave)
        self.wash_master = master

    def _airodump_loop(self) -> None:
        try:
            while not self.stop_event.wait(1.5):
                process = self.airodump

                if process is None:
                    break

                if not process.running:
                    if not self.stop_event.is_set():
                        self.on_log("[!] airodump-ng exited unexpectedly.")
                    break

                if not self.csv_file.is_file():
                    continue

                try:
                    self._parse_airodump_csv()
                except Exception as exc:
                    self.on_log(f"[-] airodump parser error: {exc}")

        except Exception as exc:
            if not self.stop_event.is_set():
                self.on_log(f"[-] airodump worker error: {exc}")

    def _parse_airodump_csv(self) -> None:
        with self.csv_file.open(
            "r",
            encoding="utf-8",
            errors="ignore",
            newline="",
        ) as file:
            rows = csv.reader(file)

            for row in rows:
                if not row:
                    continue

                first = row[0].strip()

                if first == "Station MAC":
                    break

                if not self._valid_mac(first):
                    continue

                if len(row) < 14:
                    continue

                bssid = first.upper()

                if bssid == "00:00:00:00:00:00":
                    continue

                channel = row[3].strip() or "?"

                signal = row[8].strip() or "-100"

                essid = row[13].strip() or "Hidden"

                current = self.networks_db.get(bssid)

                if current is None:
                    self.networks_db[bssid] = {
                        "bssid": bssid,
                        "essid": essid,
                        "channel": channel,
                        "signal_dbm": signal,
                        "wps_status": "Unknown",
                    }

                    self.on_log(f"[+] Network discovered: {essid} ({bssid})")
                else:
                    current["essid"] = essid
                    current["channel"] = channel
                    current["signal_dbm"] = signal

        self.on_update(self.networks_db)

    def _wash_loop(self) -> None:
        master = self.wash_master

        if master is None:
            return

        try:
            while not self.stop_event.is_set():
                process = self.wash

                if process is None:
                    break

                if not process.running:
                    if not self.stop_event.is_set():
                        self.on_log("[!] wash exited unexpectedly.")
                    break

                try:
                    readable, _, _ = select.select(
                        [master],
                        [],
                        [],
                        1.0,
                    )
                except (
                    OSError,
                    ValueError,
                ):
                    break

                if not readable:
                    continue

                try:
                    raw = os.read(
                        master,
                        4096,
                    )
                except OSError:
                    break

                if not raw:
                    continue

                output = raw.decode(
                    "utf-8",
                    errors="ignore",
                )

                for line in output.splitlines():
                    self._process_wash_line(line)

        except Exception as exc:
            if not self.stop_event.is_set():
                self.on_log(f"[-] wash worker error: {exc}")

    def _process_wash_line(
        self,
        line: str,
    ) -> None:
        clean = re.sub(
            r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])",
            "",
            line,
        ).strip()

        if not clean:
            return

        if clean.startswith("BSSID"):
            return

        if clean.startswith("---"):
            return

        fields = re.split(
            r"\s+",
            clean,
        )

        if len(fields) < 6:
            return

        bssid = fields[0].upper()

        if not self._valid_mac(bssid):
            return

        channel = fields[1] if len(fields) > 1 else "?"

        signal = fields[2] if len(fields) > 2 else "Unknown"

        lock_status = fields[4] if len(fields) > 4 else ""

        essid = " ".join(fields[6:]) if len(fields) > 6 else "Hidden"

        wps_status = "Unlocked" if lock_status.lower() == "no" else "Locked"

        network = self.networks_db.get(bssid)

        if network is None:
            self.networks_db[bssid] = {
                "bssid": bssid,
                "essid": essid or "Hidden",
                "channel": channel,
                "signal_dbm": signal,
                "wps_status": wps_status,
            }

            self.on_log(f"[+] WPS network discovered: {bssid}")
        else:
            changed = False

            if network.get("channel") != channel:
                network["channel"] = channel
                changed = True

            if network.get("signal_dbm") != signal:
                network["signal_dbm"] = signal
                changed = True

            if network.get("wps_status") != wps_status:
                network["wps_status"] = wps_status
                changed = True

            if (not network.get("essid") or network["essid"] == "Hidden") and essid:
                network["essid"] = essid
                changed = True

            if changed:
                self.on_log(f"[*] WPS state updated for {bssid}: {wps_status}")

        self.on_update(self.networks_db)

    def _stop_processes(self) -> None:
        processes = (
            ("airodump-ng", self.airodump),
            ("wash", self.wash),
        )

        for name, process in processes:
            if process is None:
                continue

            try:
                process.cleanup(timeout=2)
            except Exception as exc:
                self.on_log(f"[-] {name} cleanup failed: {exc}")

        self.airodump = None
        self.wash = None

    def _close_wash_master(self) -> None:
        if self.wash_master is None:
            return

        try:
            os.close(self.wash_master)
        except OSError:
            pass
        finally:
            self.wash_master = None

    def _cleanup_session(self) -> None:
        shutil.rmtree(
            self.session_dir,
            ignore_errors=True,
        )

    @staticmethod
    def _valid_mac(
        value: str,
    ) -> bool:
        return bool(
            re.fullmatch(
                r"[0-9A-Fa-f]{2}" r"(?::[0-9A-Fa-f]{2}){5}",
                value,
            )
        )


class TargetScanner:
    def __init__(
        self,
        interface: str,
        bssid: str,
        channel: str,
        essid: str,
        on_log,
        on_station,
    ):
        self.interface = interface
        self.bssid = bssid.upper()
        self.channel = str(channel)
        self.essid = essid

        self.on_log = on_log
        self.on_station = on_station

        self.stop_event = threading.Event()
        self.lifecycle_lock = threading.RLock()

        self.process: ManagedProcess | None = None
        self.thread: threading.Thread | None = None

        self.running = False

        self.session_dir = Path(
            tempfile.mkdtemp(
                prefix="vekt_target_",
            )
        )

        self.csv_base = self.session_dir / "target"

        self.csv_file = self.session_dir / "target-01.csv"

    def is_alive(self) -> bool:
        with self.lifecycle_lock:
            return self.running

    def start(self) -> None:
        with self.lifecycle_lock:
            if self.running:
                raise RuntimeError("Target scanner is already running.")

            self.stop_event.clear()

            self.process = ManagedProcess(
                [
                    "airodump-ng",
                    "--bssid",
                    self.bssid,
                    "-c",
                    self.channel,
                    "-w",
                    str(self.csv_base),
                    "--output-format",
                    "csv",
                    self.interface,
                ],
                name="target-airodump",
                stdout=None,
                stderr=None,
            )

            try:
                self.process.start()
            except Exception:
                self.process = None
                self._cleanup_session()
                raise

            self.thread = threading.Thread(
                target=self._read_csv,
                name="vekt-target-monitor",
                daemon=True,
            )

            self.running = True
            self.thread.start()

            self.on_log(f"[*] Target monitoring started: {self.essid}")

    def _read_csv(self) -> None:
        while not self.stop_event.wait(1.5):
            process = self.process

            if process is None:
                break

            if not process.running:
                if not self.stop_event.is_set():
                    self.on_log("[!] Target monitor exited unexpectedly.")
                break

            if not self.csv_file.is_file():
                continue

            try:
                stations = self._parse_csv()

                self.on_station(stations)
            except Exception as exc:
                self.on_log(f"[-] Station parser error: {exc}")

    def _parse_csv(
        self,
    ) -> list[dict[str, Any]]:
        stations: dict[
            str,
            dict[str, Any],
        ] = {}

        with self.csv_file.open(
            "r",
            encoding="utf-8",
            errors="ignore",
            newline="",
        ) as file:
            rows = csv.reader(file)
            in_station_section = False

            for row in rows:
                if not row:
                    continue

                first = row[0].strip()

                if first == "Station MAC":
                    in_station_section = True
                    continue

                if not in_station_section:
                    continue

                if len(row) < 4:
                    continue

                mac = first.upper()
                power = row[3].strip()

                if not self._valid_mac(mac):
                    continue

                if mac == self.bssid:
                    continue

                stations[mac] = {
                    "mac": mac,
                    "pwr": power,
                }

        return list(stations.values())

    def stop(self) -> None:
        with self.lifecycle_lock:
            if not self.running:
                return

            self.stop_event.set()

            if self.process is not None:
                try:
                    self.process.cleanup(timeout=2)
                except Exception as exc:
                    self.on_log(f"[-] Target process cleanup failed: {exc}")
                finally:
                    self.process = None

            if self.thread is not None and self.thread.is_alive():
                self.thread.join(timeout=3)

                if self.thread.is_alive():
                    self.on_log(
                        "[!] Target monitor thread did not terminate gracefully."
                    )

            self.thread = None
            self.running = False

            self.on_log("[*] Target monitoring stopped.")

            self._cleanup_session()

    def _cleanup_session(self) -> None:
        shutil.rmtree(
            self.session_dir,
            ignore_errors=True,
        )

    @staticmethod
    def _valid_mac(
        value: str,
    ) -> bool:
        return bool(
            re.fullmatch(
                r"[0-9A-Fa-f]{2}" r"(?::[0-9A-Fa-f]{2}){5}",
                value,
            )
        )
