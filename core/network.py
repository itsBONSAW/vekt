from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass


class NetworkError(RuntimeError):
    pass


def run_command(
    command: list[str],
    *,
    timeout: float = 10.0,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NetworkError(f"Command timed out: {' '.join(command)}") from exc
    except OSError as exc:
        raise NetworkError(f"Command execution failed: {exc}") from exc

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()

        message = f"Command failed ({result.returncode}): " f"{' '.join(command)}"

        if stderr:
            message = f"{message} | {stderr}"

        raise NetworkError(message)

    return result


@dataclass
class InterfaceSnapshot:
    name: str
    mode: str
    addresses: list[str]
    state: str
    network_manager_active: bool
    wpa_supplicant_active: bool


class NetworkManager:
    def __init__(
        self,
        interface: str,
    ):
        self.interface = interface
        self._snapshot: InterfaceSnapshot | None = None

    def capture_snapshot(
        self,
    ) -> InterfaceSnapshot:
        if self._snapshot is not None:
            return self._snapshot

        if not self.interface:
            raise NetworkError("Interface name is empty.")

        info = run_command(
            [
                "iw",
                "dev",
                self.interface,
                "info",
            ],
            timeout=5,
        )

        mode_match = re.search(
            r"type\s+([A-Za-z0-9_]+)",
            info.stdout,
        )

        if not mode_match:
            raise NetworkError(f"Could not determine mode of {self.interface}.")

        address_result = run_command(
            [
                "ip",
                "-o",
                "addr",
                "show",
                "dev",
                self.interface,
            ],
            timeout=5,
        )

        addresses: list[str] = []

        for line in address_result.stdout.splitlines():
            parts = line.split()

            if "inet" in parts:
                index = parts.index("inet")

                if index + 1 < len(parts):
                    addresses.append(f"inet {parts[index + 1]}")

            if "inet6" in parts:
                index = parts.index("inet6")

                if index + 1 < len(parts):
                    addresses.append(f"inet6 {parts[index + 1]}")

        state_result = run_command(
            [
                "cat",
                f"/sys/class/net/{self.interface}/operstate",
            ],
            timeout=5,
        )

        snapshot = InterfaceSnapshot(
            name=self.interface,
            mode=mode_match.group(1),
            addresses=addresses,
            state=(state_result.stdout.strip() or "unknown"),
            network_manager_active=self._service_active("NetworkManager"),
            wpa_supplicant_active=self._service_active("wpa_supplicant"),
        )

        self._snapshot = snapshot

        return snapshot

    def snapshot_exists(
        self,
    ) -> bool:
        return self._snapshot is not None

    def _service_active(
        self,
        service: str,
    ) -> bool:
        try:
            result = subprocess.run(
                [
                    "systemctl",
                    "is-active",
                    service,
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            return result.returncode == 0 and result.stdout.strip() == "active"

        except Exception:
            return False

    def _stop_service(
        self,
        service: str,
    ) -> None:
        subprocess.run(
            [
                "systemctl",
                "stop",
                service,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )

    def _start_service(
        self,
        service: str,
    ) -> None:
        subprocess.run(
            [
                "systemctl",
                "start",
                service,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )

    def set_down(self) -> None:
        run_command(
            [
                "ip",
                "link",
                "set",
                self.interface,
                "down",
            ],
            timeout=5,
        )

    def set_up(self) -> None:
        run_command(
            [
                "ip",
                "link",
                "set",
                self.interface,
                "up",
            ],
            timeout=5,
        )

    def set_mode(
        self,
        mode: str,
    ) -> None:
        if mode not in {
            "managed",
            "monitor",
        }:
            raise NetworkError(f"Unsupported interface mode: {mode}")

        run_command(
            [
                "iw",
                "dev",
                self.interface,
                "set",
                "type",
                mode,
            ],
            timeout=10,
        )

    def prepare_monitor(
        self,
    ) -> None:
        snapshot = self.capture_snapshot()

        if snapshot.network_manager_active:
            self._stop_service("NetworkManager")

        if snapshot.wpa_supplicant_active:
            self._stop_service("wpa_supplicant")

        subprocess.run(
            [
                "rfkill",
                "unblock",
                "wlan",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )

        self.set_down()
        self.set_mode("monitor")
        self.set_up()

    def prepare_managed(
        self,
        address: str | None = None,
    ) -> None:
        self.capture_snapshot()

        self.set_down()
        self.set_mode("managed")

        self.flush_addresses()

        if address:
            run_command(
                [
                    "ip",
                    "addr",
                    "add",
                    address,
                    "dev",
                    self.interface,
                ],
                timeout=5,
            )

        self.set_up()

    def flush_addresses(self) -> None:
        run_command(
            [
                "ip",
                "addr",
                "flush",
                "dev",
                self.interface,
            ],
            timeout=5,
        )

    def restore_addresses(
        self,
        addresses: list[str],
    ) -> list[str]:
        errors: list[str] = []

        for item in addresses:
            parts = item.split()

            if len(parts) != 2:
                continue

            family = parts[0]
            address = parts[1]

            try:
                if family == "inet":
                    run_command(
                        [
                            "ip",
                            "addr",
                            "add",
                            address,
                            "dev",
                            self.interface,
                        ],
                        timeout=5,
                    )

                elif family == "inet6":
                    run_command(
                        [
                            "ip",
                            "-6",
                            "addr",
                            "add",
                            address,
                            "dev",
                            self.interface,
                        ],
                        timeout=5,
                    )

            except Exception as exc:
                errors.append(f"{family} {address}: {exc}")

        return errors

    def restore(
        self,
    ) -> list[str]:
        errors: list[str] = []

        snapshot = self._snapshot

        if snapshot is None:
            return errors

        try:
            self.set_down()
        except Exception as exc:
            errors.append(f"Interface down failed: {exc}")

        try:
            self.set_mode(snapshot.mode)
        except Exception as exc:
            errors.append(f"Mode restore failed: {exc}")

        try:
            self.flush_addresses()
        except Exception as exc:
            errors.append(f"Address flush failed: {exc}")

        errors.extend(self.restore_addresses(snapshot.addresses))

        try:
            if snapshot.state == "down":
                run_command(
                    [
                        "ip",
                        "link",
                        "set",
                        self.interface,
                        "down",
                    ],
                    timeout=5,
                )
            else:
                self.set_up()

        except Exception as exc:
            errors.append(f"Interface state restore failed: {exc}")

        if snapshot.network_manager_active:
            try:
                self._start_service("NetworkManager")
            except Exception as exc:
                errors.append(f"NetworkManager restore failed: {exc}")

        if snapshot.wpa_supplicant_active:
            try:
                self._start_service("wpa_supplicant")
            except Exception as exc:
                errors.append(f"wpa_supplicant restore failed: {exc}")

        self._snapshot = None

        return errors


def list_wireless_interfaces() -> list[str]:
    result = run_command(
        [
            "iw",
            "dev",
        ],
        timeout=5,
    )

    interfaces: list[str] = []

    for line in result.stdout.splitlines():
        stripped = line.strip()

        if not stripped.startswith("Interface "):
            continue

        name = stripped.split(
            None,
            1,
        )[1].strip()

        if name:
            interfaces.append(name)

    if not interfaces:
        raise NetworkError("No wireless interfaces detected.")

    return interfaces


def get_interface_mode(
    interface: str,
) -> str:
    result = run_command(
        [
            "iw",
            "dev",
            interface,
            "info",
        ],
        timeout=5,
    )

    match = re.search(
        r"type\s+([A-Za-z0-9_]+)",
        result.stdout,
    )

    if not match:
        raise NetworkError(f"Could not determine mode for {interface}.")

    return match.group(1)


def get_interface_channel(
    interface: str,
) -> str | None:
    try:
        result = run_command(
            [
                "iw",
                "dev",
                interface,
                "info",
            ],
            timeout=5,
        )
    except NetworkError:
        return None

    match = re.search(
        r"channel\s+(\d+)",
        result.stdout,
    )

    if match:
        return match.group(1)

    return None
