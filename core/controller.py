from __future__ import annotations

import asyncio
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable


class ControllerError(RuntimeError):
    pass


class VektState(str, Enum):
    IDLE = "IDLE"
    RECON = "RECON"
    TARGETED = "TARGETED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    STOPPING = "STOPPING"
    RESTORING = "RESTORING"


@dataclass
class Target:
    bssid: str
    essid: str
    channel: str
    signal_dbm: str = "Unknown"
    wps_status: str = "Unknown"
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = {
            "bssid": self.bssid,
            "essid": self.essid,
            "channel": self.channel,
            "signal_dbm": self.signal_dbm,
            "wps_status": self.wps_status,
        }

        data.update(self.extra)

        return data


@dataclass
class Job:
    job_id: str
    name: str
    engine: Any
    state: VektState = VektState.IDLE
    started_at: float | None = None
    finished_at: float | None = None
    error: str | None = None
    result: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "name": self.name,
            "state": self.state.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "result": self.result,
        }


class VektController:
    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        broadcaster: Callable[..., Any],
        logger: Callable[[str], Any],
    ):
        self.loop = loop
        self.broadcast = broadcaster
        self.log = logger

        self.lock = asyncio.Lock()

        self.state = VektState.IDLE
        self.interface: str | None = None

        self.networks: dict[str, Target] = {}
        self.target: Target | None = None
        self.stations: list[dict[str, Any]] = []

        self.recon_engine: Any | None = None
        self.target_scanner: Any | None = None
        self.active_job: Job | None = None

        self.session_id = uuid.uuid4().hex
        self.session_dir = Path(
            tempfile.mkdtemp(
                prefix=f"vekt_{self.session_id[:8]}_",
                mode=0o700,
            )
        )

        self.shutting_down = False

    async def emit(
        self,
        event: str,
        **payload: Any,
    ) -> None:
        result = self.broadcast(
            {
                "type": event,
                **payload,
            }
        )

        if asyncio.iscoroutine(result):
            await result

    def emit_from_thread(
        self,
        event: str,
        **payload: Any,
    ) -> None:
        if self.loop.is_closed():
            return

        future = asyncio.run_coroutine_threadsafe(
            self.emit(
                event,
                **payload,
            ),
            self.loop,
        )

        def consume(
            completed: asyncio.Future,
        ) -> None:
            try:
                completed.result()
            except Exception:
                return

        future.add_done_callback(consume)

    def publish_state(self) -> None:
        job = self.active_job.to_dict() if self.active_job else None

        self.emit_from_thread(
            "state",
            state=self.state.value,
            interface=self.interface,
            target=(self.target.to_dict() if self.target else None),
            job=job,
        )

    def set_state(
        self,
        state: VektState,
    ) -> None:
        self.state = state
        self.publish_state()

    def add_or_update_network(
        self,
        data: dict[str, Any],
    ) -> None:
        bssid = str(
            data.get(
                "bssid",
                "",
            )
        ).strip()

        if not bssid:
            return

        self.networks[bssid] = Target(
            bssid=bssid,
            essid=str(
                data.get(
                    "essid",
                    "Hidden",
                )
            ),
            channel=str(
                data.get(
                    "channel",
                    "?",
                )
            ),
            signal_dbm=str(
                data.get(
                    "signal_dbm",
                    "Unknown",
                )
            ),
            wps_status=str(
                data.get(
                    "wps_status",
                    "Unknown",
                )
            ),
        )

    def update_networks(
        self,
        data: dict[str, dict[str, Any]],
    ) -> None:
        self.networks.clear()

        for value in data.values():
            if isinstance(
                value,
                dict,
            ):
                self.add_or_update_network(value)

        self.emit_from_thread(
            "targets",
            data=[target.to_dict() for target in self.networks.values()],
        )

    def update_stations(
        self,
        stations: list[dict[str, Any]],
    ) -> None:
        self.stations = list(stations)

        self.emit_from_thread(
            "stations",
            data=self.stations,
        )

    async def set_interface(
        self,
        interface: str,
    ) -> None:
        if not interface or interface == self.interface:
            return

        await self.stop_all()

        self.interface = interface
        self.networks.clear()
        self.target = None
        self.stations.clear()

        await self.emit("clear_ui")

        self.set_state(VektState.IDLE)

        self.log(f"[*] Interface selected: {interface}")

    def require_interface(self) -> str:
        if not self.interface:
            raise ControllerError("No wireless interface selected.")

        return self.interface

    def require_target(self) -> Target:
        if self.target is None:
            raise ControllerError("No target selected.")

        return self.target

    async def select_target(
        self,
        bssid: str,
    ) -> None:
        if bssid not in self.networks:
            raise ControllerError("Target is no longer available.")

        await self.stop_recon()

        target = self.networks[bssid]

        self.target = target
        self.stations.clear()

        self.set_state(VektState.TARGETED)

        await self.emit(
            "target_selected",
            target=target.to_dict(),
        )

    async def start_recon(
        self,
        engine: Any,
    ) -> None:
        if self.active_job:
            raise ControllerError("An active job already exists.")

        await self.stop_target_scanner()

        if self.recon_engine:
            await self.stop_recon()

        self.recon_engine = engine

        self.set_state(VektState.STARTING)

        try:
            await asyncio.to_thread(engine.start)
        except Exception:
            self.recon_engine = None
            self.set_state(VektState.FAILED)
            raise

        self.set_state(VektState.RECON)

        self.log("[+] Recon started.")

    async def stop_recon(self) -> None:
        engine = self.recon_engine
        self.recon_engine = None

        if engine is None:
            return

        self.set_state(VektState.STOPPING)

        try:
            await asyncio.to_thread(engine.stop)
        except Exception as exc:
            self.log(f"[-] Recon stop failed: {exc}")
        finally:
            if self.target:
                self.set_state(VektState.TARGETED)
            else:
                self.set_state(VektState.IDLE)

    async def start_target_scanner(
        self,
        engine: Any,
    ) -> None:
        self.require_target()

        await self.stop_recon()

        if self.target_scanner:
            await self.stop_target_scanner()

        self.target_scanner = engine

        try:
            await asyncio.to_thread(engine.start)
        except Exception:
            self.target_scanner = None
            raise

        self.set_state(VektState.TARGETED)

    async def stop_target_scanner(
        self,
    ) -> None:
        engine = self.target_scanner
        self.target_scanner = None

        if engine is None:
            return

        try:
            await asyncio.to_thread(engine.stop)
        except Exception as exc:
            self.log(f"[-] Target scanner stop failed: {exc}")

    def create_job(
        self,
        name: str,
        engine: Any,
    ) -> Job:
        if self.active_job:
            raise ControllerError("Another job is already running.")

        job = Job(
            job_id=(f"{name.upper()}-" f"{uuid.uuid4().hex[:8].upper()}"),
            name=name,
            engine=engine,
        )

        self.active_job = job

        return job

    async def start_job(
        self,
        job: Job,
    ) -> None:
        if self.active_job is not job:
            raise ControllerError("Job is not owned by this controller.")

        job.state = VektState.STARTING
        job.started_at = time.monotonic()

        self.set_state(VektState.STARTING)

        try:
            await asyncio.to_thread(job.engine.start)
        except Exception as exc:
            job.state = VektState.FAILED
            job.error = str(exc)
            job.finished_at = time.monotonic()

            self.set_state(VektState.FAILED)

            self.active_job = None

            raise

        job.state = VektState.RUNNING

        self.set_state(VektState.RUNNING)

        await self.emit(
            "job",
            event="started",
            job=job.to_dict(),
        )

    def job_result(
        self,
        key: str,
        value: Any,
    ) -> None:
        if self.loop.is_closed():
            return

        future = asyncio.run_coroutine_threadsafe(
            self._process_job_result(
                key,
                value,
            ),
            self.loop,
        )

        def consume(
            completed: asyncio.Future,
        ) -> None:
            try:
                completed.result()
            except Exception as exc:
                self.log(f"[-] Job result processing failed: {exc}")

        future.add_done_callback(consume)

    async def _process_job_result(
        self,
        key: str,
        value: Any,
    ) -> None:
        async with self.lock:
            job = self.active_job

            if job is None:
                return

            await self.emit(
                "success",
                job_id=job.job_id,
                job_type=job.name,
                key_type=key,
                value=value,
            )

            if job.name == "evil_twin" and key == "ap_ready":
                job.result = {
                    "key": key,
                    "value": value,
                }

                self.publish_state()
                return

            terminal = (
                (job.name == "wps" and key == "psk")
                or (job.name == "handshake" and key == "handshake")
                or (job.name == "crack" and key == "password")
            )

            if not terminal:
                return

            job.result = {
                "key": key,
                "value": value,
            }

            job.state = VektState.SUCCESS
            job.finished_at = time.monotonic()

            engine = job.engine

            try:
                await asyncio.to_thread(engine.stop)
            except Exception as exc:
                job.error = str(exc)
                self.log(f"[-] Job finalization failed: {exc}")

            completed_job = job
            self.active_job = None

            await self.emit(
                "job",
                event="success",
                job=completed_job.to_dict(),
            )

            if self.target:
                self.set_state(VektState.TARGETED)
            else:
                self.set_state(VektState.IDLE)

    async def stop_job(
        self,
    ) -> None:
        job = self.active_job

        if job is None:
            return

        job.state = VektState.STOPPING

        self.set_state(VektState.STOPPING)

        try:
            await asyncio.to_thread(job.engine.stop)
        except Exception as exc:
            job.error = str(exc)

            self.log(f"[-] Job stop failed: {exc}")

        finally:
            job.state = VektState.STOPPED
            job.finished_at = time.monotonic()

            completed_job = job
            self.active_job = None

            await self.emit(
                "job",
                event="stopped",
                job=completed_job.to_dict(),
            )

            if self.target:
                self.set_state(VektState.TARGETED)
            else:
                self.set_state(VektState.IDLE)

    async def stop_all(
        self,
    ) -> None:
        await self.stop_job()
        await self.stop_target_scanner()
        await self.stop_recon()

    async def clear_target(
        self,
    ) -> None:
        await self.stop_job()
        await self.stop_target_scanner()

        self.target = None
        self.stations.clear()

        self.set_state(VektState.IDLE)

        await self.emit("clear_ui")

    async def shutdown(
        self,
    ) -> None:
        if self.shutting_down:
            return

        self.shutting_down = True

        self.state = VektState.RESTORING
        self.publish_state()

        try:
            await self.stop_job()
            await self.stop_target_scanner()
            await self.stop_recon()
        finally:
            self.target = None
            self.stations.clear()
            self.recon_engine = None
            self.target_scanner = None
            self.active_job = None

            self.state = VektState.IDLE
            self.publish_state()

            shutil.rmtree(
                self.session_dir,
                ignore_errors=True,
            )
