from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
import tempfile
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable

import uvicorn
from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from core.recon import ReconEngine, TargetScanner
from core.attacks.wps_attack import WPSAttackEngine
from core.attacks.handshake import HandshakeCaptureEngine
from core.attacks.cracker import CrackerEngine
from core.attacks.evil_twin import EvilTwinEngine

ACCESS_TOKEN = os.getenv("VEKT_ACCESS_TOKEN")

class JobState(str, Enum):
    IDLE = "IDLE"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


class CommandError(RuntimeError):
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
        raise CommandError(f"Command timed out: {' '.join(command)}") from exc
    except OSError as exc:
        raise CommandError(f"Command execution failed: {exc}") from exc

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise CommandError(
            f"Command failed ({result.returncode}): "
            f"{' '.join(command)}" + (f" | {stderr}" if stderr else "")
        )

    return result


class ConnectionManager:
    def __init__(self):
        self.connections: set[WebSocket] = set()
        self.operator: WebSocket | None = None
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> bool:
        async with self.lock:
            if self.operator is not None:
                await websocket.accept()
                try:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "message": "Another operator is already connected.",
                        }
                    )
                finally:
                    await websocket.close(code=1008)
                return False

            await websocket.accept()
            self.operator = websocket
            self.connections.add(websocket)
            return True

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self.lock:
            self.connections.discard(websocket)
            if self.operator is websocket:
                self.operator = None

    async def broadcast(self, payload: dict[str, Any]) -> None:
        connections = tuple(self.connections)
        dead: list[WebSocket] = []

        for websocket in connections:
            try:
                await websocket.send_json(payload)
            except Exception:
                dead.append(websocket)

        for websocket in dead:
            await self.disconnect(websocket)


manager = ConnectionManager()


@dataclass
class TargetInfo:
    bssid: str
    essid: str
    channel: str
    signal_dbm: str = "Unknown"
    wps_status: str = "Unknown"

    def as_dict(self) -> dict[str, str]:
        return {
            "bssid": self.bssid,
            "essid": self.essid,
            "channel": self.channel,
            "signal_dbm": self.signal_dbm,
            "wps_status": self.wps_status,
        }


class AttackJob:
    def __init__(
        self,
        job_id: str,
        name: str,
        runner: Any,
    ):
        self.job_id = job_id
        self.name = name
        self.runner = runner
        self.state = JobState.IDLE
        self.error: str | None = None
        self.result: dict[str, Any] = {}
        self.started_at: float | None = None
        self.finished_at: float | None = None

    def serialize(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "name": self.name,
            "state": self.state.value,
            "error": self.error,
            "result": self.result,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


class VektController:
    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
    ):
        self.loop = loop

        self.interface: str | None = None

        self.networks: dict[str, TargetInfo] = {}
        self.target: TargetInfo | None = None
        self.stations: list[dict[str, Any]] = []

        self.recon: ReconEngine | None = None
        self.target_scanner: TargetScanner | None = None

        self.active_job: AttackJob | None = None

        self.session_dir = Path(
            tempfile.mkdtemp(
                prefix="vekt_"
            )
        )

        self.state_lock = asyncio.Lock()

    async def emit(
        self,
        message_type: str,
        **data: Any,
    ) -> None:
        await manager.broadcast(
            {
                "type": message_type,
                **data,
            }
        )

    def emit_from_thread(
        self,
        message_type: str,
        **data: Any,
    ) -> None:
        if self.loop.is_closed():
            return

        future = asyncio.run_coroutine_threadsafe(
            self.emit(
                message_type,
                **data,
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

    def log(self, message: str) -> None:
        self.emit_from_thread(
            "log",
            message=message,
        )

    def publish_state(self) -> None:
        job = self.active_job.serialize() if self.active_job else None

        self.emit_from_thread(
            "state",
            interface=self.interface,
            target=(self.target.as_dict() if self.target else None),
            job=job,
        )

    def clear_target_data(self) -> None:
        self.target = None
        self.stations.clear()

    def set_interface(self, interface: str) -> None:
        available = get_interfaces()

        if interface not in available:
            raise RuntimeError(f"Interface '{interface}' is not available.")

        self.interface = interface
        self.networks.clear()
        self.clear_target_data()

    async def stop_component(
        self,
        component: Any,
        name: str,
    ) -> None:
        if component is None:
            return

        try:
            await asyncio.to_thread(component.stop)
        except Exception as exc:
            self.log(f"[-] {name} stop failed: {exc}")

    async def stop_recon(self) -> None:
        component = self.recon
        self.recon = None

        await self.stop_component(
            component,
            "Recon",
        )

    async def stop_target_scanner(self) -> None:
        component = self.target_scanner
        self.target_scanner = None

        await self.stop_component(
            component,
            "Target scanner",
        )

    async def stop_active_job(self) -> None:
        job = self.active_job

        if job is None:
            return

        job.state = JobState.STOPPING
        self.publish_state()

        await self.stop_component(
            job.runner,
            job.name,
        )

        job.state = JobState.STOPPED
        job.finished_at = asyncio.get_running_loop().time()

        self.active_job = None

        await self.emit(
            "job",
            event="stopped",
            job=job.serialize(),
        )

        self.publish_state()

    async def stop_all(self) -> None:
        await self.stop_active_job()
        await self.stop_target_scanner()
        await self.stop_recon()

    def require_interface(self) -> str:
        if not self.interface:
            raise RuntimeError("No wireless interface has been selected.")

        return self.interface

    def require_target(self) -> TargetInfo:
        if self.target is None:
            raise RuntimeError("No target has been selected.")

        return self.target

    async def start_recon(self) -> None:
        interface = self.require_interface()

        await self.stop_all()

        engine = ReconEngine(
            interface,
            self.log,
            self._recon_update,
        )

        self.recon = engine

        try:
            await asyncio.to_thread(engine.start)
        except Exception:
            self.recon = None
            raise

        await self.emit(
            "state",
            recon="RUNNING",
        )

    async def stop_recon_job(self) -> None:
        await self.stop_recon()

        await self.emit(
            "state",
            recon="STOPPED",
        )

    def _recon_update(
        self,
        networks: dict[str, dict[str, Any]],
    ) -> None:
        converted: dict[str, TargetInfo] = {}

        for bssid, value in networks.items():
            try:
                converted[bssid] = TargetInfo(
                    bssid=str(
                        value.get(
                            "bssid",
                            bssid,
                        )
                    ),
                    essid=str(
                        value.get(
                            "essid",
                            "Hidden",
                        )
                    ),
                    channel=str(
                        value.get(
                            "channel",
                            "?",
                        )
                    ),
                    signal_dbm=str(
                        value.get(
                            "signal_dbm",
                            "Unknown",
                        )
                    ),
                    wps_status=str(
                        value.get(
                            "wps_status",
                            "Unknown",
                        )
                    ),
                )
            except Exception:
                continue

        self.networks = converted

        self.emit_from_thread(
            "targets",
            data=[item.as_dict() for item in converted.values()],
        )

    async def select_target(
        self,
        bssid: str,
    ) -> None:
        interface = self.require_interface()

        if bssid not in self.networks:
            raise RuntimeError("Target is no longer available.")

        await self.stop_all()

        target = self.networks[bssid]
        self.target = target
        self.stations.clear()

        scanner = TargetScanner(
            interface,
            target.bssid,
            target.channel,
            target.essid,
            self.log,
            self._station_update,
        )

        self.target_scanner = scanner

        try:
            await asyncio.to_thread(scanner.start)
        except Exception:
            self.target_scanner = None
            raise

        self.publish_state()

    def _station_update(
        self,
        stations: list[dict[str, Any]],
    ) -> None:
        self.stations = list(stations)

        self.emit_from_thread(
            "stations",
            data=self.stations,
        )

    async def back_to_scan(self) -> None:
        await self.stop_all()
        self.clear_target_data()

        await self.emit("clear_ui")

        await self.start_recon()

    def create_job(
        self,
        name: str,
        runner: Any,
    ) -> AttackJob:
        if self.active_job is not None:
            raise RuntimeError("Another attack job is already active.")

        job = AttackJob(
            job_id=(f"{name.upper()}-" f"{uuid.uuid4().hex[:8].upper()}"),
            name=name,
            runner=runner,
        )

        self.active_job = job
        return job

    async def start_job(
        self,
        job: AttackJob,
    ) -> None:
        job.state = JobState.STARTING
        job.started_at = asyncio.get_running_loop().time()

        self.publish_state()

        try:
            await asyncio.to_thread(job.runner.start)
        except Exception as exc:
            job.state = JobState.FAILED
            job.error = str(exc)
            job.finished_at = asyncio.get_running_loop().time()

            self.publish_state()

            self.active_job = None

            raise

        job.state = JobState.RUNNING

        await self.emit(
            "job",
            event="started",
            job=job.serialize(),
        )

        self.publish_state()

    async def start_wps(
        self,
        mode: str,
    ) -> None:
        interface = self.require_interface()
        target = self.require_target()

        await self.stop_recon()
        await self.stop_target_scanner()

        runner = WPSAttackEngine(
            interface,
            target.bssid,
            target.channel,
            self.log,
            self._job_success_callback("wps"),
            mode=mode,
        )

        job = self.create_job(
            "wps",
            runner,
        )

        await self.start_job(job)

    async def start_handshake(
        self,
        client_mac: str,
    ) -> None:
        interface = self.require_interface()
        target = self.require_target()

        await self.stop_recon()
        await self.stop_target_scanner()

        runner = HandshakeCaptureEngine(
            interface,
            target.bssid,
            target.channel,
            target.essid,
            client_mac,
            self.log,
            self._job_success_callback("handshake"),
        )

        job = self.create_job(
            "handshake",
            runner,
        )

        await self.start_job(job)

    async def start_crack(
        self,
        cap_file: str,
        wordlist: str,
    ) -> None:
        runner = CrackerEngine(
            cap_file,
            wordlist,
            self.log,
            self._job_success_callback("crack"),
        )

        job = self.create_job(
            "crack",
            runner,
        )

        await self.start_job(job)

    async def start_evil_twin(
        self,
    ) -> None:
        interface = self.require_interface()
        target = self.require_target()

        await self.stop_recon()
        await self.stop_target_scanner()

        runner = EvilTwinEngine(
            interface,
            target.bssid,
            target.essid,
            target.channel,
            self.log,
            self._job_success_callback("evil_twin"),
        )

        job = self.create_job(
            "evil_twin",
            runner,
        )

        await self.start_job(job)

    def _job_success_callback(
        self,
        job_type: str,
    ) -> Callable[[str, Any], None]:
        def callback(
            key_type: str,
            value: Any,
        ) -> None:
            self._handle_job_success(
                job_type,
                key_type,
                value,
            )

        return callback

    def _handle_job_success(
        self,
        job_type: str,
        key_type: str,
        value: Any,
    ) -> None:
        job = self.active_job

        if job is None:
            self.emit_from_thread(
                "success",
                job_type=job_type,
                key_type=key_type,
                value=value,
            )
            return

        job.state = JobState.SUCCESS
        job.result = {
            "key_type": key_type,
            "value": value,
        }
        job.finished_at = asyncio.get_running_loop().time()

        self.emit_from_thread(
            "success",
            job_type=job_type,
            key_type=key_type,
            value=value,
        )

        self.emit_from_thread(
            "job",
            event="success",
            job=job.serialize(),
        )

        self.emit_from_thread(
            "state",
            interface=self.interface,
            target=(self.target.as_dict() if self.target else None),
            job=job.serialize(),
        )

    async def shutdown(self) -> None:
        await self.stop_all()

        if self.session_dir.exists():
            try:
                self.session_dir.rmdir()
            except OSError:
                pass


def get_interfaces() -> list[str]:
    result = run_command(
        ["iw", "dev"],
        timeout=5,
    )

    interfaces: list[str] = []

    for line in result.stdout.splitlines():
        stripped = line.strip()

        if stripped.startswith("Interface "):
            name = stripped.split(
                None,
                1,
            )[1].strip()

            if name:
                interfaces.append(name)

    if not interfaces:
        raise RuntimeError("No wireless interfaces were found.")

    return interfaces


@asynccontextmanager
async def lifespan(app: FastAPI):
    loop = asyncio.get_running_loop()

    app.state.loop = loop
    app.state.controller = VektController(loop)

    try:
        yield
    finally:
        await app.state.controller.shutdown()


app = FastAPI(lifespan=lifespan)

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static",
)


@app.get("/api/interfaces")
async def api_interfaces():
    try:
        interfaces = get_interfaces()

        return {
            "interfaces": interfaces,
            "current": app.state.controller.interface,
        }

    except Exception as exc:
        return {
            "interfaces": [],
            "current": None,
            "error": str(exc),
        }


@app.get("/")
async def index():
    path = Path("static/index.html")

    if not path.exists():
        return HTMLResponse(
            "<h1>VEKT</h1>" "<p>Frontend not found.</p>",
            status_code=500,
        )

    return HTMLResponse(path.read_text(encoding="utf-8"))


@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
):
    if not secrets.compare_digest(
        token,
        ACCESS_TOKEN,
    ):
        await websocket.close(code=1008)
        return

    if not await manager.connect(websocket):
        return

    controller: VektController = app.state.controller

    try:
        while True:
            raw = await websocket.receive_text()

            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                await controller.emit(
                    "error",
                    message="Invalid JSON command.",
                )
                continue

            if not isinstance(
                message,
                dict,
            ):
                await controller.emit(
                    "error",
                    message="Command must be a JSON object.",
                )
                continue

            action = message.get("action")

            if not isinstance(
                action,
                str,
            ):
                await controller.emit(
                    "error",
                    message="Missing action.",
                )
                continue

            async with controller.state_lock:
                try:
                    if action == "set_interface":
                        interface = message.get("interface")

                        if not isinstance(
                            interface,
                            str,
                        ):
                            raise RuntimeError("Invalid interface.")

                        await controller.stop_all()
                        controller.set_interface(interface)

                        await controller.emit("clear_ui")

                        controller.publish_state()

                        controller.log(f"[*] Interface selected: {interface}")

                    elif action == "start_recon":
                        await controller.start_recon()

                    elif action == "stop_recon":
                        await controller.stop_recon_job()

                    elif action == "select_target":
                        bssid = message.get("bssid")

                        if not isinstance(
                            bssid,
                            str,
                        ):
                            raise RuntimeError("Invalid BSSID.")

                        await controller.select_target(bssid)

                    elif action == "back_to_scan":
                        await controller.back_to_scan()

                    elif action == "start_wps":
                        mode = message.get(
                            "mode",
                            "pixie",
                        )

                        if mode not in (
                            "pixie",
                            "bruteforce",
                        ):
                            raise RuntimeError("Invalid WPS mode.")

                        await controller.start_wps(mode)

                    elif action == "stop_wps":
                        await controller.stop_active_job()

                    elif action == "start_deauth":
                        client_mac = message.get("client_mac")

                        if not isinstance(
                            client_mac,
                            str,
                        ):
                            raise RuntimeError("Invalid client MAC.")

                        await controller.start_handshake(client_mac)

                    elif action == "stop_handshake":
                        await controller.stop_active_job()

                    elif action == "start_crack":
                        cap_file = message.get("cap_file")

                        wordlist = message.get("wordlist")

                        if not isinstance(
                            cap_file,
                            str,
                        ):
                            raise RuntimeError("Invalid capture path.")

                        if not isinstance(
                            wordlist,
                            str,
                        ):
                            raise RuntimeError("Invalid wordlist path.")

                        await controller.start_crack(
                            cap_file,
                            wordlist,
                        )

                    elif action == "stop_crack":
                        await controller.stop_active_job()

                    elif action == "start_evil_twin":
                        await controller.start_evil_twin()

                    elif action == "stop_evil_twin":
                        await controller.stop_active_job()

                    elif action == "stop_all":
                        await controller.stop_all()

                    else:
                        raise RuntimeError(f"Unknown action: {action}")

                except Exception as exc:
                    await controller.emit(
                        "error",
                        message=str(exc),
                    )

                    controller.log(f"[-] {action}: {exc}")

    except WebSocketDisconnect:
        pass

    except Exception as exc:
        controller.log(f"[-] WebSocket failure: {exc}")

    finally:
        await controller.shutdown()
        await manager.disconnect(websocket)


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST"],
)
async def fallback(
    request: Request,
    path: str,
):
    client = request.client.host if request.client else ""

    if client in (
        "127.0.0.1",
        "::1",
    ):
        if request.method == "GET":
            return await index()

        return JSONResponse(
            {"error": "Method not allowed"},
            status_code=405,
        )

    return JSONResponse(
        {"error": "Not found"},
        status_code=404,
    )

if __name__ == "__main__":
    if not ACCESS_TOKEN:
        ACCESS_TOKEN = secrets.token_urlsafe(24)
        os.environ["VEKT_ACCESS_TOKEN"] = ACCESS_TOKEN
        print(
            "\n[!] VEKT_ACCESS_TOKEN is not set."
            "\n[!] Generated temporary access token:"
            f"\n    {ACCESS_TOKEN}\n"
        )
    print(f"[+] Open VEKT in your browser: http://127.0.0.1:8000/?token={ACCESS_TOKEN}\n")
    
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        reload=False,
    )
