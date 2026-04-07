import os
import time
import json
import socket
import hashlib
import asyncio
import psutil
import websockets

# ================== CẤU HÌNH ==================
MACHINE_ID = "ubuntu-vm-01"
ZEEK_CONN_FILE = "/opt/zeek-docker-logs/conn.log"
WS_SERVER_URL = "ws://192.168.88.1:8000/ws/agent"

# Chặn vòng lặp log
BLOCK_DEST_IP = "192.168.88.1"
BLOCK_DEST_PORT = 8000

RECENT_HASHES = set()
MAX_RECENT_HASHES = 5000
CURRENT_FIELDS = []


def safe_float(x, default=0.0):
    try:
        if x in (None, "", "-", "0-", "(empty)"):
            return default
        return float(x)
    except Exception:
        return default


def safe_int(x, default=0):
    try:
        if x in (None, "", "-", "0-", "(empty)"):
            return default
        return int(float(x))
    except Exception:
        return default


def should_skip_line(text: str) -> bool:
    if not text:
        return True

    text = text.strip()
    if not text or text.startswith("#"):
        return True

    h = hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()
    if h in RECENT_HASHES:
        return True

    RECENT_HASHES.add(h)
    if len(RECENT_HASHES) > MAX_RECENT_HASHES:
        for _ in range(1000):
            try:
                RECENT_HASHES.pop()
            except KeyError:
                break

    return False


def parse_zeek_conn_line(line: str):
    global CURRENT_FIELDS

    if not line:
        return None

    line = line.rstrip("\n")

    if line.startswith("#fields"):
        parts = line.split("\t")
        CURRENT_FIELDS = parts[1:]
        return None

    if line.startswith("#"):
        return None

    parts = line.split("\t")

    if CURRENT_FIELDS and len(parts) == len(CURRENT_FIELDS):
        row = dict(zip(CURRENT_FIELDS, parts))
        return {
            "machine_id": MACHINE_ID,
            "timestamp": row.get("ts", ""),
            "src_ip": row.get("id.orig_h", ""),
            "src_port": safe_int(row.get("id.orig_p", "0")),
            "dest_ip": row.get("id.resp_h", ""),
            "dest_port": safe_int(row.get("id.resp_p", "0")),
            "proto": row.get("proto", ""),
            "service": row.get("service", "-"),
            "duration": safe_float(row.get("duration", "0")),
            "orig_bytes": safe_float(row.get("orig_bytes", "0")),
            "resp_bytes": safe_float(row.get("resp_bytes", "0")),
            "conn_state": row.get("conn_state", ""),
            "history": row.get("history", ""),
            "orig_pkts": safe_int(row.get("orig_pkts", "0")),
            "resp_pkts": safe_int(row.get("resp_pkts", "0")),
        }

    if len(parts) < 20:
        return None

    return {
        "machine_id": MACHINE_ID,
        "timestamp": parts[0],
        "src_ip": parts[2],
        "src_port": safe_int(parts[3]),
        "dest_ip": parts[4],
        "dest_port": safe_int(parts[5]),
        "proto": parts[6],
        "service": parts[7],
        "duration": safe_float(parts[8]),
        "orig_bytes": safe_float(parts[9]),
        "resp_bytes": safe_float(parts[10]),
        "conn_state": parts[11],
        "history": parts[15] if len(parts) > 15 else "",
        "orig_pkts": safe_int(parts[16]) if len(parts) > 16 else 0,
        "resp_pkts": safe_int(parts[18]) if len(parts) > 18 else 0,
    }


def should_block_event(event: dict) -> bool:
    return (
        str(event.get("dest_ip", "")).strip() == BLOCK_DEST_IP and
        safe_int(event.get("dest_port", 0)) == BLOCK_DEST_PORT
    )


def get_ip_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


def get_system_info():
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    return {
        "machine_id": MACHINE_ID,
        "hostname": socket.gethostname(),
        "ip": get_ip_address(),
        "cpu_percent": round(psutil.cpu_percent(interval=None), 2),
        "ram_total_mb": round(vm.total / 1024 / 1024, 2),
        "ram_used_mb": round(vm.used / 1024 / 1024, 2),
        "ram_percent": round(vm.percent, 2),
        "disk_total_gb": round(disk.total / 1024 / 1024 / 1024, 2),
        "disk_used_gb": round(disk.used / 1024 / 1024 / 1024, 2),
        "disk_percent": round(disk.percent, 2)
    }


async def system_info_task(ws):
    while True:
        payload = {
            "type": "system_info",
            "data": get_system_info()
        }
        await ws.send(json.dumps(payload))
        await asyncio.sleep(0.5)


async def zeek_log_task(ws):
    global CURRENT_FIELDS

    with open(ZEEK_CONN_FILE, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.1)
                continue

            event = parse_zeek_conn_line(line)
            if event is None:
                continue

            if should_skip_line(line):
                continue

            if should_block_event(event):
                continue

            payload = {
                "type": "zeek_event",
                "data": event
            }
            await ws.send(json.dumps(payload))


async def run_agent():
    while True:
        try:
            print(f"[+] Connecting to {WS_SERVER_URL}")
            async with websockets.connect(WS_SERVER_URL, max_size=10_000_000) as ws:
                print(f"[+] Connected. MACHINE_ID={MACHINE_ID}")
                await asyncio.gather(
                    system_info_task(ws),
                    zeek_log_task(ws)
                )
        except Exception as e:
            print(f"[ERROR] {e}")
            await asyncio.sleep(2)


if __name__ == "__main__":
    asyncio.run(run_agent())