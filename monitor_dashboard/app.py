import os
import json
import csv
from datetime import datetime
from typing import Dict, Any, List

import numpy as np
import pandas as pd
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import PlainTextResponse, FileResponse
from pydantic import BaseModel
from xgboost import XGBClassifier

# ================== CẤU HÌNH ==================
MODEL_PATH = "models/xgb_model_zeek.json"
FEATURES_PATH = "models/feature_columns_zeek.json"
CONFIDENCE_THRESHOLD = 0.10

LOG_CSV_PATH = "data/all_logs.csv"
ALERT_CSV_PATH = "data/alerts.csv"

GUIDE_FILE_PATH = "docs/huong_dan_cai_dat.txt"
DOWNLOAD_AGENT_PATH = "downloads/zeek_agent.py"

CLIP_MIN = -1e15
CLIP_MAX = 1e15

PROTO_MAP = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1
}

app = FastAPI(title="Zeek + AI Dashboard")

recent_events: List[Dict[str, Any]] = []
recent_alerts: List[Dict[str, Any]] = []
machines: Dict[str, Any] = {}
registered_machines: Dict[str, Any] = {}

last_alert_id = 0


class ZeekRawEvent(BaseModel):
    machine_id: str
    timestamp: str
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    proto: str
    service: str
    duration: float
    orig_bytes: float
    resp_bytes: float
    orig_pkts: int
    resp_pkts: int
    conn_state: str
    history: str = ""


class SystemInfo(BaseModel):
    machine_id: str
    hostname: str
    ip: str
    cpu_percent: float
    ram_total_mb: float
    ram_used_mb: float
    ram_percent: float
    disk_total_gb: float
    disk_used_gb: float
    disk_percent: float


class RegisterMachine(BaseModel):
    machine_id: str
    hostname: str = ""
    ip: str = ""


class UIConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_json(self, message: dict):
        dead = []
        for ws in self.active_connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ui_manager = UIConnectionManager()


def ensure_csv_dir(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)


def append_dict_to_csv(file_path, row_dict):
    ensure_csv_dir(file_path)
    file_exists = os.path.exists(file_path)

    with open(file_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(row_dict.keys()))
        if not file_exists:
            writer.writeheader()
        writer.writerow(row_dict)


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


def cleanup_numeric(value):
    try:
        v = float(value)
    except Exception:
        return 0.0

    if np.isnan(v) or np.isinf(v):
        return 0.0
    if v > CLIP_MAX:
        return float(CLIP_MAX)
    if v < CLIP_MIN:
        return float(CLIP_MIN)
    return float(v)


def load_model_and_features():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Không tìm thấy model: {MODEL_PATH}")
    if not os.path.exists(FEATURES_PATH):
        raise FileNotFoundError(f"Không tìm thấy feature list: {FEATURES_PATH}")

    model = XGBClassifier()
    model.load_model(MODEL_PATH)

    with open(FEATURES_PATH, "r", encoding="utf-8") as f:
        feature_columns = json.load(f)

    return model, feature_columns


model, feature_columns = load_model_and_features()


def build_feature_row(event: dict, feature_columns: list) -> pd.DataFrame:
    duration = cleanup_numeric(safe_float(event["duration"]))
    orig_bytes = cleanup_numeric(safe_float(event["orig_bytes"]))
    resp_bytes = cleanup_numeric(safe_float(event["resp_bytes"]))
    orig_pkts = cleanup_numeric(safe_float(event["orig_pkts"]))
    resp_pkts = cleanup_numeric(safe_float(event["resp_pkts"]))

    total_bytes = cleanup_numeric(orig_bytes + resp_bytes)
    total_pkts = cleanup_numeric(orig_pkts + resp_pkts)
    proto_num = cleanup_numeric(PROTO_MAP.get(str(event["proto"]).lower(), 0))
    conn_state = str(event["conn_state"]).strip()
    history = str(event.get("history", "")).strip()

    pkt_size_avg = cleanup_numeric((total_bytes / total_pkts) if total_pkts > 0 else 0.0)
    fwd_seg_avg = cleanup_numeric((orig_bytes / orig_pkts) if orig_pkts > 0 else 0.0)
    bwd_seg_avg = cleanup_numeric((resp_bytes / resp_pkts) if resp_pkts > 0 else 0.0)

    flow_bytes_s = cleanup_numeric((total_bytes / duration) if duration > 0 else 0.0)
    flow_pkts_s = cleanup_numeric((total_pkts / duration) if duration > 0 else 0.0)
    fwd_pkts_s = cleanup_numeric((orig_pkts / duration) if duration > 0 else 0.0)
    bwd_pkts_s = cleanup_numeric((resp_pkts / duration) if duration > 0 else 0.0)

    down_up_ratio = cleanup_numeric((resp_pkts / orig_pkts) if orig_pkts > 0 else 0.0)

    row = {col: 0.0 for col in feature_columns}

    mapping = {
        "Dst Port": cleanup_numeric(safe_int(event["dest_port"])),
        "Protocol": proto_num,
        "Flow Duration": duration,
        "Tot Fwd Pkts": orig_pkts,
        "Tot Bwd Pkts": resp_pkts,
        "TotLen Fwd Pkts": orig_bytes,
        "TotLen Bwd Pkts": resp_bytes,
        "Flow Byts/s": flow_bytes_s,
        "Flow Pkts/s": flow_pkts_s,
        "Fwd Pkts/s": fwd_pkts_s,
        "Bwd Pkts/s": bwd_pkts_s,
        "FIN Flag Cnt": 1.0 if ("F" in conn_state or "f" in history) else 0.0,
        "SYN Flag Cnt": 1.0 if (conn_state.startswith("S") or "s" in history) else 0.0,
        "RST Flag Cnt": 1.0 if ("R" in conn_state or "r" in history) else 0.0,
        "ACK Flag Cnt": 1.0 if ("a" in history or conn_state in ("S1", "S2", "S3", "SF", "RSTO", "RSTR")) else 0.0,
        "Down/Up Ratio": down_up_ratio,
        "Pkt Size Avg": pkt_size_avg,
        "Fwd Seg Size Avg": fwd_seg_avg,
        "Bwd Seg Size Avg": bwd_seg_avg,
        "Subflow Fwd Pkts": orig_pkts,
        "Subflow Fwd Byts": orig_bytes,
        "Subflow Bwd Pkts": resp_pkts,
        "Subflow Bwd Byts": resp_bytes
    }

    for k, v in mapping.items():
        if k in row:
            row[k] = cleanup_numeric(v)

    df = pd.DataFrame([row])

    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")
        df[col] = df[col].replace([np.inf, -np.inf], np.nan)
        df[col] = df[col].clip(lower=CLIP_MIN, upper=CLIP_MAX)
        df[col] = df[col].fillna(0.0).astype("float32")

    return df


def flatten_event_for_csv(data: dict):
    row = {
        "machine_id": data.get("machine_id", ""),
        "timestamp": data.get("timestamp", ""),
        "src_ip": data.get("src_ip", ""),
        "src_port": data.get("src_port", 0),
        "dest_ip": data.get("dest_ip", ""),
        "dest_port": data.get("dest_port", 0),
        "proto": data.get("proto", ""),
        "service": data.get("service", ""),
        "duration": data.get("duration", 0),
        "orig_bytes": data.get("orig_bytes", 0),
        "resp_bytes": data.get("resp_bytes", 0),
        "orig_pkts": data.get("orig_pkts", 0),
        "resp_pkts": data.get("resp_pkts", 0),
        "conn_state": data.get("conn_state", ""),
        "history": data.get("history", ""),
        "prediction_numeric": data.get("prediction_numeric", 0),
        "prediction": data.get("prediction", ""),
        "confidence": data.get("confidence", 0),
        "threshold": data.get("threshold", 0),
        "model_version": data.get("model_version", ""),
        "received_at": data.get("received_at", "")
    }

    for k, v in (data.get("features", {}) or {}).items():
        row[k] = v

    return row


async def process_system_info(system_info_raw: dict):
    sys_info = SystemInfo(**system_info_raw).dict()
    machine_id = sys_info["machine_id"].strip()

    machines[machine_id] = {
        **sys_info,
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    if machine_id not in registered_machines:
        registered_machines[machine_id] = {
            "machine_id": machine_id,
            "hostname": sys_info.get("hostname", ""),
            "ip": sys_info.get("ip", ""),
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    await ui_manager.broadcast_json({"type": "system_info", "data": machines[machine_id]})


async def process_zeek_event(zeek_event_raw: dict):
    global last_alert_id

    event = ZeekRawEvent(**zeek_event_raw).dict()
    X = build_feature_row(event, feature_columns)

    X_np = X.to_numpy(dtype=np.float32)
    if np.isinf(X_np).sum() > 0 or np.isnan(X_np).sum() > 0:
        return

    pred = int(model.predict(X)[0])
    proba = float(model.predict_proba(X)[0][1])

    features_all = {c: float(X.iloc[0][c]) for c in X.columns}

    data = {
        **event,
        "received_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "features": features_all,
        "prediction_numeric": pred,
        "prediction": "ATTACK" if pred == 1 and proba >= CONFIDENCE_THRESHOLD else "BENIGN",
        "confidence": round(proba, 6),
        "threshold": CONFIDENCE_THRESHOLD,
        "model_version": "zeek_friendly_v2"
    }

    recent_events.insert(0, data)
    append_dict_to_csv(LOG_CSV_PATH, flatten_event_for_csv(data))

    await ui_manager.broadcast_json({"type": "zeek_event", "data": data})

    if pred == 1 and proba >= CONFIDENCE_THRESHOLD:
        last_alert_id += 1
        alert = {"id": last_alert_id, **data}
        recent_alerts.insert(0, alert)

        alert_row = flatten_event_for_csv(alert)
        alert_row["id"] = last_alert_id
        append_dict_to_csv(ALERT_CSV_PATH, alert_row)

        await ui_manager.broadcast_json({"type": "alert_event", "data": alert})


# ===== REST API =====
@app.get("/zeek-events")
async def get_events():
    return recent_events


@app.get("/alerts")
async def get_alerts():
    return recent_alerts


@app.get("/machines")
async def get_machines():
    return list(machines.values())


@app.get("/machines/registered")
async def get_registered_machines():
    return list(registered_machines.values())


@app.post("/machines/register")
async def register_machine(machine: RegisterMachine):
    machine_id = machine.machine_id.strip()
    if not machine_id:
        return {"status": "error", "message": "machine_id is required"}

    registered_machines[machine_id] = {
        "machine_id": machine_id,
        "hostname": machine.hostname,
        "ip": machine.ip,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    return {"status": "ok"}


@app.get("/installation-guide", response_class=PlainTextResponse)
async def get_installation_guide():
    if not os.path.exists(GUIDE_FILE_PATH):
        return "Chưa có file hướng dẫn cài đặt."
    with open(GUIDE_FILE_PATH, "r", encoding="utf-8") as f:
        return f.read()


@app.get("/download/zeek-agent")
async def download_zeek_agent():
    if not os.path.exists(DOWNLOAD_AGENT_PATH):
        return {"status": "error", "message": "Không tìm thấy file zeek_agent.py"}
    return FileResponse(
        path=DOWNLOAD_AGENT_PATH,
        filename="zeek_agent.py",
        media_type="text/x-python"
    )


@app.get("/download/guide")
async def download_guide():
    if not os.path.exists(GUIDE_FILE_PATH):
        return {"status": "error", "message": "Không tìm thấy file hướng dẫn"}
    return FileResponse(
        path=GUIDE_FILE_PATH,
        filename="huong_dan_cai_dat.txt",
        media_type="text/plain"
    )


# ===== WEBSOCKET =====
@app.websocket("/ws/agent")
async def ws_agent(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            payload = await websocket.receive_json()
            msg_type = payload.get("type")

            if msg_type == "system_info":
                await process_system_info(payload.get("data", {}))
            elif msg_type == "zeek_event":
                await process_zeek_event(payload.get("data", {}))
            else:
                await websocket.send_json({"status": "error", "message": "unknown message type"})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"status": "error", "message": str(e)})
        except Exception:
            pass


@app.websocket("/ws/ui")
async def ws_ui(websocket: WebSocket):
    await ui_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ui_manager.disconnect(websocket)


app.mount("/", StaticFiles(directory="static", html=True), name="static")