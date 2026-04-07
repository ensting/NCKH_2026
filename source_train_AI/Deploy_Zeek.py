import os
import json
import time
import hashlib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

MODEL_PATH = "/opt/ai-flow/models_zeek/xgb_model_zeek.json"
FEATURES_PATH = "/opt/ai-flow/models_zeek/feature_columns_zeek.json"
ARCHIVE_FILE = "/var/ossec/logs/archives/archives.json"
OUTPUT_ALERT_FILE = "/opt/ai-flow/logs/ai_flow_alerts.json"

CONFIDENCE_THRESHOLD = 0.20
DEBUG = True

RECENT_HASHES = set()
MAX_RECENT_HASHES = 5000

PROTO_MAP = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1
}


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


def safe_float(x, default=0.0):
    try:
        if x in (None, "", "-", "0-"):
            return default
        return float(x)
    except Exception:
        return default


def safe_int(x, default=0):
    try:
        if x in (None, "", "-", "0-"):
            return default
        return int(float(x))
    except Exception:
        return default


def should_skip_line(full_log: str) -> bool:
    if not full_log:
        return True

    text = full_log.strip()
    if not text:
        return True

    if text.startswith("#"):
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


def parse_zeek_conn_message(msg: str):
    if not msg or msg.startswith("#"):
        return None

    parts = msg.strip().split("\t")
    if len(parts) < 20:
        return None

    try:
        return {
            "ts": parts[0],
            "uid": parts[1],
            "src_ip": parts[2],
            "src_port": parts[3],
            "dest_ip": parts[4],
            "dest_port": parts[5],
            "proto": parts[6],
            "service": parts[7],
            "duration": parts[8],
            "orig_bytes": parts[9],
            "resp_bytes": parts[10],
            "conn_state": parts[11],
            "orig_pkts": parts[16] if len(parts) > 16 else "0",
            "orig_ip_bytes": parts[17] if len(parts) > 17 else "0",
            "resp_pkts": parts[18] if len(parts) > 18 else "0",
            "resp_ip_bytes": parts[19] if len(parts) > 19 else "0",
        }
    except Exception:
        return None


def build_feature_row(event: dict, feature_columns: list) -> pd.DataFrame:
    duration = safe_float(event["duration"])
    orig_bytes = safe_float(event["orig_bytes"])
    resp_bytes = safe_float(event["resp_bytes"])
    orig_pkts = safe_float(event["orig_pkts"])
    resp_pkts = safe_float(event["resp_pkts"])

    total_bytes = orig_bytes + resp_bytes
    total_pkts = orig_pkts + resp_pkts
    proto_num = PROTO_MAP.get(event["proto"], 0)
    conn_state = event["conn_state"]

    pkt_size_avg = (total_bytes / total_pkts) if total_pkts > 0 else 0.0
    fwd_seg_avg = (orig_bytes / orig_pkts) if orig_pkts > 0 else 0.0
    bwd_seg_avg = (resp_bytes / resp_pkts) if resp_pkts > 0 else 0.0

    row = {col: 0.0 for col in feature_columns}

    mapping = {
        "Dst Port": safe_int(event["dest_port"]),
        "Protocol": proto_num,
        "Flow Duration": duration,
        "Tot Fwd Pkts": orig_pkts,
        "Tot Bwd Pkts": resp_pkts,
        "TotLen Fwd Pkts": orig_bytes,
        "TotLen Bwd Pkts": resp_bytes,
        "Flow Byts/s": (total_bytes / duration) if duration > 0 else 0.0,
        "Flow Pkts/s": (total_pkts / duration) if duration > 0 else 0.0,
        "Fwd Pkts/s": (orig_pkts / duration) if duration > 0 else 0.0,
        "Bwd Pkts/s": (resp_pkts / duration) if duration > 0 else 0.0,
        "FIN Flag Cnt": 1.0 if "F" in conn_state else 0.0,
        "SYN Flag Cnt": 1.0 if conn_state.startswith("S") else 0.0,
        "RST Flag Cnt": 1.0 if "R" in conn_state else 0.0,
        "ACK Flag Cnt": 1.0 if conn_state in ("S1", "S2", "S3", "SF") else 0.0,
        "Down/Up Ratio": (resp_pkts / orig_pkts) if orig_pkts > 0 else 0.0,
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
            row[k] = v

    df = pd.DataFrame([row])

    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0).astype("float32")

    return df


def write_alert(event: dict, confidence: float):
    os.makedirs(os.path.dirname(OUTPUT_ALERT_FILE), exist_ok=True)

    out = {
        "ai_engine": "xgboost_zeek_friendly",
        "event_type": "network_flow_alert",
        "src_ip": event["src_ip"],
        "src_port": safe_int(event["src_port"]),
        "dest_ip": event["dest_ip"],
        "dest_port": safe_int(event["dest_port"]),
        "proto": event["proto"],
        "service": event["service"],
        "duration": safe_float(event["duration"]),
        "orig_bytes": safe_float(event["orig_bytes"]),
        "resp_bytes": safe_float(event["resp_bytes"]),
        "orig_pkts": safe_int(event["orig_pkts"]),
        "resp_pkts": safe_int(event["resp_pkts"]),
        "conn_state": event["conn_state"],
        "prediction": "ATTACK",
        "confidence": round(float(confidence), 4),
        "model_version": "zeek_friendly_v1"
    }

    with open(OUTPUT_ALERT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(out, ensure_ascii=False) + "\n")


def follow_file(path: str):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def main():
    model, feature_columns = load_model_and_features()
    print("[+] AI started (zeek-friendly model)")

    for line in follow_file(ARCHIVE_FILE):
        try:
            obj = json.loads(line)
        except Exception:
            continue

        full_log = obj.get("full_log", "")
        if should_skip_line(full_log):
            continue

        event = parse_zeek_conn_message(full_log)
        if not event:
            continue

        try:
            X = build_feature_row(event, feature_columns)
            pred = int(model.predict(X)[0])
            proba = float(model.predict_proba(X)[0][1])
        except Exception as e:
            print(f"[ERROR] Predict failed: {e}")
            continue

        if DEBUG:
            non_zero = {c: float(X.iloc[0][c]) for c in X.columns if float(X.iloc[0][c]) != 0.0}
            print(
                f"[DEBUG] {event['src_ip']}:{event['src_port']} -> "
                f"{event['dest_ip']}:{event['dest_port']} "
                f"proto={event['proto']} service={event['service']} "
                f"state={event['conn_state']} pred={pred} prob={proba:.4f} "
                f"non_zero={len(non_zero)}"
            )

        if pred == 1 and proba >= CONFIDENCE_THRESHOLD:
            write_alert(event, proba)
            print(
                f"[ALERT] {event['src_ip']}:{event['src_port']} -> "
                f"{event['dest_ip']}:{event['dest_port']} prob={proba:.4f}"
            )


if __name__ == "__main__":
    main()