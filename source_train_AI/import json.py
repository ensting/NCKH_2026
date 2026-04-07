import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

ARCHIVE_FILE = "/var/ossec/logs/archives/archives.json"
OUTPUT_FILE = "/var/log/zeek_from_archives.json"

TARGET_LOCATIONS = {
    "/opt/zeek-docker-logs/conn.log",
}

ZEEK_CONN_FIELDS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "tunnel_parents",
    "ip_proto",
]

ZEEK_CONN_TYPES = {
    "ts": "time",
    "uid": "string",
    "id.orig_h": "addr",
    "id.orig_p": "port",
    "id.resp_h": "addr",
    "id.resp_p": "port",
    "proto": "enum",
    "service": "string",
    "duration": "interval",
    "orig_bytes": "count",
    "resp_bytes": "count",
    "conn_state": "string",
    "local_orig": "bool",
    "local_resp": "bool",
    "missed_bytes": "count",
    "history": "string",
    "orig_pkts": "count",
    "orig_ip_bytes": "count",
    "resp_pkts": "count",
    "resp_ip_bytes": "count",
    "tunnel_parents": "set[string]",
    "ip_proto": "count",
}


def safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, "", "-", "(empty)"):
            return default
        return int(float(value))
    except Exception:
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value in (None, "", "-", "(empty)"):
            return default
        return float(value)
    except Exception:
        return default


def safe_bool(value: Any, default: bool = False) -> bool:
    if value in (True, "T", "true", "True", 1, "1"):
        return True
    if value in (False, "F", "false", "False", 0, "0"):
        return False
    return default


def parse_set_string(value: Any):
    if value in (None, "", "-", "(empty)"):
        return []
    return [str(value)]


def to_iso_timestamp(ts: Any) -> str:
    value = safe_float(ts, 0.0)
    if value <= 0:
        return datetime.now(timezone.utc).isoformat()
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def convert_by_type(field: str, raw_value: str):
    zeek_type = ZEEK_CONN_TYPES.get(field, "string")

    if raw_value == "-":
        if zeek_type == "set[string]":
            return []
        return None

    if raw_value == "(empty)":
        if zeek_type == "set[string]":
            return []
        return ""

    if zeek_type in ("count", "port"):
        return safe_int(raw_value)

    if zeek_type in ("time", "interval"):
        return safe_float(raw_value)

    if zeek_type == "bool":
        return safe_bool(raw_value)

    if zeek_type == "set[string]":
        return parse_set_string(raw_value)

    return raw_value


def parse_zeek_tsv_full_log(full_log: str) -> Optional[Dict[str, Any]]:
    if not full_log:
        return None

    parts = full_log.split("\t")
    if len(parts) < len(ZEEK_CONN_FIELDS):
        return None

    parts = parts[:len(ZEEK_CONN_FIELDS)]

    parsed: Dict[str, Any] = {}
    for field, raw in zip(ZEEK_CONN_FIELDS, parts):
        parsed[field] = convert_by_type(field, raw)

    return parsed


def normalize_record(archive_event: Dict[str, Any], zeek: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "@timestamp": to_iso_timestamp(zeek.get("ts")),
        "event_type": "zeek_conn",
        "source": "wazuh_archives_tsv",
        "archive_location": archive_event.get("location", ""),
        "archive_timestamp": archive_event.get("timestamp", ""),
        "agent_id": archive_event.get("agent", {}).get("id", ""),
        "agent_name": archive_event.get("agent", {}).get("name", ""),
        "manager_name": archive_event.get("manager", {}).get("name", ""),
        "decoder_name": archive_event.get("decoder", {}).get("name", ""),
        "input_type": archive_event.get("input", {}).get("type", ""),
        "uid": zeek.get("uid", ""),
        "src_ip": zeek.get("id.orig_h", ""),
        "src_port": zeek.get("id.orig_p", 0),
        "dest_ip": zeek.get("id.resp_h", ""),
        "dest_port": zeek.get("id.resp_p", 0),
        "proto": zeek.get("proto", ""),
        "service": zeek.get("service") or "",
        "duration": zeek.get("duration", 0.0),
        "conn_state": zeek.get("conn_state", ""),
        "local_orig": zeek.get("local_orig", False),
        "local_resp": zeek.get("local_resp", False),
        "missed_bytes": zeek.get("missed_bytes", 0),
        "history": zeek.get("history", ""),
        "orig_pkts": zeek.get("orig_pkts", 0),
        "resp_pkts": zeek.get("resp_pkts", 0),
        "orig_ip_bytes": zeek.get("orig_ip_bytes", 0),
        "resp_ip_bytes": zeek.get("resp_ip_bytes", 0),
        "orig_bytes": zeek.get("orig_bytes", 0),
        "resp_bytes": zeek.get("resp_bytes", 0),
        "tunnel_parents": zeek.get("tunnel_parents", []),
        "ip_proto": zeek.get("ip_proto", 0),
        "raw_full_log": archive_event.get("full_log", ""),
    }


def process_line(line: str, out) -> bool:
    line = line.strip()
    if not line:
        return False

    try:
        event = json.loads(line)
    except Exception:
        return False

    location = event.get("location", "")
    if location not in TARGET_LOCATIONS:
        return False

    full_log = event.get("full_log", "")
    zeek = parse_zeek_tsv_full_log(full_log)
    if not zeek:
        return False

    normalized = normalize_record(event, zeek)
    out.write(json.dumps(normalized, ensure_ascii=False) + "\n")
    out.flush()
    return True


def follow_file(filepath: str):
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)  # chỉ đọc log mới phát sinh
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def main() -> None:
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    processed = 0
    matched = 0

    print(f"Watching: {ARCHIVE_FILE}")
    print(f"Writing:  {OUTPUT_FILE}")
    print("Press Ctrl+C to stop.")

    try:
        with open(OUTPUT_FILE, "a", encoding="utf-8") as out:
            for line in follow_file(ARCHIVE_FILE):
                processed += 1
                if process_line(line, out):
                    matched += 1
                    print(f"[+] Matched: {matched} | Processed new lines: {processed}")
    except KeyboardInterrupt:
        print("\nStopped by user.")
        print(f"Processed new lines: {processed}")
        print(f"Matched and written: {matched}")


if __name__ == "__main__":
    main()