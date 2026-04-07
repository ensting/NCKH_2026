import os
import glob
import pandas as pd
import numpy as np

INPUT_FOLDER = "data/filtered"
OUTPUT_FOLDER = "data/behavior_5s"
OUTPUT_FILE = os.path.join(OUTPUT_FOLDER, "behavior_dataset_5s.csv")

os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Nếu để [] thì lấy tất cả CSV trong INPUT_FOLDER
SELECTED_FILES = [
    # "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
    "02-14-2018.csv",
    "02-15-2018.csv",
    "02-16-2018.csv",
    "02-20-2018.csv",
    "02-21-2018.csv",
    "02-22-2018.csv",
    "02-23-2018.csv",
    "02-28-2018.csv",
    "03-01-2018.csv",
    "03-02-2018.csv"
]

LABEL_CANDIDATES = ["Label", "label", " Label"]

REQUIRED_COLUMNS = [
    "Timestamp",
    "Src IP",
    "Dst IP",
    "Dst Port",
    "Protocol",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Pkt Len Mean",
    "Down/Up Ratio",
    "Label",
]

WINDOW_SECONDS = 5


def get_csv_files():
    if SELECTED_FILES:
        files = []
        for f in SELECTED_FILES:
            path = os.path.join(INPUT_FOLDER, f)
            if os.path.exists(path):
                files.append(path)
            else:
                print(f"[!] Không tìm thấy file: {path}")
        return files
    return glob.glob(os.path.join(INPUT_FOLDER, "*.csv"))


def normalize_columns(df):
    df.columns = [c.strip() for c in df.columns]
    return df


def find_label_column(df):
    for c in LABEL_CANDIDATES:
        if c in df.columns:
            return c
    raise ValueError("Không tìm thấy cột Label")


def find_src_ip_col(df):
    candidates = ["Src IP", "Source IP"]
    for c in candidates:
        if c in df.columns:
            return c
    raise ValueError("Không tìm thấy cột Src IP")


def find_dst_ip_col(df):
    candidates = ["Dst IP", "Destination IP"]
    for c in candidates:
        if c in df.columns:
            return c
    raise ValueError("Không tìm thấy cột Dst IP")


def preprocess_one_file(file_path):
    print(f"[+] Đang xử lý file: {file_path}")
    df = pd.read_csv(file_path, low_memory=False)
    df = normalize_columns(df)

    label_col = find_label_column(df)
    src_ip_col = find_src_ip_col(df)
    dst_ip_col = find_dst_ip_col(df)

    keep_cols = [
        c for c in [
            "Timestamp",
            src_ip_col,
            dst_ip_col,
            "Dst Port",
            "Protocol",
            "Flow Duration",
            "Tot Fwd Pkts",
            "Tot Bwd Pkts",
            "TotLen Fwd Pkts",
            "TotLen Bwd Pkts",
            "Flow Byts/s",
            "Flow Pkts/s",
            "Pkt Len Mean",
            "Down/Up Ratio",
            label_col,
        ] if c in df.columns
    ]

    df = df[keep_cols].copy()

    # Đổi tên cột cho thống nhất
    rename_map = {
        src_ip_col: "Src IP",
        dst_ip_col: "Dst IP",
        label_col: "Label"
    }
    df.rename(columns=rename_map, inplace=True)

    # Chuẩn hóa Label
    df["Label"] = df["Label"].astype(str).str.strip().str.upper()
    df["label"] = np.where(df["Label"] == "BENIGN", 0, 1).astype("int8")

    # Parse time
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    df = df.dropna(subset=["Timestamp"])

    # Chuyển numeric
    numeric_cols = [
        "Dst Port",
        "Protocol",
        "Flow Duration",
        "Tot Fwd Pkts",
        "Tot Bwd Pkts",
        "TotLen Fwd Pkts",
        "TotLen Bwd Pkts",
        "Flow Byts/s",
        "Flow Pkts/s",
        "Pkt Len Mean",
        "Down/Up Ratio",
    ]

    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # Thay inf và NaN
    for col in numeric_cols:
        if col in df.columns:
            s = df[col]
            s = s.mask(np.isinf(s), np.nan)
            median_val = s.median()
            if pd.isna(median_val):
                median_val = 0.0
            df[col] = s.fillna(median_val).astype("float32")

    return df


def build_behavior_features(df):
    # Tạo window 5 giây
    # floor timestamp về mốc 5 giây
    ts_int = df["Timestamp"].astype("int64") // 10**9
    df["window_start"] = (ts_int // WINDOW_SECONDS) * WINDOW_SECONDS

    # map proto
    df["is_tcp"] = (df["Protocol"] == 6).astype("int8")
    df["is_udp"] = (df["Protocol"] == 17).astype("int8")
    df["is_icmp"] = (df["Protocol"] == 1).astype("int8")

    # heuristic để tạo trạng thái gần đúng từ flow
    # Vì CICFlowMeter không có conn_state như Zeek, ta dùng label nhẹ cho failed behavior gần đúng
    # chỉ để tạo feature hành vi cho AI tầng 2
    df["is_failed_like"] = ((df["TotLen Bwd Pkts"] <= 0) | (df["Flow Byts/s"] <= 1)).astype("int8")
    df["is_rej_like"] = ((df["TotLen Bwd Pkts"] <= 0) & (df["Tot Bwd Pkts"] <= 0)).astype("int8")
    df["is_s0_like"] = ((df["Tot Bwd Pkts"] <= 0) & (df["Tot Fwd Pkts"] > 0)).astype("int8")
    df["is_rst_like"] = ((df["Flow Duration"] < 1) & (df["TotLen Bwd Pkts"] <= 0)).astype("int8")
    df["is_sf_like"] = ((df["Tot Bwd Pkts"] > 0) & (df["TotLen Bwd Pkts"] > 0)).astype("int8")

    grouped = df.groupby(["Src IP", "Dst IP", "window_start"], dropna=False)

    behavior_df = grouped.agg(
        flow_count=("Dst Port", "count"),
        unique_dest_ports=("Dst Port", "nunique"),
        rej_count=("is_rej_like", "sum"),
        s0_count=("is_s0_like", "sum"),
        rst_count=("is_rst_like", "sum"),
        sf_count=("is_sf_like", "sum"),
        failed_like_count=("is_failed_like", "sum"),
        tcp_count=("is_tcp", "sum"),
        udp_count=("is_udp", "sum"),
        icmp_count=("is_icmp", "sum"),
        avg_duration=("Flow Duration", "mean"),
        avg_tot_fwd_pkts=("Tot Fwd Pkts", "mean"),
        avg_tot_bwd_pkts=("Tot Bwd Pkts", "mean"),
        avg_totlen_fwd_pkts=("TotLen Fwd Pkts", "mean"),
        avg_totlen_bwd_pkts=("TotLen Bwd Pkts", "mean"),
        avg_flow_byts_s=("Flow Byts/s", "mean"),
        avg_flow_pkts_s=("Flow Pkts/s", "mean"),
        avg_pkt_len_mean=("Pkt Len Mean", "mean"),
        avg_down_up_ratio=("Down/Up Ratio", "mean"),
        attack_ratio=("label", "mean"),
        attack_count=("label", "sum"),
    ).reset_index()

    behavior_df["failed_ratio"] = (
        behavior_df["failed_like_count"] / behavior_df["flow_count"].replace(0, 1)
    ).astype("float32")

    # Gán label cho whole window:
    # nếu trong nhóm có >= 50% flow attack thì coi là attack
    behavior_df["label"] = (behavior_df["attack_ratio"] >= 0.5).astype("int8")

    # Đổi tên cho rõ
    behavior_df.rename(columns={
        "Src IP": "src_ip",
        "Dst IP": "dest_ip"
    }, inplace=True)

    # Đổi window_start về datetime để dễ nhìn
    behavior_df["window_start"] = pd.to_datetime(behavior_df["window_start"], unit="s")

    # Chỉ giữ cột cần dùng
    final_cols = [
        "src_ip",
        "dest_ip",
        "window_start",
        "flow_count",
        "unique_dest_ports",
        "rej_count",
        "s0_count",
        "rst_count",
        "sf_count",
        "failed_ratio",
        "tcp_count",
        "udp_count",
        "icmp_count",
        "avg_duration",
        "avg_tot_fwd_pkts",
        "avg_tot_bwd_pkts",
        "avg_totlen_fwd_pkts",
        "avg_totlen_bwd_pkts",
        "avg_flow_byts_s",
        "avg_flow_pkts_s",
        "avg_pkt_len_mean",
        "avg_down_up_ratio",
        "label",
    ]

    behavior_df = behavior_df[final_cols].copy()
    return behavior_df


def main():
    files = get_csv_files()
    if not files:
        raise FileNotFoundError("Không có file CSV nào trong data/filtered")

    all_behavior = []

    for file_path in files:
        try:
            df = preprocess_one_file(file_path)
            behavior_df = build_behavior_features(df)
            print(f"    -> behavior shape: {behavior_df.shape}")
            all_behavior.append(behavior_df)
        except Exception as e:
            print(f"[!] Lỗi file {file_path}: {e}")

    if not all_behavior:
        raise ValueError("Không có dữ liệu behavior hợp lệ")

    final_df = pd.concat(all_behavior, ignore_index=True)

    print("\n===== THỐNG KÊ DATASET HÀNH VI =====")
    print("Shape:", final_df.shape)
    print("Số lượng nhãn:")
    print(final_df["label"].value_counts())

    final_df.to_csv(OUTPUT_FILE, index=False)
    print(f"\n[+] Đã lưu dataset hành vi: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()