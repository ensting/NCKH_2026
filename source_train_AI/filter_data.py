import os
import glob
import pandas as pd

INPUT_FOLDER = "data/filtered"
OUTPUT_FOLDER = "data/zeek_friendly"
OUTPUT_FILE = os.path.join(OUTPUT_FOLDER, "merged_zeek_features.csv")

os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Nếu để [] thì lấy tất cả file CSV trong INPUT_FOLDER
SELECTED_FILES = [
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
    # "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
]

ZEEK_FRIENDLY_FEATURES = [
    "Dst Port",
    "Protocol",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Fwd Header Len",
    "Bwd Header Len",
    "Fwd Pkts/s",
    "Bwd Pkts/s",
    "Pkt Len Min",
    "Pkt Len Max",
    "Pkt Len Mean",
    "FIN Flag Cnt",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "ACK Flag Cnt",
    "Down/Up Ratio",
    "Pkt Size Avg",
    "Fwd Seg Size Avg",
    "Bwd Seg Size Avg",
    "Subflow Fwd Pkts",
    "Subflow Fwd Byts",
    "Subflow Bwd Pkts",
    "Subflow Bwd Byts",
    "Init Fwd Win Byts",
    "Init Bwd Win Byts",
    "Fwd Act Data Pkts",
    "Fwd Seg Size Min",
]

LABEL_CANDIDATES = ["Label", "label", " Label"]


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


def find_label_column(df):
    for c in LABEL_CANDIDATES:
        if c in df.columns:
            return c
    raise ValueError("Không tìm thấy cột Label")


def normalize_columns(df):
    df.columns = [c.strip() for c in df.columns]
    return df


def filter_one_file(file_path):
    print(f"[+] Đang xử lý: {file_path}")
    df = pd.read_csv(file_path, low_memory=False)
    df = normalize_columns(df)

    label_col = find_label_column(df)

    required_cols = [c for c in ZEEK_FRIENDLY_FEATURES if c in df.columns]
    missing_cols = [c for c in ZEEK_FRIENDLY_FEATURES if c not in df.columns]

    if missing_cols:
        print(f"[!] File thiếu {len(missing_cols)} cột:")
        for c in missing_cols:
            print(f"    - {c}")

    # Chỉ giữ các cột feature có trong file + label
    keep_cols = required_cols + [label_col]
    df = df[keep_cols].copy()

    # Chuẩn hóa label
    df[label_col] = df[label_col].astype(str).str.strip().str.upper()

    # Đổi nhãn nhị phân
    df["target"] = (df[label_col] != "BENIGN").astype("int8")
    df.drop(columns=[label_col], inplace=True)

    # Với cột bị thiếu, thêm vào và gán 0
    for c in ZEEK_FRIENDLY_FEATURES:
        if c not in df.columns:
            df[c] = 0.0

    # Đảm bảo đúng thứ tự cột
    df = df[ZEEK_FRIENDLY_FEATURES + ["target"]]

    # Chuyển numeric
    for c in ZEEK_FRIENDLY_FEATURES:
        df[c] = pd.to_numeric(df[c], errors="coerce")

    # Thay inf bằng NaN theo từng cột
    for c in ZEEK_FRIENDLY_FEATURES:
        s = df[c]
        s = s.mask(s == float("inf"), pd.NA)
        s = s.mask(s == float("-inf"), pd.NA)
        df[c] = s

    # Điền NaN bằng median
    for c in ZEEK_FRIENDLY_FEATURES:
        median_val = df[c].median()
        if pd.isna(median_val):
            median_val = 0.0
        df[c] = df[c].fillna(median_val).astype("float32")

    print(f"    -> shape: {df.shape}")
    return df


def main():
    files = get_csv_files()
    if not files:
        raise FileNotFoundError("Không có file CSV nào trong data/filtered")

    all_dfs = []
    for file_path in files:
        try:
            df = filter_one_file(file_path)
            all_dfs.append(df)
        except Exception as e:
            print(f"[!] Lỗi file {file_path}: {e}")

    if not all_dfs:
        raise ValueError("Không có dữ liệu hợp lệ để gộp")

    merged_df = pd.concat(all_dfs, ignore_index=True)

    print("\n===== THỐNG KÊ SAU KHI GỘP =====")
    print("Shape:", merged_df.shape)
    print("Số lượng nhãn:")
    print(merged_df["target"].value_counts())

    merged_df.to_csv(OUTPUT_FILE, index=False)
    print(f"\n[+] Đã lưu file: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()