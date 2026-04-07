import pandas as pd
import numpy as np
import os
import glob
import json

# ================== CẤU HÌNH ==================
INPUT_DIR = r"F:\nckh\XGBoost\data\raw"
OUTPUT_FILE = r"F:\nckh\cic2018_processed_for_xgboost.parquet"
REPORT_FILE = r"F:\nckh\cic2018_preprocess_report.json"

FEATURE_COLUMNS = [
    "Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
    "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Flow Byts/s", "Flow Pkts/s",
    "Fwd Pkts/s", "Bwd Pkts/s", "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt",
    "ACK Flag Cnt", "Down/Up Ratio", "Pkt Size Avg", "Fwd Seg Size Avg",
    "Bwd Seg Size Avg", "Subflow Fwd Pkts", "Subflow Fwd Byts",
    "Subflow Bwd Pkts", "Subflow Bwd Byts"
]

RENAME_MAP = {
    "Total Fwd Packets": "Tot Fwd Pkts",
    "Total Backward Packets": "Tot Bwd Pkts",
    "Total Length of Fwd Packets": "TotLen Fwd Pkts",
    "Total Length of Bwd Packets": "TotLen Bwd Pkts",
    "Flow Bytes/s": "Flow Byts/s",
    "Flow Packets/s": "Flow Pkts/s",
    "Fwd Packets/s": "Fwd Pkts/s",
    "Bwd Packets/s": "Bwd Pkts/s",
    "FIN Flag Count": "FIN Flag Cnt",
    "SYN Flag Count": "SYN Flag Cnt",
    "RST Flag Count": "RST Flag Cnt",
    "ACK Flag Count": "ACK Flag Cnt",
    "Average Packet Size": "Pkt Size Avg",
    "Avg Fwd Segment Size": "Fwd Seg Size Avg",
    "Avg Bwd Segment Size": "Bwd Seg Size Avg",
    "Subflow Fwd Packets": "Subflow Fwd Pkts",
    "Subflow Fwd Bytes": "Subflow Fwd Byts",
    "Subflow Bwd Packets": "Subflow Bwd Pkts",
    "Subflow Bwd Bytes": "Subflow Bwd Byts",
}

CLIP_MIN = -1e15
CLIP_MAX = 1e15


def preprocess_cic2018():
    print("Đang tiền xử lý CIC-IDS-2018...")

    csv_files = glob.glob(os.path.join(INPUT_DIR, "**", "*.csv"), recursive=True)
    if not csv_files:
        raise FileNotFoundError(f"Không tìm thấy file CSV nào trong: {INPUT_DIR}")

    print(f"Tìm thấy {len(csv_files)} file CSV")

    dfs = []
    report = {
        "input_dir": INPUT_DIR,
        "output_file": OUTPUT_FILE,
        "files_total": len(csv_files),
        "files_processed": 0,
        "files_skipped": 0,
        "total_rows_before": 0,
        "total_rows_after": 0,
        "total_missing_cells_before_fill": 0,
        "file_details": []
    }

    for file in csv_files:
        filename = os.path.basename(file)
        print("\n" + "=" * 70)
        print(f"Đang đọc: {filename}")

        file_info = {
            "filename": filename,
            "rows_before": 0,
            "rows_after": 0,
            "missing_feature_columns_added": [],
            "nan_before_fill": 0,
            "status": "processed"
        }

        try:
            df = pd.read_csv(
                file,
                low_memory=False,
                on_bad_lines="skip",
                encoding="utf-8"
            )
        except Exception as e:
            print(f"   → Lỗi đọc file: {e}")
            file_info["status"] = f"read_error: {str(e)}"
            report["files_skipped"] += 1
            report["file_details"].append(file_info)
            continue

        original_rows = len(df)
        file_info["rows_before"] = int(original_rows)
        report["total_rows_before"] += int(original_rows)

        # Chuẩn hóa tên cột
        df.columns = [str(c).strip() for c in df.columns]
        df = df.rename(columns=RENAME_MAP)

        # Loại dòng header lặp an toàn hơn:
        # nếu giá trị cột đầu tiên bằng đúng tên cột đầu tiên thì coi là header lặp
        if len(df) > 0:
            first_col = df.columns[0]
            df = df[
                df[first_col].astype(str).str.strip().str.lower() != first_col.strip().lower()
            ].copy()

        # Bắt buộc phải có Label
        if "Label" not in df.columns:
            print("   → Bỏ qua file vì thiếu cột Label")
            file_info["status"] = "skipped_missing_label"
            report["files_skipped"] += 1
            report["file_details"].append(file_info)
            continue

        # Nếu thiếu feature thì thêm 0 để cố định schema
        missing_cols = [col for col in FEATURE_COLUMNS if col not in df.columns]
        for col in missing_cols:
            df[col] = 0

        file_info["missing_feature_columns_added"] = missing_cols

        # Giữ đúng schema
        df = df[FEATURE_COLUMNS + ["Label"]].copy()

        # Ép toàn bộ feature sang numeric
        for col in FEATURE_COLUMNS:
            df[col] = pd.to_numeric(df[col], errors="coerce")

        # Thay inf/-inf thành NaN
        df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan)

        # Chặn giá trị quá lớn
        df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].clip(lower=CLIP_MIN, upper=CLIP_MAX)

        # Thống kê NaN trước fill
        nan_count = int(df[FEATURE_COLUMNS].isna().sum().sum())
        file_info["nan_before_fill"] = nan_count
        report["total_missing_cells_before_fill"] += nan_count

        # Fill NaN và ép float32
        df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].fillna(0).astype("float32")

        # Xử lý Label
        df["Label"] = df["Label"].astype(str).str.strip().str.lower()
        df["Label"] = df["Label"].apply(lambda x: 0 if x == "benign" else 1).astype("int8")

        file_info["rows_after"] = int(len(df))
        report["total_rows_after"] += int(len(df))
        report["files_processed"] += 1

        print(f"   → Dòng gốc                : {original_rows:,}")
        print(f"   → Dòng sau làm sạch       : {len(df):,}")
        print(f"   → Cột thiếu được thêm 0   : {len(missing_cols)}")
        print(f"   → Số ô NaN trước fill     : {nan_count:,}")

        dfs.append(df)
        report["file_details"].append(file_info)

    if not dfs:
        raise ValueError("Không có dữ liệu hợp lệ sau tiền xử lý")

    print("\nGhép các file lại...")
    final_df = pd.concat(dfs, ignore_index=True)

    # Kiểm tra lần cuối
    X_np = final_df[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    final_inf = int(np.isinf(X_np).sum())
    final_nan = int(np.isnan(X_np).sum())

    print("\n" + "=" * 70)
    print("KIỂM TRA CUỐI")
    print("=" * 70)
    print(f"Final inf : {final_inf}")
    print(f"Final nan : {final_nan}")
    print(f"Max value : {np.nanmax(X_np)}")
    print(f"Min value : {np.nanmin(X_np)}")

    if final_inf > 0 or final_nan > 0:
        raise ValueError("Dữ liệu cuối vẫn còn inf hoặc nan, không an toàn để train!")

    # Lưu parquet
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    final_df.to_parquet(OUTPUT_FILE, index=False, compression="snappy")

    # Thêm tổng kết report
    report["final_inf"] = final_inf
    report["final_nan"] = final_nan
    report["final_rows"] = int(len(final_df))
    report["attack_count"] = int(final_df["Label"].sum())
    report["benign_count"] = int(len(final_df) - final_df["Label"].sum())
    report["feature_columns"] = FEATURE_COLUMNS

    # Lưu report json
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print("\n" + "=" * 70)
    print("HOÀN THÀNH TIỀN XỬ LÝ")
    print("=" * 70)
    print(f"File output  : {OUTPUT_FILE}")
    print(f"File report  : {REPORT_FILE}")
    print(f"Tổng samples : {len(final_df):,}")
    print(f"Attack       : {final_df['Label'].sum():,}")
    print(f"Benign       : {len(final_df) - final_df['Label'].sum():,}")


if __name__ == "__main__":
    preprocess_cic2018()