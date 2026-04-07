import pandas as pd
import numpy as np
import os
import glob
import json
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

# ================== CẤU HÌNH ==================
CIC2017_DIR = r"F:\nckh\MachineLearningCVE"
MODEL_PATH = r"F:\nckh\XGBoost\models_zeek\xgb_model_zeek.json"
FEATURES_PATH = r"F:\nckh\XGBoost\models_zeek\feature_columns_zeek.json"
OUTPUT_PRED_FILE = r"F:\nckh\XGBoost\cic2017_test_predictions.csv"

THRESHOLD = 0.1
CLIP_MIN = -1e15
CLIP_MAX = 1e15

# Nếu không muốn load từ json thì có thể dùng list cứng
DEFAULT_FEATURE_COLUMNS = [
    "Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
    "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Flow Byts/s", "Flow Pkts/s",
    "Fwd Pkts/s", "Bwd Pkts/s", "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt",
    "ACK Flag Cnt", "Down/Up Ratio", "Pkt Size Avg", "Fwd Seg Size Avg",
    "Bwd Seg Size Avg", "Subflow Fwd Pkts", "Subflow Fwd Byts",
    "Subflow Bwd Pkts", "Subflow Bwd Byts"
]

RENAME_MAP = {
    "Destination Port": "Dst Port",
    "Dst Port": "Dst Port",

    "Protocol": "Protocol",
    "Flow Duration": "Flow Duration",

    "Total Fwd Packets": "Tot Fwd Pkts",
    "Tot Fwd Pkts": "Tot Fwd Pkts",

    "Total Backward Packets": "Tot Bwd Pkts",
    "Tot Bwd Pkts": "Tot Bwd Pkts",

    "Total Length of Fwd Packets": "TotLen Fwd Pkts",
    "TotLen Fwd Pkts": "TotLen Fwd Pkts",

    "Total Length of Bwd Packets": "TotLen Bwd Pkts",
    "TotLen Bwd Pkts": "TotLen Bwd Pkts",

    "Flow Bytes/s": "Flow Byts/s",
    "Flow Byts/s": "Flow Byts/s",

    "Flow Packets/s": "Flow Pkts/s",
    "Flow Pkts/s": "Flow Pkts/s",

    "Fwd Packets/s": "Fwd Pkts/s",
    "Fwd Pkts/s": "Fwd Pkts/s",

    "Bwd Packets/s": "Bwd Pkts/s",
    "Bwd Pkts/s": "Bwd Pkts/s",

    "FIN Flag Count": "FIN Flag Cnt",
    "FIN Flag Cnt": "FIN Flag Cnt",

    "SYN Flag Count": "SYN Flag Cnt",
    "SYN Flag Cnt": "SYN Flag Cnt",

    "RST Flag Count": "RST Flag Cnt",
    "RST Flag Cnt": "RST Flag Cnt",

    "ACK Flag Count": "ACK Flag Cnt",
    "ACK Flag Cnt": "ACK Flag Cnt",

    "Down/Up Ratio": "Down/Up Ratio",

    "Average Packet Size": "Pkt Size Avg",
    "Pkt Size Avg": "Pkt Size Avg",

    "Avg Fwd Segment Size": "Fwd Seg Size Avg",
    "Fwd Seg Size Avg": "Fwd Seg Size Avg",

    "Avg Bwd Segment Size": "Bwd Seg Size Avg",
    "Bwd Seg Size Avg": "Bwd Seg Size Avg",

    "Subflow Fwd Packets": "Subflow Fwd Pkts",
    "Subflow Fwd Pkts": "Subflow Fwd Pkts",

    "Subflow Fwd Bytes": "Subflow Fwd Byts",
    "Subflow Fwd Byts": "Subflow Fwd Byts",

    "Subflow Bwd Packets": "Subflow Bwd Pkts",
    "Subflow Bwd Pkts": "Subflow Bwd Pkts",

    "Subflow Bwd Bytes": "Subflow Bwd Byts",
    "Subflow Bwd Byts": "Subflow Bwd Byts",
}


def load_feature_columns():
    if os.path.exists(FEATURES_PATH):
        with open(FEATURES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return DEFAULT_FEATURE_COLUMNS


def normalize_label(x):
    x = str(x).strip().lower()
    return 0 if x == "benign" else 1


def preprocess_cic2017_file(file_path, feature_columns):
    filename = os.path.basename(file_path)
    print("\n" + "=" * 70)
    print(f"Đang xử lý file: {filename}")

    df = pd.read_csv(
        file_path,
        low_memory=False,
        on_bad_lines="skip",
        encoding="utf-8"
    )

    original_rows = len(df)
    print(f"Dòng gốc: {original_rows:,}")

    # Chuẩn hóa tên cột
    df.columns = [str(c).strip() for c in df.columns]
    df = df.rename(columns=RENAME_MAP)

    # Loại header lặp nếu có
    if len(df) > 0:
        first_col = df.columns[0]
        df = df[
            df[first_col].astype(str).str.strip().str.lower() != first_col.strip().lower()
        ].copy()

    if "Label" not in df.columns:
        print("   → Bỏ qua vì thiếu cột Label")
        return None

    # Thêm cột thiếu để khớp schema model
    missing_cols = [col for col in feature_columns if col not in df.columns]
    for col in missing_cols:
        df[col] = 0

    # Chỉ giữ đúng cột model cần
    df = df[feature_columns + ["Label"]].copy()

    # Ép kiểu số
    for col in feature_columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Làm sạch
    df[feature_columns] = df[feature_columns].replace([np.inf, -np.inf], np.nan)
    df[feature_columns] = df[feature_columns].clip(lower=CLIP_MIN, upper=CLIP_MAX)

    nan_before_fill = int(df[feature_columns].isna().sum().sum())
    df[feature_columns] = df[feature_columns].fillna(0).astype("float32")

    # Label nhị phân
    df["Label"] = df["Label"].apply(normalize_label).astype("int8")

    # Kiểm tra cuối
    X_np = df[feature_columns].to_numpy(dtype=np.float32)
    inf_count = int(np.isinf(X_np).sum())
    nan_count = int(np.isnan(X_np).sum())

    print(f"Dòng sau xử lý        : {len(df):,}")
    print(f"Cột thiếu thêm số 0   : {len(missing_cols)}")
    print(f"NaN trước fill        : {nan_before_fill:,}")
    print(f"Inf còn lại           : {inf_count}")
    print(f"NaN còn lại           : {nan_count}")

    if inf_count > 0 or nan_count > 0:
        raise ValueError(f"{filename} vẫn còn inf/nan sau xử lý.")

    return df


def main():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Không tìm thấy model: {MODEL_PATH}")

    feature_columns = load_feature_columns()
    print(f"Số feature của model: {len(feature_columns)}")

    csv_files = glob.glob(os.path.join(CIC2017_DIR, "**", "*.csv"), recursive=True)
    if not csv_files:
        raise FileNotFoundError(f"Không tìm thấy file CSV nào trong: {CIC2017_DIR}")

    print(f"Tìm thấy {len(csv_files)} file CSV trong CIC2017")

    # Load model
    model = XGBClassifier()
    model.load_model(MODEL_PATH)

    dfs = []
    for file_path in csv_files:
        try:
            df_file = preprocess_cic2017_file(file_path, feature_columns)
            if df_file is not None and len(df_file) > 0:
                dfs.append(df_file)
        except Exception as e:
            print(f"   → Lỗi file {os.path.basename(file_path)}: {e}")

    if not dfs:
        raise ValueError("Không có dữ liệu CIC2017 hợp lệ để test.")

    print("\nGhép toàn bộ dữ liệu CIC2017...")
    df = pd.concat(dfs, ignore_index=True)

    X = df[feature_columns]
    y = df["Label"]

    print(f"Tổng samples test : {len(df):,}")
    print(f"Benign            : {(y == 0).sum():,}")
    print(f"Attack            : {(y == 1).sum():,}")

    # Predict
    y_proba = model.predict_proba(X)[:, 1]
    y_pred = (y_proba >= THRESHOLD).astype(int)

    # Metrics
    auc = roc_auc_score(y, y_proba)
    cm = confusion_matrix(y, y_pred)

    print("\n" + "=" * 70)
    print("KẾT QUẢ TEST TRÊN CIC-IDS-2017")
    print("=" * 70)
    print(f"Threshold: {THRESHOLD}")
    print(classification_report(y, y_pred, target_names=["Benign", "Attack"]))
    print(f"AUC Score: {auc:.6f}")
    print("Confusion Matrix:")
    print(cm)

    # Lưu kết quả dự đoán
    result_df = df.copy()
    result_df["Pred_Proba"] = y_proba
    result_df["Pred_Label"] = y_pred
    result_df.to_csv(OUTPUT_PRED_FILE, index=False, encoding="utf-8-sig")

    print("\nĐã lưu file dự đoán:")
    print(OUTPUT_PRED_FILE)


if __name__ == "__main__":
    main()