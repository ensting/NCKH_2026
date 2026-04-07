import pandas as pd
import numpy as np
import os
import json
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

FEATURE_COLUMNS = [
    "Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
    "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Flow Byts/s", "Flow Pkts/s",
    "Fwd Pkts/s", "Bwd Pkts/s", "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt",
    "ACK Flag Cnt", "Down/Up Ratio", "Pkt Size Avg", "Fwd Seg Size Avg",
    "Bwd Seg Size Avg", "Subflow Fwd Pkts", "Subflow Fwd Byts",
    "Subflow Bwd Pkts", "Subflow Bwd Byts"
]

DATA_PATH = r"F:\nckh\cic2018_processed_for_xgboost.parquet"

MODEL_DIR = r"F:\nckh\XGBoost\models_zeek"
MODEL_PATH = os.path.join(MODEL_DIR, "xgb_model_zeek.json")
FEATURES_PATH = os.path.join(MODEL_DIR, "feature_columns_zeek.json")
METADATA_PATH = os.path.join(MODEL_DIR, "metadata_zeek.json")

CLIP_MIN = -1e15
CLIP_MAX = 1e15
THRESHOLD = 0.1


def train():
    print("Bắt đầu train XGBoost")

    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Không tìm thấy file dữ liệu: {DATA_PATH}")

    df = pd.read_parquet(DATA_PATH)
    print(f"Dataset loaded: {df.shape}")

    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Thiếu cột feature: {missing}")
    if "Label" not in df.columns:
        raise ValueError("Thiếu cột Label")

    # Làm sạch lần cuối trước khi train
    for col in FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan)
    df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].clip(lower=CLIP_MIN, upper=CLIP_MAX)
    df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].fillna(0).astype("float32")
    df["Label"] = pd.to_numeric(df["Label"], errors="coerce").fillna(0).astype("int8")

    # Debug tổng quát trước khi tách tập
    X_np = df[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    print("\nKIỂM TRA DỮ LIỆU TRƯỚC TRAIN")
    print(f"Còn inf trong X : {np.isinf(X_np).sum()}")
    print(f"Còn nan trong X : {np.isnan(X_np).sum()}")
    print(f"Max toàn bộ X   : {np.nanmax(X_np)}")
    print(f"Min toàn bộ X   : {np.nanmin(X_np)}")

    # Debug theo từng cột nếu cần
    print("\nCÁC CỘT CÓ GIÁ TRỊ BẤT THƯỜNG")
    found_issue = False
    for col in FEATURE_COLUMNS:
        s = pd.to_numeric(df[col], errors="coerce")
        inf_count = int(np.isinf(s).sum())
        nan_count = int(s.isna().sum())
        too_large = int((np.abs(s.fillna(0)) > 1e15).sum())
        if inf_count > 0 or nan_count > 0 or too_large > 0:
            found_issue = True
            print(f"{col}: inf={inf_count}, nan={nan_count}, too_large={too_large}")
    if not found_issue:
        print("Không phát hiện cột bất thường sau làm sạch.")

    # Nếu vẫn còn lỗi thì dừng hẳn
    if np.isinf(X_np).sum() > 0 or np.isnan(X_np).sum() > 0:
        raise ValueError("Dữ liệu vẫn còn inf hoặc nan, không thể train.")

    X = df[FEATURE_COLUMNS]
    y = df["Label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    neg = int((y_train == 0).sum())
    pos = int((y_train == 1).sum())
    scale_pos_weight = (neg / pos) if pos > 0 else 1.0

    print("\nTHỐNG KÊ TẬP TRAIN/TEST")
    print(f"Train size         : {len(X_train):,}")
    print(f"Test size          : {len(X_test):,}")
    print(f"Benign train       : {neg:,}")
    print(f"Attack train       : {pos:,}")
    print(f"scale_pos_weight   : {scale_pos_weight:.6f}")

    model = XGBClassifier(
        n_estimators=300,
        max_depth=7,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        random_state=42,
        n_jobs=-1,
        tree_method="hist",
        eval_metric="auc",
        scale_pos_weight=scale_pos_weight
    )

    print("\nĐang train model...")
    model.fit(X_train, y_train)

    y_proba = model.predict_proba(X_test)[:, 1]
    y_pred = (y_proba >= THRESHOLD).astype(int)

    auc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 70)
    print("KẾT QUẢ ĐÁNH GIÁ MODEL")
    print("=" * 70)
    print(f"Threshold: {THRESHOLD}")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Attack"]))
    print(f"AUC Score: {auc:.6f}")
    print("Confusion Matrix:")
    print(cm)

    os.makedirs(MODEL_DIR, exist_ok=True)
    model.save_model(MODEL_PATH)

    with open(FEATURES_PATH, "w", encoding="utf-8") as f:
        json.dump(FEATURE_COLUMNS, f, ensure_ascii=False, indent=2)

    metadata = {
        "data_path": DATA_PATH,
        "threshold": THRESHOLD,
        "feature_count": len(FEATURE_COLUMNS),
        "feature_columns": FEATURE_COLUMNS,
        "train_size": int(len(X_train)),
        "test_size": int(len(X_test)),
        "scale_pos_weight": float(scale_pos_weight),
        "auc": float(auc),
        "confusion_matrix": cm.tolist(),
        "model_params": model.get_params()
    }

    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)

    print("\nĐÃ LƯU XONG")
    print(f"Model    : {MODEL_PATH}")
    print(f"Features : {FEATURES_PATH}")
    print(f"Metadata : {METADATA_PATH}")


if __name__ == "__main__":
    train()