import os
import json
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

MODEL_PATH = "models/xgb_model.json"
FEATURES_PATH = "models/feature_columns.json"

INPUT_FILE = "data/filtered/03-02-2018.csv"
OUTPUT_FILE = "data/predicted/predicted_test.csv"

os.makedirs("data/predicted", exist_ok=True)


def find_label_column(df):
    for c in ["Label", "label", " Label"]:
        if c in df.columns:
            return c
    return None


def load_artifacts():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Không tìm thấy model: {MODEL_PATH}")

    if not os.path.exists(FEATURES_PATH):
        raise FileNotFoundError(f"Không tìm thấy feature list: {FEATURES_PATH}")

    model = XGBClassifier()
    model.load_model(MODEL_PATH)

    with open(FEATURES_PATH, "r", encoding="utf-8") as f:
        feature_columns = json.load(f)

    return model, feature_columns


def preprocess_for_prediction(df, feature_columns):
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]

    # Bỏ cột nhãn nếu có
    label_col = find_label_column(df)
    if label_col:
        df = df.drop(columns=[label_col], errors="ignore")

    # Bỏ một số cột không dùng
    
    drop_cols = [
    "Timestamp",
    "Flow ID",
    "Src IP",
    "Dst IP",
    "Source IP",
    "Destination IP",
    "Src Port",
    "Source Port",
    ]
    
    df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors="ignore")

    # Chuyển về numeric
    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.replace([np.inf, -np.inf], np.nan)

    # Tạo đủ feature theo model
    for col in feature_columns:
        if col not in df.columns:
            df[col] = 0

    # Chỉ giữ đúng thứ tự feature
    df = df[feature_columns]

    # Điền NaN
    for col in df.columns:
        median_val = df[col].median()
        if pd.isna(median_val):
            median_val = 0
        df[col] = df[col].fillna(median_val)

    return df


def main():
    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(f"Không tìm thấy file input: {INPUT_FILE}")

    model, feature_columns = load_artifacts()

    df_raw = pd.read_csv(INPUT_FILE, low_memory=False)
    print(f"[+] Đã đọc file: {INPUT_FILE}")
    print(f"[+] Số dòng: {len(df_raw)}")

    df_input = preprocess_for_prediction(df_raw, feature_columns)

    preds = model.predict(df_input)
    probas = model.predict_proba(df_input)[:, 1]

    df_result = df_raw.copy()
    df_result["Predicted_Label"] = preds
    df_result["Predicted_Name"] = df_result["Predicted_Label"].map({0: "BENIGN", 1: "ATTACK"})
    df_result["Attack_Probability"] = probas

    df_result.to_csv(OUTPUT_FILE, index=False)

    print(f"[+] Đã lưu kết quả: {OUTPUT_FILE}")
    print("\nThống kê dự đoán:")
    print(df_result["Predicted_Name"].value_counts())


if __name__ == "__main__":
    main()