import os
import json
import pandas as pd
from xgboost import XGBClassifier

MODEL_PATH = "models/xgb_model.json"
FEATURES_PATH = "models/feature_columns.json"


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


def main():
    model, feature_columns = load_artifacts()

    print("[+] Load model thành công")
    print(f"[+] Số feature: {len(feature_columns)}")

    # Tạo 1 dòng dữ liệu giả để test
    sample = {col: 0 for col in feature_columns}
    df_sample = pd.DataFrame([sample])

    pred = model.predict(df_sample)[0]
    proba = model.predict_proba(df_sample)[0]

    print("\n===== KẾT QUẢ TEST =====")
    print("Prediction:", int(pred))
    print("Probabilities:", proba.tolist())


if __name__ == "__main__":
    main()