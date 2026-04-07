import os
import glob
import json
import warnings
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

# =========================
# Cấu hình
# =========================
DATA_FOLDER = "data/filtered"
MODEL_FOLDER = "models"
os.makedirs(MODEL_FOLDER, exist_ok=True)

# Chỉ train các file này.
# Nếu để [] thì lấy tất cả file CSV trong thư mục
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
]

# Các cột muốn bỏ hẳn
DROP_COLUMNS = [
    "Timestamp",
    "Flow ID",
    "Src IP",
    "Dst IP",
    "Source IP",
    "Destination IP",
    "Src Port",
    "Source Port"
]

# =========================
# Hàm đọc dữ liệu
# =========================
def get_csv_files():
    if SELECTED_FILES:
        files = []
        for f in SELECTED_FILES:
            path = os.path.join(DATA_FOLDER, f)
            if os.path.exists(path):
                files.append(path)
            else:
                print(f"[!] Không tìm thấy file: {path}")
        return files
    else:
        return glob.glob(os.path.join(DATA_FOLDER, "*.csv"))


def load_data():
    files = get_csv_files()

    if not files:
        raise FileNotFoundError("Không có file CSV nào để train.")

    df_list = []

    for file in files:
        print(f"[+] Đang đọc: {file}")
        try:
            df = pd.read_csv(file, low_memory=False)
            df.columns = [c.strip() for c in df.columns]

            # giảm bộ nhớ cho cột object lặp
            for col in df.select_dtypes(include=["object"]).columns:
                nunique = df[col].nunique(dropna=False)
                total = len(df[col])
                if total > 0 and nunique / total < 0.5:
                    df[col] = df[col].astype("category")

            df_list.append(df)
            print(f"    -> shape: {df.shape}")
            print(f"    -> RAM tạm: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")

        except Exception as e:
            print(f"[!] Lỗi đọc file {file}: {e}")

    if not df_list:
        raise ValueError("Không đọc được dữ liệu hợp lệ.")

    df_all = pd.concat(df_list, ignore_index=True)
    print(f"[+] Tổng số dòng sau khi gộp: {len(df_all)}")
    print(f"[+] RAM sau gộp: {df_all.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
    return df_all


# =========================
# Hàm tìm cột nhãn
# =========================
def find_label_column(df):
    for c in ["Label", "label", " Label"]:
        if c in df.columns:
            return c
    raise ValueError("Không tìm thấy cột Label trong dữ liệu.")


# =========================
# Làm sạch dữ liệu
# =========================
def preprocess_data(df):
    label_col = find_label_column(df)

    # Chuẩn hóa nhãn
    df[label_col] = df[label_col].astype(str).str.strip().str.upper()

    print("\n[+] Các nhãn hiện có:")
    print(df[label_col].value_counts())

    # Đổi về nhị phân
    df["target"] = np.where(df[label_col] == "BENIGN", 0, 1).astype("int8")

    # Bỏ cột nhãn gốc
    df = df.drop(columns=[label_col], errors="ignore")

    # Bỏ các cột không muốn dùng
    drop_cols = [c for c in DROP_COLUMNS if c in df.columns]
    if drop_cols:
        print(f"\n[+] Bỏ các cột: {drop_cols}")
        df = df.drop(columns=drop_cols, errors="ignore")

    # Chuyển toàn bộ cột còn lại sang numeric từng cột
    feature_cols = [c for c in df.columns if c != "target"]
    for col in feature_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Xử lý inf / -inf từng cột để tránh bùng RAM
    for col in feature_cols:
        s = df[col]
        s = s.mask(np.isinf(s), np.nan)
        df[col] = s.astype("float32")

    # Xóa cột toàn NaN
    all_nan_cols = [c for c in feature_cols if df[c].isna().all()]
    if all_nan_cols:
        print(f"[+] Bỏ cột toàn NaN: {all_nan_cols}")
        df = df.drop(columns=all_nan_cols, errors="ignore")

    # Cập nhật lại feature_cols
    feature_cols = [c for c in df.columns if c != "target"]

    # Điền NaN bằng median từng cột
    for col in feature_cols:
        median_val = df[col].median()
        if pd.isna(median_val):
            median_val = 0.0
        df[col] = df[col].fillna(median_val).astype("float32")

    # Xóa cột hằng số
    constant_cols = []
    for col in feature_cols:
        if df[col].nunique(dropna=False) <= 1:
            constant_cols.append(col)

    if constant_cols:
        print(f"[+] Bỏ cột hằng số: {constant_cols}")
        df = df.drop(columns=constant_cols, errors="ignore")

    print(f"\n[+] Kích thước dữ liệu sau xử lý: {df.shape}")
    print(f"[+] Dung lượng RAM ước tính: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
    return df


# =========================
# Train model
# =========================
def train_model(df):
    X = df.drop(columns=["target"])
    y = df["target"]

    feature_columns = X.columns.tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    neg = (y_train == 0).sum()
    pos = (y_train == 1).sum()
    scale_pos_weight = neg / pos if pos > 0 else 1.0

    print(f"\n[+] Số mẫu train BENIGN: {neg}")
    print(f"[+] Số mẫu train ATTACK: {pos}")
    print(f"[+] scale_pos_weight: {scale_pos_weight:.4f}")

    model = XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
        scale_pos_weight=scale_pos_weight
    )

    print("\n[*] Đang train model...")
    model.fit(X_train, y_train)

    print("[*] Đang đánh giá model...")
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    pre = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print("\n===== KẾT QUẢ =====")
    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {pre:.4f}")
    print(f"Recall   : {rec:.4f}")
    print(f"F1-score : {f1:.4f}")

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, digits=4, zero_division=0))

    return model, feature_columns


# =========================
# Lưu model
# =========================
def save_artifacts(model, feature_columns):
    model_path = os.path.join(MODEL_FOLDER, "xgb_model.json")
    features_path = os.path.join(MODEL_FOLDER, "feature_columns.json")

    model.save_model(model_path)

    with open(features_path, "w", encoding="utf-8") as f:
        json.dump(feature_columns, f, ensure_ascii=False, indent=2)

    print(f"\n[+] Đã lưu model vào: {model_path}")
    print(f"[+] Đã lưu danh sách feature vào: {features_path}")


# =========================
# Main
# =========================
def main():
    print("[*] Bắt đầu đọc dữ liệu...")
    df = load_data()

    print("[*] Tiền xử lý dữ liệu...")
    df = preprocess_data(df)

    print("[*] Train XGBoost...")
    model, feature_columns = train_model(df)

    print("[*] Lưu model...")
    save_artifacts(model, feature_columns)

    print("\n[+] Train hoàn tất.")


if __name__ == "__main__":
    main()