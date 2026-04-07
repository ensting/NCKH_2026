import os
import glob
import pandas as pd

# Thư mục chứa file gốc và file sau khi lọc
input_folder = "data/raw"
output_folder = "data/filtered"
os.makedirs(output_folder, exist_ok=True)

# Chỉ xử lý các file này
selected_files = [
    "02-16-2018.csv",
    "02-28-2018.csv",
    "03-01-2018.csv"
    
]

# Các nhãn cần xóa
remove_labels = [
    "INFILTERATION",
    "INFILTRATION",
    "LABEL"   # nếu thực sự có nhãn tên là Label
]

for file_name in selected_files:
    file_path = os.path.join(input_folder, file_name)

    if not os.path.exists(file_path):
        print(f"[!] Không tìm thấy file: {file_path}")
        continue

    print("=" * 70)
    print(f"Đang xử lý: {file_path}")

    try:
        df = pd.read_csv(file_path, low_memory=False)
    except Exception as e:
        print(f"[!] Lỗi khi đọc file {file_name}: {e}")
        continue

    # Chuẩn hóa tên cột
    df.columns = [c.strip() for c in df.columns]

    # Tìm cột nhãn
    label_col = None
    for c in ["Label", "label", " Label"]:
        if c in df.columns:
            label_col = c
            break

    if label_col is None:
        print("[!] Không tìm thấy cột Label, bỏ qua file này.\n")
        continue

    # Chuẩn hóa nhãn để kiểm tra
    labels = df[label_col].astype(str).str.strip()

    print("\nCác nhãn có trong file:")
    unique_labels = sorted(labels.unique())
    for lbl in unique_labels:
        print("-", lbl)

    print("\nSố lượng từng nhãn:")
    print(labels.value_counts())

    before = len(df)

    # Xóa các dòng có nhãn nằm trong remove_labels
    remove_labels_upper = [x.upper() for x in remove_labels]
    df_filtered = df[
        ~df[label_col].astype(str).str.strip().str.upper().isin(remove_labels_upper)
    ]

    after = len(df_filtered)

    output_path = os.path.join(output_folder, file_name)
    df_filtered.to_csv(output_path, index=False)

    print(f"\nĐã lưu file mới: {output_path}")
    print(f"Số dòng ban đầu: {before}")
    print(f"Số dòng còn lại : {after}")
    print(f"Số dòng bị xóa  : {before - after}\n")