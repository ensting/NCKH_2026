# NCKH_2026  
## Đề tài: **Nghiên cứu và xây dựng Hệ thống quản lý và giám sát ATTT mạng ứng dụng công nghệ Big Data và AI**

<p align="center">
  <img alt="Status" src="https://img.shields.io/badge/Tr%E1%BA%A1ng%20th%C3%A1i-%C4%90%C3%A3%20nghi%C3%AAn%20c%E1%BB%A9u%20xong-brightgreen">
  <img alt="Model" src="https://img.shields.io/badge/M%C3%B4%20h%C3%ACnh-XGBoost-success">
  <img alt="Dataset" src="https://img.shields.io/badge/Dataset-CIC--IDS--2018-orange">
  <img alt="Field" src="https://img.shields.io/badge/L%C4%A9nh%20v%E1%BB%B1c-An%20to%C3%A0n%20th%C3%B4ng%20tin-red">
</p>

---

## 1. Giới thiệu đề tài

Đề tài tập trung vào việc nghiên cứu và xây dựng một hệ thống quản lý, giám sát và hỗ trợ phát hiện bất thường trong mạng máy tính bằng cách kết hợp **Big Data**, **AI** và các phương pháp phân tích dữ liệu an toàn thông tin.  

Trong hướng tiếp cận hiện tại, nhóm sử dụng thuật toán **XGBoost** để thử nghiệm trên bộ dữ liệu **CIC-IDS-2018**, từ đó đánh giá khả năng nhận diện lưu lượng mạng bình thường và lưu lượng có dấu hiệu tấn công.

### Thông tin cốt lõi
- **Tên đề tài:** Nghiên cứu và xây dựng Hệ thống quản lý và giám sát ATTT mạng ứng dụng công nghệ Big Data và AI
- **Phương pháp / mô hình đang sử dụng:** XGBoost
- **Bộ dữ liệu sử dụng:** CIC-IDS-2018
- **Đánh giá hiện tại:** **5/10**
- **Nhận xét:** Phương pháp nghiên cứu hiện tại còn chưa phù hợp hoàn toàn với bài toán **giám sát flow network**, đồng thời việc triển khai thực tế gặp khó khăn do **chưa có bộ dataset thật sự phù hợp với đặc trưng lưu lượng mạng cần phân tích**.

---

## 2. Thông tin thực hiện

| Mục | Nội dung |
|---|---|
| **Người tham gia** | `En2tiwg Nguyễn (chủ trì) ` |
|                    | `Phạm Téo ` |
| **Giảng viên hướng dẫn** | `TS.Cao Văn Lợi` |
| **Lĩnh vực** | An toàn thông tin mạng / Phân tích dữ liệu / Trí tuệ nhân tạo |
| **Thời gian báo cáo** | `02/04/2026` |

---

## 3. Mục tiêu nghiên cứu

- Tìm hiểu các mô hình học máy trong bài toán phát hiện xâm nhập mạng.
- Nghiên cứu khả năng áp dụng **Big Data** vào thu thập, lưu trữ và xử lý log / network flow.
- Xây dựng hướng tiếp cận cho hệ thống quản lý và giám sát ATTT mạng.
- Đánh giá mức độ phù hợp của **XGBoost + CIC-IDS-2018** đối với bài toán thực tế.
- Rút ra hạn chế về dữ liệu, cách tiền xử lý và khả năng áp dụng trong môi trường thật.

---

## 4. Công nghệ và phương pháp sử dụng

### 4.1. Mô hình học máy
- **XGBoost** là thư viện gradient boosting tối ưu hóa cho hiệu năng, thường được dùng trong các bài toán phân loại dữ liệu bảng và có tài liệu chính thức hỗ trợ Python / Scikit-Learn rất đầy đủ.

### 4.2. Bộ dữ liệu
- **CIC-IDS-2018** là bộ dữ liệu phục vụ nghiên cứu phát hiện xâm nhập, bao gồm nhiều kịch bản tấn công như brute-force, botnet, DoS, DDoS, web attack, infiltration... với các đặc trưng được trích xuất từ lưu lượng mạng bằng CICFlowMeter.

### 4.3. Hướng áp dụng trong đề tài
- Thu thập hoặc sử dụng dữ liệu flow mạng.
- Tiền xử lý dữ liệu và chuẩn hóa nhãn.
- Huấn luyện mô hình XGBoost.
- Đánh giá mô hình trên các chỉ số như Accuracy, Precision, Recall, F1-score.
- Phân tích khả năng tích hợp vào hệ thống giám sát ATTT mạng.

---

## 5. Đánh giá hiện trạng của đề tài

### Điểm đánh giá
> **5/10**

### Nguyên nhân chính
- Phương pháp đang chọn **chưa thật sự phù hợp** với mục tiêu nghiên cứu tổng thể.
- Bộ **CIC-IDS-2018** hữu ích cho nghiên cứu IDS, nhưng **chưa chắc phù hợp hoàn toàn với dữ liệu flow network thực tế** mà hệ thống quản lý và giám sát cần xử lý.
- Khó khăn trong việc:
  - Làm sạch và chuẩn hóa dữ liệu
  - Chuyển từ môi trường nghiên cứu sang môi trường triển khai
  - Đảm bảo dữ liệu đầu vào phản ánh sát hệ thống thật
  - Kết nối giữa mô hình AI và hệ thống giám sát vận hành thực tế

---

## 6. Những điều học được từ NCKH này

Qua quá trình thực hiện đề tài, có thể rút ra nhiều bài học quan trọng:

### Về chuyên môn
- Hiểu rõ hơn về bài toán **phát hiện xâm nhập mạng** và phân tích lưu lượng mạng.
- Biết cách tiếp cận một bài toán ATTT bằng tư duy **dữ liệu + mô hình AI**.
- Nắm được quy trình cơ bản của một bài toán machine learning:
  - Thu thập dữ liệu
  - Tiền xử lý dữ liệu
  - Chọn đặc trưng
  - Huấn luyện mô hình
  - Đánh giá kết quả
- Nhận ra rằng **chất lượng dữ liệu** ảnh hưởng rất lớn đến chất lượng mô hình.
- Hiểu rằng mô hình có điểm số tốt trên dataset mẫu **không đồng nghĩa** với việc áp dụng tốt trong môi trường thật.

### Về tư duy nghiên cứu
- Cần chọn bài toán và phương pháp phù hợp ngay từ đầu.
- Cần đánh giá tính khả thi của dataset trước khi đi sâu vào triển khai.
- Một đề tài ATTT không chỉ cần mô hình AI mà còn cần:
  - Kiến trúc hệ thống phù hợp
  - Nguồn dữ liệu ổn định
  - Khả năng mở rộng
  - Khả năng triển khai thực tế
- Biết cách nhìn nhận, đánh giá lại hướng nghiên cứu khi phát hiện phương pháp hiện tại chưa tối ưu.

### Về kỹ năng mềm
- Kỹ năng đọc tài liệu kỹ thuật.
- Kỹ năng trình bày và báo cáo tiến độ nghiên cứu.
- Kỹ năng làm việc nhóm và phân chia nhiệm vụ.
- Kỹ năng tự học và sửa đổi hướng đi khi gặp hạn chế.

---

## 7. Link tài liệu tham khảo

- **Tài liệu XGBoost chính thức:** https://xgboost.readthedocs.io/
- **Hướng dẫn bắt đầu với XGBoost:** https://xgboost.readthedocs.io/en/stable/get_started.html
- **Tham số mô hình XGBoost:** https://xgboost.readthedocs.io/en/stable/parameter.html

---

## 8. Link dataset

- **Trang dataset CIC-IDS-2018:** https://www.unb.ca/cic/datasets/ids-2018.html
- **Danh mục datasets của Canadian Institute for Cybersecurity:** https://www.unb.ca/cic/datasets/
- **Kaggel : https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv

---

## 9. Hướng phát triển đề tài

Trong giai đoạn tiếp theo, đề tài có thể phát triển theo các hướng sau:

### 9.1. Cải thiện dữ liệu
- Tìm bộ dữ liệu phù hợp hơn với bài toán **network flow monitoring**.
- Kết hợp thêm dữ liệu log thực tế từ firewall, IDS/IPS, router, switch hoặc SIEM.
- Xây dựng pipeline thu thập dữ liệu gần với môi trường thật hơn.
- **Xây dựng Network IDS using Hybrid Model : https://www.kaggle.com/code/likhithasaila/network-ids-using-hybrid-model

### 9.2. Cải thiện mô hình
- So sánh XGBoost với các mô hình khác như:
  - Random Forest
  - LightGBM
  - CatBoost
  - LSTM / Autoencoder / Deep Learning cho dữ liệu chuỗi thời gian
- Tối ưu feature engineering cho dữ liệu flow.

### 9.3. Cải thiện hệ thống
- Thiết kế kiến trúc hệ thống giám sát hoàn chỉnh hơn:
  - Thu thập dữ liệu
  - Lưu trữ
  - Phân tích
  - Cảnh báo
  - Trực quan hóa dashboard
- Tích hợp với các nền tảng như:
  - ELK Stack
  - Wazuh
  - Zeek
  - Suricata
  - Kafka / Spark cho xử lý dữ liệu lớn

### 9.4. Hướng nghiên cứu sâu hơn
- Thử nghiệm phát hiện bất thường theo thời gian thực.
- Kết hợp học máy với luật phát hiện truyền thống.
- Nghiên cứu khả năng giải thích mô hình để phục vụ chuyên gia ATTT.
- Đánh giá mô hình trên dữ liệu nội bộ hoặc dữ liệu mô phỏng sát môi trường triển khai.

---

## 10. Kết luận ngắn

Đề tài có ý nghĩa thực tiễn cao vì nằm ở giao điểm của **An toàn thông tin**, **Big Data** và **AI**. Tuy nhiên, kết quả hiện tại cho thấy việc chọn phương pháp nghiên cứu và dataset là yếu tố quyết định đến tính khả thi của toàn bộ hệ thống.  

Dù hướng đi hiện tại còn hạn chế, quá trình thực hiện vẫn mang lại giá trị lớn về mặt học thuật, tư duy nghiên cứu và kinh nghiệm triển khai thực tế. Đây là nền tảng quan trọng để tiếp tục cải tiến đề tài trong các giai đoạn tiếp theo.

---


<p align="center"><i>Telegram: @Ens_bui</i></p>
