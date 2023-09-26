import queue
import numpy as np
import os
import sqlite3
import re
from sklearn.ensemble import RandomForestClassifier
import pickle
from threading import Thread
import tkinter as tk
from tkinter import filedialog

# Tạo một Tkinter window
window = tk.Tk()
window.title("Hệ thống giám sát an ninh")

# Tạo một Text widget để hiển thị nhật ký
log_text_widget = tk.Text(window, height=10, width=50)
log_text_widget.config(state=tk.DISABLED)
log_text_widget.pack()

# Hàm để cập nhật văn bản nhật ký
def update_log_text(message):
    log_text_widget.config(state=tk.NORMAL)
    log_text_widget.insert(tk.END, message + '\n')
    log_text_widget.config(state=tk.DISABLED)

# Tạo một biến để theo dõi trạng thái giám sát thời gian thực
real_time_monitoring_enabled = tk.BooleanVar()
real_time_monitoring_enabled.set(False)

# Hàm để bật/tắt giám sát thời gian thực
def toggle_real_time_monitoring():
    global real_time_monitoring_thread, packet_queue  # Rename 'queue' to 'packet_queue'

    if real_time_monitoring_enabled.get():
        update_log_text('Bắt đầu giám sát lưu lượng...')
        real_time_monitoring_thread = Thread(target=start_monitoring)
        real_time_monitoring_thread.start()
    else:
        update_log_text('Dừng giám sát lưu lượng...')

# Checkbutton để bật/tắt giám sát thời gian thực
real_time_monitoring_checkbox = tk.Checkbutton(window, text="Bật giám sát thời gian thực", variable=real_time_monitoring_enabled, command=toggle_real_time_monitoring)
real_time_monitoring_checkbox.pack()

# Tạo một nút để xóa nhật ký
clear_log_button = tk.Button(window, text="Xóa nhật ký", command=lambda: update_log_text('Nhật ký đã được xóa.'))
clear_log_button.pack()

# Tạo một menu bar
menubar = tk.Menu(window)
window.config(menu=menubar)

# Tạo một "File" menu
file_menu = tk.Menu(menubar, tearoff=0)
menubar.add_cascade(label="Tệp", menu=file_menu)

# Hàm để xuất nhật ký
def export_log():
    filename = filedialog.asksaveasfilename(title="Xuất nhật ký", defaultextension=".txt")
    if filename:
        with open(filename, "w") as f:
            log_contents = log_text_widget.get("1.0", tk.END)
            f.write(log_contents)

# Thêm tùy chọn "Xuất nhật ký" vào menu "Tệp"
file_menu.add_command(label="Xuất nhật ký", command=export_log)

# Tạo một Entry widget để nhập các loại gói cần giám sát
packet_types_label = tk.Label(window, text="Nhập các loại gói cần giám sát")
packet_types_label.pack()

packet_types_entry = tk.Entry(window, width=50)
packet_types_entry.pack()

# Tạo một nút để đào tạo mô hình học máy mới
def train_new_model():
    global packet_types

    packet_types_input = packet_types_entry.get()
    # Chuyển đổi đầu vào chuỗi thành danh sách các loại gói
    packet_types = packet_types_input.split(",")

    # Tạo dữ liệu đào tạo
    x_train, y_train = generate_training_data(packet_types)

    # Tạo một mô hình học máy
    model = RandomForestClassifier()
    # Train the model with x_train and y_train

# Hàm để tính toán các đặc trưng nâng cao
def calculate_advanced_features(packet):
    features = []

    # Tính toán entropi của nội dung gói
    entropy_feature = np.entropy(packet.payload)
    features.append(entropy_feature)

    # Tính phân phối cổng
    port_distribution = np.histogram(packet.dport, bins=10, range=(0, 65535))[0]
    features.extend(port_distribution)

    # Tính độ dài chuỗi IP nguồn
    source_ip_length = len(packet.src)
    features.append(source_ip_length)

    # Tính độ dài chuỗi IP đích
    destination_ip_length = len(packet.dst)
    features.append(destination_ip_length)

    return features

# Hàm để phát hiện tấn công DDoS
def detect_ddos(features):
    # Sử dụng mô hình học máy để dự đoán
    prediction = model.predict(np.array([features]))

    # Nếu dự đoán là tấn công DDoS, hãy trả về True
    if prediction > 0.5:
        return True
    return False

# Hàm để xử lý gói
def packet_callback(packet):
    global packet_queue

    # Kiểm tra xem loại gói có nằm trong danh sách các loại được giám sát hay không
    if packet.type not in packet_types:
        return

    # Tính toán các đặc trưng cho gói
    features = []

    # Tính toán các đặc trưng thống kê và thời gian
    for feature in calculate_statistics_and_temporal_features(packet):
        features.append(feature)

    # Tính toán các đặc trưng nâng cao
    advanced_features = calculate_advanced_features(packet)
    features.extend(advanced_features)

    # Dự đoán xem gói có phải là tấn công DDoS hay không
    is_attack = detect_ddos(features)

    # Nếu là tấn công DDoS, hãy thêm tin nhắn nhật ký vào hàng đợi
    if is_attack:
        packet_queue.put('Cuộc tấn công DDoS có thể từ {}: {} ({})'.format(packet.src, packet.summary(), packet.type))

# Hàm để khởi động giám sát thời gian thực
def start_monitoring():
    global real_time_monitoring_thread, packet_queue  # Rename 'queue' to 'packet_queue'

    packet_queue = queue.Queue()

    # Define the main_thread function before starting it
    def main_thread():
        while True:
            pass

    real_time_monitoring_thread = Thread(target=start_monitoring_thread)
    real_time_monitoring_thread.start()

    main_thread = Thread(target=main_thread)  # Rename the variable
    main_thread.start()

# Hàm để thực hiện giám sát thời gian thực
def start_monitoring_thread():
    while True:
        message = packet_queue.get()
        if message is None:
            break

        # Cập nhật nhật ký
        update_log_text(message)

# Khởi chạy vòng lặp chính của Tkinter
window.mainloop()
