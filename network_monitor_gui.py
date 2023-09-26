import tkinter as tk
from tkinter import ttk, filedialog
from scapy.all import *
import numpy as np
import os
import sqlite3
import re
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.optimizers import Adam

# Tạo một Tkinter window
window = tk.Tk()
window.title("Security Monitoring System")

# Thêm hộp kiểm để bật hoặc tắt giám sát thời gian thực
real_time_monitoring_checkbox = tk.Checkbutton(window, text="Bật giám sát thời gian thực")
real_time_monitoring_checkbox.pack()

# Thêm nút để xóa nhật ký
clear_log_button = tk.Button(window, text="Xóa nhật ký")
clear_log_button.pack()

# Thêm menu mới
menubar = tk.Menu(window)
window.config(menu=menubar)

# Thêm mục menu mới
file_menu = tk.Menu(menubar, tearoff=0)
menubar.add_cascade(label="Tệp", menu=file_menu)

# Định nghĩa hàm để xuất nhật ký sang tệp
def export_log():
    filename = filedialog.asksaveasfilename(title="Xuất nhật ký", defaultextension=".txt")
    if filename:
        with open(filename, "w") as f:
            for log in log_list:
                f.write(log + "\n")

# Gắn hàm này vào mục menu "Xuất nhật ký"
file_menu.add_command(label="Xuất nhật ký", command=export_log)

# Tạo widget Text để hiển thị nhật ký
log_text_widget = tk.Text(window, height=10, width=50)
log_text_widget.config(state=tk.DISABLED)
log_text_widget.pack()

# Tạo widget Entry widget cho các loại gói cần theo dõi
packet_types_label = tk.Label(window, text="Nhập các loại gói cần giám sát")
packet_types_label.pack()

packet_types_entry = tk.Entry(window, width=50)
packet_types_entry.pack()

# Tạo nút để đào tạo mô hình học máy mới
train_model_button = tk.Button(window, text="Đào tạo mô hình học máy mới")
train_model_button.pack()

# Tạo thanh trượt để điều chỉnh độ nhạy của thuật toán phát hiện tấn công
sensitivity_label = tk.Label(window, text="Điều chỉnh độ nhạy của thuật toán phát hiện tấn công")
sensitivity_label.pack()

sensitivity_slider = tk.Scale(window, from_=0, to=100, orient="horizontal")
sensitivity_slider.pack()

# Set thresholds for each packet type
THRESHOLDS = {
    'tcp': 1000,
    'udp': 1000,
    'arp': 1000,
    'dns': 1000,
    'http': 1000,
    'https': 1000
}

# Set window size in seconds
window_size = 60  # Thay đổi giá trị này dựa trên yêu cầu của bạn

# Initialize timestamps and attacking IP addresses
timestamps = []
attacking_ip_addresses = set()

# Create a database to store the log messages
with sqlite3.connect('logs.db') as conn:
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS logs (message TEXT)')

# Create a deep learning model for intrusion detection
feature_dim = 16  # Điều chỉnh kích thước của đặc trưng dựa trên mô hình của bạn
model = Sequential()
model.add(Dense(128, input_dim=feature_dim, activation='relu'))
model.add(Dropout(0.5))
model.add(Dense(64, activation='relu'))
model.add(Dense(1, activation='sigmoid'))
model.compile(loss='binary_crossentropy', optimizer=Adam(lr=0.001), metrics=['accuracy'])

# Define a function to train the deep learning model
def train_new_model():
    global model

    # Load and preprocess your training data
    # ...

    # Train the model
    model.fit(X_train, y_train, epochs=10, batch_size=64)

# Define a function to compute more sophisticated features
def compute_features(packet):
    # Tính các đặc trưng thống kê
    statistical_features = [
        len(packet),
        packet.len,
        packet.ttl,
        np.mean(packet.time),
        np.median(packet.time),
        np.std(packet.time),
        np.min(packet.time),
        np.max(packet.time),
    ]

    # Tính các đặc trưng thời gian
    temporal_features = [
        len(timestamps),
        np.mean(timestamps),
        np.median(timestamps),
        np.std(timestamps),
        np.min(timestamps),
        np.max(timestamps),
    ]

    # Trả về tất cả các đặc trưng
    return statistical_features + temporal_features

# Define a function to get the packet type
def get_packet_type(packet):
    header = packet.summary()
    match = re.match(r'(?P<type>tcp|udp|arp|dns|icmp)', header)
    if match:
        return match.group('type')
    return None

# Define a function to process each captured packet using the deep learning model
def packet_callback(packet):
    global timestamps, attacking_ip_addresses

    # Kiểm tra xem loại gói tin có trong danh sách các loại gói cần giám sát
    if packet.type not in packet_types:
        return

    # Cập nhật timestamps
    timestamps.append(packet.time)

    # Tính các đặc trưng
    features = compute_features(packet)

    # Lấy loại gói tin
    packet_type = get_packet_type(packet)

    # Dự đoán bằng mô hình deep learning
    prediction = model.predict(np.array([features]))

    # Nếu dự đoán cho thấy một sự bất thường, ghi nhật ký
    if prediction > 0.5:  # Điều chỉnh ngưỡng theo yêu cầu
        # Thêm trường vào thông điệp nhật ký để lưu loại gói tin
        log_message = 'Gói tin bất thường từ {}: {} ({})'.format(packet.src, packet.summary(), packet_type)
        log_text_widget.config(state=tk.NORMAL)
        log_text_widget.insert(tk.END, log_message + '\n')
        log_text_widget.config(state=tk.DISABLED)
        conn.execute('INSERT INTO logs (message) VALUES (?)', (log_message,))
        conn.commit()

# Khởi động vòng lặp giám sát
def start_monitoring():
    global real_time_monitoring_is_enabled

    # Kiểm tra xem giám sát thời gian thực đã được bật chưa
    if not real_time_monitoring_is_enabled:
        return

    # Bắt đầu bắt gói tin
    try:
        log_text_widget.config(state=tk.NORMAL)
        log_text_widget.insert(tk.END, 'Bắt đầu giám sát lưu lượng...\n')
        log_text_widget.config(state=tk.DISABLED)

        sniff(filter='tcp, udp, arp, dns, icmp', prn=packet_callback)
    except KeyboardInterrupt:
        log_text_widget.config(state=tk.NORMAL)
        log_text_widget.insert(tk.END, 'Kết thúc chương trình...\n')
        log_text_widget.config(state=tk.DISABLED)

# Gắn nút "Đào tạo mô hình học máy mới" vào hàm để đào tạo mô hình mới
train_model_button.config(command=train_new_model)

# Bắt đầu vòng lặp chính của Tkinter
window.mainloop()
