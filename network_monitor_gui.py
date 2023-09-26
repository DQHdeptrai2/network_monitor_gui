import queue
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import pickle
from threading import Thread
import requests
import schedule
import time
import tkinter as tk
from tkinter import filedialog
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest

# Tạo một Tkinter window
window = tk.Tk()
window.title("Hệ thống giám sát an ninh")
window.geometry("800x600")

# Tạo một Text widget để hiển thị nhật ký
log_text_widget = tk.Text(window, height=10, width=50)
log_text_widget.config(state=tk.DISABLED)
log_text_widget.pack()

# Hàm để cập nhật văn bản nhật ký
def update_log_text(message):
    log_text_widget.config(state=tk.NORMAL)
    log_text_widget.insert(tk.END, message + '\n')
    log_text_widget.config(state=tk.DISABLED)
    log_text_widget.see(tk.END)

# Define a list to store detected packet types
detected_packet_types = []

# Hàm để bắt đầu giám sát dựa trên các loại gói được phát hiện
def start_monitoring_auto():
    global real_time_monitoring_thread, packet_queue, detected_packet_types

    packet_queue = queue.Queue()

    # Define the main_thread function before starting it
    def main_thread():
        while True:
            # Get a packet from the queue
            message = packet_queue.get()
            if message is None:
                break

            # Send the data to the IDS or NMS
            send_data_to_ids_or_nms(message)

    # Start the main thread
    main_thread = Thread(target=main_thread)
    main_thread.start()

# Hàm để bật/tắt tự động phát hiện
def toggle_auto_detection():
    global auto_detection_enabled

    if auto_detection_enabled.get():
        # Khởi động giám sát thời gian thực
        toggle_real_time_monitoring()
    else:
        # Dừng giám sát thời gian thực
        toggle_real_time_monitoring(False)

# Hàm để tải mô hình học máy
def load_model():
    global model

    # Mở tệp mô hình
    with open('model.pkl', 'rb') as f:
        model = pickle.load(f)

# Hàm để tính toán các đặc trưng cho gói
def calculate_features(packet):
    # Tính toán các đặc trưng thống kê và thời gian
    statistical_and_temporal_features = calculate_statistics_and_temporal_features(packet)

    # Tính toán các đặc trưng nâng cao
    advanced_features = calculate_advanced_features(packet)

    # Trả về danh sách các đặc trưng
    return statistical_and_temporal_features + advanced_features

# Hàm để dự đoán xem gói có phải là tấn công DDoS hay không
def detect_ddos(features):
    # Sử dụng mô hình học máy để dự đoán
    return model.predict(features.reshape(1, -1))[0]

# Hàm để gửi dữ liệu đến hệ thống IDS hoặc NMS
def send_data_to_ids_or_nms(message):
    # Gửi dữ liệu đến hệ thống IDS hoặc NMS
    response = requests.post('https://example.com/api/v1/ddos/detect', json={'message': message})

    # Xử lý phản hồi từ hệ thống IDS hoặc NMS
    if response.status_code == 200:
        # Nếu phản hồi thành công, hãy cập nhật nhật ký
        update_log_text('Tấn công DDoS được phát hiện: ' + response.json()['message'])
    else:
        # Nếu phản hồi không thành công, hãy cập nhật nhật ký
        update_log_text('Lỗi: ' + response.json()['message'])
# Hàm để bắt đầu giám sát thời gian thực
def start_monitoring():
    global real_time_monitoring_thread, packet_queue, detected_packet_types

    packet_queue = queue.Queue()

    # Define the main_thread function before starting it
    def main_thread():
        while True:
            # Get a packet from the queue
            message = packet_queue.get()
            if message is None:
                break

            # Send the data to the IDS or NMS
            send_data_to_ids_or_nms(message)

    # Start the main thread
    main_thread = Thread(target=main_thread)
    main_thread.start()

# Hàm để thực hiện giám sát thời gian thực
def start_monitoring_thread():
    while True:
        # Sniff packets
        packet = sniff(filter='ip', prn=packet_callback)

        # Add packet to the queue
        if packet:
            packet_queue.put(packet)

# Hàm để gửi dữ liệu đến hệ thống IDS hoặc NMS
def send_data_to_ids_or_nms(message):
    # Gửi dữ liệu đến hệ thống IDS hoặc NMS
    response = requests.post('https://example.com/api/v1/ddos/detect', json={'message': message})

    # Xử lý phản hồi từ hệ thống IDS hoặc NMS
    if response.status_code == 200:
        # Nếu phản hồi thành công, hãy cập nhật nhật ký
        update_log_text('Tấn công DDoS được xác nhận')
    else:
        # Nếu phản hồi không thành công, hãy cập nhật nhật ký
        update_log_text('Không thể xác minh tấn công DDoS')

# Khởi chạy vòng lặp chính của Tkinter
window.mainloop()

# Chức năng chính
if __name__ == '__main__':
    # Load mô hình học máy
    load_model()

    # Tạo danh sách các loại gói được giám sát
    detected_packet_types = [IP, TCP, UDP]

    # Khởi động giám sát thời gian thực
    start_monitoring()
