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

# Function to start monitoring based on detected packet types
def start_monitoring_auto():
    global real_time_monitoring_thread, packet_queue, detected_packet_types
    
    packet_queue = queue.Queue()
    
    # Function to handle packet sniffing and detection
    def packet_sniffer(packet):
        if packet.type not in detected_packet_types:
            return
# Thêm một biến để theo dõi trạng thái tự động phát hiện
auto_detection_enabled = tk.BooleanVar()
auto_detection_enabled.set(False)

# Hàm để bật/tắt tự động phát hiện
def toggle_auto_detection():
    global auto_detection_enabled

    if auto_detection_enabled.get():
        # Khởi động giám sát thời gian thực
        toggle_real_time_monitoring()
    else:
        # Dừng giám sát thời gian thực
        toggle_real_time_monitoring(False)

# Thêm một checkbutton để bật/tắt tự động phát hiện
auto_detection_checkbox = tk.Checkbutton(window, text="Tự động phát hiện", variable=auto_detection_enabled, command=toggle_auto_detection)
auto_detection_checkbox.pack()

# Sửa đổi hàm `toggle_real_time_monitoring()`
def toggle_real_time_monitoring(enable_auto_detection=True):
    global real_time_monitoring_thread, packet_queue

    if real_time_monitoring_enabled.get():
        # Dừng giám sát thời gian thực
        if enable_auto_detection:
            auto_detection_enabled.set(False)

        real_time_monitoring_thread.join()

        # Thông báo cho người dùng rằng giám sát thời gian thực đã được tắt
        tk.messagebox.showinfo("Thông báo", "Giám sát thời gian thực đã được tắt")
    else:
        # Khởi động giám sát thời gian thực
        if enable_auto_detection:
            auto_detection_enabled.set(True)

        update_log_text('Bắt đầu giám sát lưu lượng...')
        real_time_monitoring_thread = Thread(target=start_monitoring)
        real_time_monitoring_thread.start()

        # Thông báo cho người dùng rằng giám sát thời gian thực đã được bật
        tk.messagebox.showinfo("Thông báo", "Giám sát thời gian thực đã được bật")

# Sửa đổi hàm `packet_callback()`
def packet_callback(packet):
    """
    Callback function for handling incoming packets.

    This function calculates various features for the packet, including statistical and temporal features,
    as well as advanced features. It then uses these features to predict whether the packet is part of a DDoS attack.
    If the packet is part of a DDoS attack, a log message is added to the packet queue.

    Args:
        packet: The packet to process.

    Returns:
        None
    """
    global packet_queue

    # Nếu tự động phát hiện được bật, hãy kiểm tra xem gói có cần được xử lý hay không
    if auto_detection_enabled.get():
        # Kiểm tra xem loại gói có nằm trong danh sách các loại được giám sát hay không
        if packet.type not in packet_types:
            return

    # Tính toán các đặc trưng cho gói
    features
def packet_callback(packet):
    """
    Callback function for handling incoming packets.

    This function calculates various features for the packet, including statistical and temporal features,
    as well as advanced features. It then uses these features to predict whether the packet is part of a DDoS attack.
    If the packet is part of a DDoS attack, a log message is added to the packet queue.

    Args:
        packet: The packet to process.

    Returns:
        None
    """
    global packet_queue

    # Nếu tự động phát hiện được bật, hãy kiểm tra xem gói có cần được xử lý hay không
    if auto_detection_enabled.get():
        # Kiểm tra xem loại gói có nằm trong danh sách các loại được giám sát hay không
        if packet.type not in packet_types:
            return

    # Tính toán các đặc trưng cho gói
    features = []

    # Tính toán các đặc trưng thống kê và thời gian
    features.extend(calculate_statistics_and_temporal_features(packet))

    # Tính toán các đặc trưng nâng cao
    advanced_features = calculate_advanced_features(packet)
    features.extend(advanced_features)

    # Dự đoán xem gói có phải là tấn công DDoS hay không
    is_attack = detect_ddos(features)

    # Nếu là tấn công DDoS, hãy thêm tin nhắn nhật ký vào hàng đợi
    if is_attack:
        # Thêm tin nhắn nhật ký vào hàng đợi
        packet_queue.put('Cuộc tấn công DDoS có thể từ {}: {} ({})'.format(packet.src, packet.summary(), packet.type))

    # Nếu tự động phát hiện bị tắt, hãy gửi gói đến hệ thống IDS hoặc NMS
    else:
        # Gửi gói đến hệ thống IDS hoặc NMS
        send_data_to_ids_or_nms(packet)

# Hàm để khởi động giám sát thời gian thực
def start_monitoring():
    global real_time_monitoring_thread, packet_queue

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
        message = packet_queue.get()
        if message is None:
            break

        # Update the log text
        update_log_text(message)

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
