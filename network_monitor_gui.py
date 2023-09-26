import tkinter as tk
from tkinter import ttk
from scapy.all import *
import numpy as np
import time
import os 
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA

# Create a Tkinter window
window = tk.Tk()
window.title("Security Monitoring System")

# Create a StringVar to store the default value
default_value = tk.StringVar()
default_value.set("50")

# Create an Entry widget and link it to the StringVar
window_size_entry = tk.Entry(window, width=50, textvariable=default_value)

# Pack the Entry widget to display it
window_size_entry.pack()

# Start the Tkinter main loop
window.mainloop()

# Hàm để chặn IP sử dụng iptables
def ban_ip(ip, duration=600):
    os.system(f'iptables -A INPUT -s {ip} -j DROP')
    time.sleep(duration)
    os.system(f'iptables -D INPUT -s {ip} -j DROP')

# Mô hình học máy
model = RandomForestClassifier(n_estimators=100, random_state=0)

# Dữ liệu để huấn luyện mô hình
training_data = []

# Hàm xử lý gói tin
def packet_callback(packet):
    protocol = packet.name.lower()
    if protocol in packet_types:
        timestamps.append(packet.time)
        if len(timestamps) > thresholds[protocol]:
            # Tính đặc trưng thời gian và thống kê mạng
            time_features = compute_time_features(timestamps)
            network_features = compute_network_features(packet)

            # Kết hợp các đặc trưng lại
            features = np.concatenate((time_features, network_features), axis=None)

            log_message = f'{protocol} traffic ({len(timestamps)} {protocol} packets in {window_size} seconds)'
            log_text.config(state=tk.NORMAL)
            log_text.insert(tk.END, log_message + "\n")
            log_text.config(state=tk.DISABLED)

            # Phân tích lưu lượng mạng bất thường bằng mô hình Random Forest
            is_abnormal = model.predict([features])[0]

            if is_abnormal:
                log_text.config(state=tk.NORMAL)
                log_text.insert(tk.END, 'Detected abnormal network traffic\n')
                log_text.config(state=tk.DISABLED)

                # Chặn IP nguồn và ghi nhật ký
                scapy.send(IP(src=packet.dst, dst=packet.src)/ICMP(type=ICMP.ECHO_REPLY)/packet.payload)
                attacking_ip_addresses.add(packet.src)
                with open('icmp_flood.log', 'a') as f:
                    f.write(str(packet) + '\n')
                ban_ip(packet.src)

        if packet.src in attacking_ip_addresses:
            scapy.send(packet, ack=0, ttl=0)

# Tính đặc trưng thời gian
def compute_time_features(timestamps):
    timestamps = np.array(timestamps)
    time_diff = np.diff(timestamps)
    return [len(timestamps), time_diff.mean(), time_diff.std()]

# Tính đặc trưng thống kê mạng
def compute_network_features(packet):
    # Tính toán các đặc trưng thống kê từ gói tin mạng
    # Đây là ví dụ, bạn có thể sử dụng các đặc trưng phù hợp với vấn đề cụ thể của bạn.
    return [len(packet), packet.len, packet.ttl]

# Callback function when the "Start Monitoring" button is clicked
def start_monitoring():
    global packet_types, thresholds, window_size, timestamps, attacking_ip_addresses
    packet_types = ['tcp', 'udp', 'arp', 'dns', 'http', 'https']
    thresholds = {
        'tcp': 1,
        'udp': 1,
        'arp': 1,
        'dns': 1,
        'http': 1,
        'https': 1
    }
    window_size = int(window_size_entry.get())
    timestamps = []
    attacking_ip_addresses = set()

    log_text.config(state=tk.NORMAL)
    log_text.delete(1.0, tk.END)
    log_text.config(state=tk.DISABLED)

    try:
        log_text.config(state=tk.NORMAL)
        log_text.insert(tk.END, 'Starting to monitor traffic...\n')
        log_text.config(state=tk.DISABLED)

        # Sử dụng scapy để bắt gói tin mạng
        sniff(filter='tcp, udp, arp, dns, icmp', prn=packet_callback)
    except KeyboardInterrupt:
        log_text.config(state=tk.NORMAL)
        log_text.insert(tk.END, 'Ending program...\n')
        log_text.config(state=tk.DISABLED)

# Create GUI elements
label_packet_types = tk.Label(window, text="Packet types to monitor (comma-separated):")
packet_types_entry = tk.Entry(window)
label_window_size = tk.Label(window, text="Window size (s):")
window_size_entry = tk.Entry(window)
start_button = tk.Button(window, text="Start Monitoring", command=start_monitoring)
log_text = tk.Text(window, height=10, width=50)
log_text.config(state=tk.DISABLED)

# Grid layout for GUI elements
label_packet_types.grid(row=0, column=0, sticky="w")
packet_types_entry.grid(row=0, column=1)
label_window_size.grid(row=1, column=0, sticky="w")
window_size_entry.grid(row=1, column=1)
start_button.grid(row=2, columnspan=2)
log_text.grid(row=3, columnspan=2)

# Define packet types to monitor
packet_types = ['tcp', 'udp', 'arp', 'dns', 'http', 'https']

# Set thresholds for each packet type
thresholds = {
    'tcp': 1000,
    'udp': 1000,
    'arp': 1000,
    'dns': 1000,
    'http': 1000,
    'https': 1000
}

# Set window size in seconds
window_size = 50

# Initialize timestamps and attacking IP addresses
timestamps = []
attacking_ip_addresses = set()

# Start the GUI main loop
window.mainloop()
