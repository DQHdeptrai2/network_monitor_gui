import tkinter as tk
from tkinter import filedialog
import scapy
import numpy as np
from threading import Thread

# Định nghĩa biến toàn cục để lưu trữ nhật ký
log_list = []

# Tạo hàm để bật/tắt giám sát thời gian thực
def toggle_real_time_monitoring():
    global real_time_monitoring_enabled

    if real_time_monitoring_enabled.get():
        # Bắt đầu giám sát lưu lượng trong một luồng mới
        monitoring_thread = Thread(target=start_monitoring)
        monitoring_thread.start()

        # Bật nút "Huấn luyện mô hình học máy mới" và thanh trượt "Điều chỉnh độ nhạy phát hiện xâm nhập"
        train_model_button.config(state=tk.NORMAL)
        sensitivity_slider.config(state=tk.NORMAL)
    else:
        # Dừng giám sát lưu lượng
        pass

        # Tắt nút "Huấn luyện mô hình học máy mới" và thanh trượt "Điều chỉnh độ nhạy phát hiện xâm nhập"
        train_model_button.config(state=tk.DISABLED)
        sensitivity_slider.config(state=tk.DISABLED)

# Tạo cửa sổ chính
window = tk.Tk()
window.title("Màn hình giám sát mạng")

# Tạo khung để nhóm các loại gói cần theo dõi, nút "Huấn luyện mô hình học máy mới" và thanh trượt "Điều chỉnh độ nhạy phát hiện xâm nhập"
label_frame = tk.LabelFrame(window, text="Loại gói cần theo dõi")
label_frame.pack()

# Tạo danh sách hộp cho các loại gói cần theo dõi
packet_types_listbox = tk.Listbox(label_frame, selectmode=tk.MULTIPLE)
packet_types_listbox.pack()

# Tạo nút "Huấn luyện mô hình học máy mới"
train_model_button = tk.Button(label_frame, text="Huấn luyện mô hình học máy mới", state=tk.DISABLED)
train_model_button.pack()

# Tạo thanh trượt để điều chỉnh độ nhạy của thuật toán phát hiện xâm nhập
sensitivity_slider = tk.Scale(label_frame, from_=0, to=100, orient="horizontal", state=tk.DISABLED)
sensitivity_slider.pack()
def start_monitoring():
    # Use Scapy to capture packets
    # Example: packets = sniff(filter="tcp and port 80", count=10)
    # Process the packets and log any suspicious activity
    # Example: for packet in packets:
    #              if detect_ddos(packet):
    #                  log_list.append("DDoS attack detected from " + packet.src)
    #                  log_text_widget.config(state=tk.NORMAL)
    #                  log_text_widget.insert(tk.END, "DDoS attack detected from " + packet.src + "\n")
    #                  log_text_widget.config(state=tk.DISABLED)
    #              else:
    #                  log_list.append("Normal traffic from " + packet.src)
    #                  log_text_widget.config(state=tk.NORMAL)
    #                  log_text_widget.insert(tk.END, "Normal traffic from " + packet.src + "\n")
    #                  log_text_widget.config(state=tk.DISABLED)
    pass
    
real_time_monitoring_enabled = tk.IntVar(value=0)

# Create the main window
window = tk.Tk()
window.title("Network Monitor GUI")

# Create the real-time monitoring checkbox
real_time_monitoring_checkbox = tk.Checkbutton(window, text="Enable Real-Time Monitoring", variable=real_time_monitoring_enabled, command=toggle_real_time_monitoring)
real_time_monitoring_checkbox.pack()

# Create a function to toggle real-time monitoring
def toggle_real_time_monitoring():
    if real_time_monitoring_enabled.get():
        # Real-time monitoring is enabled
        print("Real-time monitoring is enabled")
    else:
        # Real-time monitoring is disabled
        print("Real-time monitoring is disabled")

# Create a button to clear the log
clear_log_button = tk.Button(window, text="Clear Log")
clear_log_button.pack()

# Create a menu bar
menubar = tk.Menu(window)
window.config(menu=menubar)

# Create a "File" menu
file_menu = tk.Menu(menubar, tearoff=0)
menubar.add_cascade(label="File", menu=file_menu)

# Function to export log
def export_log():
    filename = filedialog.asksaveasfilename(title="Export Log", defaultextension=".txt")
    if filename:
        with open(filename, "w") as f:
            for log in log_list:
                f.write(log + "\n")

# Add the "Export Log" option to the "File" menu
file_menu.add_command(label="Export Log", command=export_log)

# Create a Text widget to display the log
log_text_widget = tk.Text(window, height=50, width=50)
log_text_widget.config(state=tk.DISABLED)
log_text_widget.pack()

# Create an Entry widget for entering packet types to monitor
packet_types_label = tk.Label(window, text="Enter packet types to monitor")
packet_types_label.pack()

packet_types_entry = tk.Entry(window, width=50)
packet_types_entry.pack()

# Create a button to train a new machine learning model
train_model_button = tk.Button(window, text="Train New Machine Learning Model")
train_model_button.pack()

# Create a Scale widget to adjust the sensitivity of the intrusion detection algorithm
sensitivity_label = tk.Label(window, text="Adjust Intrusion Detection Sensitivity")
sensitivity_label.pack()

sensitivity_slider = tk.Scale(window, from_=0, to=100, orient="horizontal")
sensitivity_slider.pack()

# ... (Thresholds, window size, timestamps, attacking_ip_addresses, database creation, and model initialization)

# Define a function to calculate advanced features
def compute_advanced_features(packet):
    # Calculate advanced features such as entropy, port distribution, etc.
    # Example: entropy_feature = calculate_entropy(packet.payload)
    # Return a list of advanced features
    return []

# Define a function to detect DDoS attacks
def detect_ddos(packet):
    # Implement DDoS detection logic here
    # Example: Check for a sudden increase in traffic from multiple sources
    return False

# Modify the packet callback function to use advanced features and DDoS detection
# Define a global variable for the packet types to monitor
packet_types = []

# Checkbutton to toggle real-time monitoring
real_time_monitoring_checkbox = tk.Button(window, text="Enable Real-time Monitoring", variable=real_time_monitoring_enabled, command=toggle_real_time_monitoring)
real_time_monitoring_checkbox.pack()

# Create a button to clear the log
clear_log_button = tk.Button(window, text="Clear Log")
clear_log_button.pack()

# Create a menu bar
menubar = tk.Menu(window)
window.config(menu=menubar)

# Create a "File" menu
file_menu = tk.Menu(menubar, tearoff=0)
menubar.add_cascade(label="File", menu=file_menu)

# Function to export log
def export_log():
    filename = filedialog.asksaveasfilename(title="Export Log", defaultextension=".txt")
    if filename:
        with open(filename, "w") as f:
            for log in log_list:
                f.write(log + "\n")

# Add the "Export Log" option to the "File" menu
file_menu.add_command(label="Export Log", command=export_log)

# Create a Text widget to display the log
log_text_widget = tk.Text(window, height=50, width=50)
log_text_widget.config(state=tk.DISABLED)
log_text_widget.pack()

# Create an Entry widget for entering packet types to monitor
packet_types_label = tk.Label(window, text="Enter packet types to monitor")
packet_types_label.pack()

packet_types_entry = tk.Entry(window, width=50)
packet_types_entry.pack()

# Create a button to train a new machine learning model
train_model_button = tk.Button(window, text="Train New Machine Learning Model")
train_model_button.pack()

# Create a Scale widget to adjust the sensitivity of the intrusion detection algorithm
sensitivity_label = tk.Label(window, text="Adjust Intrusion Detection Sensitivity")
sensitivity_label.pack()

sensitivity_slider = tk.Scale(window, from_=0, to=100, orient="horizontal")
sensitivity_slider.pack()

# ... (Thresholds, window size, timestamps, attacking_ip_addresses, database creation, and model initialization)

# Define a function to calculate advanced features
def compute_advanced_features(packet):
    # Calculate advanced features such as entropy, port distribution, etc.
    # Example: entropy_feature = calculate_entropy(packet.payload)
    # Return a list of advanced features
    return []

# Define a function to detect DDoS attacks
def detect_ddos(packet):
    # Implement DDoS detection logic here
    # Example: Check for a sudden increase in traffic from multiple sources
    return False

# Modify the packet callback function to use advanced features and DDoS detection
def packet_callback(packet):
    """
    Callback function that is called for each packet captured by the network monitor.
    This function performs the following tasks:
    - Checks if the packet type is in the list of monitored types
    - Updates timestamps
    - Calculates statistical and temporal features
    - Calculates advanced features
    - Merges the feature vectors
    - Detects DDoS attacks
    - Logs DDoS attacks
    - Makes predictions using the machine learning model
    - Logs anomalous packets

    Args:
        packet: A packet object representing the captured network packet.

    Returns:
        None
    """
    global timestamps, attacking_ip_addresses, packet_types

    # Check if the packet type is in the list of monitored types
    if packet.type not in packet_types:
        return

    # Update timestamps
    timestamps.append(packet.time)

    # Calculate statistical and temporal features
    # Calculate statistical and temporal features
    def calculate_statistical_features(packet):
        """
        Calculates statistical features based on the packet payload.

        Args:
            packet: A packet object representing the captured network packet.

        Returns:
            A list of statistical features.
        """
        # Calculate the length of the packet payload
        payload_length = len(packet.payload)

        # Calculate the mean, standard deviation, and maximum byte value of the packet payload
        mean_byte_value = np.mean(packet.payload)
        std_byte_value = np.std(packet.payload)
        max_byte_value = np.max(packet.payload)

        # Return the statistical features as a list
        return [payload_length, mean_byte_value, std_byte_value, max_byte_value]
    def calculate_temporal_features(timestamps):
        """
        Calculates temporal features based on the list of timestamps.

        Args:
            timestamps: A list of timestamps.

        Returns:
            A list of temporal features.
        """
        # Calculate the time difference between each pair of consecutive timestamps
        time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

        # Calculate the mean, standard deviation, and maximum time difference
        mean_time_diff = np.mean(time_diffs)
        std_time_diff = np.std(time_diffs)
        max_time_diff = np.max(time_diffs)

        # Return the temporal features as a list
        return [mean_time_diff, std_time_diff, max_time_diff]
    
    # Calculate advanced features
    advanced_features = compute_advanced_features(packet)
    
    # Merge the feature vectors
    features += advanced_features

    # Get the packet type
    import subprocess;
    subprocess.run(['pip', 'install', 'scapy'])
    packet_type = packet.type
    import sqlite3
    import subprocess

    # Install necessary libraries
    subprocess.run(['pip', 'install', 'scapy'])
    subprocess.run(['pip', 'install', 'scikit-learn'])

    # Detect DDoS attacks
    if detect_ddos(packet):
        # Log the DDoS attack
        log_message = 'Possible DDoS attack from {}: {} ({})'.format(packet.src, packet.summary(), packet_type)
        log_text_widget.config(state=tk.NORMAL)
        log_text_widget.insert(tk.END, log_message + '\n')
        log_text_widget.config(state=tk.DISABLED)
        conn.execute('INSERT INTO logs (message) VALUES (?)', (log_message,))

        # Commit the changes to the database
        conn.commit()

        # Close the connection
        # Define the connection to the database
        import sqlite3
        conn = sqlite3.connect('logs.db')

        # Close the connection
        conn.close()

    # Make predictions using the machine learning model
    # Import the necessary libraries
    from sklearn import joblib

    # Load the pre-trained model
    model = joblib.load('model.pkl')

    # Make a prediction using the machine learning model
    prediction = model.predict(features)

    if prediction > 0.5:  # Adjust the threshold as needed
        # Add a field to the log message to store the packet type
        packet_type = packet.type
        log_message = 'Anomalous packet from {}: {} ({})'.format(packet.src, packet.summary(), packet_type)
        log_text_widget.config(state=tk.NORMAL)
        log_text_widget.insert(tk.END, log_message + '\n')
        log_text_widget.config(state=tk.DISABLED)
        conn.execute('INSERT INTO logs (message) VALUES (?)', (log_message,))

        # Commit the changes to the database
        conn.commit()

        # Close the connection
        conn.close()

    # Load the pre-trained model
    model = joblib.load('model.pkl')

    # If the prediction indicates an anomaly, log it
    # Make predictions using the machine learning model
    # Import the necessary libraries
    from sklearn import joblib

    # Load the pre-trained model
    model = joblib.load('model.pkl')

    # Make a prediction using the machine learning model
    prediction = model.predict(features)

    if prediction > 0.5:  # Adjust the threshold as needed
        # Add a field to the log message to store the packet type
        packet_type = packet.type
        log_message = 'Anomalous packet from {}: {} ({})'.format(packet.src, packet.summary(), packet_type)
        log_text_widget.config(state=tk.NORMAL)
        log_text_widget.insert(tk.END, log_message + '\n')
        log_text_widget.config(state=tk.DISABLED)
        conn.execute('INSERT INTO logs (message) VALUES (?)', (log_message,))
        conn.commit()

# Modify the start_monitoring function to use advanced_packet_callback


# Bind the clear log button to a function to clear the log
def clear_log():
    log_text_widget.config(state=tk.NORMAL)
    log_text_widget.delete('1.0', tk.END)
    log_text_widget.config(state=tk.DISABLED)

clear_log_button.config(command=clear_log)

# Bind the train model button to a function to train a new machine learning model
# Define a function to train a new machine-learning model
def train_new_model():
    # Implement logic to train a new machine-learning model
    # Example: model = train_model()
    pass

# Start the Tkinter main loop
window.mainloop()
