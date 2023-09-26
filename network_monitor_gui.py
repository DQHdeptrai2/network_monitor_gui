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
from threading import Thread

# Create a Tkinter window
window = tk.Tk()
window.title("Security Monitoring System")

# Create a Text widget to display the log
log_text_widget = tk.Text(window, height=10, width=50)
log_text_widget.config(state=tk.DISABLED)
log_text_widget.pack()

# Function to update log text
def update_log_text(message):
    log_text_widget.config(state=tk.NORMAL)
    log_text_widget.insert(tk.END, message + '\n')
    log_text_widget.config(state=tk.DISABLED)

# Create a variable to track real-time monitoring state
real_time_monitoring_enabled = tk.BooleanVar()
real_time_monitoring_enabled.set(False)

# Function to toggle real-time monitoring
def toggle_real_time_monitoring():
    global real_time_monitoring_thread
    if real_time_monitoring_enabled.get():
        update_log_text('Starting traffic monitoring...')
        real_time_monitoring_thread = Thread(target=start_monitoring)
        real_time_monitoring_thread.start()
    else:
        update_log_text('Stopping traffic monitoring...')

# Checkbutton to toggle real-time monitoring
real_time_monitoring_checkbox = tk.Checkbutton(window, text="Enable Real-time Monitoring", variable=real_time_monitoring_enabled, command=toggle_real_time_monitoring)
real_time_monitoring_checkbox.pack()

# Create a button to clear the log
clear_log_button = tk.Button(window, text="Clear Log", command=lambda: update_log_text('Log cleared.'))
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
            log_contents = log_text_widget.get("1.0", tk.END)
            f.write(log_contents)

# Add the "Export Log" option to the "File" menu
file_menu.add_command(label="Export Log", command=export_log)

# Create an Entry widget for entering packet types to monitor
packet_types_label = tk.Label(window, text="Enter packet types to monitor")
packet_types_label.pack()

packet_types_entry = tk.Entry(window, width=50)
packet_types_entry.pack()

# Create a button to train a new machine learning model
def train_new_model():
    # Your code to train a new machine learning model goes here
    pass

train_model_button = tk.Button(window, text="Train New Machine Learning Model", command=train_new_model)
train_model_button.pack()

# Create a Scale widget to adjust the sensitivity of the intrusion detection algorithm
sensitivity_label = tk.Label(window, text="Adjust Intrusion Detection Sensitivity")
sensitivity_label.pack()

sensitivity_slider = tk.Scale(window, from_=0, to=100, orient="horizontal")
sensitivity_slider.pack()

# ... (Thresholds, window size, timestamps, attacking_ip_addresses, database creation, and model initialization)

# Define a function to calculate advanced features
def calculate_advanced_features(packet):
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
    global timestamps, attacking_ip_addresses

    # Check if the packet type is in the list of monitored types
    if packet.type not in packet_types:
        return

    # Update timestamps
    timestamps.append(packet.time)

    # Calculate statistical and temporal features
    features = compute_features(packet)

    # Calculate advanced features
    advanced_features = calculate_advanced_features(packet)

    # Merge the feature vectors
    features += advanced_features

    # Get the packet type
    packet_type = get_packet_type(packet)

    # Detect DDoS attacks
    if detect_ddos(packet):
        # Log the DDoS attack
        log_message = 'Possible DDoS attack from {}: {} ({})'.format(packet.src, packet.summary(), packet_type)
        update_log_text(log_message)
        # conn.execute('INSERT INTO logs (message) VALUES (?)', (log_message,))
        # conn.commit()

    # Make predictions using the machine learning model
    prediction = model.predict(np.array([features]))

    # If the prediction indicates an anomaly, log it
    if prediction > 0.5:  # Adjust the threshold as needed
        # Add a field to the log message to store the packet type
        log_message = 'Anomalous packet from {}: {} ({})'.format(packet.src, packet.summary(), packet_type)
        update_log_text(log_message)
        # conn.execute('INSERT INTO logs (message) VALUES (?)', (log_message,))
        # conn.commit()

# Modify the start_monitoring function to use packet_callback
def start_monitoring():
    global real_time_monitoring_enabled

    # Check if real-time monitoring is enabled
    if not real_time_monitoring_enabled.get():
        return

    try:
        update_log_text('Starting traffic monitoring...')
        # Sniff packets and use the packet_callback function
        sniff(filter='tcp or udp or arp or dns or icmp', prn=packet_callback)
    except KeyboardInterrupt:
        update_log_text('Program terminated...')

# Bind the clear log button to a function to clear the log
def clear_log():
    log_text_widget.config(state=tk.NORMAL)
    log_text_widget.delete('1.0', tk.END)
    log_text_widget.config(state=tk.DISABLED)

clear_log_button.config(command=clear_log)

# Bind the train model button to a function to train a new machine learning model
train_model_button.config(command=train_new_model)

# Start the Tkinter main loop
window.mainloop()
