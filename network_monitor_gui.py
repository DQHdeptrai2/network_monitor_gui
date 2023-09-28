import threading
import scapy.all as scapy
from scapy.all import *
import time
import re
import logging
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest
import threading
from html import unescape

# Khai báo các biến cấu hình
IP_ADDRESS = "172.30.248.107"
PORT = 80
THRESHOLD = 10000  # Số lượng gói tin cho phép trước khi bắt đầu chặn

# Khai báo một logger
logger = logging.getLogger(__name__)

# Thiết lập hệ thống ghi log
logging.basicConfig(filename='security.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Thiết lập mức độ log
logger.setLevel(logging.DEBUG)

# Tạo một handler để ghi log vào file
handler = logging.FileHandler("blocked_ips.log")
handler.setLevel(logging.INFO)

# Tạo một formatter để định dạng các thông tin log
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)

# Đăng ký handler với logger
logger.addHandler(handler)

# Danh sách lưu trữ các địa chỉ IP đã gửi nhiều gói tin đến
ip_counter = {}

# Danh sách các địa chỉ IP đã bị chặn
ip_block_list = set()

# Khóa chia sẻ để đồng bộ hóa danh sách các địa chỉ IP đã bị chặn
ip_block_list_lock = threading.Lock()

def check_and_block_ip(src_ip):
    with ip_block_list_lock:
        if src_ip in ip_block_list: 
            return False  

def block_ip(ip):
    ip_block_list_lock.acquire()
    ip_block_list.add(ip)
    ip_block_list_lock.release()

def process_packet(packet):
    if scapy.layers.http.HTTPRequest in packet.layers():
        http_request = packet.get_layer(scapy.layers.http.HTTPRequest)
        src_ip = packet[scapy.layers.inet.IP].src
        dst_ip = packet[scapy.layers.inet.IP].dst
        sport = packet[scapy.layers.inet.TCP].sport
        dport = packet[scapy.layers.inet.TCP].dport
        

def process_packet(packet):
    src_ip = packet[scapy.layers.inet.IP].src
    dst_ip = packet[scapy.layers.inet.IP].dst
    sport = packet[scapy.layers.inet.TCP].sport
    dport = packet[scapy.layers.inet.TCP].dport

# Xử lý gói tin HTTP
    if scapy.layers.http.HTTPRequest in packet.layers():
        http_request = packet.get_layer(scapy.layers.http.HTTPRequest)

# Xử lý gói tin UDP
    elif scapy.layers.inet.UDP in packet.layers():
        udp_payload = str(packet[scapy.layers.inet.UDP].payload)
        print("----------------------------------------------------------------------")
        print("UDP Packet:")
        print("Payload:", udp_payload)
        print("Source Port:", sport)
        print("Destination Port:", dport)
        print("----------------------------------------------------------------------")
# Xử lý gói tin TCP
    elif scapy.layers.inet.TCP in packet.layers():
        tcp_payload = str(packet[scapy.layers.inet.TCP].payload)
        print("----------------------------------------------------------------------")
        print("TCP Packet:")
        print("Payload:", tcp_payload)
        print("Source Port:", sport)
        print("Destination Port:", dport)
        print("----------------------------------------------------------------------")

def is_malicious_payload(payload):
    # Tìm kiếm các từ khóa độc hại trong payload
    malicious_keywords = ["malware", "phishing", "virus"]
    for keyword in malicious_keywords:
        if keyword in payload:
            return True
    return False

def is_sensitive_data(payload):
    # Tìm kiếm các mẫu dữ liệu nhạy cảm trong payload
    sensitive_data_patterns = [
        re.compile(r"[a-z0-9]{32}-[a-z0-9]{16}"),  # Mẫu mã hash MD5
        re.compile(r"[a-z0-9]{64}"),  # Mẫu mã hash SHA-1
    ]
    for pattern in sensitive_data_patterns:
        match = pattern.search(payload)
        if match:
            return True
    return False

# Kiểm tra các gói tin
for packet in sniff(filter="tcp or udp"):
    if TCP in packet:
        payload = str(packet[TCP].payload)
        if is_malicious_payload(payload):
            print("Phát hiện gói tin độc hại!")
            block_ip(packet[IP].src)

        if is_sensitive_data(payload):
            print("Phát hiện gói tin chứa dữ liệu nhạy cảm!")
            block_ip(packet[IP].src)

    if UDP in packet:
        payload = str(packet[UDP].payload)
        if is_malicious_payload(payload):
            print("Phát hiện gói tin độc hại!")
            block_ip(packet[IP].src)

        if is_sensitive_data(payload):
            print("Phát hiện gói tin chứa dữ liệu nhạy cảm!")
            block_ip(packet[IP].src)        

# Kiểm tra cuộc tấn công SQL Injection
def is_sql_injection(http_payload):
    sql_injection_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "UNION", "DROP"]
    for keyword in sql_injection_keywords:
        if keyword in http_payload.upper():
            # Phát hiện SQL Injection
            logging.warning(f"Phát hiện tấn công SQL Injection từ {src_ip}")
            block_ip(src_ip)  # Chặn địa chỉ IP bất thường
            return True
    return False

# Kiểm tra xem URL có chứa các từ khóa độc hại hay không
def is_url_malicious(url):
    malicious_keywords = ["malware", "phishing", "virus"]
    for keyword in malicious_keywords:
        if keyword in url:
            return True
        print("URL độc hại!")
    return False

# Kiểm tra cuộc tấn công XSS
def is_xss(http_payload):
    decoded_payload = unescape(http_payload)
    if decoded_payload != http_payload:
        logger.warning(f"Phát hiện cuộc tấn công XSS từ {src_ip}")
        block_ip(src_ip)  # Chặn địa chỉ IP bất thường
        return True
    return False 

# Kiểm tra xem gói tin có phải là một cuộc tấn công Brute Force hay không
def is_sql_injection(http_payload):
    regex = r"[^\w\s()'`\.,;:!?@#$%^&*()<>/{}|\\]+"
    match = re.search(regex, http_payload)
    return match is not None

# Kiểm tra cuộc tấn công Brute Force
def is_brute_force(packet):
    global ip_counter
    src_ip = packet[IP].src

    if src_ip not in ip_counter:
        ip_counter[src_ip] = 0
    ip_counter[src_ip] += 1
    if ip_counter[src_ip] > THRESHOLD:
        logger.warning(f"Đã phát hiện tấn công Brute Force từ địa chỉ IP {src_ip}")
        block_ip(src_ip)
        return True
    return False 
        
# Kiểm tra lớp mạng layer 7 (HTTP)
if Raw in packet:
    http_payload = str(packet[Raw].load)
    if "HTTP" in http_payload:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        http_request = HTTPRequest(http_payload)

# Trích xuất đường dẫn URL
url_pattern = re.compile(r"(https?:\/\/(?:www\.)?([^\s]+))")
url_match = url_pattern.search(http_payload)
if url_match:
    url = url_match.group(1)
    print(f"URL: {url}")

# Ngưỡng tần suất yêu cầu HTTP
THRESHOLD = 50000
TIME_WINDOW = 60  # 1 phút

def block_ip(ip):
    print(f"Chặn địa chỉ IP: {ip}")

def process_http_request(src_ip):
    current_time = time.time()
    if src_ip not in ip_counter:
        ip_counter[src_ip] = []
    ip_counter[src_ip].append(current_time)
# Xóa các yêu cầu cũ hơn 1 phút
    ip_counter[src_ip] = [t for t in ip_counter[src_ip] if t > (current_time - TIME_WINDOW)]
    if len(ip_counter[src_ip]) > THRESHOLD:
        print(f"Đã phát hiện tấn công DDoS từ {src_ip}. Đang chặn...")
        block_ip(src_ip)  # Chặn địa chỉ IP bất thường 

def process_packet(packet):
    if scapy.layers.http.HTTPRequest in packet.layers():
        http_request = packet.get_layer(scapy.layers.http.HTTPRequest)
        src_ip = packet[scapy.layers.inet.IP].src
        dst_ip = packet[scapy.layers.inet.IP].dst
        sport = packet[scapy.layers.inet.TCP].sport
        dport = packet[scapy.layers.inet.TCP].dport
# Kiểm tra xem có một yêu cầu HTTP hợp lệ không
    if http_request is not None:
        if http_request.method == "GET":
            print(f"Lớp mạng layer 7 (HTTP) GET request từ {src_ip}:{sport} đến {dst_ip}:{dport}")
        elif http_request.method == "POST":
            print(f"Lớp mạng layer 7 (HTTP) POST request từ {src_ip}:{sport} đến {dst_ip}:{dport}")
    else:
        print("Không phải yêu cầu HTTP hợp lệ.")
        block_ip(src_ip)  # Chặn địa chỉ IP bất thường

# Kiểm tra lớp mạng layer 4 (TCP/UDP)
    if src_ip != IP_ADDRESS:
        if src_ip in ip_counter:
           ip_counter[src_ip] += 1
        if ip_counter[src_ip] > THRESHOLD:
            print(f"Đã phát hiện lưu lượng truy cập bất thường từ {src_ip}. Đang chặn...")
            block_ip(src_ip)  # Chặn địa chỉ IP bất thường

# Phát hiện tấn công SYN Flood (đảm bảo rằng gói tin là TCP)
if TCP in packet and packet[TCP].flags == 2:
    src_ip_syn_flood = packet[IP].src
    dst_ip_syn_flood = packet[IP].dst

    # Kiểm tra xem gói tin có thuộc SYN Flood hay không
    if packet.seq == 0:
        # Kiểm tra xem thời gian trễ giữa các gói SYN nhỏ hơn một giá trị tham chiếu
        if (time.time() - packet.time) < THRESHOLD:
            print(f"Đã phát hiện SYN Flood từ {src_ip_syn_flood}. Đang chặn...")
            block_ip(src_ip_syn_flood)

# Phát hiện tấn công phân tán
if src_ip != IP_ADDRESS:
    if src_ip not in ip_counter:
        ip_counter[src_ip] = 0

    ip_counter[src_ip] += 1

    if len(ip_counter) > THRESHOLD:
        print(f"Đã phát hiện tấn công phân tán. Đang chặn tất cả các địa chỉ IP.")
        for ip in ip_counter:
            block_ip(ip)
            
if UDP in packet:
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[UDP].sport
    dst_port = packet[UDP].dport

    # Ghi log thông tin gói tin
    logger.info("Đã nhận được gói tin từ %s:%s đến %s:%s", src_ip, src_port, dst_ip, dst_port)
    logger.info("Đã nhận được gói tin UDP từ %s:%s đến %s:%s", src_ip, src_port, dst_ip, dst_port)

def block_ip(ip):
    ip_block_list_lock.acquire()
    ip_block_list.add(ip)
    ip_block_list_lock.release()

# Bắt đầu lắng nghe gói tin trên một luồng riêng
def start_sniffing():
    sniff(filter="tcp and dst port 80-8080", prn=process_packet)
    pass
def process_udp_packet(packet):
    sniff(filter="udp", prn=process_udp_packet)
    pass

if __name__ == "__main__":

# Bắt đầu lắng nghe gói tin trên một luồng riêng
    t = threading.Thread(target=start_sniffing)
    t.start()
    t.join()
