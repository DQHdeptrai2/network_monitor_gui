import threading
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest
from html import unescape
from scapy.all import sniff
import time
import re
import logging
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest
from html import unescape

# Các biến cấu hình
IP_ADDRESS = "172.30.248.107"
THRESHOLD = 10000
LOG_FILENAME = 'security.log'

# Tạo một logger
logger = logging.getLogger(__name__)

# Cài đặt ghi log
logging.basicConfig(filename=LOG_FILENAME, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger.setLevel(logging.DEBUG)

# Tạo một bộ xử lý tệp cho các địa chỉ IP bị chặn
handler = logging.FileHandler("blocked_ips.log")
handler.setLevel(logging.INFO)

# Định dạng thông điệp ghi log
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)

# Đăng ký bộ xử lý với logger
logger.addHandler(handler)

# Tạo một từ điển lưu trữ số lượng yêu cầu từ các địa chỉ IP
ip_counter = {}

# Tập hợp lưu trữ địa chỉ IP bị chặn
ip_block_list = set()

# Khóa để đồng bộ hóa quyền truy cập vào tập hợp địa chỉ IP bị chặn
ip_block_list_lock = threading.Lock()

def block_ip(ip):
    with ip_block_list_lock:
        ip_block_list.add(ip)

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        sport = packet.sport
        dport = packet.dport

        if TCP in packet:
            process_tcp_packet(packet, src_ip, dst_ip, sport, dport)
        elif UDP in packet:
            process_udp_packet(packet, src_ip, dst_ip, sport, dport)

def process_tcp_packet(packet, src_ip, dst_ip, sport, dport):
    payload = str(packet[TCP].payload)

    if is_malicious_payload(payload) or is_sensitive_data(payload):
        logger.warning(f"Phát hiện dữ liệu độc hại hoặc nhạy cảm từ {src_ip}")
        block_ip(src_ip)

    if HTTPRequest in packet:
        http_request = packet.getlayer(HTTPRequest)
        if http_request.method in ["GET", "POST"]:
            logger.info(f"Yêu cầu HTTP {http_request.method} từ {src_ip}:{sport} đến {dst_ip}:{dport}")
            if is_sql_injection(http_request.Path) or is_url_malicious(http_request.Path) or is_xss(http_request.Path):
                logger.warning(f"Phát hiện cuộc tấn công web từ {src_ip}")
                block_ip(src_ip)

def process_udp_packet(packet, src_ip, dst_ip, sport, dport):
    payload = str(packet[UDP].payload)
    if is_malicious_payload(payload) or is_sensitive_data(payload):
        logger.warning(f"Phát hiện dữ liệu độc hại hoặc nhạy cảm từ {src_ip}")
        block_ip(src_ip)

def is_malicious_payload(payload):
    malicious_keywords = ["malware", "phishing", "virus"]
    return any(keyword in payload for keyword in malicious_keywords)

def is_sensitive_data(payload):
    sensitive_data_patterns = [
        re.compile(r"[a-z0-9]{32}-[a-z0-9]{16}"),  # Mẫu hash MD5
        re.compile(r"[a-z0-9]{64}"),  # Mẫu hash SHA-1
    ]
    return any(pattern.search(payload) for pattern in sensitive_data_patterns)

def is_sql_injection(http_payload):
    sql_injection_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "UNION", "DROP"]
    return any(keyword in http_payload.upper() for keyword in sql_injection_keywords)

def is_url_malicious(url):
    malicious_keywords = ["malware", "phishing", "virus"]
    return any(keyword in url for keyword in malicious_keywords)

def is_xss(http_payload):
    decoded_payload = unescape(http_payload)
    return decoded_payload != http_payload

def start_sniffing():
    sniff(filter="tcp or udp", prn=process_packet)

if __name__ == "__main__":
    t = threading.Thread(target=start_sniffing)
    t.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        exit_flag = True  # Thông báo cho luồng thoát một cách tử tế
        t.join()  # Đợi luồng kết thúc
