import threading
from scapy.all import *
import re
import logging
import fail2ban as fail2ban_client
from scapy.layers.http import HTTPRequest
import threading

# Khai báo các biến cấu hình
IP_ADDRESS = "your_server_ip"
PORT = 80
THRESHOLD = 10000  # Số lượng gói tin cho phép trước khi bắt đầu chặn

# Khai báo một logger
logger = logging.getLogger(__name__)

# Thiết lập mức độ log
logger.setLevel(logging.DEBUG)

# Tạo một handler để ghi log vào file
handler = logging.FileHandler("log.txt")
handler.setLevel(logging.DEBUG)

# Tạo một formatter để định dạng các thông tin log
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)

# Đăng ký handler với logger
logger.addHandler(handler)

# Danh sách lưu trữ các địa chỉ IP đã gửi nhiều gói tin đến
ip_counter = {}

from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTPRequest
        
def is_url_malicious(url):
    malicious_keywords = ["malware", "phishing", "virus"]
    for keyword in malicious_keywords:
        if keyword in url:
            return True
    return False

def process_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    
        # Kiểm tra xem địa chỉ IP đã bị chặn hay chưa
        with ip_block_list_lock:
            if src_ip in ip_block_list:
                return
        
        # Kiểm tra lớp mạng layer 7 (HTTP)
        if Raw in packet:
            http_payload = str(packet[Raw].load)
            if "HTTP" in http_payload:
                print(f"Detected Layer 7 (HTTP) traffic from {src_ip}:{sport} to {dst_ip}:{dport}")
                
                # Kiểm tra xem gói tin có phải là HTTP hay HTTPS
                http_request = HTTPRequest(http_payload)
                if http_request:
                    if http_request.method == "GET":
                        print(f"Lớp mạng layer 7 (HTTP) GET request từ {src_ip}:{sport} đến {dst_ip}:{dport}")
                    elif http_request.method == "POST":
                        print(f"Lớp mạng layer 7 (HTTP) POST request từ {src_ip}:{sport} đến {dst_ip}:{dport}")

                # Trích xuất đường dẫn URL
                url_pattern = re.compile(r"(https?:\/\/(?:www\.)?([^\s]+))")
                url_match = url_pattern.search(http_payload)
                if url_match:
                    url = url_match.group(1)
                    print(f"URL: {url}")

                    # Kiểm tra xem URL có chứa các từ khóa độc hại hay không
                    if is_url_malicious(url):
                        print("URL độc hại!")

        # Kiểm tra lớp mạng layer 4 (TCP/UDP)
        if src_ip != IP_ADDRESS:
            if src_ip in ip_counter:
                ip_counter[src_ip] += 1
                if ip_counter[src_ip] > THRESHOLD:
                    print(f"Đã phát hiện lưu lượng truy cập bất thường từ {src_ip}. Đang chặn...")
                    block_ip(src_ip)  # Chặn địa chỉ IP bất thường
                    
        # Ghi log thông tin gói tin
        logger.info("Đã nhận được gói tin từ %s:%s đến %s:%s", src_ip, sport, dst_ip, dport)

def block_ip(ip):
    ip_block_list_lock.acquire()
    ip_block_list.add(ip)
    ip_block_list_lock.release()

# Khóa chia sẻ để đồng bộ hóa danh sách các địa chỉ IP đã bị chặn
ip_block_list_lock = threading.Lock()

# Danh sách các địa chỉ IP đã bị chặn
ip_block_list = set()

def start_sniffing():
    sniff(filter="dst port 80-8080", prn=process_packet)

if __name__ == "__main__":

    # Bắt đầu lắng nghe gói tin trên một luồng riêng
    t = threading.Thread(target=start_sniffing)
    t.start()

    # Điều này có thể là nơi khởi động fail2ban nếu cần thiết
    fail2ban_client.start()
