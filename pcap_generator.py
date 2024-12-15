# from scapy.all import *
# from scapy.layers.inet import IP, TCP
# from scapy.layers.http import HTTP, HTTPRequest
# from scapy.packet import Raw
# import random
# import warnings
# import os

# # Suppress all warnings by redirecting to os.devnull
# class NullHandler:
#     def write(self, message):
#         pass

# # Redirect warnings to null
# warnings.simplefilter("ignore")
# warnings.showwarning = NullHandler().write

# def generate_normal_traffic(pcap_file, count=50):
#     """Simulate normal HTTP GET traffic."""
#     packets = []
#     for i in range(count):
#         pkt = (Ether()/
#                IP(src=f"192.168.1.{random.randint(2, 254)}", dst="127.0.0.1")/
#                TCP(sport=random.randint(1024, 65535), dport=80, flags='S')/
#                HTTP()/HTTPRequest(
#                    Method=b"GET", 
#                    Path=b"/index.html",
#                    Host=b"example.com"
#                ))
#         packets.append(pkt)
#     wrpcap(pcap_file, packets, append=True)
#     print(f"{count} Normal traffic packets generated and saved.")


# def generate_xss_attack(pcap_file, count=50):  # Increased from 20 to 50
#     """Simulate XSS attack with variations."""
#     packets = []
#     xss_payloads = [
#         b"username=<script>alert('XSS')</script>&password=test",
#         b"username=<img src=x onerror=alert('XSS')>&password=test",
#         b"username=<svg/onload=alert('XSS')>&password=test",
#         b"username=<body onload=alert('XSS')>&password=test",  # More variations
#         b"username=<iframe src='javascript:alert(1)'></iframe>&password=test"  # More variations

#     ]
#     for i in range(count):
#         xss_payload = random.choice(xss_payloads)
#         pkt = (Ether()/
#                IP(src=f"192.168.1.{random.randint(2, 254)}", dst="127.0.0.1")/
#                TCP(sport=random.randint(1024, 65535), dport=80)/
#                Raw(load=xss_payload))
#         packets.append(pkt)
#     wrpcap(pcap_file, packets, append=True)
#     print(f"{count} XSS attack packets generated and saved.")

# def generate_sql_injection(pcap_file, count=50):
#     """Simulate SQL Injection attack with variations."""
#     packets = []
#     sql_payloads = [
#         b"username=admin' OR 1=1 --&password=dummy",
#         b"username=admin' UNION SELECT * FROM users --&password=dummy",
#         b"username=admin' AND 1=1 --&password=dummy",
#         b"username=admin' OR 'x'='x' --&password=dummy",
#         b"username=admin' DROP TABLE users; --&password=dummy",
#          b"username=admin' DROP TABLE users; --&password=dummy",
#         b"username=admin' AND (SELECT COUNT(*) FROM users) > 0 --&password=dummy",  # More complex
#         b"username=admin' OR EXISTS(SELECT * FROM users) --&password=dummy"  # More complex
#     ]
#     for i in range(count):
#         sql_payload = random.choice(sql_payloads)
#         pkt = (Ether()/
#                IP(src=f"192.168.1.{random.randint(2, 254)}", dst="127.0.0.1")/
#                TCP(sport=random.randint(1024, 65535), dport=80)/
#                Raw (load=sql_payload))
#         packets.append(pkt)
#     wrpcap(pcap_file, packets, append=True)
#     print(f"{count} SQL Injection packets generated and saved.")

# def generate_cmd_injection(pcap_file, count=50):
#     """Simulate Command Injection attack."""
#     packets = []
#     cmd_payload = b"username=admin&password=; ls -la"
#     for i in range(count):
#         pkt = (Ether()/
#                IP(src=f"192.168.1.{random.randint(2, 254)}", dst="192.168.1.10")/
#                TCP(sport=random.randint(1024, 65535), dport=80, flags='PA')/
#                HTTP()/HTTPRequest(
#                    Method=b"POST",
#                    Path=b"/cmd_exec",
#                    Host=b"vulnerable-site.com",
#                    Content_Length=str(len(cmd_payload)).encode(),
#                    Content_Type=b"application/x-www-form-urlencoded"
#                )/Raw(load=cmd_payload))  # Add the payload as Raw
#         packets.append(pkt)
#     wrpcap(pcap_file, packets, append=True)
#     print(f"{count} Command Injection packets generated and saved.")

# def main():
#      # Define the output directory and PCAP file name
#     output_dir = "pcaps"
#     os.makedirs(output_dir, exist_ok=True)  # Create the directory if it doesn't exist
#     pcap_file = os.path.join(output_dir, "simulated_attack_traffic.pcap")

from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTP, HTTPRequest
from scapy.packet import Raw
import random
import warnings
import os

# Suppress all warnings by redirecting to os.devnull
class NullHandler:
    def write(self, message):
        pass

# Redirect warnings to null
warnings.simplefilter("ignore")
warnings.showwarning = NullHandler().write

def generate_normal_traffic(pcap_file, count=50):
    """Simulate normal HTTP GET traffic."""
    packets = []
    for _ in range(count):
        pkt = (Ether() /
               IP(src=f"192.168.1.{random.randint(2, 254)}", dst="127.0.0.1") /
               TCP(sport=random.randint(1024, 65535), dport=80, flags='S') /
               HTTP() / HTTPRequest(
                   Method=b"GET",
                   Path=b"/index.html",
                   Host=b"example.com"
               ))
        packets.append(pkt)
    wrpcap(pcap_file, packets, append=True)
    print(f"{count} Normal traffic packets generated and saved.")

def generate_xss_attack(pcap_file, count=50):
    """Simulate XSS attack with variations."""
    packets = []
    xss_payloads = [
        b"username=<script>alert('XSS')</script>&password=test",
        b"username=<img src=x onerror=alert('XSS')>&password=test",
        b"username=<svg/onload=alert('XSS')>&password=test",
        b"username=<body onload=alert('XSS')>&password=test",
        b"username=<iframe src='javascript:alert(1)'></iframe>&password=test"
    ]
    for _ in range(count):
        xss_payload = random.choice(xss_payloads)
        pkt = (Ether() /
               IP(src=f"192.168.1.{random.randint(2, 254)}", dst="127.0.0.1") /
               TCP(sport=random.randint(1024, 65535), dport=80) /
               Raw(load=xss_payload))
        packets.append(pkt)
    wrpcap(pcap_file, packets, append=True)
    print(f"{count} XSS attack packets generated and saved.")

def generate_sql_injection(pcap_file, count=50):
    """Simulate SQL Injection attack with variations."""
    packets = []
    sql_payloads = [
        b"username=admin' OR 1=1 --&password=dummy",
        b"username=admin' UNION SELECT * FROM users --&password=dummy",
        b"username=admin' AND 1=1 --&password=dummy",
        b"username=admin' OR 'x'='x' --&password=dummy",
        b"username=admin' DROP TABLE users; --&password=dummy",
        b"username=admin' AND (SELECT COUNT(*) FROM users) > 0 --&password=dummy",
        b"username=admin' OR EXISTS(SELECT * FROM users) --&password=dummy"
    ]
    for _ in range(count):
        sql_payload = random.choice(sql_payloads)
        pkt = (Ether() /
               IP(src=f"192.168.1.{random.randint(2, 254)}", dst="127.0.0.1") /
               TCP(sport=random.randint(1024, 65535), dport=80) /
               Raw(load=sql_payload))
        packets.append(pkt)
    wrpcap(pcap_file, packets, append=True)
    print(f"{count} SQL Injection packets generated and saved.")

def generate_cmd_injection(pcap_file, count=50):
    """Simulate Command Injection attack."""
    packets = []
    cmd_payload = b"username=admin&password=; ls -la"
    for _ in range(count):
        pkt = (Ether() /
               IP(src=f"192.168.1.{random.randint(2, 254)}", dst="192.168.1.10") /
               TCP(sport=random.randint(1024, 65535), dport=80, flags='PA') /
               HTTP() / HTTPRequest(
                   Method=b"POST",
                   Path=b"/cmd_exec",
                   Host=b"vulnerable-site.com",
                   Content_Length=str(len(cmd_payload)).encode(),
                   Content_Type=b"application/x-www-form-urlencoded"
               ) / Raw(load=cmd_payload))
        packets.append(pkt)
    wrpcap(pcap_file, packets, append=True)
    print(f"{count} Command Injection packets generated and saved.")

def main():
    os.makedirs("pcaps", exist_ok= True)
    pcap_file = "pcaps/simulated_attack_traffic.pcap"
    
    # Generate different types of traffic
    generate_normal_traffic(pcap_file, count=100)
    generate_xss_attack(pcap_file, count=50)
    generate_sql_injection(pcap_file, count=50)
    generate_cmd_injection(pcap_file, count=50)

if __name__ == "__main__":
    main()