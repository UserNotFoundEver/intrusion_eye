import logging
from scapy.all import sniff, IP, TCP, UDP

# Set up logging - fixed july 29
logging.basicConfig(filename='network_traffic.log', level=logging.INFO)

def process_packet(packet):
    tcp_layer = None  # Initialize tcp_layer to avoid UnboundLocalError
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        log_msg = f"[IP] {ip_layer.src} -> {ip_layer.dst}"

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            log_msg += f" [TCP] Port: {tcp_layer.sport} -> {tcp_layer.dport}"

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            log_msg += f" [UDP] Port: {udp_layer.sport} -> {udp_layer.dport}"

        print(log_msg)
        logging.info(log_msg)

        # Simple port scan detection
        if tcp_layer and (tcp_layer.sport < 1024 or tcp_layer.dport < 1024):
            print(f"Potential port scan detected from {ip_layer.src}")
            logging.warning(f"Potential port scan detected from {ip_layer.src}")

print("Starting network traffic monitor...")
sniff(prn=process_packet, store=False)
