from scapy.all import sniff, IP, TCP, UDP

# Function to process each packet prints the IP addresses and port information for each packet
def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"[IP] {ip_layer.src} -> {ip_layer.dst}")

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"   [TCP] Port: {tcp_layer.sport} -> {tcp_layer.dport}")

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"   [UDP] Port: {udp_layer.sport} -> {udp_layer.dport}")

# Capture packets
print("Starting network traffic monitor...")
sniff(prn=process_packet, store=False)
