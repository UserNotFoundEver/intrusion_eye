import logging

logging.basicConfig(filename='network_traffic.log', level=logging.INFO)

def process_packet(packet):
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

sniff(prn=process_packet, store=False)
