from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

from detector import (
    check_large_packet,
    check_suspicious_port,
    count_packets,
    check_port_scan
)
# Dictionary of common services
COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
}

def get_service(port):
    return COMMON_PORTS.get(port, "Unknown")


def packet_callback(packet):
    print("=" * 60)

    if packet.haslayer(IP):
        ip = packet[IP]

        count_packets(ip.src)
        check_large_packet(packet)

        print(f"Source IP       : {ip.src}")
        print(f"Destination IP  : {ip.dst}")

        service = "Unknown"

        if packet.haslayer(TCP):
            tcp = packet[TCP]

            print("Protocol        : TCP")
            print(f"Source Port     : {tcp.sport}")
            print(f"Destination Port: {tcp.dport}")
            check_suspicious_port(tcp.dport, ip.src)
            check_port_scan(ip.src, tcp.dport)

            service = get_service(tcp.dport)
            print(f"Service         : {service}")

        elif packet.haslayer(UDP):
            udp = packet[UDP]

            print("Protocol        : UDP")
            print(f"Source Port     : {udp.sport}")
            print(f"Destination Port: {udp.dport}")
            check_suspicious_port(udp.dport, ip.src)
            check_port_scan(ip.src, udp.dport)

            service = get_service(udp.dport)
            print(f"Service         : {service}")

        elif packet.haslayer(ICMP):
            print("Protocol        : ICMP")
            service = "ICMP"

        print("\nDetection Result:")

        if service == "HTTP":
            print("[WARNING] HTTP traffic detected (not encrypted).")

        elif service == "HTTPS":
            print("[SAFE] Secure HTTPS traffic detected.")

        elif service == "DNS":
            print("[INFO] DNS query detected.")

        elif service == "SSH":
            print("[INFO] Secure remote login (SSH) detected.")

        elif service == "ICMP":
            print("[INFO] ICMP packet detected (possible ping).")

        else:
            print("[INFO] No specific rule matched.")

        print(f"Packet Length   : {len(packet)} bytes")

    print("=" * 60)

print("CyberGuard-AI Packet Analyzer Started...\n")

sniff(prn=packet_callback, count=10)

print("\nCapture Finished!")