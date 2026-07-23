from colorama import Fore, Style, init
from logger import log_alert
init(autoreset=True)

# Suspicious ports
SUSPICIOUS_PORTS = {
    4444: "Metasploit",
    1337: "Backdoor",
    6667: "IRC Botnet",
    31337: "Elite Hacker Port"
}

# Packet counter
packet_count = {}

# Port scan tracker
scan_tracker = {}

# ICMP tracker
icmp_tracker = {}


# Detect large packets
def check_large_packet(packet):

    if len(packet) > 1500:
        print(
            Fore.YELLOW +
            f"[WARNING] Large Packet Detected: {len(packet)} bytes"
        )
        log_alert(
            f"Large Packet Detected | Size: {len(packet)} bytes"
        )


# Detect suspicious ports
def check_suspicious_port(port, ip):

    if port in SUSPICIOUS_PORTS:

        print(
            Fore.RED +
            "\n[ALERT] Suspicious Port Detected!"
        )

        print(f"IP     : {ip}")
        print(f"Port   : {port}")
        print(f"Reason : {SUSPICIOUS_PORTS[port]}")
        log_alert(
    f"Suspicious Port | IP: {ip} | Port: {port} | Reason: {SUSPICIOUS_PORTS[port]}"
)


# Count packets from each IP
def count_packets(ip):

    if ip not in packet_count:
        packet_count[ip] = 1
    else:
        packet_count[ip] += 1

    print(
        Fore.GREEN +
        f"[INFO] {ip} packets: {packet_count[ip]}"
    )


# Detect Port Scanning
def check_port_scan(ip, port):

    if ip not in scan_tracker:
        scan_tracker[ip] = set()

    scan_tracker[ip].add(port)

    if len(scan_tracker[ip]) > 10:

        print(
            Fore.RED +
            f"[ALERT] Possible Port Scan detected from {ip}"
        )

        log_alert(
            f"Possible Port Scan | Source IP: {ip}"
        )


# Detect ICMP Flood
def check_icmp_flood(ip):

    if ip not in icmp_tracker:
        icmp_tracker[ip] = 1
    else:
        icmp_tracker[ip] += 1

    if icmp_tracker[ip] > 1:

        print(
            Fore.RED +
            f"[ALERT] Possible ICMP Flood detected from {ip}"
        )