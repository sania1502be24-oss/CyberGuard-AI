from colorama import Fore, Style, init

init()

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


# Detect large packets
def check_large_packet(packet):

    if len(packet) > 1500:
        print(
            Fore.YELLOW +
            f"[WARNING] Large Packet Detected: {len(packet)} bytes"
            + Style.RESET_ALL
        )


# Detect suspicious ports
def check_suspicious_port(port, ip):

    if port in SUSPICIOUS_PORTS:

        print(
            Fore.RED +
            "\n[ALERT] Suspicious Port Detected!"
            + Style.RESET_ALL
        )

        print("IP:", ip)
        print("Port:", port)
        print("Reason:", SUSPICIOUS_PORTS[port])


# Count packets from IP
def count_packets(ip):

    if ip not in packet_count:
        packet_count[ip] = 1
    else:
        packet_count[ip] += 1

    print(
        Fore.GREEN +
        f"[INFO] {ip} packets: {packet_count[ip]}"
        + Style.RESET_ALL
    )


# Detect port scanning
def check_port_scan(ip, port):

    if ip not in scan_tracker:
        scan_tracker[ip] = set()

    scan_tracker[ip].add(port)

    if len(scan_tracker[ip]) > 10:

        print(
            Fore.RED +
            f"[ALERT] Possible Port Scan detected from {ip}"
            + Style.RESET_ALL
        )