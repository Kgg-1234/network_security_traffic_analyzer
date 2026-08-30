from collections import Counter
from datetime import datetime
from pathlib import Path

from scapy.all import IP, TCP, UDP, ICMP

from security_detector import check_suspicious_activity


protocol_stats = Counter()

LOG_FILE = Path("logs/traffic.log")


def log_packet(packet_info):
    """Save analyzed packet information to a log file."""

    LOG_FILE.parent.mkdir(exist_ok=True)

    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(packet_info + "\n")


def analyze_packet(packet):
    """Analyze an IP packet and display its information."""

    if IP not in packet:
        return

    ip_layer = packet[IP]

    protocol = "OTHER"

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"

    protocol_stats[protocol] += 1

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    packet_info = (
        f"[{timestamp}] "
        f"Source={ip_layer.src} | "
        f"Destination={ip_layer.dst} | "
        f"Protocol={protocol}"
    )

    if TCP in packet:
        packet_info += (
            f" | SourcePort={packet[TCP].sport}"
            f" | DestinationPort={packet[TCP].dport}"
        )

    elif UDP in packet:
        packet_info += (
            f" | SourcePort={packet[UDP].sport}"
            f" | DestinationPort={packet[UDP].dport}"
        )

    print("\n" + "=" * 50)
    print(f"PACKET #{sum(protocol_stats.values())}")
    print("=" * 50)
    print(packet_info)

    # Save packet information
    log_packet(packet_info)

    # Check for simple security indicators
    alerts = check_suspicious_activity(packet)

    for alert in alerts:
        print(f"\n[ALERT] {alert}")


def print_statistics():
    """Display protocol statistics."""

    print("\n" + "=" * 50)
    print("TRAFFIC STATISTICS")
    print("=" * 50)

    for protocol, count in protocol_stats.items():
        print(f"{protocol}: {count}")

    print(f"\nTotal IP Packets Analyzed: {sum(protocol_stats.values())}")