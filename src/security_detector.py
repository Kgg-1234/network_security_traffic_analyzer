from collections import Counter

from scapy.all import IP, TCP


source_ip_count = Counter()


def check_suspicious_activity(packet):
    """Perform simple rule-based checks on a captured packet."""

    alerts = []

    if IP not in packet:
        return alerts

    source_ip = packet[IP].src
    source_ip_count[source_ip] += 1

    # Rule 1: High packet count from one source IP
    if source_ip_count[source_ip] == 20:
        alerts.append(
            f"HIGH TRAFFIC ALERT: {source_ip} has generated 20 packets."
        )

    # Rule 2: TCP SYN packet
    if TCP in packet:
        tcp_flags = packet[TCP].flags

        if "S" in str(tcp_flags) and "A" not in str(tcp_flags):
            alerts.append(
                f"TCP SYN DETECTED: {source_ip} -> "
                f"{packet[IP].dst}:{packet[TCP].dport}"
            )

    return alerts