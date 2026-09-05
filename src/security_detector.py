from collections import Counter, defaultdict

from scapy.all import IP, TCP


source_ip_count = Counter()
syn_ports = defaultdict(set)


def check_suspicious_activity(packet):
    """Perform basic rule-based network security checks."""

    alerts = []

    if IP not in packet:
        return alerts

    source_ip = packet[IP].src
    source_ip_count[source_ip] += 1

    # Rule 1: High traffic from one source
    if source_ip_count[source_ip] == 20:
        alerts.append(
            f"HIGH TRAFFIC: {source_ip} generated 20 packets."
        )

    # Rule 2: TCP SYN detection
    if TCP in packet:

        flags = str(packet[TCP].flags)

        if "S" in flags and "A" not in flags:

            destination_port = packet[TCP].dport

            syn_ports[source_ip].add(destination_port)

            alerts.append(
                f"TCP SYN: {source_ip} -> "
                f"{packet[IP].dst}:{destination_port}"
            )

            # Rule 3: Multiple destination ports
            if len(syn_ports[source_ip]) >= 5:
                alerts.append(
                    f"PORT SCAN INDICATOR: {source_ip} "
                    f"has attempted {len(syn_ports[source_ip])} "
                    f"different TCP ports."
                )

    return alerts