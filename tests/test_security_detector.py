from scapy.all import IP, TCP

from src.security_detector import check_suspicious_activity


def test_tcp_syn_detection():
    packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(
        sport=5000,
        dport=80,
        flags="S"
    )

    alerts = check_suspicious_activity(packet)

    assert any("TCP SYN" in alert for alert in alerts)


def test_port_scan_detection():
    alerts = []

    for port in [21, 22, 23, 80, 443]:
        packet = IP(
            src="192.168.1.10",
            dst="192.168.1.20"
        ) / TCP(
            sport=5000,
            dport=port,
            flags="S"
        )

        alerts.extend(check_suspicious_activity(packet))

    assert any("PORT SCAN INDICATOR" in alert for alert in alerts)