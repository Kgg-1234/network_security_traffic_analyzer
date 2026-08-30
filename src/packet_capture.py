from scapy.all import sniff


def start_capture(packet_handler, packet_count=50):
    """Capture IP packets and send them to the analyzer."""

    print(f"\nStarting packet capture for {packet_count} IP packets...\n")

    sniff(
        prn=packet_handler,
        store=False,
        count=packet_count,
        filter="ip"
    )

    print("\nPacket capture completed.")