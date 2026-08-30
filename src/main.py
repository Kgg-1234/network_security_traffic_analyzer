from packet_capture import start_capture
from packet_analyzer import analyze_packet, print_statistics


def main():
    print("=" * 50)
    print("   NETWORK SECURITY TRAFFIC ANALYZER")
    print("=" * 50)

    try:
        start_capture(analyze_packet, packet_count=50)
        print_statistics()

    except PermissionError:
        print("\nPermission denied.")
        print("Try running VS Code or the terminal as Administrator.")


if __name__ == "__main__":
    main()