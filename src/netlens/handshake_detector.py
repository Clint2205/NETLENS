from pathlib import Path
import pyshark


# ------------------------------------------------------------
# NetLens — Step 5
# TCP Handshake Detection
# ------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

PCAP_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "pcaps"
    / "first_capture.pcapng"
)


def get_addresses(packet):
    """Return source and destination IP addresses."""

    source = "UNKNOWN"
    destination = "UNKNOWN"

    if hasattr(packet, "ip"):
        source = getattr(packet.ip, "src", "UNKNOWN")
        destination = getattr(packet.ip, "dst", "UNKNOWN")

    elif hasattr(packet, "ipv6"):
        source = getattr(packet.ipv6, "src", "UNKNOWN")
        destination = getattr(packet.ipv6, "dst", "UNKNOWN")

    return source, destination


def detect_syn_packets(pcap_file: Path) -> None:
    """Find TCP SYN packets in the capture."""

    print("=" * 110)
    print("NETLENS — TCP SYN DETECTION")
    print("=" * 110)

    print(f"Capture file: {pcap_file}")
    print()

    if not pcap_file.exists():
        print("ERROR: Capture file not found.")
        return

    capture = pyshark.FileCapture(
        str(pcap_file),
        display_filter="tcp.flags.syn == 1",
        keep_packets=False
    )

    syn_count = 0

    print(
        f"{'Packet':<10}"
        f"{'Time':<16}"
        f"{'Source':<40}"
        f"{'Destination':<40}"
        f"{'Src Port':<10}"
        f"{'Dst Port':<10}"
        f"{'Flags':<10}"
    )

    print("-" * 140)

    try:

        for packet in capture:

            syn_count += 1

            source, destination = get_addresses(packet)

            tcp = packet.tcp

            source_port = getattr(
                tcp,
                "srcport",
                "UNKNOWN"
            )

            destination_port = getattr(
                tcp,
                "dstport",
                "UNKNOWN"
            )

            flags = getattr(
                tcp,
                "flags",
                "UNKNOWN"
            )

            timestamp = str(
                getattr(
                    packet,
                    "sniff_time",
                    "UNKNOWN"
                )
            )

            if " " in timestamp:
                timestamp = timestamp.split(" ", 1)[1]

            print(
                f"{packet.number:<10}"
                f"{timestamp:<16}"
                f"{str(source):<40}"
                f"{str(destination):<40}"
                f"{str(source_port):<10}"
                f"{str(destination_port):<10}"
                f"{str(flags):<10}"
            )

    finally:
        capture.close()

    print()
    print("-" * 140)
    print(f"TCP SYN packets found: {syn_count}")
    print("-" * 140)
    print("=" * 110)


if __name__ == "__main__":
    detect_syn_packets(PCAP_FILE)