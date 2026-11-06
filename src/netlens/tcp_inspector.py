from pathlib import Path
import pyshark


# ------------------------------------------------------------
# NetLens — Step 4
# TCP packet inspection
# ------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

PCAP_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "pcaps"
    / "first_capture.pcapng"
)


def inspect_tcp_packets(pcap_file: Path, limit: int = 30) -> None:
    """Display TCP packets and their flags."""

    print("=" * 110)
    print("NETLENS — TCP PACKET INSPECTION")
    print("=" * 110)

    print(f"Capture file: {pcap_file}")
    print()

    if not pcap_file.exists():
        print("ERROR: Capture file not found.")
        return

    capture = pyshark.FileCapture(
        str(pcap_file),
        display_filter="tcp",
        keep_packets=False
    )

    print(
        f"{'No.':<7}"
        f"{'Time':<16}"
        f"{'Source':<25}"
        f"{'Destination':<25}"
        f"{'Src Port':<10}"
        f"{'Dst Port':<10}"
        f"{'Flags':<15}"
    )

    print("-" * 110)

    tcp_count = 0

    try:

        for packet in capture:

            tcp_count += 1

            if tcp_count > limit:
                break

            # ------------------------------------------------
            # IP addresses
            # ------------------------------------------------

            source = "UNKNOWN"
            destination = "UNKNOWN"

            if hasattr(packet, "ip"):

                source = getattr(
                    packet.ip,
                    "src",
                    "UNKNOWN"
                )

                destination = getattr(
                    packet.ip,
                    "dst",
                    "UNKNOWN"
                )

            elif hasattr(packet, "ipv6"):

                source = getattr(
                    packet.ipv6,
                    "src",
                    "UNKNOWN"
                )

                destination = getattr(
                    packet.ipv6,
                    "dst",
                    "UNKNOWN"
                )

            # ------------------------------------------------
            # TCP information
            # ------------------------------------------------

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

            # ------------------------------------------------
            # Timestamp
            # ------------------------------------------------

            timestamp = str(
                getattr(
                    packet,
                    "sniff_time",
                    "UNKNOWN"
                )
            )

            if " " in timestamp:
                timestamp = timestamp.split(" ", 1)[1]

            # ------------------------------------------------
            # Display
            # ------------------------------------------------

            print(
                f"{tcp_count:<7}"
                f"{timestamp:<16}"
                f"{str(source):<25}"
                f"{str(destination):<25}"
                f"{str(source_port):<10}"
                f"{str(destination_port):<10}"
                f"{str(flags):<15}"
            )

    finally:
        capture.close()

    print()
    print("-" * 110)
    print(f"TCP packets inspected: {min(tcp_count, limit)}")
    print("-" * 110)
    print("=" * 110)


if __name__ == "__main__":
    inspect_tcp_packets(PCAP_FILE)