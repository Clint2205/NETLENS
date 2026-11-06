from pathlib import Path
import pyshark


# ------------------------------------------------------------
# NetLens â€” Step 1
# Inspect a Wireshark capture
# ------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

PCAP_FILE = PROJECT_ROOT / "data" / "raw" / "pcaps" / "first_capture.pcapng"


def inspect_capture(pcap_file: Path) -> None:
    """Read a PCAP/PCAPNG file and print basic packet information."""

    print("=" * 70)
    print("NETLENS â€” PCAP INSPECTION")
    print("=" * 70)

    print(f"Capture file: {pcap_file}")
    print()

    if not pcap_file.exists():
        print("ERROR: Capture file not found.")
        return

    print("Loading capture...")

    capture = pyshark.FileCapture(
        str(pcap_file),
        keep_packets=False
    )

    packet_count = 0
    protocols = {}

    for packet in capture:
        packet_count += 1

        protocol = getattr(packet, "highest_layer", "UNKNOWN")

        protocols[protocol] = protocols.get(protocol, 0) + 1

    capture.close()

    print()
    print("-" * 70)
    print(f"Total packets: {packet_count}")
    print("-" * 70)

    print()
    print("Protocols:")

    for protocol, count in sorted(
        protocols.items(),
        key=lambda item: item[1],
        reverse=True
    ):
        print(f"{protocol:<15} {count}")

    print()
    print("=" * 70)


if __name__ == "__main__":
    inspect_capture(PCAP_FILE)
