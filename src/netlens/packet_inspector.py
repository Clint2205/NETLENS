from pathlib import Path
import pyshark


# ------------------------------------------------------------
# NetLens — Step 3
# Improved packet inspection
# ------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

PCAP_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "pcaps"
    / "first_capture.pcapng"
)


def shorten_address(address: str, max_length: int = 24) -> str:
    """Shorten a network address so the packet table remains readable."""

    if len(address) <= max_length:
        return address

    return address[:max_length - 3] + "..."


def inspect_packets(pcap_file: Path, limit: int = 20) -> None:
    """Display basic information about individual packets."""

    print("=" * 110)
    print("NETLENS — PACKET INSPECTION")
    print("=" * 110)

    print(f"Capture file: {pcap_file}")
    print(f"Showing first {limit} packets")
    print()

    if not pcap_file.exists():
        print("ERROR: Capture file not found.")
        return

    capture = pyshark.FileCapture(
        str(pcap_file),
        keep_packets=False
    )

    print(
        f"{'No.':<6}"
        f"{'Time':<16}"
        f"{'Source':<25}"
        f"{'Destination':<25}"
        f"{'Protocol':<12}"
        f"{'Length':<8}"
    )

    print("-" * 110)

    try:
        for packet_number, packet in enumerate(capture, start=1):

            if packet_number > limit:
                break

            # ------------------------------------------------
            # Timestamp
            # ------------------------------------------------

            timestamp = getattr(
                packet,
                "sniff_time",
                "UNKNOWN"
            )

            timestamp = str(timestamp)

            # Keep only HH:MM:SS.microseconds
            if " " in timestamp:
                timestamp = timestamp.split(" ", 1)[1]

            # ------------------------------------------------
            # Packet length
            # ------------------------------------------------

            length = getattr(
                packet,
                "length",
                "UNKNOWN"
            )

            # ------------------------------------------------
            # Network addresses
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

            source = shorten_address(str(source))
            destination = shorten_address(str(destination))

            # ------------------------------------------------
            # Protocol
            # ------------------------------------------------

            protocol = getattr(
                packet,
                "highest_layer",
                "UNKNOWN"
            )

            # ------------------------------------------------
            # Display
            # ------------------------------------------------

            print(
                f"{packet_number:<6}"
                f"{timestamp:<16}"
                f"{source:<25}"
                f"{destination:<25}"
                f"{protocol:<12}"
                f"{str(length):<8}"
            )

    finally:
        capture.close()

    print()
    print("=" * 110)


if __name__ == "__main__":
    inspect_packets(PCAP_FILE)