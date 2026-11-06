from pathlib import Path
import pyshark


# ------------------------------------------------------------
# NetLens — Step 6
# TCP SYN → SYN/ACK Detection
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


def detect_handshake_pairs(pcap_file: Path) -> None:
    """Find SYN packets and their corresponding SYN/ACK packets."""

    print("=" * 120)
    print("NETLENS — TCP HANDSHAKE DETECTION")
    print("=" * 120)

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

    syn_packets = {}

    handshake_count = 0

    try:

        for packet in capture:

            source, destination = get_addresses(packet)

            tcp = packet.tcp

            source_port = getattr(
                tcp,
                "srcport",
                None
            )

            destination_port = getattr(
                tcp,
                "dstport",
                None
            )

            flags = getattr(
                tcp,
                "flags",
                ""
            )

            # ------------------------------------------------
            # SYN
            #
            # 0x0002 = SYN
            # ------------------------------------------------

            if flags == "0x0002":

                connection_key = (
                    source,
                    destination,
                    source_port,
                    destination_port
                )

                syn_packets[connection_key] = {
                    "packet_number": packet.number,
                    "timestamp": packet.sniff_time
                }

            # ------------------------------------------------
            # SYN + ACK
            #
            # 0x0012 = SYN + ACK
            # ------------------------------------------------

            elif flags == "0x0012":

                connection_key = (
                    destination,
                    source,
                    destination_port,
                    source_port
                )

                if connection_key in syn_packets:

                    syn = syn_packets[connection_key]

                    delay = (
                        packet.sniff_time
                        - syn["timestamp"]
                    )

                    handshake_count += 1

                    print(
                        f"Handshake #{handshake_count}"
                    )

                    print(
                        f"  SYN packet:     "
                        f"{syn['packet_number']}"
                    )

                    print(
                        f"  SYN/ACK packet: "
                        f"{packet.number}"
                    )

                    print(
                        f"  Connection:     "
                        f"{source}:{source_port}"
                        f" → "
                        f"{destination}:{destination_port}"
                    )

                    print(
                        f"  SYN → SYN/ACK:  "
                        f"{delay.total_seconds() * 1000:.3f} ms"
                    )

                    print("-" * 120)

    finally:
        capture.close()

    print()
    print("=" * 120)
    print(
        f"SYN → SYN/ACK pairs found: "
        f"{handshake_count}"
    )
    print("=" * 120)


if __name__ == "__main__":
    detect_handshake_pairs(PCAP_FILE)