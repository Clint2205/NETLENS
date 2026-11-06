from pathlib import Path
import pyshark

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


def detect_complete_handshakes(pcap_file: Path) -> None:
    """Detect complete TCP three-way handshakes."""

    print("=" * 120)
    print("NETLENS — COMPLETE TCP HANDSHAKE DETECTION")
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
    synack_packets = {}

    complete_handshakes = 0

    try:

        for packet in capture:

            source, destination = get_addresses(packet)

            tcp = packet.tcp

            source_port = getattr(tcp, "srcport", None)
            destination_port = getattr(tcp, "dstport", None)

            flags = getattr(tcp, "flags", "")

            sequence_number = getattr(
                tcp,
                "seq",
                None
            )

            acknowledgement_number = getattr(
                tcp,
                "ack",
                None
            )

            # --------------------------------------------------
            # STEP 1 — Store SYN packets
            # --------------------------------------------------

            if flags == "0x0002":

                connection_key = (
                    source,
                    destination,
                    source_port,
                    destination_port
                )

                syn_packets[connection_key] = {
                    "packet_number": packet.number,
                    "timestamp": packet.sniff_time,
                    "sequence": sequence_number
                }

            # --------------------------------------------------
            # STEP 2 — Store SYN/ACK packets
            # --------------------------------------------------

            elif flags == "0x0012":

                connection_key = (
                    destination,
                    source,
                    destination_port,
                    source_port
                )

                if connection_key in syn_packets:

                    syn = syn_packets[connection_key]

                    synack_packets[connection_key] = {
                        "packet_number": packet.number,
                        "timestamp": packet.sniff_time,
                        "sequence": sequence_number,
                        "acknowledgement": acknowledgement_number,
                        "syn": syn
                    }

            # --------------------------------------------------
            # STEP 3 — Look for final ACK
            # --------------------------------------------------

            elif flags == "0x0010":

                connection_key = (
                    source,
                    destination,
                    source_port,
                    destination_port
                )

                if connection_key in synack_packets:

                    synack = synack_packets[connection_key]

                    complete_handshakes += 1

                    syn = synack["syn"]

                    syn_to_synack = (
                        synack["timestamp"]
                        - syn["timestamp"]
                    )

                    synack_to_ack = (
                        packet.sniff_time
                        - synack["timestamp"]
                    )

                    total_handshake_time = (
                        packet.sniff_time
                        - syn["timestamp"]
                    )

                    print(
                        f"Handshake #{complete_handshakes}"
                    )

                    print(
                        f"  SYN packet:        "
                        f"{syn['packet_number']}"
                    )

                    print(
                        f"  SYN/ACK packet:    "
                        f"{synack['packet_number']}"
                    )

                    print(
                        f"  Final ACK packet:  "
                        f"{packet.number}"
                    )

                    print(
                        f"  Connection:        "
                        f"{source}:{source_port}"
                        f" → "
                        f"{destination}:{destination_port}"
                    )

                    print(
                        f"  SYN → SYN/ACK:     "
                        f"{syn_to_synack.total_seconds() * 1000:.3f} ms"
                    )

                    print(
                        f"  SYN/ACK → ACK:     "
                        f"{synack_to_ack.total_seconds() * 1000:.3f} ms"
                    )

                    print(
                        f"  Total handshake:   "
                        f"{total_handshake_time.total_seconds() * 1000:.3f} ms"
                    )

                    print(
                        f"  SYN sequence:      "
                        f"{syn['sequence']}"
                    )

                    print(
                        f"  SYN/ACK ACK:       "
                        f"{synack['acknowledgement']}"
                    )

                    print("-" * 120)

                    # Remove completed handshake so that
                    # later ACK packets are not counted again.
                    del synack_packets[connection_key]

    finally:
        capture.close()

    print()
    print("=" * 120)
    print(
        f"Complete TCP handshakes found: "
        f"{complete_handshakes}"
    )
    print("=" * 120)


if __name__ == "__main__":
    detect_complete_handshakes(PCAP_FILE)