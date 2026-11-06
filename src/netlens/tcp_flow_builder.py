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


def build_tcp_flows(pcap_file: Path) -> None:
    """Build logical TCP flows from packets."""

    print("=" * 120)
    print("NETLENS — TCP FLOW BUILDER")
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

    flows = {}

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

            flow_key = (
                source,
                destination,
                source_port,
                destination_port
            )

            timestamp = packet.sniff_time

            packet_length = int(
                getattr(
                    packet,
                    "length",
                    0
                )
            )

            flags = getattr(
                tcp,
                "flags",
                ""
            )

            if flow_key not in flows:

                flows[flow_key] = {
                    "source": source,
                    "destination": destination,
                    "source_port": source_port,
                    "destination_port": destination_port,
                    "start_time": timestamp,
                    "end_time": timestamp,
                    "packet_count": 0,
                    "total_bytes": 0,
                    "syn": 0,
                    "syn_ack": 0,
                    "ack": 0,
                }

            flow = flows[flow_key]

            flow["end_time"] = timestamp

            flow["packet_count"] += 1

            flow["total_bytes"] += packet_length

            if flags == "0x0002":
                flow["syn"] += 1

            elif flags == "0x0012":
                flow["syn_ack"] += 1

            elif flags == "0x0010":
                flow["ack"] += 1

    finally:
        capture.close()

    print()
    print("-" * 120)
    print(f"TCP flows found: {len(flows)}")
    print("-" * 120)
    print()

    for flow_number, flow in enumerate(
        flows.values(),
        start=1
    ):

        duration = (
            flow["end_time"]
            - flow["start_time"]
        )

        print(f"Flow #{flow_number}")

        print(
            f"  Connection:     "
            f"{flow['source']}:{flow['source_port']}"
            f" → "
            f"{flow['destination']}:{flow['destination_port']}"
        )

        print(
            f"  Start time:     "
            f"{flow['start_time']}"
        )

        print(
            f"  End time:       "
            f"{flow['end_time']}"
        )

        print(
            f"  Duration:       "
            f"{duration.total_seconds() * 1000:.3f} ms"
        )

        print(
            f"  Packets:        "
            f"{flow['packet_count']}"
        )

        print(
            f"  Total bytes:    "
            f"{flow['total_bytes']}"
        )

        print(
            f"  SYN packets:    "
            f"{flow['syn']}"
        )

        print(
            f"  SYN/ACK packets:"
            f" {flow['syn_ack']}"
        )

        print(
            f"  ACK packets:    "
            f"{flow['ack']}"
        )

        print("-" * 120)


if __name__ == "__main__":
    build_tcp_flows(PCAP_FILE)