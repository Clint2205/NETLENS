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


def create_connection_key(
    source,
    destination,
    source_port,
    destination_port
):
    """
    Create a direction-independent TCP connection key.

    The two endpoints are sorted so that:

        A → B

    and:

        B → A

    produce the same key.
    """

    endpoint_a = (
        str(source),
        str(source_port)
    )

    endpoint_b = (
        str(destination),
        str(destination_port)
    )

    return tuple(
        sorted(
            [endpoint_a, endpoint_b]
        )
    )


def build_tcp_connections(pcap_file: Path) -> None:
    """Build bidirectional TCP connections from a packet capture."""

    print("=" * 120)
    print("NETLENS — BIDIRECTIONAL TCP CONNECTION BUILDER")
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

    connections = {}

    directional_flow_count = 0

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

            connection_key = create_connection_key(
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

            directional_key = (
                source,
                destination,
                source_port,
                destination_port
            )

            if connection_key not in connections:

                connections[connection_key] = {
                    "endpoint_a": connection_key[0],
                    "endpoint_b": connection_key[1],

                    "directions": {},

                    "start_time": timestamp,
                    "end_time": timestamp,

                    "total_packets": 0,
                    "total_bytes": 0,

                    "syn": 0,
                    "syn_ack": 0,
                    "ack": 0,
                }

            connection = connections[connection_key]

            # --------------------------------------------------------
            # Create directional record inside the connection
            # --------------------------------------------------------

            if directional_key not in connection["directions"]:

                connection["directions"][directional_key] = {
                    "source": source,
                    "destination": destination,
                    "source_port": source_port,
                    "destination_port": destination_port,

                    "packet_count": 0,
                    "total_bytes": 0,

                    "start_time": timestamp,
                    "end_time": timestamp,

                    "syn": 0,
                    "syn_ack": 0,
                    "ack": 0,
                }

                directional_flow_count += 1

            direction = connection["directions"][directional_key]

            # --------------------------------------------------------
            # Update directional statistics
            # --------------------------------------------------------

            direction["packet_count"] += 1

            direction["total_bytes"] += packet_length

            direction["end_time"] = timestamp

            if flags == "0x0002":
                direction["syn"] += 1
                connection["syn"] += 1

            elif flags == "0x0012":
                direction["syn_ack"] += 1
                connection["syn_ack"] += 1

            elif flags == "0x0010":
                direction["ack"] += 1
                connection["ack"] += 1

            # --------------------------------------------------------
            # Update connection-wide statistics
            # --------------------------------------------------------

            connection["total_packets"] += 1

            connection["total_bytes"] += packet_length

            if timestamp < connection["start_time"]:
                connection["start_time"] = timestamp

            if timestamp > connection["end_time"]:
                connection["end_time"] = timestamp

    finally:
        capture.close()

    # ------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------

    print()
    print("-" * 120)
    print(
        f"Directional flows processed: "
        f"{directional_flow_count}"
    )
    print(
        f"Bidirectional TCP connections: "
        f"{len(connections)}"
    )
    print("-" * 120)

    # ------------------------------------------------------------
    # Display connections
    # ------------------------------------------------------------

    print()

    for connection_number, connection in enumerate(
        connections.values(),
        start=1
    ):

        duration = (
            connection["end_time"]
            - connection["start_time"]
        )

        print(f"Connection #{connection_number}")

        print(
            f"  Endpoint A:       "
            f"{connection['endpoint_a'][0]}"
            f":"
            f"{connection['endpoint_a'][1]}"
        )

        print(
            f"  Endpoint B:       "
            f"{connection['endpoint_b'][0]}"
            f":"
            f"{connection['endpoint_b'][1]}"
        )

        print(
            f"  Start time:       "
            f"{connection['start_time']}"
        )

        print(
            f"  End time:         "
            f"{connection['end_time']}"
        )

        print(
            f"  Duration:         "
            f"{duration.total_seconds() * 1000:.3f} ms"
        )

        print(
            f"  Directions:       "
            f"{len(connection['directions'])}"
        )

        print(
            f"  Total packets:    "
            f"{connection['total_packets']}"
        )

        print(
            f"  Total bytes:      "
            f"{connection['total_bytes']}"
        )

        print(
            f"  SYN packets:      "
            f"{connection['syn']}"
        )

        print(
            f"  SYN/ACK packets:  "
            f"{connection['syn_ack']}"
        )

        print(
            f"  ACK packets:      "
            f"{connection['ack']}"
        )

        print()

        # --------------------------------------------------------
        # Display each direction
        # --------------------------------------------------------

        for direction_number, direction in enumerate(
            connection["directions"].values(),
            start=1
        ):

            print(
                f"  Direction #{direction_number}: "
                f"{direction['source']}"
                f":"
                f"{direction['source_port']}"
                f" → "
                f"{direction['destination']}"
                f":"
                f"{direction['destination_port']}"
            )

            print(
                f"    Packets:        "
                f"{direction['packet_count']}"
            )

            print(
                f"    Bytes:          "
                f"{direction['total_bytes']}"
            )

            print(
                f"    SYN:            "
                f"{direction['syn']}"
            )

            print(
                f"    SYN/ACK:        "
                f"{direction['syn_ack']}"
            )

            print(
                f"    ACK:            "
                f"{direction['ack']}"
            )

        print("-" * 120)
    return list(connections.values())


if __name__ == "__main__":
    build_tcp_connections(PCAP_FILE)