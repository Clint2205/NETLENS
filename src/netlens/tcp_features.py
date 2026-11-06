"""
NETLENS - TCP Connection Feature Extraction

Step 10:
Convert bidirectional TCP connections into useful
connection-level network features.
"""


def calculate_connection_features(connection):
    """
    Calculate higher-level features for one bidirectional
    TCP connection produced by tcp_connection_builder.py.
    """

    # ------------------------------------------------------------
    # Connection-level statistics
    # ------------------------------------------------------------

    start_time = connection.get("start_time")
    end_time = connection.get("end_time")

    total_packets = connection.get("total_packets", 0) or 0
    total_bytes = connection.get("total_bytes", 0) or 0

    # Calculate duration directly from the timestamps.
    if start_time is not None and end_time is not None:
        duration_seconds = (
            end_time - start_time
        ).total_seconds()
    else:
        duration_seconds = 0

    duration_ms = duration_seconds * 1000

    # ------------------------------------------------------------
    # Directional statistics
    # ------------------------------------------------------------

    directions = connection.get("directions", {})

    direction_values = list(
        directions.values()
    )

    # Direction 1
    if len(direction_values) >= 1:

        direction_1 = direction_values[0]

        direction_1_packets = (
            direction_1.get("packet_count", 0) or 0
        )

        direction_1_bytes = (
            direction_1.get("total_bytes", 0) or 0
        )

    else:

        direction_1_packets = 0
        direction_1_bytes = 0

    # Direction 2
    if len(direction_values) >= 2:

        direction_2 = direction_values[1]

        direction_2_packets = (
            direction_2.get("packet_count", 0) or 0
        )

        direction_2_bytes = (
            direction_2.get("total_bytes", 0) or 0
        )

    else:

        direction_2_packets = 0
        direction_2_bytes = 0

    # ------------------------------------------------------------
    # Rate features
    # ------------------------------------------------------------

    if duration_seconds > 0:

        packets_per_second = (
            total_packets / duration_seconds
        )

        bytes_per_second = (
            total_bytes / duration_seconds
        )

    else:

        packets_per_second = 0
        bytes_per_second = 0

    # ------------------------------------------------------------
    # Packet ratios
    # ------------------------------------------------------------

    if total_packets > 0:

        direction_1_packet_ratio = (
            direction_1_packets / total_packets
        )

        direction_2_packet_ratio = (
            direction_2_packets / total_packets
        )

    else:

        direction_1_packet_ratio = 0
        direction_2_packet_ratio = 0

    # ------------------------------------------------------------
    # Byte ratios
    # ------------------------------------------------------------

    if total_bytes > 0:

        direction_1_byte_ratio = (
            direction_1_bytes / total_bytes
        )

        direction_2_byte_ratio = (
            direction_2_bytes / total_bytes
        )

    else:

        direction_1_byte_ratio = 0
        direction_2_byte_ratio = 0

    # ------------------------------------------------------------
    # Return feature record
    # ------------------------------------------------------------

    return {

        "endpoint_a": connection.get(
            "endpoint_a"
        ),

        "endpoint_b": connection.get(
            "endpoint_b"
        ),

        "start_time": start_time,

        "end_time": end_time,

        "duration_ms": duration_ms,

        "duration_seconds": duration_seconds,

        "total_packets": total_packets,

        "total_bytes": total_bytes,

        "direction_count": len(
            direction_values
        ),

        "direction_1_packets": direction_1_packets,

        "direction_2_packets": direction_2_packets,

        "direction_1_bytes": direction_1_bytes,

        "direction_2_bytes": direction_2_bytes,

        "packets_per_second": packets_per_second,

        "bytes_per_second": bytes_per_second,

        "direction_1_packet_ratio": (
            direction_1_packet_ratio
        ),

        "direction_2_packet_ratio": (
            direction_2_packet_ratio
        ),

        "direction_1_byte_ratio": (
            direction_1_byte_ratio
        ),

        "direction_2_byte_ratio": (
            direction_2_byte_ratio
        ),
    }


def calculate_features(connections):
    """
    Calculate connection-level features for multiple
    bidirectional TCP connections.
    """

    return [
        calculate_connection_features(connection)
        for connection in connections
    ]