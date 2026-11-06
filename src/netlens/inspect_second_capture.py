
from pathlib import Path

from netlens.tcp_connection_builder import build_tcp_connections


PROJECT_ROOT = Path(__file__).resolve().parents[2]

PCAP_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "pcaps"
    / "second_capture.pcapng"
)


def main():
    print("=" * 70)
    print("NETLENS — SECOND CAPTURE INSPECTION")
    print("=" * 70)
    print(f"Capture: {PCAP_FILE}")
    print(f"File exists: {PCAP_FILE.exists()}")

    if not PCAP_FILE.exists():
        print("ERROR: Second capture was not found.")
        return

    print("\nProcessing TCP packets. This may take some time...")

    connections = build_tcp_connections(PCAP_FILE)

    if connections is None:
        print("\nThe connection builder did not return results.")
        return

    print("\n" + "=" * 70)
    print("SECOND CAPTURE SUMMARY")
    print("=" * 70)
    print(f"TCP connections: {len(connections):,}")

    total_packets = sum(
        connection["total_packets"]
        for connection in connections
    )

    total_bytes = sum(
        connection["total_bytes"]
        for connection in connections
    )

    print(f"TCP packets processed: {total_packets:,}")
    print(f"Total TCP bytes: {total_bytes:,}")
    print("Existing feature CSV has not been modified.")


if __name__ == "__main__":
    main()
