
"""
NETLENS - Export Second Capture TCP Features to CSV

Processes second_capture.pcapng and writes a separate CSV.
The original feature dataset is not modified.
"""

import csv
from pathlib import Path

from netlens.tcp_connection_builder import build_tcp_connections
from netlens.tcp_features import calculate_features


PROJECT_ROOT = Path(__file__).resolve().parents[2]

PCAP_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "pcaps"
    / "second_capture.pcapng"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "outputs"
    / "features"
    / "tcp_connection_features_second_capture.csv"
)


def main():
    print("=" * 65)
    print("NETLENS - SECOND CAPTURE FEATURE EXPORT")
    print("=" * 65)
    print(f"Input:  {PCAP_FILE}")
    print(f"Output: {OUTPUT_FILE}")

    if not PCAP_FILE.exists():
        print("ERROR: Second capture file not found.")
        return

    connections = build_tcp_connections(PCAP_FILE)

    if not connections:
        print("No TCP connections found. Export cancelled.")
        return

    features = calculate_features(connections)

    rows = []

    for feature in features:
        row = feature.copy()

        endpoint_a = row.pop("endpoint_a", None)
        endpoint_b = row.pop("endpoint_b", None)

        row["endpoint_a_ip"] = endpoint_a[0] if endpoint_a else ""
        row["endpoint_a_port"] = endpoint_a[1] if endpoint_a else ""
        row["endpoint_b_ip"] = endpoint_b[0] if endpoint_b else ""
        row["endpoint_b_port"] = endpoint_b[1] if endpoint_b else ""

        for column in ("start_time", "end_time"):
            value = row.get(column)
            if value is not None:
                row[column] = value.isoformat()

        rows.append(row)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = list(rows[0].keys())

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(rows)

    print("\nEXPORT COMPLETE")
    print(f"Connections exported: {len(rows):,}")
    print(f"Columns: {len(fieldnames)}")
    print(f"Output file: {OUTPUT_FILE}")
    print("\nOriginal feature CSV was not modified.")


if __name__ == "__main__":
    main()
