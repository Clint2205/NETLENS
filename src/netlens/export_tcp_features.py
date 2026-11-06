
"""
NETLENS - Export TCP Connection Features to CSV

Reads the PCAP, builds bidirectional TCP connections,
extracts features, and saves them to a CSV file.
"""

import csv
from pathlib import Path

from netlens.tcp_connection_builder import (
    build_tcp_connections,
    PCAP_FILE,
)
from netlens.tcp_features import calculate_features


# Project and output paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]

OUTPUT_FILE = (
    PROJECT_ROOT
    / "outputs"
    / "features"
    / "tcp_connection_features.csv"
)


def main():
    print("=" * 65)
    print("NETLENS — TCP FEATURE EXPORT")
    print("=" * 65)

    # Build connections from the PCAP
    connections = build_tcp_connections(PCAP_FILE)

    if not connections:
        print("No TCP connections found. Export cancelled.")
        return

    # Extract connection-level features
    features = calculate_features(connections)

    # Create the output directory if it does not exist
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Flatten endpoint tuples into separate CSV columns
    rows = []

    for feature in features:
        row = feature.copy()

        endpoint_a = row.pop("endpoint_a", None)
        endpoint_b = row.pop("endpoint_b", None)

        row["endpoint_a_ip"] = endpoint_a[0] if endpoint_a else ""
        row["endpoint_a_port"] = endpoint_a[1] if endpoint_a else ""
        row["endpoint_b_ip"] = endpoint_b[0] if endpoint_b else ""
        row["endpoint_b_port"] = endpoint_b[1] if endpoint_b else ""

        # Store timestamps in a readable format
        for column in ("start_time", "end_time"):
            value = row.get(column)
            if value is not None:
                row[column] = value.isoformat()

        rows.append(row)

    # Write the CSV
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
    print(f"Connections exported: {len(rows)}")
    print(f"Features per connection: {len(fieldnames)}")
    print(f"Output file: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
