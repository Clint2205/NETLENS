
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_FILE = (
    PROJECT_ROOT
    / "outputs"
    / "features"
    / "tcp_connection_features_second_capture.csv"
)


def main():
    print("=" * 70)
    print("NETLENS — SECOND CAPTURE DATASET AUDIT")
    print("=" * 70)

    if not DATA_FILE.exists():
        print(f"ERROR: Dataset not found: {DATA_FILE}")
        return

    df = pd.read_csv(DATA_FILE)

    print("\n1. DATASET SIZE")
    print(f"Rows: {df.shape[0]:,}")
    print(f"Columns: {df.shape[1]}")

    print("\n2. COLUMN NAMES AND TYPES")
    print(df.dtypes.to_string())

    print("\n3. MISSING VALUES")
    missing = df.isna().sum()
    missing = missing[missing > 0]

    if missing.empty:
        print("No missing values detected.")
    else:
        print(missing.to_string())

    print("\n4. DUPLICATE ROWS")
    print(f"Exact duplicate rows: {df.duplicated().sum():,}")

    print("\n5. DUPLICATE ENDPOINT PAIRS")
    endpoint_columns = [
        "endpoint_a_ip",
        "endpoint_a_port",
        "endpoint_b_ip",
        "endpoint_b_port",
    ]

    if all(column in df.columns for column in endpoint_columns):
        print(
            "Repeated endpoint-pair rows:",
            int(df.duplicated(subset=endpoint_columns).sum()),
        )

    print("\n6. BASIC NUMERIC CHECKS")
    checks = {
        "Non-positive packet counts": (df["total_packets"] <= 0).sum(),
        "Negative byte counts": (df["total_bytes"] < 0).sum(),
        "Negative durations": (df["duration_seconds"] < 0).sum(),
        "Negative packet rates": (df["packets_per_second"] < 0).sum(),
        "Negative byte rates": (df["bytes_per_second"] < 0).sum(),
    }

    for description, count in checks.items():
        print(f"{description}: {int(count):,}")

    print("\n7. PACKET/BYTE RATE CONSISTENCY")
    positive_duration = df["duration_seconds"] > 0

    if positive_duration.any():
        expected_packet_rate = (
            df.loc[positive_duration, "total_packets"]
            / df.loc[positive_duration, "duration_seconds"]
        )
        packet_rate_errors = (
            expected_packet_rate
            - df.loc[positive_duration, "packets_per_second"]
        ).abs() > 0.01

        print(
            "Packet-rate mismatches:",
            int(packet_rate_errors.sum()),
        )

        expected_byte_rate = (
            df.loc[positive_duration, "total_bytes"]
            / df.loc[positive_duration, "duration_seconds"]
        )
        byte_rate_errors = (
            expected_byte_rate
            - df.loc[positive_duration, "bytes_per_second"]
        ).abs() > 0.01

        print(
            "Byte-rate mismatches:",
            int(byte_rate_errors.sum()),
        )
    else:
        print("No positive-duration connections available for rate checks.")

    print("\n8. CONNECTION DURATION")
    print(df["duration_seconds"].describe().round(3).to_string())

    print("\n9. CAPTURE TIME RANGE")
    start = pd.to_datetime(df["start_time"], errors="coerce")
    end = pd.to_datetime(df["end_time"], errors="coerce")

    print(f"Earliest connection: {start.min()}")
    print(f"Latest connection:   {end.max()}")
    print(f"Unparseable start times: {int(start.isna().sum())}")
    print(f"Unparseable end times:   {int(end.isna().sum())}")

    print("\n" + "=" * 70)
    print("AUDIT COMPLETE — CSV was not modified.")
    print("=" * 70)


if __name__ == "__main__":
    main()
