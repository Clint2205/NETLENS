
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

ORIGINAL_FILE = (
    PROJECT_ROOT / "outputs" / "features"
    / "tcp_connection_features.csv"
)

SECOND_FILE = (
    PROJECT_ROOT / "outputs" / "features"
    / "tcp_connection_features_second_capture.csv"
)

OUTPUT_FILE = (
    PROJECT_ROOT / "outputs" / "features"
    / "tcp_anomaly_dataset.csv"
)

MODEL_FEATURES = [
    "duration_seconds",
    "total_packets",
    "total_bytes",
    "direction_count",
    "direction_1_packets",
    "direction_2_packets",
    "direction_1_bytes",
    "direction_2_bytes",
    "packets_per_second",
    "bytes_per_second",
    "direction_1_packet_ratio",
    "direction_2_packet_ratio",
    "direction_1_byte_ratio",
    "direction_2_byte_ratio",
]


def main():
    print("=" * 70)
    print("NETLENS — PREPARE ANOMALY DETECTION DATASET")
    print("=" * 70)

    if not ORIGINAL_FILE.exists() or not SECOND_FILE.exists():
        print("ERROR: One or both source CSVs are missing.")
        return

    original = pd.read_csv(ORIGINAL_FILE)
    second = pd.read_csv(SECOND_FILE)

    if set(original.columns) != set(second.columns):
        print("ERROR: The source CSV schemas differ.")
        return

    original["capture_source"] = "first_capture"
    second["capture_source"] = "second_capture"

    combined = pd.concat(
        [original, second],
        ignore_index=True,
    )

    missing_features = [
        column for column in MODEL_FEATURES
        if column not in combined.columns
    ]

    if missing_features:
        print(f"ERROR: Missing model features: {missing_features}")
        return

    numeric_features = combined[MODEL_FEATURES].apply(
        pd.to_numeric,
        errors="coerce",
    )

    if numeric_features.isna().any().any():
        print("ERROR: Missing or non-numeric model feature values found.")
        print(numeric_features.isna().sum().to_string())
        return

    if not numeric_features.map(
        lambda column: column
    ).equals(numeric_features):
        print("NOTE: Feature validation continuing.")

    if (numeric_features < 0).any().any():
        negative_counts = (numeric_features < 0).sum()
        print("ERROR: Negative values found in features:")
        print(negative_counts[negative_counts > 0].to_string())
        return

    combined[MODEL_FEATURES] = numeric_features

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(OUTPUT_FILE, index=False)

    print("\nDATASET PREPARED")
    print(f"Rows: {len(combined):,}")
    print(f"Columns: {len(combined.columns)}")
    print(f"Model features: {len(MODEL_FEATURES)}")
    print(f"First capture rows: {(combined['capture_source'] == 'first_capture').sum():,}")
    print(f"Second capture rows: {(combined['capture_source'] == 'second_capture').sum():,}")
    print(f"Output: {OUTPUT_FILE}")
    print("\nSource CSV files were not modified.")


if __name__ == "__main__":
    main()
