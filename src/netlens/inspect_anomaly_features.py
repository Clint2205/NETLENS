
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_FILE = (
    PROJECT_ROOT
    / "outputs"
    / "features"
    / "tcp_anomaly_dataset.csv"
)

FEATURES = [
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
    print("=" * 72)
    print("NETLENS — ANOMALY FEATURE INSPECTION")
    print("=" * 72)

    if not DATA_FILE.exists():
        print(f"ERROR: Dataset not found: {DATA_FILE}")
        return

    df = pd.read_csv(DATA_FILE)

    print("\n1. DATASET")
    print(f"Rows: {len(df):,}")
    print(f"Model features: {len(FEATURES)}")
    print("\nRows by capture:")
    print(df["capture_source"].value_counts().to_string())

    X = df[FEATURES].apply(pd.to_numeric, errors="coerce")

    print("\n2. INVALID NUMERIC VALUES")
    print("Missing values per feature:")
    print(X.isna().sum().to_string())

    infinite_counts = pd.Series(
        np.isinf(X.to_numpy()).sum(axis=0),
        index=X.columns,
    )
    print("\nInfinite values per feature:")
    print(infinite_counts.to_string())

    print("\n3. ZERO-DURATION CONNECTIONS")
    zero_duration = X["duration_seconds"] == 0

    print(f"Zero-duration connections: {zero_duration.sum():,}")
    print(
        "Zero-duration percentage: "
        f"{zero_duration.mean() * 100:.2f}%"
    )

    print("\n4. FEATURE DISTRIBUTIONS")
    print(
        X.describe(
            percentiles=[0.50, 0.90, 0.95, 0.99]
        ).round(3).to_string()
    )

    print("\n5. DIRECTIONAL RATIO CHECKS")
    packet_ratio_sum = (
        X["direction_1_packet_ratio"]
        + X["direction_2_packet_ratio"]
    )

    byte_ratio_sum = (
        X["direction_1_byte_ratio"]
        + X["direction_2_byte_ratio"]
    )

    print(
        "Packet ratio sums outside tolerance:",
        int(
            (~np.isclose(packet_ratio_sum, 1.0, atol=0.001)).sum()
        ),
    )

    print(
        "Byte ratio sums outside tolerance:",
        int(
            (~np.isclose(byte_ratio_sum, 1.0, atol=0.001)).sum()
        ),
    )

    print("\n6. MOST CORRELATED FEATURE PAIRS")
    correlation = X.corr().abs()

    upper = correlation.where(
        np.triu(
            np.ones(correlation.shape),
            k=1,
        ).astype(bool)
    )

    pairs = upper.stack().sort_values(ascending=False)

    if pairs.empty:
        print("No feature pairs available.")
    else:
        for (first, second), value in pairs.head(12).items():
            print(f"{first} vs {second}: {value:.3f}")

    print("\n7. ZERO-DURATION RATE VALUES")

    if zero_duration.any():
        print(
            X.loc[
                zero_duration,
                [
                    "total_packets",
                    "total_bytes",
                    "packets_per_second",
                    "bytes_per_second",
                ],
            ].describe().round(3).to_string()
        )
    else:
        print("No zero-duration connections.")

    print("\n" + "=" * 72)
    print("INSPECTION COMPLETE — source CSV was not modified.")
    print("=" * 72)


if __name__ == "__main__":
    main()
