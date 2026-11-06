
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

RESULTS_FILE = (
    PROJECT_ROOT
    / "outputs"
    / "features"
    / "tcp_anomaly_results.csv"
)


def main():
    print("=" * 72)
    print("NETLENS — ANOMALY RESULTS AUDIT")
    print("=" * 72)

    if not RESULTS_FILE.exists():
        print(f"ERROR: Results file not found: {RESULTS_FILE}")
        return

    df = pd.read_csv(RESULTS_FILE)

    df["zero_duration"] = df["duration_seconds"] == 0
    df["single_packet"] = df["total_packets"] == 1

    print("\n1. OVERALL COUNTS")
    print(f"Total connections: {len(df):,}")
    print(
        "Flagged as anomalies: "
        f"{(df['anomaly_label'] == 'anomaly').sum():,}"
    )

    print("\n2. ANOMALIES BY CAPTURE")
    print(
        pd.crosstab(
            df["capture_source"],
            df["anomaly_label"],
            margins=True,
        ).to_string()
    )

    print("\n3. ZERO-DURATION CONNECTIONS")
    print(
        pd.crosstab(
            df["zero_duration"],
            df["anomaly_label"],
            margins=True,
        ).to_string()
    )

    print("\n4. SINGLE-PACKET CONNECTIONS")
    print(
        pd.crosstab(
            df["single_packet"],
            df["anomaly_label"],
            margins=True,
        ).to_string()
    )

    print("\n5. FEATURE SUMMARY BY MODEL LABEL")
    summary = df.groupby("anomaly_label").agg(
        connections=("anomaly_label", "size"),
        zero_duration_count=("zero_duration", "sum"),
        single_packet_count=("single_packet", "sum"),
        median_duration=("duration_seconds", "median"),
        median_packets=("total_packets", "median"),
        median_bytes=("total_bytes", "median"),
        median_score=("anomaly_score", "median"),
    )

    print(summary.round(3).to_string())

    print("\n6. FLAGGED CONNECTIONS THAT ARE NOT ZERO-DURATION")
    flagged_nonzero = df[
        (df["anomaly_label"] == "anomaly")
        & (~df["zero_duration"])
    ].sort_values("anomaly_score", ascending=False)

    print(f"Count: {len(flagged_nonzero):,}")

    columns = [
        "capture_source",
        "endpoint_a_ip",
        "endpoint_a_port",
        "endpoint_b_ip",
        "endpoint_b_port",
        "total_packets",
        "total_bytes",
        "duration_seconds",
        "anomaly_score",
    ]

    if flagged_nonzero.empty:
        print("No non-zero-duration anomalies found.")
    else:
        print(flagged_nonzero[columns].head(20).to_string(index=False))

    print("\n7. ANOMALY PERCENTAGE WITHIN EACH CAPTURE")
    capture_summary = df.groupby("capture_source").agg(
        total_connections=("anomaly_label", "size"),
        flagged=("anomaly_label", lambda s: (s == "anomaly").sum()),
    )

    capture_summary["flagged_percentage"] = (
        capture_summary["flagged"]
        / capture_summary["total_connections"]
        * 100
    )

    print(capture_summary.round(2).to_string())

    print("\n" + "=" * 72)
    print("AUDIT COMPLETE — original datasets were not modified.")
    print("=" * 72)


if __name__ == "__main__":
    main()
