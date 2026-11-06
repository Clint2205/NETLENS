

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    PROJECT_ROOT
    / "outputs"
    / "features"
    / "tcp_anomaly_dataset.csv"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "outputs"
    / "features"
    / "tcp_anomaly_results.csv"
)

MODEL_FILE = (
    PROJECT_ROOT
    / "outputs"
    / "models"
    / "isolation_forest.joblib"
)


def main():
    print("=" * 72)
    print("NETLENS — INITIAL ISOLATION FOREST EXPERIMENT")
    print("=" * 72)

    if not INPUT_FILE.exists():
        print(f"ERROR: Input dataset not found: {INPUT_FILE}")
        return

    df = pd.read_csv(INPUT_FILE)

    # Build compact behavioural features.
    X = pd.DataFrame(index=df.index)

    X["log_duration"] = np.log1p(
        df["duration_seconds"].clip(lower=0)
    )

    X["log_total_packets"] = np.log1p(
        df["total_packets"].clip(lower=0)
    )

    X["log_total_bytes"] = np.log1p(
        df["total_bytes"].clip(lower=0)
    )

    X["direction_count"] = df["direction_count"]

    X["packet_imbalance"] = (
        df["direction_1_packet_ratio"]
        - df["direction_2_packet_ratio"]
    ).abs()

    X["byte_imbalance"] = (
        df["direction_1_byte_ratio"]
        - df["direction_2_byte_ratio"]
    ).abs()

    if X.isna().any().any():
        raise ValueError("Missing values found in model features.")

    if not np.isfinite(X.to_numpy()).all():
        raise ValueError("Infinite or invalid model features found.")

    print(f"\nConnections loaded: {len(df):,}")
    print(f"Model features: {len(X.columns)}")
    print("\nFeatures used:")
    for column in X.columns:
        print(f"- {column}")

    # Train an unsupervised anomaly detector.
    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )

    predictions = model.fit_predict(X)

    # Lower decision_function values indicate more unusual records.
    df["anomaly_score"] = -model.decision_function(X)
    df["anomaly_label"] = np.where(
        predictions == -1,
        "anomaly",
        "normal",
    )

    # Preserve the engineered values for later investigation.
    for column in X.columns:
        df[f"model_{column}"] = X[column]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)

    df.to_csv(OUTPUT_FILE, index=False)

    # Save the fitted model and feature names together.
    import joblib

    joblib.dump(
        {
            "model": model,
            "feature_names": list(X.columns),
        },
        MODEL_FILE,
    )

    anomaly_count = int((predictions == -1).sum())
    normal_count = int((predictions == 1).sum())

    print("\n" + "-" * 72)
    print("INITIAL MODEL RESULTS")
    print("-" * 72)
    print(f"Connections labelled unusual: {anomaly_count:,}")
    print(f"Connections labelled normal:  {normal_count:,}")
    print(f"Unusual percentage: {anomaly_count / len(df) * 100:.2f}%")

    print("\nAnomaly counts by capture:")
    print(
        df.groupby(
            ["capture_source", "anomaly_label"]
        ).size().to_string()
    )

    print("\nTop 15 most unusual connections:")
    columns_to_show = [
        "capture_source",
        "endpoint_a_ip",
        "endpoint_a_port",
        "endpoint_b_ip",
        "endpoint_b_port",
        "total_packets",
        "total_bytes",
        "duration_seconds",
        "anomaly_score",
        "anomaly_label",
    ]

    print(
        df.nlargest(15, "anomaly_score")[columns_to_show]
        .to_string(index=False)
    )

    print("\nResults CSV:")
    print(OUTPUT_FILE)

    print("\nSaved model:")
    print(MODEL_FILE)

    print("\nIMPORTANT:")
    print(
        "These are statistically unusual connections, "
        "not confirmed malicious activity."
    )
    print(
        "Review the results and capture differences before "
        "drawing security conclusions."
    )

    print("\nMODEL EXPERIMENT COMPLETE")
    print("=" * 72)


if __name__ == "__main__":
    main()
