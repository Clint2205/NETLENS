
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

ORIGINAL_FILE = (
    PROJECT_ROOT
    / "outputs"
    / "features"
    / "tcp_connection_features.csv"
)

SECOND_FILE = (
    PROJECT_ROOT
    / "outputs"
    / "features"
    / "tcp_connection_features_second_capture.csv"
)

ENDPOINT_COLUMNS = [
    "endpoint_a_ip",
    "endpoint_a_port",
    "endpoint_b_ip",
    "endpoint_b_port",
]


def main():
    print("=" * 70)
    print("NETLENS — TCP DATASET COMPARISON")
    print("=" * 70)

    if not ORIGINAL_FILE.exists() or not SECOND_FILE.exists():
        print("ERROR: One or both feature CSV files are missing.")
        print(f"Original: {ORIGINAL_FILE.exists()}")
        print(f"Second:   {SECOND_FILE.exists()}")
        return

    original = pd.read_csv(ORIGINAL_FILE)
    second = pd.read_csv(SECOND_FILE)

    print("\n1. DATASET SIZES")
    print(f"Original capture connections: {len(original):,}")
    print(f"Second capture connections:   {len(second):,}")
    print(f"Combined row count:           {len(original) + len(second):,}")

    print("\n2. COLUMN SCHEMA")
    original_columns = set(original.columns)
    second_columns = set(second.columns)

    print(f"Same columns: {original_columns == second_columns}")
    print(f"Only in original: {sorted(original_columns - second_columns)}")
    print(f"Only in second:   {sorted(second_columns - original_columns)}")

    if not all(column in original.columns for column in ENDPOINT_COLUMNS):
        print("\nERROR: Endpoint columns are missing from the original dataset.")
        return

    if not all(column in second.columns for column in ENDPOINT_COLUMNS):
        print("\nERROR: Endpoint columns are missing from the second dataset.")
        return

    print("\n3. ENDPOINT-PAIR OVERLAP")

    original_pairs = set(
        map(
            tuple,
            original[ENDPOINT_COLUMNS].astype(str).to_numpy(),
        )
    )

    second_pairs = set(
        map(
            tuple,
            second[ENDPOINT_COLUMNS].astype(str).to_numpy(),
        )
    )

    overlap = original_pairs & second_pairs

    print(f"Unique endpoint pairs in original: {len(original_pairs):,}")
    print(f"Unique endpoint pairs in second:   {len(second_pairs):,}")
    print(f"Endpoint pairs present in both:    {len(overlap):,}")

    print("\n4. NUMERIC FEATURE COMPATIBILITY")

    original_numeric = set(
        original.select_dtypes(include="number").columns
    )
    second_numeric = set(
        second.select_dtypes(include="number").columns
    )

    print(
        "Same numeric columns:",
        original_numeric == second_numeric,
    )
    print(
        "Numeric columns in both:",
        sorted(original_numeric & second_numeric),
    )

    print("\n5. DATASET TIMESPANS")

    for label, df in [
        ("Original", original),
        ("Second", second),
    ]:
        start = pd.to_datetime(df["start_time"], errors="coerce")
        end = pd.to_datetime(df["end_time"], errors="coerce")

        print(f"{label}: {start.min()} to {end.max()}")

    print("\n" + "=" * 70)
    print("COMPARISON COMPLETE — source CSVs were not modified.")
    print("=" * 70)


if __name__ == "__main__":
    main()
