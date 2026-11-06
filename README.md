@'
# NETLENS

**Network Traffic Analysis and Anomaly Detection Using Python**

NETLENS is a practical network traffic analysis project exploring how packet captures can be processed into structured network features and analysed using Python and machine learning.

The project covers packet inspection, TCP connection analysis, feature extraction, anomaly detection and results auditing.

## Project objectives

- Inspect network traffic captured in PCAP and PCAPNG formats.
- Examine packet-level information and network protocols.
- Reconstruct TCP connections and investigate TCP handshakes.
- Extract connection-level features for data analysis.
- Prepare datasets for anomaly detection.
- Apply machine learning to identify potentially unusual network connections.
- Audit and compare anomaly detection results across different captures.

## Technologies

- Python
- Wireshark and TShark
- Jupyter Notebook
- Pandas and NumPy
- Scikit-learn
- Joblib

## Project structure

    NETLENS/
    |-- data/
    |   `-- raw/              Private captures (excluded from Git)
    |-- notebooks/
    |   `-- data_science.ipynb
    |-- outputs/              Generated results (excluded from Git)
    |-- src/
    |   `-- netlens/          Network analysis modules
    |-- tests/
    |-- .gitignore
    `-- README.md

## Analysis workflow

1. Inspect packet captures.
2. Examine packet and protocol information.
3. Identify and reconstruct TCP connections.
4. Analyse TCP handshake behaviour.
5. Extract connection-level features.
6. Prepare datasets for anomaly detection.
7. Train and evaluate an anomaly detection model.
8. Audit and compare the results.

## Data privacy

Raw packet captures and generated analysis outputs are excluded from this repository by design.

Network captures can contain sensitive information, including IP addresses, MAC addresses, hostnames and communication metadata. Do not publish captures or derived datasets containing identifiable or private network information without reviewing and sanitising them first.

## Project status

NETLENS is an ongoing practical project in network analysis, Python data science and machine learning.
'@ | Set-Content -Path README.md -Encoding UTF8