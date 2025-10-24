# 🔎 LogLyzer Web Security Dashboard

## Project Overview

LogLyzer is a comprehensive Python-based **Web Log Security Analyzer** designed to process standard web server access logs. It automatically identifies suspicious or anomalous behavior and presents the findings through an interactive **Streamlit web dashboard**.

### ✨ Key Features

* **Security Analysis (401 Detection):** Automatically flags and aggregates requests resulting in `401 Unauthorized` responses to identify potential brute-force or credential-stuffing attacks.
* **GeoIP Enrichment:** Utilizes the `geoip2` library to accurately map malicious and high-volume IP addresses to their precise geographic locations.
* **Interactive Streamlit Dashboard:** Provides a user-friendly interface for uploading logs, viewing security metrics, and visualizing data using dynamic charts powered by Plotly.
* **Dynamic Filtering:** Allows users to filter all displayed results (including charts) by **IP Address** and **HTTP Status Code** via a sidebar.

---

## 🚀 Getting Started (Run the Dashboard)

This project requires Python 3.9+ and assumes you are running the Streamlit app from the `LogLyzer_GUI` directory.

### 1. Setup Environment

First, navigate to the project directory and activate your virtual environment:

```bash
# Example for Windows. Use 'source .venv/bin/activate' on Linux/macOS
cd LogLyzer_GUI
source .venv/Scripts/activate