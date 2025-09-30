# LogLyzer: SIEM-Lite Log Anomaly Detector

## 🤖 Project Overview
LogLyzer is a Python-based Security Information and Event Management (SIEM) tool focused on identifying suspicious or anomalous behavior within web server logs. It employs unsupervised Machine Learning (Isolation Forest) and integrates GeoIP enrichment to provide context to security alerts.

## ✨ Key Features
* **Log Ingestion:** Parses standard web server log formats (e.g., Apache Common Log Format).
* **Anomaly Detection:** Uses the **Isolation Forest** model from `scikit-learn` to flag outlier log entries based on status codes and request frequency.
* **Geo-Enrichment:** Maps anomalous IP addresses to a physical location using a public GeoIP API (`ip-api.com`).
* **Visualization & Reporting:** Generates a professional **HTML report** (`LogLyzer_Report.html`) that includes a chart of status code distribution and a detailed table of detected anomalies.

## 🛠️ Installation and Setup

### 1. Clone the Repository
```bash
git clone [https://github.com/YOUR_GITHUB_USERNAME/LogLyzer.git](https://github.com/YOUR_GITHUB_USERNAME/LogLyzer.git)
cd LogLyzer