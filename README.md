## 🤖 Project Overview

LogLyzer is a Python-based Security Information and Event Management (SIEM) tool focused on identifying suspicious or anomalous behavior within web server logs. It employs a **request-counting model** to detect brute-force activity and integrates offline GeoIP enrichment to provide context to security alerts.

## ✨ Key Features

* **Log Ingestion:** Parses standard web server log formats (e.g., Apache Common Log Format).
* **Anomaly Detection:** Flags suspicious activity (e.g., repeated `401 Unauthorized` responses) based on a simple, effective request count threshold.
* **Geo-Enrichment:** **Integrates GeoIP database enrichment (GeoLite2)** to map anomalous IP addresses to a physical location using a local, offline database.
* **Reporting:** Generates a clean, professional **HTML report** (`LogLyzer_Report.html`) summarizing findings and providing Geo-enriched anomaly details.

---

## ⚙️ Prerequisites & Setup

To run LogLyzer, you need the Python `geoip2` library and the GeoLite2 database file.

### 1. Install Dependencies

Ensure you are in your project's virtual environment and install the required Python library:

```bash
pip install geoip2