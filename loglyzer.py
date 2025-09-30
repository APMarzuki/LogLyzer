# loglyzer.py

import pandas as pd
from sklearn.ensemble import IsolationForest
import numpy as np
import argparse
import sys
from tqdm import tqdm
import requests
import matplotlib.pyplot as plt  # <-- NEW IMPORT
import seaborn as sns  # <-- NEW IMPORT
import os  # <-- NEW IMPORT


class LogLyzer:
    """
    A lightweight log analysis and anomaly detection tool.
    Phase 4: Incorporate Visualization and HTML Report generation.
    """

    def __init__(self, log_path, log_format='apache_common', contamination=0.05):
        self.log_path = log_path
        self.log_format = log_format
        self.contamination = contamination
        self.df = None
        self.anomalies = pd.DataFrame()
        print(f"[*] LogLyzer initialized for log file: {self.log_path}")

    def _enrich_with_geoip(self, ip_address):
        """Looks up the city and country for a given IP using a public API."""

        # Skip local/private IPs
        if ip_address.startswith(('192.168.', '10.', '172.16.', '127.', '0.')):
            return "Local/Private IP"

        try:
            # Using the free public API from ip-api.com
            url = f"http://ip-api.com/json/{ip_address}?fields=country,city"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                data = response.json()
                if data and data.get('status') == 'success':
                    country = data.get('country', 'N/A')
                    city = data.get('city', 'N/A')
                    return f"{city}, {country}"
                elif data.get('message') == 'reserved range':
                    return "Local/Private IP"
                else:
                    return "API Error"
            else:
                return f"HTTP Error {response.status_code}"
        except requests.exceptions.RequestException as e:
            return f"Network Error: {e}"

    def _parse_log(self):
        # ... (Parsing method remains unchanged) ...
        print("[*] Starting log parsing...")
        data = []
        try:
            with open(self.log_path, 'r', encoding='utf-8') as f:
                total_lines = sum(1 for line in open(self.log_path, 'r', encoding='utf-8'))

                for line in tqdm(f, total=total_lines, desc="Parsing"):
                    line = line.strip()
                    if not line:
                        continue

                    parts = line.split(' ')

                    if len(parts) < 10:
                        continue

                    try:
                        ip = parts[0]
                        timestamp = parts[3].strip('[')
                        request = parts[6]
                        status = int(parts[8])
                        size = parts[9]

                        data.append({
                            'ip': ip,
                            'timestamp': timestamp,
                            'request': request,
                            'status': status,
                            'size': size
                        })
                    except Exception:
                        continue

            self.df = pd.DataFrame(data)
            print(f"[+] Parsing complete. Loaded {len(self.df)} log entries.")

        except FileNotFoundError:
            print(f"[!] Error: Log file not found at {self.log_path}")
            sys.exit(1)
        except Exception as e:
            print(f"[!] An unexpected error occurred during parsing: {e}")
            sys.exit(1)

    def _detect_anomalies(self):
        """
        Applies the Isolation Forest algorithm to detect anomalies.
        """
        print("[*] Training Isolation Forest model for anomaly detection...")

        features = self.df[['status', 'request_count']].values

        model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100
        )

        self.df['anomaly_score'] = model.fit_predict(features)

        self.anomalies = self.df[self.df['anomaly_score'] == -1].copy()

        print(f"[+] Anomaly detection complete. Found {len(self.anomalies)} potential anomalies.")

        if not self.anomalies.empty:

            # GEO-ENRICHMENT OF ANOMALIES
            print("[*] Performing Geo-enrichment of anomalous IPs via API...")
            anomalous_ips = self.anomalies['ip'].unique()
            ip_to_geo = {ip: self._enrich_with_geoip(ip) for ip in tqdm(anomalous_ips, desc="Geo-lookup")}
            self.anomalies['location'] = self.anomalies['ip'].map(ip_to_geo)

            print("\n--- Potential Anomalies Detected (LogLyzer Alert) ---")
            display_cols = ['timestamp', 'ip', 'location', 'request', 'status', 'request_count']
            print(self.anomalies[display_cols].to_string())
            print("------------------------------------------------------\n")
        else:
            print("[+] No significant anomalies detected based on the current model settings.")

    # --- NEW REPORT GENERATION METHOD ---

    def _generate_report(self):
        """
        Generates an HTML report containing key metrics, charts, and anomaly details.
        """
        print("[*] Generating report and visualization...")
        report_file = 'LogLyzer_Report.html'

        # 1. Generate Status Code Distribution Chart
        plt.style.use('seaborn-v0_8-darkgrid')

        plt.figure(figsize=(10, 5))
        sns.countplot(x='status', data=self.df, palette='viridis')
        plt.title('HTTP Status Code Distribution', fontsize=16)
        plt.xlabel('Status Code')
        plt.ylabel('Count')

        # Save the plot as a PNG image
        chart_path = 'status_code_distribution.png'
        plt.savefig(chart_path)
        plt.close()

        # 2. Convert Anomalies DataFrame to an HTML Table
        if not self.anomalies.empty:
            anomaly_table = self.anomalies[[
                'timestamp', 'ip', 'location', 'request', 'status', 'request_count'
            ]].to_html(
                index=False,
                classes='table table-striped',
                border=0
            )
        else:
            anomaly_table = "<p>No anomalies were detected during this analysis run.</p>"

        # 3. Assemble the Final HTML Content (using Bootstrap for clean styling)
        total_logs = len(self.df)
        total_anomalies = len(self.anomalies)

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>LogLyzer Analysis Report</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
            <style>
                body {{ font-family: Arial, sans-serif; padding: 20px; }}
                h1 {{ color: #007bff; }}
                .alert-danger {{ color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; }}
                table {{ width: 100%; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="text-center">LogLyzer Security Analysis Report</h1>
                <p class="text-center text-muted">Generated on {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

                <div class="row mt-4">
                    <div class="col-md-6">
                        <div class="card p-3">
                            <h4>Summary Statistics</h4>
                            <p><strong>Total Log Entries Processed:</strong> {total_logs}</p>
                            <p class="alert alert-danger"><strong>Potential Anomalies Detected:</strong> {total_anomalies}</p>
                        </div>
                    </div>
                </div>

                <h2 class="mt-5">Status Code Distribution</h2>
                <img src="{chart_path}" alt="Status Code Chart" class="img-fluid border p-2">

                <h2 class="mt-5">Anomaly Details (Geo-Enriched)</h2>
                {anomaly_table}

                <p class="text-center text-muted mt-5">--- End of Report ---</p>
            </div>
        </body>
        </html>
        """

        with open(report_file, 'w') as f:
            f.write(html_content)

        print(f"[+] Report generated successfully: {report_file}")

    def analyze(self):
        """
        Main function to run the analysis pipeline and generate report.
        """
        self._parse_log()

        if self.df is not None and not self.df.empty:
            print("[*] Data cleaning and feature engineering phase...")

            self.df['status'] = pd.to_numeric(self.df['status'], errors='coerce')
            self.df.dropna(subset=['status'], inplace=True)

            # Feature: Count of requests per IP
            ip_counts = self.df['ip'].value_counts().reset_index()
            ip_counts.columns = ['ip', 'request_count']
            self.df = pd.merge(self.df, ip_counts, on='ip', how='left')

            print("[*] Feature engineering complete.")

            # --- Call the detection method (includes enrichment) ---
            self._detect_anomalies()

            # --- Call the report method ---
            self._generate_report()

            print("[+] LogLyzer analysis pipeline finished.")
        else:
            print("[!] No data to analyze.")


def main():
    parser = argparse.ArgumentParser(description="LogLyzer: A Python-based Log Anomaly Detector.")
    parser.add_argument('log_file', type=str, help="Path to the log file for analysis.")
    parser.add_argument('-c', '--contamination', type=float, default=0.05,
                        help="Estimated proportion of outliers in the data (e.g., 0.01 for 1%). Default is 0.05.")

    args = parser.parse_args()

    analyzer = LogLyzer(args.log_file, contamination=args.contamination)
    analyzer.analyze()


if __name__ == "__main__":
    main()