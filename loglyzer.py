import re
import sys
import collections
import html
import geoip2.database
import geoip2.errors
from datetime import datetime

# Configuration
ANOMALY_THRESHOLD = 5
REPORT_FILE = "LogLyzer_Report.html"
GEOIP_DB_PATH = "GeoLite2-City.mmdb"  # Path to your local database file


class LogLyzer:
    """Analyzes web server logs for potential security anomalies and generates an HTML report."""

    def __init__(self, log_file):
        """Initializes the LogLyzer with the log file path and GeoIP database."""
        self.log_file = log_file
        self.ip_counts = collections.defaultdict(int)
        self.anomalous_ips = {}
        self.geoip_db = GEOIP_DB_PATH
        self.log_pattern = re.compile(
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)\] "(.*?)" (\d+) (\d+)'
        )

        try:
            # Check if the GeoIP database file exists
            with open(self.geoip_db, 'rb'):
                print(f"[*] Local GeoIP database found: {self.geoip_db}")
        except FileNotFoundError:
            print(f"[!] GeoIP database not found at {self.geoip_db}. Geo-enrichment disabled.")
            self.geoip_db = None

    def _parse_log(self, line):
        """Extracts IP, timestamp, request, and status code from a log line."""
        match = self.log_pattern.match(line)
        if match:
            ip, timestamp_str, request, status_code, _ = match.groups()
            # Attempt to normalize/simplify the request string
            request_type, path = self._extract_request_details(request)
            timestamp = self._parse_timestamp(timestamp_str)
            return ip, timestamp, request_type, path, status_code
        return None, None, None, None, None

    def _extract_request_details(self, request_line):
        """Extracts the method and path from the request string."""
        try:
            parts = request_line.split()
            if len(parts) >= 2:
                return parts[0], parts[1]
        except Exception:
            pass
        return 'N/A', 'N/A'

    def _parse_timestamp(self, timestamp_str):
        """Converts the log timestamp string into a datetime object."""
        # Example format: 10/Oct/2025:13:55:34 +0200
        try:
            return datetime.strptime(timestamp_str.split(' ')[0], '%d/%b/%Y:%H:%M:%S')
        except ValueError:
            return None

    def _enrich_with_geoip(self, ip_address):
        """Looks up the city and country for a given IP using the local GeoLite2 DB."""

        # 1. Skip if no IP address was provided by the parser (Robustness Fix)
        if not ip_address:
            return "Invalid/Corrupt IP"

        # 2. Skip local/private IPs (must be public IP for GeoIP lookup)
        if ip_address.startswith(('192.168.', '10.', '172.16.', '127.', '0.')):
            return "Local/Private IP"

        if not self.geoip_db:
            return "GeoIP Disabled"

        # Use the local database reader
        try:
            with geoip2.database.Reader(self.geoip_db) as reader:
                response = reader.city(ip_address)
                city = response.city.name if response.city.name else 'N/A'
                country = response.country.name if response.country.name else 'N/A'
                return f"{city}, {country}"
        except geoip2.errors.AddressNotFound:
            return "IP Not Found"
        except ValueError:
            # Catches the specific 'ValueError: does not appear to be an IPv4 or IPv6 address'
            return "GeoIP Error: Invalid Format"
        except Exception:
            # Catches other reader errors
            return "GeoIP Error"

    def analyze(self):
        """Reads the log file, counts IP occurrences, and identifies anomalies."""
        print(f"[*] Starting analysis of {self.log_file}...")

        with open(self.log_file, 'r') as f:
            for line in f:
                ip, _, _, _, status_code = self._parse_log(line)

                if ip:
                    self.ip_counts[ip] += 1

                    # Anomaly condition: High volume of failed logins (401 status)
                    if status_code == '401' and self.ip_counts[ip] >= ANOMALY_THRESHOLD:
                        if ip not in self.anomalous_ips:
                            self.anomalous_ips[ip] = {'requests': 0, 'status_codes': collections.defaultdict(int)}

                        self.anomalous_ips[ip]['requests'] += 1
                        self.anomalous_ips[ip]['status_codes'][status_code] += 1

        print(f"[*] Analysis complete. Found {len(self.anomalous_ips)} potential anomalies.")

        if self.anomalous_ips and self.geoip_db:
            print("[*] Performing Geo-enrichment of anomalous IPs via local GeoLite2 DB...")
            for ip in self.anomalous_ips:
                location = self._enrich_with_geoip(ip)
                self.anomalous_ips[ip]['location'] = location
                print(f"    - IP: {ip} | Location: {location}")

    def generate_report(self):
        """Generates an HTML report of the findings."""
        if not self.anomalous_ips:
            print("[*] No anomalies found. Skipping report generation.")
            return

        print(f"[*] Generating report: {REPORT_FILE}")

        html_content = f"""
        <html>
        <head>
            <title>LogLyzer Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f9; }}
                h1 {{ color: #333; }}
                h2 {{ color: #cc0000; border-bottom: 2px solid #cc0000; padding-bottom: 5px; }}
                .anomaly-card {{ background-color: #fff; border: 1px solid #ddd; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .ip-detail {{ font-weight: bold; color: #333; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f0f0f0; }}
            </style>
        </head>
        <body>
            <h1>LogLyzer Security Anomaly Report</h1>
            <p>Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Analysis ran on log file: <strong>{html.escape(self.log_file)}</strong></p>
            <p>Total Anomalies Found: <strong style="color: #cc0000;">{len(self.anomalous_ips)}</strong> (Threshold: {ANOMALY_THRESHOLD} failed requests)</p>

            <h2>Detected Anomalies</h2>
        """

        for ip, data in self.anomalous_ips.items():
            location = data.get('location', 'N/A (GeoIP not performed/disabled)')

            html_content += f"""
            <div class="anomaly-card">
                <h3>Suspicious IP Address: <span class="ip-detail">{html.escape(ip)}</span></h3>
                <p><strong>Geo Location:</strong> {html.escape(location)}</p>
                <p><strong>Total Anomalous Requests:</strong> {data['requests']}</p>

                <h4>Status Code Breakdown:</h4>
                <table>
                    <tr><th>Status Code</th><th>Count</th></tr>
            """
            for status, count in data['status_codes'].items():
                html_content += f"<tr><td>{html.escape(status)}</td><td>{count}</td></tr>"

            html_content += "</table></div>"

        html_content += "</body></html>"

        with open(REPORT_FILE, 'w') as f:
            f.write(html_content)

        print(f"[*] Report successfully written to {REPORT_FILE}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python loglyzer.py <log_file_path>")
        sys.exit(1)

    log_file = sys.argv[1]

    # Check if the log file exists before proceeding
    try:
        with open(log_file, 'r'):
            pass
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {log_file}")
        sys.exit(1)

    analyzer = LogLyzer(log_file)
    analyzer.analyze()
    analyzer.generate_report()


if __name__ == "__main__":
    main()