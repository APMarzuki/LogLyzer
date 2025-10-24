# loglyzer_core.py

import re
from collections import Counter
import pandas as pd
from datetime import datetime

# --- NEW IMPORTS FOR GEOIP ---
import geoip2.database
import geoip2.errors
import os

# -----------------------------

# Path to the GeoLite2 database: Assumes GeoLite2-City.mmdb is in the parent directory (LogLyzer folder)
GEOIP_DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'GeoLite2-City.mmdb')


class LogLyzer:
    """
    A class to parse, analyze, and report on log files.
    """

    def __init__(self, log_data):
        """Initializes with log data (content as a list of strings) and GeoIP Reader."""
        self.log_data = log_data
        self.parsed_logs = []
        self.suspicious_ips = Counter()
        self.total_logs = 0

        # Initialize the database reader once in the constructor
        self.geoip_reader = None
        if os.path.exists(GEOIP_DB_PATH):
            try:
                self.geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
            except Exception as e:
                # This ensures the app doesn't crash if the file is corrupted
                print(f"GeoIP Reader failed to initialize: {e}")
        else:
            print(f"GeoIP Database not found at: {GEOIP_DB_PATH}. Geo-enrichment will be limited.")

    # Helper functions (keeping other functions the same)
    def _parse_log(self, line):
        """Parses a single log line (Apache/Nginx common format)."""
        # Regex to capture IP, timestamp, request, status, size
        LOG_PATTERN = re.compile(
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+|-)'
        )
        match = LOG_PATTERN.match(line)
        if match:
            ip, timestamp_str, request, status, size = match.groups()
            return {
                'ip_address': ip,
                'timestamp': self._parse_timestamp(timestamp_str),
                'request': request,
                'status_code': int(status) if status.isdigit() else None,
                'size': int(size) if size.isdigit() and size != '-' else 0
            }
        return None

    def _parse_timestamp(self, timestamp_str):
        """Parses the log timestamp string into a datetime object."""
        try:
            # Example format: '24/Oct/2025:12:00:00 +0200'
            return datetime.strptime(timestamp_str.split(' ')[0], '%d/%b/%Y:%H:%M:%S')
        except ValueError:
            return None

    def _enrich_with_geoip(self, ip_address):
        """Looks up the country and location using the GeoLite2 database."""
        # Handle IPs that shouldn't be enriched (like private IPs)
        if ip_address.startswith('192.168.') or ip_address.startswith('10.') or ip_address.startswith('172.'):
            return 'Internal/Private'

        if not self.geoip_reader:
            return 'GeoIP Failed/Disabled'

        try:
            response = self.geoip_reader.city(ip_address)
            country = response.country.name
            city = response.city.name

            # Combine city and country if both exist
            if city and country:
                return f"{city}, {country}"
            return country  # Fallback to country name

        except geoip2.errors.AddressNotFoundError:
            return 'Unknown Location'
        except Exception:
            # Catch other potential errors during lookup (e.g., non-IP format)
            return 'GeoIP Error'

            # Core function modifications

    def analyze(self):
        """
        Parses all logs, analyzes for suspicious activity, and RETURNS structured results.
        """
        self.total_logs = 0
        parsed_data = []

        # --- Parsing and Analysis Loop ---
        for line in self.log_data:
            self.total_logs += 1
            log_entry = self._parse_log(line)

            if log_entry:
                # Check for suspicious activity (e.g., 401 Unauthorized)
                if log_entry['status_code'] == 401:
                    self.suspicious_ips[log_entry['ip_address']] += 1

                # Add GeoIP enrichment
                log_entry['country'] = self._enrich_with_geoip(log_entry['ip_address'])

                parsed_data.append(log_entry)

        # Convert all parsed data to a DataFrame for easier manipulation
        self.df = pd.DataFrame(parsed_data)

        # --- Prepare Analysis Outputs for the GUI ---

        # Output 1: Top 401 Offenders (Suspicious Activity)
        suspicious_df = pd.DataFrame(
            self.suspicious_ips.most_common(),
            columns=['IP Address', '401 Count']
        )
        # Apply a simple threshold for demonstration
        suspicious_df = suspicious_df[suspicious_df['401 Count'] > 0]

        # Output 2: Status Code Distribution
        # Note: We reset the index to make the columns 'Status Code' and 'Count' explicit
        status_counts = self.df['status_code'].value_counts().reset_index()
        status_counts.columns = ['Status Code', 'Count']

        # Output 3: Geographic Distribution
        geo_counts = self.df['country'].value_counts().reset_index()
        geo_counts.columns = ['Country', 'Requests']

        # Return a dictionary of all results
        return {
            'total_logs': self.total_logs,
            'suspicious_ips': suspicious_df,
            'status_distribution': status_counts,
            'geo_distribution': geo_counts
        }