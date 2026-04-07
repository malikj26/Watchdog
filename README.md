# Watchdog

Watchdog is a threat intel ingestion and comparison tool that is dedicated to taking malicious IP data from multiple sources and comparing it to data from one internal IP database. It won't take internal action within an environment, but it can let you know whether there is a malicious IP interacting with your environment so you can take action to analyze or block it.

Docker setup
Run:
Step 1: docker build -t watchdog.
Step 2: docker run -it --rm -v "$(pwd)/data:/app/data" watchdog
Step 3: Enter path to CSV file containing IPs

Local Python Usage

Run Watchdog and feed it data to compare to malicious IPs
python threat_compare.py --input <insert input csv>

Run Watchdog, feed it data to compare, and force refresh of feed data
python threat_compare.py --input <insert input csv> --refresh

Export to JSON
python threat_compare.py --input <insert input csv> --output json 

Export to JSON with custom filename
python threat_compare.py --input <insert input csv> --output json --output-file <insert output filename>

Export to CSV
python threat_compare.py --input <insert input csv> --output csv

Export to CSV with custom filename
python threat_compare.py --input <insert input csv> --output csv --output-file <insert output filename>

Using a column name other than ip_address
python threat_compare.py --input <insert input csv> --column <insert column name>