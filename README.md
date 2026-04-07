# Watchdog

Watchdog is a threat intel ingestion and comparison tool that is dedicated to taking malicious IP data from multiple sources and comparing it to data from one internal IP database. It won't take internal action within an environment, but it can let you know whether there is a malicious IP interacting with your environment so you can take action to analyze or block it.


# Docker setup

Build Docker image
docker build -t watchdog.

Run the Watchdog Docker image and mount the location of your data. With it, you must add the --input argument pointing to your ip input csv
Step 2: docker run --rm \
  -v /Users/John/Downloads:/data \
  watchdog \
  --input /data/example_ips.csv

The following arguments can be used to modify your analysis:
Force refresh of feed data
--refresh

Export to JSON or CSV
--output (JSON/CSV)

Provide export file with name
--output-file (insert output-file name)

Insert name of column for IPs
--column (insert name of column if it is not ip_address)


# Local Python Usage

Run Watchdog and feed it data to compare to malicious IPs
python threat_compare.py --input (insert input csv)

Run Watchdog, feed it data to compare, and force refresh of feed data
python threat_compare.py --input (insert input csv) --refresh

Export to JSON
python threat_compare.py --input (insert input csv) --output json 

Export to JSON with custom filename
python threat_compare.py --input (insert input csv) --output json --output-file (insert output filename)

Export to CSV
python threat_compare.py --input (insert input csv) --output csv

Export to CSV with custom filename
python threat_compare.py --input (insert input csv) --output csv --output-file (insert output filename)

Using a column name other than ip_address
python threat_compare.py --input (insert input csv) --column (insert column name)

# Running on Windows
docker run --rm `
  -v ${PWD}:/data `
  watchdog `
  --input /data/example_data.csv