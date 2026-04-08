# Watchdog 

Watchdog is a lightweight threat intelligence ingestion and comparison tool designed to identify malicious IP addresses interacting with your environment.

It aggregates threat data from multiple reputable sources and compares it against a provided IP dataset, helping you quickly detect potentially malicious activity.

Watchdog is a detection tool — it does not take automated action. It is intended to support analysis and response workflows.


## Features

- Ingests threat intelligence from multiple sources (FireHOL, Spamhaus, more to come)
- Compares external threat data against internal IP datasets
- Supports CSV-based input
- Export results to JSON or CSV
- Built-in caching for faster repeated runs
- Dockerized for easy portability
- DevSecOps pipeline with:
  - Linting (Ruff)
  - Testing (pytest)
  - SAST (Bandit)
  - Dependency scanning (pip-audit)
  - CodeQL integration


## Prerequisites

Make sure you have the following installed:

- Python 3.10+ (for local usage)
- Docker (for containerized usage)


## Installation

### Clone the Repository or Download zip

```
git clone https://github.com/malikj26/Watchdog.git
```

Then enter the watchdog directory:

```
cd watchdog
```

### Install dependencies

```
pip install -r requirements.txt
```

###


## Create or download a CSV

Your CSV file should contain a column of IP addresses that can be targeted for analysis.

### Default format in a CSV file:

```
ip_address
8.8.8.8
1.1.1.1
```

# Running with Docker on linux/mac
```
- Step 1: Build Docker image

docker build -t watchdog .

- Step 2: Run the Watchdog Docker image and mount the location of your data. 
With it, you must add the --input argument pointing to your ip input csv

docker run --rm -v ~/Downloads:/data watchdog --input /data/example_ips.csv
> To run test with the example_ips.csv file included in the repo:
docker run --rm watchdog --input example_ips.csv

> Important Notice 1: The container cannot access your local files unless you mount them with -v
> Important Notice 2: /data inside the container maps to your local folder

The following arguments can be appended to the command to modify your analysis:
Force refresh of feed data
--refresh

Export to JSON or CSV
--output (JSON/CSV)

Provide export file with name
--output-file (insert output-file name)

Insert name of column for IPs
--column (insert name of column if it is not ip_address)
```


# Local Python Usage
```
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
```


# Running with Docker on Windows
```
docker run --rm -v ${PWD}:/data watchdog --input /data/example_data.csv

> Important Notice 1: The container cannot access your local files unless you mount them with -v
> Important Notice 2: /data inside the container maps to your local folder

The following arguments can be used to modify your analysis:
Force refresh of feed data
--refresh

Export to JSON or CSV
--output (JSON/CSV)

Provide export file with name
--output-file (insert output-file name)

Insert name of column for IPs
--column (insert name of column if it is not ip_address)
```
