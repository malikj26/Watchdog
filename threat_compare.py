import csv
import ipaddress
import os
import sys
from typing import List
from core.aggregator import gather_all_feeds
from core.comparator import compare_ips

#run in terminal:
#python threat_compare.py <path_to_csv>

def load_ips_from_csv(file_path: str, column_name: str = "ips") -> List[str]:
    ips = []

    try:
        with open(file_path, "r", newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)

            print(f"Detected headers: {reader.fieldnames}")

            for row in reader:
                value = row.get(column_name)

                if not value:
                    continue

                value = value.strip()

                try:
                    ipaddress.ip_address(value)
                    ips.append(value)
                except ValueError:
                    print(f"Skipping invalid IP: {value}")

    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return []

    return ips


def main():
    if len(sys.argv) < 2:
        print("Usage: python threat_compare.py <path_to_csv>")
        return

    file_path = sys.argv[1]

    if not os.path.isfile(file_path):
        print("Invalid file path.")
        return

    your_ips = load_ips_from_csv(file_path)

    if not your_ips:
        print("No valid IPs found in input file.")
        return

    print(f"Loaded {len(your_ips)} IPs from file.")

    threat_data = gather_all_feeds()
    print(f"Total threat indicators gathered: {len(threat_data)}")

    matches = compare_ips(your_ips, threat_data)

    print("\nMatches found:")
    if not matches:
        print("No matches found.")
    else:
        for match in matches:
            print(match)


if __name__ == "__main__":
    main()