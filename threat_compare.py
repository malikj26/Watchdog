import csv
import json
import ipaddress
import os
from typing import List
from core.aggregator import gather_all_feeds
from core.comparator import compare_ips

#run in terminal:
#python threat_compare.py <path_to_csv>
#csv column should be named "ips" and contain IP addresses to compare against threat feeds.

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

def export_to_json(matches, filename="matches.json"):
    with open(filename, "w") as f:
        json.dump(matches, f, indent=4)
    print(f"Results exported to {filename}")


def export_to_csv(matches, filename="matches.csv"):
    if not matches:
        print("No matches to export.")
        return

    keys = matches[0].keys()

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(matches)

    print(f"Results exported to {filename}")

def main():
    file_path = input("Enter path to CSV file containing IPs: ").strip()

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

    # Ask user if they want to export
    export_choice = input("\nWould you like to export the results? (y/n): ").lower()

    if export_choice == "y":
        format_choice = input("Export as JSON or CSV? (json/csv): ").lower()

        if format_choice == "json":
            export_to_json(matches)
        elif format_choice == "csv":
            export_to_csv(matches)
        else:
            print("Invalid format choice. Skipping export.")


if __name__ == "__main__":
    main()