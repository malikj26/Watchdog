import argparse
import csv
import json
import ipaddress
import os
from typing import List

from core.aggregator import gather_all_feeds
from core.comparator import compare_ips

#
def load_ips_from_csv(file_path: str, column_name: str = "ip_address") -> List[str]:
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


def export_to_json(matches, filename: str = "matches.json") -> None:
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(matches, f, indent=4)
    print(f"Results exported to {filename}")


def export_to_csv(matches, filename: str = "matches.csv") -> None:
    if not matches:
        print("No matches to export.")
        return

    keys = matches[0].keys()

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(matches)

    print(f"Results exported to {filename}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Compare a CSV list of IPs against threat intelligence feeds."
    )

    parser.add_argument(
        "--input",
        required=True,
        help='Path to the input CSV file. CSV must include a column named "ip_address" by default.'
    )

    parser.add_argument(
        "--column",
        default="ip_address",
        help='CSV column name containing IP addresses. Default: "ip_address"'
    )

    parser.add_argument(
        "--output",
        choices=["json", "csv", "none"],
        default="none",
        help='Optional output format for matches. Choices: json, csv, none. Default: none'
    )

    parser.add_argument(
        "--output-file",
        help="Optional output filename. If omitted, defaults to matches.json or matches.csv"
    )

    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Fetch fresh threat feed data instead of using the cache"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if not os.path.isfile(args.input):
        print(f"Invalid file path: {args.input}")
        return

    your_ips = load_ips_from_csv(args.input, column_name=args.column)

    if not your_ips:
        print("No valid IPs found in input file.")
        return

    print(f"Loaded {len(your_ips)} IPs from file.")

    use_cache = not args.refresh
    threat_data = gather_all_feeds(use_cache=use_cache)
    print(f"Total threat indicators gathered: {len(threat_data)}")

    matches = compare_ips(your_ips, threat_data)

    print("\nMatches found:")
    if not matches:
        print("No matches found.")
    else:
        for match in matches:
            print(match)

    if args.output == "json":
        output_file = args.output_file or "matches.json"
        export_to_json(matches, filename=output_file)

    elif args.output == "csv":
        output_file = args.output_file or "matches.csv"
        export_to_csv(matches, filename=output_file)


if __name__ == "__main__":
    main()