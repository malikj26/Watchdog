from core.aggregator import gather_all_feeds
from core.comparator import compare_ips


def main():
    your_ips = [
        "8.8.8.8",
        "1.1.1.1",
        "45.134.26.10",
        "23.147.52.15"
    ]

    threat_data = gather_all_feeds()
    print(f"Total threat indicators gathered: {len(threat_data)}")

    matches = compare_ips(your_ips, threat_data)

    print("\nMatches found:")
    for match in matches:
        print(match)


if __name__ == "__main__":
    main()