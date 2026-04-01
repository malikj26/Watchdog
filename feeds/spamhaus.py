import requests
import ipaddress
from typing import List, Dict, Any

SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"


def fetch_spamhaus() -> List[Dict[str, Any]]:
    """
    Fetch indicators from Spamhaus DROP and EDROP and normalize them
    into a standard structure.

    Returns:
        A list of dictionaries, where each dictionary contains:
        - value: original indicator string
        - type: 'cidr'
        - source: 'spamhaus_drop' or 'spamhaus_edrop'
        - parsed: parsed ipaddress network object
    """
    indicators = []

    urls = [
        (SPAMHAUS_DROP_URL, "spamhaus_drop"),
        (SPAMHAUS_EDROP_URL, "spamhaus_edrop")
    ]

    for url, source_name in urls:
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Error fetching {source_name}: {e}")
            continue

        for line in response.text.splitlines():
            line = line.strip()

            if not line or line.startswith(";"):
                continue

            network = line.split(";")[0].strip()

            try:
                parsed_value = ipaddress.ip_network(network, strict=False)
                indicators.append({
                    "value": str(parsed_value),
                    "type": "cidr",
                    "source": source_name,
                    "parsed": parsed_value
                })
            except ValueError:
                continue

    return indicators


if __name__ == "__main__":
    data = fetch_spamhaus()
    print(f"Total indicators fetched: {len(data)}")

    for item in data[:10]:
        print(item)