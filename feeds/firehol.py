import ipaddress
import requests
from typing import List, Dict, Any

FIREHOL_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"


def fetch_firehol() -> List[Dict[str, Any]]:
    """
    Fetch indicators from FireHOL and normalize them into a standard structure.

    Returns:
        A list of dictionaries, where each dictionary contains:
        - value: original indicator string
        - type: 'cidr' or 'ip'
        - source: 'firehol'
        - parsed: parsed ipaddress object
    """
    try:
        response = requests.get(FIREHOL_URL, timeout=30)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching FireHOL data: {e}")
        return []

    indicators = []

    for line in response.text.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        try:
            if "/" in line:
                parsed_value = ipaddress.ip_network(line, strict=False)
                indicator_type = "cidr"
            else:
                parsed_value = ipaddress.ip_address(line)
                indicator_type = "ip"

            indicators.append({
                "value": line,
                "type": indicator_type,
                "source": "firehol",
                "parsed": parsed_value
            })

        except ValueError:
            # Skip malformed entries
            continue

    return indicators

if __name__ == "__main__":
    indicators = fetch_firehol()

    print(f"Total indicators fetched: {len(indicators)}")

    assert isinstance(indicators, list), "fetch_firehol() should return a list"

    if indicators:
        print("First 5 indicators:")
        for item in indicators[:5]:
            print(item)

        first = indicators[0]
        assert "value" in first
        assert "type" in first
        assert "source" in first
        assert "parsed" in first

        print("\nTest passed.")
    else:
        print("No indicators returned.")