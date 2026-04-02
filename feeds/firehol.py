import ipaddress
import requests
from typing import List, Dict, Any

FIREHOL_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"


def fetch_firehol() -> List[Dict[str, Any]]:
    """
    Fetch indicators from FireHOL and normalize them into a standard structure.

    Returns:
        A list of dictionaries with:
        - value: normalized indicator string
        - type: 'ip' or 'cidr'
        - source: 'firehol'
        - parsed: parsed ipaddress object
    """
    indicators: List[Dict[str, Any]] = []

    try:
        response = requests.get(FIREHOL_URL, timeout=30)
        response.raise_for_status()
    except requests.RequestException:
        return []

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
                "value": str(parsed_value),
                "type": indicator_type,
                "source": "firehol",
                "parsed": parsed_value
            })

        except ValueError:
            continue

    return indicators

#for testing run:
#if __name__ == "__main__":
#    data = fetch_firehol()
#    print(f"Total indicators fetched: {len(data)}")
#
#    for item in data[:10]:
#        print(item)