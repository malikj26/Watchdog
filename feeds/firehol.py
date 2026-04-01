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