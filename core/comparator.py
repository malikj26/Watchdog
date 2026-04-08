import ipaddress
from typing import List, Dict, Any


def compare_ips(your_ips: List[str], threat_indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []

    ip_indicators = []
    cidr_indicators = []

    for indicator in threat_indicators:
        if indicator.get("type") == "ip":
            ip_indicators.append(indicator)
        elif indicator.get("type") == "cidr":
            cidr_indicators.append(indicator)

    for ip in your_ips:
        try:
            parsed_ip = ipaddress.ip_address(ip)
        except ValueError:
            continue

        # Exact IP matches
        for indicator in ip_indicators:
            if parsed_ip == indicator["parsed"]:
                matches.append({
                    "ip": ip,
                    "matched_value": indicator["value"],
                    "source": indicator["source"],
                    "match_type": "exact_ip"
                })

        # CIDR matches
        for indicator in cidr_indicators:
            if parsed_ip in indicator["parsed"]:
                matches.append({
                    "ip": ip,
                    "matched_value": indicator["value"],
                    "source": indicator["source"],
                    "match_type": "cidr_contains_ip"
                })

    return matches