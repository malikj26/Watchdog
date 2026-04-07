import ipaddress
from core.comparator import compare_ips


def test_compare_ips_exact_match():
    your_ips = ["1.2.3.4"]
    threat_indicators = [
        {
            "value": "1.2.3.4",
            "type": "ip",
            "source": "test_feed",
            "parsed": ipaddress.ip_address("1.2.3.4"),
        }
    ]

    matches = compare_ips(your_ips, threat_indicators)

    assert len(matches) == 1
    assert matches[0]["ip"] == "1.2.3.4"
    assert matches[0]["matched_value"] == "1.2.3.4"
    assert matches[0]["source"] == "test_feed"
    assert matches[0]["match_type"] == "exact_ip"


def test_compare_ips_cidr_match():
    your_ips = ["10.10.10.25"]
    threat_indicators = [
        {
            "value": "10.10.10.0/24",
            "type": "cidr",
            "source": "test_feed",
            "parsed": ipaddress.ip_network("10.10.10.0/24"),
        }
    ]

    matches = compare_ips(your_ips, threat_indicators)

    assert len(matches) == 1
    assert matches[0]["ip"] == "10.10.10.25"
    assert matches[0]["matched_value"] == "10.10.10.0/24"
    assert matches[0]["source"] == "test_feed"
    assert matches[0]["match_type"] == "cidr_contains_ip"


def test_compare_ips_no_match():
    your_ips = ["8.8.8.8"]
    threat_indicators = [
        {
            "value": "10.10.10.0/24",
            "type": "cidr",
            "source": "test_feed",
            "parsed": ipaddress.ip_network("10.10.10.0/24"),
        }
    ]

    matches = compare_ips(your_ips, threat_indicators)

    assert matches == []


def test_compare_ips_skips_invalid_ip_input():
    your_ips = ["not_an_ip", "1.2.3.4"]
    threat_indicators = [
        {
            "value": "1.2.3.4",
            "type": "ip",
            "source": "test_feed",
            "parsed": ipaddress.ip_address("1.2.3.4"),
        }
    ]

    matches = compare_ips(your_ips, threat_indicators)

    assert len(matches) == 1
    assert matches[0]["ip"] == "1.2.3.4"