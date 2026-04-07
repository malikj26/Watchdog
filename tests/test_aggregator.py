import ipaddress
from unittest.mock import patch

from core.aggregator import (
    gather_all_feeds,
    serialize_indicators,
    deserialize_indicators,
)


def test_serialize_indicators_removes_parsed_field():
    indicators = [
        {
            "value": "1.2.3.4",
            "type": "ip",
            "source": "firehol",
            "parsed": ipaddress.ip_address("1.2.3.4"),
        }
    ]

    serialized = serialize_indicators(indicators)

    assert serialized == [
        {
            "value": "1.2.3.4",
            "type": "ip",
            "source": "firehol",
        }
    ]


def test_deserialize_indicators_rebuilds_ip_parsed_field():
    indicators = [
        {
            "value": "1.2.3.4",
            "type": "ip",
            "source": "firehol",
        }
    ]

    deserialized = deserialize_indicators(indicators)

    assert len(deserialized) == 1
    assert deserialized[0]["value"] == "1.2.3.4"
    assert str(deserialized[0]["parsed"]) == "1.2.3.4"


def test_deserialize_indicators_rebuilds_cidr_parsed_field():
    indicators = [
        {
            "value": "10.0.0.0/24",
            "type": "cidr",
            "source": "spamhaus_drop",
        }
    ]

    deserialized = deserialize_indicators(indicators)

    assert len(deserialized) == 1
    assert deserialized[0]["value"] == "10.0.0.0/24"
    assert str(deserialized[0]["parsed"]) == "10.0.0.0/24"


@patch("core.aggregator.fetch_spamhaus")
@patch("core.aggregator.fetch_firehol")
def test_gather_all_feeds_combines_feed_results(mock_fetch_firehol, mock_fetch_spamhaus):
    mock_fetch_firehol.return_value = [
        {
            "value": "1.2.3.4",
            "type": "ip",
            "source": "firehol",
            "parsed": ipaddress.ip_address("1.2.3.4"),
        }
    ]

    mock_fetch_spamhaus.return_value = [
        {
            "value": "10.0.0.0/24",
            "type": "cidr",
            "source": "spamhaus_drop",
            "parsed": ipaddress.ip_network("10.0.0.0/24"),
        }
    ]

    results = gather_all_feeds(use_cache=False)

    assert len(results) == 2
    assert any(item["source"] == "firehol" for item in results)
    assert any(item["source"] == "spamhaus_drop" for item in results)