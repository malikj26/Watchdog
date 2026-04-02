from typing import List, Dict, Any
from feeds.firehol import fetch_firehol
from feeds.spamhaus import fetch_spamhaus


def gather_all_feeds() -> List[Dict[str, Any]]:
    indicators: List[Dict[str, Any]] = []

    indicators.extend(fetch_firehol())
    indicators.extend(fetch_spamhaus())

    return indicators


if __name__ == "__main__":
    data = gather_all_feeds()
    print(f"Total indicators gathered: {len(data)}")

    for item in data[:10]:
        print(item)