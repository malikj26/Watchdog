import json
import logging
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any

from feeds.firehol import fetch_firehol
from feeds.spamhaus import fetch_spamhaus


CACHE_DIR = "data/cache"
CACHE_FILE = os.path.join(CACHE_DIR, "threat_feeds.json")
CACHE_EXPIRATION_HOURS = 24


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)


def ensure_cache_dir() -> None:
    os.makedirs(CACHE_DIR, exist_ok=True)


def serialize_indicators(indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove non-JSON-serializable fields like parsed before caching.
    """
    serialized = []

    for item in indicators:
        serialized.append({
            "value": item["value"],
            "type": item["type"],
            "source": item["source"]
        })

    return serialized


def deserialize_indicators(indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Rebuild parsed objects after loading from cache.
    """
    import ipaddress

    deserialized = []

    for item in indicators:
        value = item["value"]
        indicator_type = item["type"]

        try:
            if indicator_type == "ip":
                parsed_value = ipaddress.ip_address(value)
            elif indicator_type == "cidr":
                parsed_value = ipaddress.ip_network(value, strict=False)
            else:
                continue

            deserialized.append({
                "value": value,
                "type": indicator_type,
                "source": item["source"],
                "parsed": parsed_value
            })
        except ValueError:
            continue

    return deserialized


def is_cache_valid(cache_file: str, expiration_hours: int) -> bool:
    if not os.path.isfile(cache_file):
        return False

    modified_time = datetime.fromtimestamp(os.path.getmtime(cache_file))
    age = datetime.now() - modified_time

    return age < timedelta(hours=expiration_hours)


def load_cache() -> List[Dict[str, Any]]:
    logging.info("Loading indicators from cache: %s", CACHE_FILE)

    with open(CACHE_FILE, "r", encoding="utf-8") as f:
        cached_data = json.load(f)

    return deserialize_indicators(cached_data)


def save_cache(indicators: List[Dict[str, Any]]) -> None:
    ensure_cache_dir()

    logging.info("Saving indicators to cache: %s", CACHE_FILE)

    serializable_data = serialize_indicators(indicators)

    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(serializable_data, f, indent=2)


def gather_all_feeds(use_cache: bool = True) -> List[Dict[str, Any]]:
    if use_cache and is_cache_valid(CACHE_FILE, CACHE_EXPIRATION_HOURS):
        logging.info("Using valid cache.")
        return load_cache()

    logging.info("Cache missing or expired. Fetching live threat feeds.")

    indicators: List[Dict[str, Any]] = []

    logging.info("Fetching FireHOL feed.")
    firehol_data = fetch_firehol()
    logging.info("Fetched %d FireHOL indicators.", len(firehol_data))
    indicators.extend(firehol_data)

    logging.info("Fetching Spamhaus feed.")
    spamhaus_data = fetch_spamhaus()
    logging.info("Fetched %d Spamhaus indicators.", len(spamhaus_data))
    indicators.extend(spamhaus_data)

    logging.info("Total indicators gathered: %d", len(indicators))

    if use_cache:
        save_cache(indicators)

    return indicators

#if __name__ == "__main__":
#    data = gather_all_feeds()
#    print(f"Total indicators gathered: {len(data)}")
#    for item in data[:10]:
#        print(item)