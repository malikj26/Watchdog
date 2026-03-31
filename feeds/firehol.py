import requests
import ipaddress

FIREHOL_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"

def get_ips():
    try:
        response = requests.get(FIREHOL_URL, timeout=10)
        response.raise_for_status()

        networks = []

        for line in response.text.splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            networks.append(ipaddress.ip_network(line))

        return networks

    except requests.RequestException as e:
        print(f"Error fetching FireHOL list: {e}")
        return []

def ip_in_blocklist(ip, networks):
    ip_obj = ipaddress.ip_address(ip)

    for network in networks:
        if ip_obj in network:
            return True

    return False

#firehol_networks = get_ips()
#test_ip = "102.203.68.15"
#if ip_in_blocklist(test_ip, firehol_networks):
#    print("ALERT: IP found in FireHOL blocklist")
#else:
#    print("IP clean")