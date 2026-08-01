from ipaddress import ip_address, ip_network


class IpPoolExhausted(RuntimeError):
    pass


def networks_overlap(first_cidr: str, second_cidr: str) -> bool:
    first = ip_network(first_cidr, strict=False)
    second = ip_network(second_cidr, strict=False)
    if first.version != second.version:
        return False
    return first.overlaps(second)


def allocate_ip(cidr: str, server_address: str, used_ips: set[str]) -> str:
    network = ip_network(cidr, strict=False)
    server_ip = ip_address(server_address.split("/", 1)[0])

    if server_ip.version != network.version or server_ip not in network:
        raise ValueError(f"Server address {server_address} is outside {cidr}")

    used = set()
    for value in used_ips:
        used_ip = ip_address(value)
        if used_ip.version != network.version or used_ip not in network:
            raise ValueError(f"Used IP {value} is outside {cidr}")
        used.add(used_ip)

    for candidate in network.hosts():
        if candidate == server_ip:
            continue
        if candidate in used:
            continue
        return str(candidate)

    raise IpPoolExhausted(f"No free IPs in {cidr}")
