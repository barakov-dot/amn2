import pytest

from app.vpn.ipam import IpPoolExhausted, allocate_ip, networks_overlap


def test_allocate_ip_skips_network_server_broadcast_and_used_addresses():
    ip = allocate_ip(
        cidr="10.8.0.0/29",
        server_address="10.8.0.1",
        used_ips={"10.8.0.2", "10.8.0.3"},
    )

    assert ip == "10.8.0.4"


def test_allocate_ip_accepts_server_address_with_prefix():
    ip = allocate_ip(
        cidr="10.8.0.0/29",
        server_address="10.8.0.1/24",
        used_ips={"10.8.0.2", "10.8.0.3"},
    )

    assert ip == "10.8.0.4"


def test_allocate_ip_reports_pool_exhaustion():
    with pytest.raises(IpPoolExhausted):
        allocate_ip(
            cidr="10.8.0.0/30",
            server_address="10.8.0.1",
            used_ips={"10.8.0.2"},
        )


def test_allocate_ip_rejects_server_address_outside_cidr():
    with pytest.raises(ValueError):
        allocate_ip(
            cidr="10.8.0.0/29",
            server_address="10.8.1.1",
            used_ips=set(),
        )


def test_allocate_ip_rejects_server_address_family_mismatch():
    with pytest.raises(ValueError):
        allocate_ip(
            cidr="10.8.0.0/29",
            server_address="fd00::1",
            used_ips=set(),
        )


@pytest.mark.parametrize("used_ip", ["10.8.1.2", "fd00::2"])
def test_allocate_ip_rejects_used_ip_outside_cidr_or_family_mismatch(used_ip):
    with pytest.raises(ValueError):
        allocate_ip(
            cidr="10.8.0.0/29",
            server_address="10.8.0.1",
            used_ips={used_ip},
        )


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        ("10.212.12.0/24", "10.212.12.128/25", True),
        ("10.212.12.0/24", "10.212.13.0/24", False),
        ("10.212.12.7/24", "10.212.12.0/25", True),
        ("10.212.12.0/24", "fd00::/64", False),
    ],
)
def test_networks_overlap_is_deterministic(first, second, expected):
    assert networks_overlap(first, second) is expected
