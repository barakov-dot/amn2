from dataclasses import dataclass

AwgParameter = int | str

DEFAULT_CLIENT_AWG_JC = 3
DEFAULT_CLIENT_AWG_JMIN = 10
DEFAULT_CLIENT_AWG_JMAX = 30
DEFAULT_CLIENT_AWG_S1 = 15
DEFAULT_CLIENT_AWG_S2 = 18
DEFAULT_CLIENT_AWG_S3 = 20
DEFAULT_CLIENT_AWG_S4 = 23
DEFAULT_CLIENT_AWG_H1 = 1020325451
DEFAULT_CLIENT_AWG_H2 = 3288052141
DEFAULT_CLIENT_AWG_H3 = 1766607858
DEFAULT_CLIENT_AWG_H4 = 2528465083


@dataclass(frozen=True)
class ClientConfigDefaults:
    dns: str = "8.8.8.8, 8.8.4.4"
    allowed_ips: str = "0.0.0.0/0, ::/0"
    persistent_keepalive: int = 25
    jc: int = DEFAULT_CLIENT_AWG_JC
    jmin: int = DEFAULT_CLIENT_AWG_JMIN
    jmax: int = DEFAULT_CLIENT_AWG_JMAX
    s1: int = DEFAULT_CLIENT_AWG_S1
    s2: int = DEFAULT_CLIENT_AWG_S2
    s3: int = DEFAULT_CLIENT_AWG_S3
    s4: int = DEFAULT_CLIENT_AWG_S4
    h1: AwgParameter = DEFAULT_CLIENT_AWG_H1
    h2: AwgParameter = DEFAULT_CLIENT_AWG_H2
    h3: AwgParameter = DEFAULT_CLIENT_AWG_H3
    h4: AwgParameter = DEFAULT_CLIENT_AWG_H4
    i1: str = ""
    i2: str = ""
    i3: str = ""
    i4: str = ""
    i5: str = ""


@dataclass(frozen=True)
class ClientConfigInput:
    private_key: str
    address: str
    dns: str
    server_public_key: str
    preshared_key: str
    endpoint: str
    allowed_ips: str
    persistent_keepalive: int
    jc: int
    jmin: int
    jmax: int
    s1: int
    s2: int
    s3: int = 0
    s4: int = 0
    h1: AwgParameter = 1
    h2: AwgParameter = 2
    h3: AwgParameter = 3
    h4: AwgParameter = 4
    i1: str = ""
    i2: str = ""
    i3: str = ""
    i4: str = ""
    i5: str = ""


def render_client_config(config: ClientConfigInput) -> str:
    lines = [
        "[Interface]",
        f"Address = {config.address}",
        f"DNS = {config.dns}",
        f"PrivateKey = {config.private_key}",
        f"Jc = {config.jc}",
        f"Jmin = {config.jmin}",
        f"Jmax = {config.jmax}",
        f"S1 = {config.s1}",
        f"S2 = {config.s2}",
        f"S3 = {config.s3}",
        f"S4 = {config.s4}",
        f"H1 = {config.h1}",
        f"H2 = {config.h2}",
        f"H3 = {config.h3}",
        f"H4 = {config.h4}",
        f"I1 = {config.i1}",
        f"I2 = {config.i2}",
        f"I3 = {config.i3}",
        f"I4 = {config.i4}",
        f"I5 = {config.i5}",
        "",
        "[Peer]",
        f"PublicKey = {config.server_public_key}",
        f"PresharedKey = {config.preshared_key}",
        f"AllowedIPs = {config.allowed_ips}",
        f"Endpoint = {config.endpoint}",
        f"PersistentKeepalive = {config.persistent_keepalive}",
    ]
    return "\n".join(lines) + "\n"
