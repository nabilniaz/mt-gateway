import pytest

from gateway.ssrf import UnsafeUpstream, is_public_ip, system_resolver, validate_upstream

DNS = {
    "public.test": ["93.184.216.34"],
    "metadata.test": ["169.254.169.254"],
    "loopback.test": ["127.0.0.1"],
    "private.test": ["10.1.2.3"],
    "mixed.test": ["93.184.216.34", "192.168.1.1"],
    "mapped.test": ["::ffff:127.0.0.1"],
    "internal.test": ["10.0.0.5"],
    "empty.test": [],
}


async def fake_resolver(host: str, port: int) -> list[str]:
    if host not in DNS:
        raise OSError("NXDOMAIN")
    return DNS[host]


async def check(url: str) -> None:
    await validate_upstream(url, allowed_private_hosts={"internal.test"}, resolver=fake_resolver)


@pytest.mark.parametrize(
    "url",
    ["https://public.test", "http://public.test:8080/v1", "http://internal.test:8080"],
)
async def test_allows_safe_upstreams(url: str) -> None:
    await check(url)


@pytest.mark.parametrize(
    ("url", "match"),
    [
        ("ftp://public.test", "http or https"),
        ("file:///etc/passwd", "http or https"),
        ("https://user:pw@public.test", "credentials"),
        ("https://public.test/?a=1", "query"),
        ("https://public.test/#x", "query"),
        ("https://", "no host"),
        ("http://public.test:99999", "not a valid URL"),
        ("http://metadata.test", "non-public"),
        ("http://169.254.169.254/latest/meta-data", "non-public"),
        ("http://[::1]:8080", "non-public"),
        ("http://loopback.test", "non-public"),
        ("http://private.test", "non-public"),
        ("http://mixed.test", "non-public"),
        ("http://mapped.test", "non-public"),
        ("http://nxdomain.test", "does not resolve"),
        ("http://empty.test", "does not resolve"),
    ],
)
async def test_rejects_unsafe_upstreams(url: str, match: str) -> None:
    with pytest.raises(UnsafeUpstream, match=match):
        await check(url)


@pytest.mark.parametrize(
    ("ip", "public"),
    [
        ("8.8.8.8", True),
        ("2606:4700:4700::1111", True),
        ("10.0.0.1", False),
        ("172.16.0.1", False),
        ("192.168.0.1", False),
        ("127.0.0.1", False),
        ("169.254.169.254", False),
        ("100.64.0.1", False),
        ("0.0.0.0", False),
        ("::1", False),
        ("fe80::1%en0", False),
        ("fd00::1", False),
        ("224.0.0.1", False),
        ("::ffff:10.0.0.1", False),
    ],
)
def test_is_public_ip(ip: str, public: bool) -> None:
    assert is_public_ip(ip) is public


async def test_system_resolver_resolves_ip_literals_without_network() -> None:
    assert "127.0.0.1" in await system_resolver("127.0.0.1", 80)
    with pytest.raises(UnsafeUpstream, match="non-public"):
        await validate_upstream("http://127.0.0.1:9000", allowed_private_hosts=())
