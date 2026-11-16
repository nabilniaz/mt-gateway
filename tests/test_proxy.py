import pytest

from gateway.models import Route
from gateway.proxy import downstream_response_headers, upstream_request_headers, upstream_url


def route(prefix: str = "/orders", strip: bool = True) -> Route:
    return Route(route_id="r", prefix=prefix, upstream="https://svc/v1", strip_prefix=strip)


@pytest.mark.parametrize(
    ("base", "strip", "path", "query", "expected"),
    [
        ("https://svc/v1", True, "/orders/42", "", "https://svc/v1/42"),
        ("https://svc/v1/", True, "/orders/42", "", "https://svc/v1/42"),
        ("https://svc/v1", True, "/orders", "", "https://svc/v1"),
        ("https://svc", True, "/orders", "", "https://svc/"),
        ("https://svc", False, "/orders/42", "a=1&b=2", "https://svc/orders/42?a=1&b=2"),
        ("https://svc", True, "/orders/a b/?#", "", "https://svc/a%20b/%3F%23"),
        ("https://svc", True, "/orders/café", "", "https://svc/caf%C3%A9"),
    ],
)
def test_upstream_url(base: str, strip: bool, path: str, query: str, expected: str) -> None:
    assert upstream_url(base, route(strip=strip), path, query) == expected


def test_request_headers_strip_connection_listed_and_add_gateway_headers() -> None:
    out = upstream_request_headers(
        [("Connection", "close, X-Hop"), ("X-Hop", "1"), ("Accept", "*/*"), ("TE", "trailers")],
        request_id="rid",
        tenant_id="acme",
        client_ip=None,
        scheme="https",
    )
    assert out == [
        ("Accept", "*/*"),
        ("x-request-id", "rid"),
        ("x-tenant-id", "acme"),
        ("x-forwarded-proto", "https"),
    ]


def test_response_headers_keep_duplicates_and_drop_hop_by_hop() -> None:
    out = downstream_response_headers(
        [
            (b"Set-Cookie", b"a=1"),
            (b"Set-Cookie", b"b=2"),
            (b"Transfer-Encoding", b"chunked"),
            (b"Connection", b"X-Internal"),
            (b"X-Internal", b"secret"),
            (b"X-Request-ID", b"upstream-id"),
            (b"Content-Type", b"application/json"),
        ]
    )
    assert out == [
        (b"set-cookie", b"a=1"),
        (b"set-cookie", b"b=2"),
        (b"content-type", b"application/json"),
    ]
