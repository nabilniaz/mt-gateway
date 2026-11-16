import pytest

from gateway.paths import InvalidPath, has_prefix, normalize_path, normalize_prefix


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"/", "/"),
        (b"/orders/42", "/orders/42"),
        (b"/orders/42/", "/orders/42/"),
        (b"/orders/42?x=1", "/orders/42"),
        (b"/files/caf%C3%A9", "/files/café"),
        (b"/search/a%20b", "/search/a b"),
        (b"/v1.2/file.txt", "/v1.2/file.txt"),
        (b"/a/...", "/a/..."),  # three dots is an ordinary name
    ],
)
def test_accepts_clean_paths(raw: bytes, expected: str) -> None:
    assert normalize_path(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        b"/orders/../admin",
        b"/orders/./admin",
        b"/orders/..",
        b"/orders/%2e%2e/admin",
        b"/orders/%2E%2E/admin",
        b"/orders/.%2e/admin",
        b"/orders%2fadmin",
        b"/orders%2Fadmin",
        b"/orders%5cadmin",
        b"/orders\\admin",
        b"//admin",
        b"/orders//admin",
        b"/orders/%00",
        b"/orders/%0a",
        b"/orders/%7f",
        b"/orders/%252e%252e/admin",  # double encoding
        b"/orders/%zz",
        b"/orders/%C3",  # truncated UTF-8
        b"/caf\xc3\xa9",  # raw non-ASCII bytes
        b"orders",
        b"",
        b"/" + b"a" * 2048,
    ],
)
def test_rejects_ambiguous_paths(raw: bytes) -> None:
    with pytest.raises(InvalidPath) as exc:
        normalize_path(raw)
    assert exc.value.status == 400
    assert exc.value.code == "invalid_path"


@pytest.mark.parametrize(
    ("prefix", "expected"),
    [("/", "/"), ("/orders", "/orders"), ("/orders/", "/orders"), ("/a/b", "/a/b")],
)
def test_normalize_prefix(prefix: str, expected: str) -> None:
    assert normalize_prefix(prefix) == expected


@pytest.mark.parametrize("prefix", ["orders", "/a/../b", "/a%20b", "//x"])
def test_normalize_prefix_rejects(prefix: str) -> None:
    with pytest.raises(ValueError, match=r"."):
        normalize_prefix(prefix)


@pytest.mark.parametrize(
    ("path", "prefix", "expected"),
    [
        ("/orders", "/orders", True),
        ("/orders/42", "/orders", True),
        ("/orders/", "/orders", True),
        ("/ordersX", "/orders", False),
        ("/order", "/orders", False),
        ("/anything", "/", True),
        ("/orders/admin/7", "/orders/admin", True),
    ],
)
def test_has_prefix_respects_segment_boundaries(path: str, prefix: str, expected: bool) -> None:
    assert has_prefix(path, prefix) is expected
