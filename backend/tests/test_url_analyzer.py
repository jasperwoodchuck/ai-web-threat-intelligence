from app.analyzers.url import UrlAnalyzer


def test_normal_https_url_is_normalized() -> None:
    result = UrlAnalyzer().analyze("https://example.com")

    assert result.is_valid is True
    assert result.original_url == "https://example.com"
    assert result.normalized_url == "https://example.com/"
    assert result.scheme == "https"
    assert result.hostname == "example.com"
    assert result.path == "/"
    assert result.registered_domain == "example.com"


def test_http_url_is_supported() -> None:
    result = UrlAnalyzer().analyze("http://example.com/")

    assert result.is_valid is True
    assert result.scheme == "http"
    assert result.normalized_url == "http://example.com/"


def test_uppercase_scheme_and_hostname_are_normalized() -> None:
    result = UrlAnalyzer().analyze("HTTPS://EXAMPLE.COM/Path")

    assert result.is_valid is True
    assert result.scheme == "https"
    assert result.hostname == "example.com"
    assert result.normalized_url == "https://example.com/Path"


def test_subdomain_is_extracted() -> None:
    result = UrlAnalyzer().analyze("https://shop.eu.example.com/")

    assert result.subdomain == "shop.eu"
    assert result.registered_domain == "example.com"


def test_path_query_and_fragment_are_preserved() -> None:
    result = UrlAnalyzer().analyze("https://example.com/a/b?next=home#section")

    assert result.path == "/a/b"
    assert result.has_query is True
    assert result.has_fragment is True
    assert result.normalized_url == "https://example.com/a/b?next=home#section"


def test_multipart_public_suffix_is_supported() -> None:
    result = UrlAnalyzer().analyze("https://store.example.co.uk/")

    assert result.registered_domain == "example.co.uk"
    assert result.subdomain == "store"
    assert result.public_suffix == "co.uk"


def test_explicit_port_is_preserved() -> None:
    result = UrlAnalyzer().analyze("https://example.com:8443/status")

    assert result.port == 8443
    assert result.normalized_url == "https://example.com:8443/status"


def test_ip_address_hostname_is_detected() -> None:
    result = UrlAnalyzer().analyze("http://192.0.2.10/path")

    assert result.is_ip_address is True
    assert result.hostname == "192.0.2.10"
    assert result.registered_domain is None


def test_username_and_password_presence_are_reported() -> None:
    result = UrlAnalyzer().analyze("https://user:secret@example.com/path")

    assert result.is_valid is True
    assert result.has_username is True
    assert result.has_password is True
    assert result.normalized_url == "https://user:secret@example.com/path"


def test_malformed_url_is_not_rewritten_as_valid() -> None:
    result = UrlAnalyzer().analyze("https:///missing-host")

    assert result.is_valid is False
    assert result.normalized_url is None
    assert result.original_url == "https:///missing-host"
    assert result.validation_error


def test_invalid_percent_escape_is_rejected() -> None:
    result = UrlAnalyzer().analyze("https://example.com/%ZZ")

    assert result.is_valid is False
    assert result.normalized_url is None


def test_unsupported_schemes_are_rejected() -> None:
    for url in ("ftp://example.com/file", "file:///tmp/a", "javascript:alert(1)"):
        result = UrlAnalyzer().analyze(url)

        assert result.is_valid is False
        assert result.normalized_url is None
        assert result.validation_error == "Only HTTP and HTTPS URLs are supported."
