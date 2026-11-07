from app.config import load_environment
from app.threat_intel.urlhaus import UrlhausProvider


def test_backend_env_file_loads_urlhaus_api_key(tmp_path, monkeypatch) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("URLHAUS_API_KEY=unit-test-key\n", encoding="utf-8")
    monkeypatch.delenv("URLHAUS_API_KEY", raising=False)

    load_environment(env_file)

    provider = UrlhausProvider()
    assert provider.api_key == "unit-test-key"
