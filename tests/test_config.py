import os

import pytest

from net_sec_investigation.config import ConfigError, load_settings

# a path that will never exist, so load_dotenv() is a no-op
NO_ENV = os.devnull


def _set_required(monkeypatch):
    monkeypatch.setenv("POSTGRES_PASSWORD", "pw")
    monkeypatch.setenv("NEO4J_PASSWORD", "pw")


def test_defaults_apply_when_optional_vars_unset(monkeypatch):
    for key in ("POSTGRES_HOST", "POSTGRES_PORT", "LOG_LEVEL"):
        monkeypatch.delenv(key, raising=False)
    _set_required(monkeypatch)

    settings = load_settings(NO_ENV)

    assert settings.postgres_host == "localhost"
    assert settings.postgres_port == 5432
    assert settings.log_level == "INFO"
    
def test_missing_password_raises(monkeypatch):
    monkeypatch.setenv("NEO4J_PASSWORD", "pw")
    monkeypatch.delenv("POSTGRES_PASSWORD", raising=False)

    with pytest.raises(ConfigError):
        load_settings(NO_ENV)


def test_port_is_parsed_to_int(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("POSTGRES_PORT", "5433")

    settings = load_settings(NO_ENV)

    assert settings.postgres_port == 5433
    assert isinstance(settings.postgres_port, int)


def test_invalid_port_raises(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("POSTGRES_PORT", "banana")

    with pytest.raises(ConfigError):
        load_settings(NO_ENV)


def test_invalid_log_level_raises(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("LOG_LEVEL", "BANANA")

    with pytest.raises(ConfigError):
        load_settings(NO_ENV)