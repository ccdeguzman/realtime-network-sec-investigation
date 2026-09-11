
import pytest

from net_sec_investigation.config import ConfigError, load_settings


@pytest.fixture
def no_env_file(tmp_path):
    """A .env path that doesn't exist, so the developer's real .env is never read."""
    return tmp_path / ".env"


def _set_required(monkeypatch):
    monkeypatch.setenv("POSTGRES_PASSWORD", "pw")
    monkeypatch.setenv("NEO4J_PASSWORD", "pw")


def test_defaults_apply_when_optional_vars_unset(monkeypatch):
    for key in ("POSTGRES_HOST", "POSTGRES_PORT", "LOG_LEVEL"):
        monkeypatch.delenv(key, raising=False)
    _set_required(monkeypatch)

    settings = load_settings(no_env_file)

    assert settings.postgres_host == "localhost"
    assert settings.postgres_port == 5432
    assert settings.log_level == "INFO"
    
def test_missing_password_raises(monkeypatch):
    monkeypatch.setenv("NEO4J_PASSWORD", "pw")
    monkeypatch.delenv("POSTGRES_PASSWORD", raising=False)

    with pytest.raises(ConfigError):
        load_settings(no_env_file)


def test_port_is_parsed_to_int(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("POSTGRES_PORT", "5433")

    settings = load_settings(no_env_file)

    assert settings.postgres_port == 5433
    assert isinstance(settings.postgres_port, int)


def test_invalid_port_raises(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("POSTGRES_PORT", "banana")

    with pytest.raises(ConfigError):
        load_settings(no_env_file)


def test_invalid_log_level_raises(monkeypatch):
    _set_required(monkeypatch)
    monkeypatch.setenv("LOG_LEVEL", "BANANA")

    with pytest.raises(ConfigError):
        load_settings(no_env_file)
        
def test_values_are_read_from_given_env_file(monkeypatch, tmp_path):
    _set_required(monkeypatch)
    # load_dotenv writes into os.environ, but monkeypatch only undoes its OWN
    # changes. setenv-then-delenv registers LOG_LEVEL with monkeypatch, so it
    # gets restored after this test instead of leaking DEBUG into others.
    monkeypatch.setenv("LOG_LEVEL", "placeholder")
    monkeypatch.delenv("LOG_LEVEL")

    env_file = tmp_path / ".env"
    env_file.write_text("LOG_LEVEL=DEBUG\n")

    settings = load_settings(env_file)

    assert settings.log_level == "DEBUG"