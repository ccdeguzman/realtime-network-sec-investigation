import os
from dataclasses import dataclass, field
from pathlib import Path
from dotenv import load_dotenv


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""
    pass

@dataclass
class Settings:
    postgres_host: str
    postgres_port: int
    postgres_db: str
    postgres_user: str
    postgres_password: str = field(repr=False)
    
    neo4j_uri: str
    neo4j_user: str
    neo4j_password: str = field(repr=False)
    
    qdrant_url: str
    ollama_url: str
    
    log_level: str

def _require(key: str) -> str:
    value = os.getenv(key)
    if not value:
        raise ConfigError(f"Missing required environment variable: {key}")
    return value

def _int(key, default) -> int:
    value = os.getenv(key, str(default))
    try:
        return int(value)
    except ValueError:
        raise ConfigError(
            f"Environment variable {key} must be an integer, got: {value!r}"
        ) from None
        
def load_settings(dotenv_path: str | Path | None = None) -> Settings:
    load_dotenv(dotenv_path)
    
    return Settings(
        postgres_host=os.getenv("POSTGRES_HOST", "localhost"),
        postgres_password=_require("POSTGRES_PASSWORD"),
        postgres_port=_int("POSTGRES_PORT", 5432), 
        postgres_db=os.getenv("POSTGRES_DB", "postgres"),
        postgres_user=os.getenv("POSTGRES_USER", "postgres"),
        
        # Neo4j
        neo4j_uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
        neo4j_user=os.getenv("NEO4J_USER", "neo4j"),
        neo4j_password=_require("NEO4J_PASSWORD"),
        
        # Qdrant
        qdrant_url=os.getenv("QDRANT_URL", "http://localhost:6333"),
        
        # Ollama
        ollama_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
        
        # Logging
        log_level=_log_level("LOG_LEVEL", "INFO")
    )
    
VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})

def _log_level(key: str, default: str) -> str:
    value=os.getenv(key.upper(), default).upper()
    if value not in VALID_LOG_LEVELS:
        raise ConfigError(
            f"Invalid value for {key}: {value!r}. "
            f"Valid options are: {', '.join(sorted(VALID_LOG_LEVELS))}"
        )
    return value