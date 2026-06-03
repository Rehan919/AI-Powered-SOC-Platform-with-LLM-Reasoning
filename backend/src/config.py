import os


def _csv_env(name: str, default: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentinelforge.db")
LLM_URL = os.getenv("LLM_URL", "http://localhost:8080")
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "http://localhost:9999/webhook")
CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
CORS_ORIGINS = _csv_env("CORS_ORIGINS", "http://localhost:3000")

# Dedup window (minutes) for correlating repeat alerts into one incident
DEDUP_WINDOW_MIN = int(os.getenv("DEDUP_WINDOW_MIN", "60"))

# Wazuh indexer (OpenSearch) for real log search
INDEXER_URL = os.getenv("INDEXER_URL", "https://localhost:9200")
INDEXER_USER = os.getenv("INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("INDEXER_PASS", "SecretPassword")

# Wazuh manager API for real active-response
WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://localhost:55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = os.getenv("WAZUH_API_PASS", "MyS3cr37P450r.*-")

# Optional threat-intel + auth (off by default)
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
API_KEY = os.getenv("API_KEY", "")
