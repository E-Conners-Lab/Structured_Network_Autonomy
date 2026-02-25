"""Application configuration via environment variables with Pydantic validation.

All configuration is loaded from environment variables (with .env file support).
The app fails loudly at startup if required values are missing or invalid.
"""

from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """SNA application settings. All values sourced from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Database
    database_url: str = "sqlite+aiosqlite:///./sna.db"
    db_pool_timeout: int = 5
    db_connect_timeout: int = 5

    # Policy
    policy_file_path: str = "./policies/default.yaml"

    # Notifications — both optional, notifications sent to whichever is configured
    discord_webhook_url: AnyHttpUrl | None = None
    teams_webhook_url: AnyHttpUrl | None = None

    # EAS — new agents start near-zero trust
    default_eas: float = 0.1

    # API server
    api_host: str = "127.0.0.1"
    api_port: int = 8000

    # Authentication — required, app will not start without these
    sna_api_key: str
    sna_admin_api_key: str

    # Dashboard
    dashboard_enabled: bool = True
    dashboard_static_path: str = "./dashboard/dist"

    # CORS
    cors_allowed_origins: str = "http://localhost:3000,http://localhost:5173"

    # HTTP client
    httpx_timeout_seconds: float = 10.0

    # Request limits
    max_request_body_bytes: int = 1_048_576

    # Rate limiting (requests per minute)
    rate_limit_evaluate: int = 100
    rate_limit_escalation_decision: int = 20
    rate_limit_policy_reload: int = 5

    # Agent defaults
    default_agent_eas: float = 0.1

    # MCP Server
    mcp_server_host: str = "127.0.0.1"
    mcp_server_port: int = 8001
    mcp_transport: str = "stdio"

    # NetBox integration
    netbox_url: str | None = None
    netbox_token: str | None = None
    netbox_sync_interval: int = 300  # seconds
    netbox_cache_ttl: float = 300.0  # seconds

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    @field_validator("database_url")
    @classmethod
    def database_url_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("DATABASE_URL must not be empty")
        return v

    @field_validator("sna_api_key", "sna_admin_api_key")
    @classmethod
    def api_keys_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("API keys must not be empty — set SNA_API_KEY and SNA_ADMIN_API_KEY")
        return v

    @field_validator("default_eas")
    @classmethod
    def eas_in_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("DEFAULT_EAS must be between 0.0 and 1.0")
        return v

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse comma-separated CORS origins into a list."""
        return [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]


def get_settings() -> Settings:
    """Create and return a validated Settings instance.

    Raises ValidationError with clear messages if required env vars are missing.
    """
    return Settings()  # type: ignore[call-arg]
