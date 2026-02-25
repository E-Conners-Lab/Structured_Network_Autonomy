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
        extra="ignore",
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

    # Device enrichment
    enrichment_enabled: bool = True
    enrichment_criticality_default: float = 0.5

    # Validation
    validation_trigger_rollback: bool = True
    pyats_enabled: bool = False
    pyats_testbed_path: str | None = None

    # Batch operations
    max_batch_size: int = 10
    rate_limit_batch: int = 5

    # Slack integration
    slack_webhook_url: AnyHttpUrl | None = None

    # PagerDuty integration
    pagerduty_routing_key: str | None = None
    pagerduty_api_url: str = "https://events.pagerduty.com/v2/enqueue"

    # OpenTelemetry
    otel_enabled: bool = False
    otel_endpoint: str | None = None
    otel_service_name: str = "sna"

    # Vault integration
    vault_addr: str | None = None
    vault_token: str | None = None
    vault_mount_path: str = "secret"
    vault_tls_verify: bool = True
    vault_cache_ttl: int = 300

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
        if len(v.strip()) < 32:
            raise ValueError("API keys must be at least 32 characters")
        return v

    @field_validator("default_eas")
    @classmethod
    def eas_in_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("DEFAULT_EAS must be between 0.0 and 1.0")
        return v

    # Device inventory
    inventory_file_path: str | None = None

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse comma-separated CORS origins into a list.

        Rejects wildcard '*' when allow_credentials=True (browser security).
        Warns on non-HTTPS origins (except localhost).
        """
        import logging

        origins = [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]
        validated: list[str] = []
        for origin in origins:
            if origin == "*":
                logging.getLogger(__name__).warning(
                    "CORS origin '*' is not allowed with allow_credentials=True — skipping"
                )
                continue
            if not origin.startswith("https://") and "localhost" not in origin and "127.0.0.1" not in origin:
                logging.getLogger(__name__).warning(
                    "CORS origin '%s' is not HTTPS — consider using HTTPS in production", origin
                )
            validated.append(origin)
        return validated


def get_settings() -> Settings:
    """Create and return a validated Settings instance.

    Raises ValidationError with clear messages if required env vars are missing.
    """
    return Settings()  # type: ignore[call-arg]
