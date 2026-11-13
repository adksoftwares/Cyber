from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "ARY CyberShield"
    database_url: str = "sqlite:///./cybershield.db"
    ingest_key: str = "change-this-ingest-key"
    admin_key: str = "change-this-admin-key"
    allowed_origins: list[str] = ["http://localhost:5173"]
    cloudflare_api_token: str = ""
    cloudflare_zone_id: str = ""
    otx_api_key: str = ""
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()

