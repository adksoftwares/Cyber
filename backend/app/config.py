from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "ARY CyberShield"
    database_url: str = "sqlite:///./cybershield.db"
    ingest_key: str = "change-this-ingest-key"
    admin_key: str = "change-this-admin-key"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
