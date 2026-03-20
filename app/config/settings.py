# app/config/settings.py

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --------------------
    # Application
    # --------------------
    APP_NAME: str = "Meika Secure ID"
    ENV: str = "local"

    # --------------------
    # Database (PostgreSQL)
    # --------------------
    DB_HOST: str
    DB_PORT: int = 5432
    DB_NAME: str
    DB_USER: str
    DB_PASSWORD: str

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
    )


settings = Settings()

