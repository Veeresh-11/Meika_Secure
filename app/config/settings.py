from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    # --------------------
    # Application
    # --------------------
    app_name: str = "Meika Secure ID"
    env: str = "local"

    # --------------------
    # Database (PostgreSQL)
    # --------------------
    db_host: str = Field(..., alias="DB_HOST")
    db_port: int = Field(5432, alias="DB_PORT")
    db_name: str = Field(..., alias="DB_NAME")
    db_user: str = Field(..., alias="DB_USER")
    db_password: str = Field(..., alias="DB_PASSWORD")
    
    
    signing_private_key: str = Field(..., alias="SIGNING_PRIVATE_KEY")

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        populate_by_name=True,
    )


settings = Settings()