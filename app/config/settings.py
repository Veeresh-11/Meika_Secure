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
    jwt_secret_key: str = Field(..., min_length=32, alias="JWT_SECRET_KEY")

    # WebAuthn relying-party configuration must match the deployed HTTPS origin.
    webauthn_rp_id: str = Field("localhost", alias="WEBAUTHN_RP_ID")
    webauthn_rp_name: str = Field("Meika Secure ID", alias="WEBAUTHN_RP_NAME")
    webauthn_expected_origins: str = Field("http://localhost", alias="WEBAUTHN_EXPECTED_ORIGINS")

    @property
    def webauthn_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.webauthn_expected_origins.split(",") if origin.strip()]

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        populate_by_name=True,
    )


settings = Settings()