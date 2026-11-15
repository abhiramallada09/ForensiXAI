import os
from pathlib import Path
from typing import List, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "ForensiX AI"
    APP_DESCRIPTION: str = "AI-Assisted Memory Forensics and Evidence Reconstruction Platform"
    ACADEMIC_TITLE: str = (
        "Memory Forensics for Volatile Data Analysis via Deep Learning-based "
        "Deleted File and Timestamp Reconstruction, Applied to Cloud Service "
        "Provider (SaaS/IaaS) Evidence Recovery"
    )
    APP_ENV: str = "development"
    APP_VERSION: str = "0.1.0"
    
    # Database
    DATABASE_URL: str = "sqlite:///./database.db"
    
    # Storage Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent.parent
    UPLOAD_DIR: str = "./data/uploads"
    WORKING_DIR: str = "./data/working"
    REPORT_DIR: str = "./data/reports"
    MODEL_DIR: str = "./models"
    
    # Limits & Security
    MAX_UPLOAD_SIZE_MB: int = 2048
    SECRET_KEY: str = "forensix_development_secret_key_change_in_production"
    VOLATILITY_PATH: str = ""
    LOG_LEVEL: str = "INFO"
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    def resolved_upload_dir(self) -> Path:
        p = Path(self.UPLOAD_DIR)
        if not p.is_absolute():
            p = self.BASE_DIR / p
        p.mkdir(parents=True, exist_ok=True)
        return p

    def resolved_working_dir(self) -> Path:
        p = Path(self.WORKING_DIR)
        if not p.is_absolute():
            p = self.BASE_DIR / p
        p.mkdir(parents=True, exist_ok=True)
        return p

    def resolved_report_dir(self) -> Path:
        p = Path(self.REPORT_DIR)
        if not p.is_absolute():
            p = self.BASE_DIR / p
        p.mkdir(parents=True, exist_ok=True)
        return p


settings = Settings()

