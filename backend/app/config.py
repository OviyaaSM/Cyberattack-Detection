import os
from typing import List
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseModel):
    PROJECT_NAME: str = "Intelligent Cyberattack Detection Using Temporal Knowledge Representation"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    # Database - anchor default sqlite path to backend directory for consistency
    _default_db = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "cyberattack_detection.db")).replace("\\", "/")
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{_default_db}")
    
    # Server
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # CORS
    CORS_ORIGINS: List[str] = [
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,*"
        ).split(",")
        if origin.strip()
    ]
    
    # AI / LLM Integration (optional)
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "deterministic")
    AI_API_KEY: str = os.getenv("AI_API_KEY", "")
    
    # Temporal & Detection Thresholds
    BRUTE_FORCE_WINDOW_MINUTES: int = int(os.getenv("BRUTE_FORCE_WINDOW_MINUTES", "10"))
    BRUTE_FORCE_MIN_FAILURES: int = int(os.getenv("BRUTE_FORCE_MIN_FAILURES", "3"))
    LATERAL_MOVEMENT_WINDOW_MINUTES: int = int(os.getenv("LATERAL_MOVEMENT_WINDOW_MINUTES", "30"))
    DATA_EXFILTRATION_WINDOW_MINUTES: int = int(os.getenv("DATA_EXFILTRATION_WINDOW_MINUTES", "20"))
    PRIVILEGE_ESCALATION_WINDOW_MINUTES: int = int(os.getenv("PRIVILEGE_ESCALATION_WINDOW_MINUTES", "15"))
    MULTI_STAGE_WINDOW_MINUTES: int = int(os.getenv("MULTI_STAGE_WINDOW_MINUTES", "60"))

settings = Settings()
