from pydantic_settings import BaseSettingsModel
from dotenv import load_dotenv
import os

load_dotenv()

class Settings(BaseSettingsModel):
    app_name: str = "Awesome API"
    MODEL_PATH: str
    FEATURE_VERSION: int = 2
    THRESHOLD: float = 0.5
    MAX_FILE_SIZE: int
    UPLOADED_FILES_DIR: str

settings = Settings(
    MODEL_PATH=os.getenv('MODEL_PATH'),
    FEATURE_VERSION=os.getenv('FEATURE_VERSION', 2),
    THRESHOLD=os.getenv('THRESHOLD', 0.5),
    MAX_FILE_SIZE=os.getenv('MAX_FILE_SIZE', 10485760),
    UPLOADED_FILES_DIR=os.getenv('UPLOADED_FILES_DIR', 'uploaded_file')
)
