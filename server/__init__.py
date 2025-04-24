from dotenv import load_dotenv, set_key
from fastapi import FastAPI
from server.models.user import User
from library.cryto_tools import (
    generate_rsa_key_pair, 
    convert_private_key_to_pem,
    convert_public_key_to_pem,
    load_private_key_from_pem,
    verify_crypto_package
)
from server.database import engine, Base
import os
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path=env_path)

# Global variables for server keys and watermark passwords
watermark_template = os.getenv('WATERMARK_TEMPLATE')
print(f"watermark_template : {watermark_template} {len(watermark_template)-9}")

watermark_template_len = len(watermark_template)-9

# Check if keys exist in .env
private_key_pem = os.getenv('SERVER_PRIVATE_KEY')
public_key_pem = os.getenv('SERVER_PUBLIC_KEY')
    
if not private_key_pem or not public_key_pem:

    # Generate new key pair
    private_key, public_key = generate_rsa_key_pair()
        
    # Convert to PEM format
    private_key_pem = convert_private_key_to_pem(private_key)
    public_key_pem = convert_public_key_to_pem(public_key)
        
    # Save to .env
    set_key(env_path, 'SERVER_PRIVATE_KEY', private_key_pem)
    set_key(env_path, 'SERVER_PUBLIC_KEY', public_key_pem)
        
app = FastAPI()

# Temporary directory for saving uploaded files
temp_dir = "temp"
os.makedirs(temp_dir, exist_ok=True)

# Create database tables
Base.metadata.create_all(bind=engine)

