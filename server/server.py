from fastapi import FastAPI, File, UploadFile, Form, APIRouter, Depends, HTTPException, Body
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
from server.database import get_db, engine, Base
from server.models.user import User, UserResponse
from dotenv import load_dotenv, set_key
from library.watermark import embed_watermark, extract_watermark
from library.cryto_tools import (
    generate_rsa_key_pair, 
    convert_private_key_to_pem,
    convert_public_key_to_pem,
    load_private_key_from_pem,
    load_public_key_from_pem,
    encrypt_server_public_key
)
from urllib.parse import unquote
import shutil
import os
import uuid
from pydantic import BaseModel
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Global variables for server keys
SERVER_PRIVATE_KEY = None
pub_key = None

def initialize_server_keys():
    global SERVER_PRIVATE_KEY, pub_key
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    
    # Check if keys exist in .env
    priv_key = os.getenv('SERVER_PRIVATE_KEY')
    pub_key = os.getenv('SERVER_PUBLIC_KEY')
    
    if not priv_key or not pub_key:
        # Generate new key pair
        private_key, public_key = generate_rsa_key_pair()
        
        # Convert to PEM format
        priv_pem = convert_private_key_to_pem(private_key)
        pub_pem = convert_public_key_to_pem(public_key)
        
        # Save to .env
        set_key(env_path, 'SERVER_PRIVATE_KEY', priv_pem)
        set_key(env_path, 'SERVER_PUBLIC_KEY', pub_pem)
        
        SERVER_PRIVATE_KEY = private_key
        pub_key = pub_pem
    else:
        # Load existing keys
        SERVER_PRIVATE_KEY = load_private_key_from_pem(priv_key)

# Initialize server keys before starting the app
initialize_server_keys()

app = FastAPI()
v1_router = APIRouter(prefix="/api/v1")

# Temporary directory for saving uploaded files
TEMP_DIR = "temp"
os.makedirs(TEMP_DIR, exist_ok=True)

# Create database tables
Base.metadata.create_all(bind=engine)

@v1_router.post("/user", response_model=UserResponse)
async def register_user(user_id: str = Body(..., embed=True), db: Session = Depends(get_db)):
    """
    Register a new user and generate an app key
    """
    # Generate API key
    api_key = str(uuid.uuid4())
    
    # Create new user
    db_user = User(
        user_id=user_id,
        user_api_key=api_key
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user

class UserKeyUpdate(BaseModel):
    app_key: str
    user_public_key: str

@v1_router.put("/user/{user_id}")
async def update_user_key(
    user_id: str,
    key_data: UserKeyUpdate,
    db: Session = Depends(get_db)
):
    """Update user's public key and return encrypted server public key"""
    try:
        logger.debug(f"Received update request for user: {user_id}")
        logger.debug(f"Request data: {key_data}")

        # Clean up public key
        user_public_key = key_data.user_public_key.strip()
        if not user_public_key.startswith('-----BEGIN PUBLIC KEY-----'):
            logger.error(f"Invalid public key format: {user_public_key[:50]}...")
            raise ValueError("Invalid public key format")

        # Verify user and app_key
        user = db.query(User).filter(
            User.user_id == user_id, 
            User.user_api_key == key_data.app_key
        ).first()
        
        if not user:
            logger.error(f"User verification failed - ID: {user_id}")
            raise HTTPException(status_code=404, detail="Invalid user or app key")
        
        logger.debug("User verified successfully")
        
        # Update user's public key and commit
        user.user_public_key = user_public_key
        db.commit()
        logger.debug("User public key updated in database")
        
        # Instead of returning the raw object, return the PEM string for json serialization
        sp_public_key_pem = pub_key
        logger.debug(f"Returning server public key PEM : {sp_public_key_pem[:50]}...")
        
        return {"sp_public_key": sp_public_key_pem}
    
    except ValueError as ve:
        logger.error(f"Validation error: {str(ve)}")
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Unexpected error during key exchange: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Key exchange failed: {str(e)}")

@v1_router.post("/embed-watermark/")
async def embed_watermark_api(
    image: UploadFile = File(...), 
    watermark_text: str = Form(...)
):
    """
    API to embed a watermark into an image.
    """
    input_path = os.path.join(TEMP_DIR, image.filename)
    output_path = os.path.join(TEMP_DIR, f"watermarked_{image.filename}")

    # Save the uploaded image to the temp directory
    with open(input_path, "wb") as buffer:
        shutil.copyfileobj(image.file, buffer)

    # Embed the watermark
    embed_watermark(input_path, watermark_text, output_path)

    # Return the watermarked image
    return FileResponse(output_path, media_type="image/jpeg", filename=f"watermarked_{image.filename}")


@v1_router.post("/extract-watermark/")
async def extract_watermark_api(
    image: UploadFile = File(...)
):
    """
    API to extract a watermark from an image.
    """
    input_path = os.path.join(TEMP_DIR, image.filename)

    # Save the uploaded image to the temp directory
    with open(input_path, "wb") as buffer:
        shutil.copyfileobj(image.file, buffer)

    # Extract the watermark with a fixed length of 215
    len_wm = 215
    extracted_text = extract_watermark(input_path, len_wm)

    # Return the extracted watermark text
    return JSONResponse(content={"watermark_text": extracted_text})

# Include the v1 router
app.include_router(v1_router)