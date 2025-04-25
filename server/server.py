from fastapi import File, UploadFile, Form, APIRouter, Depends, HTTPException, Body
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
from server.database import get_db
from server.models.user import User, UserKeyUpdate, UserResponse
from library.watermark import embed_watermark, extract_watermark
from library.cryto_tools import (
    generate_rsa_key_pair, 
    convert_private_key_to_pem,
    convert_public_key_to_pem,
    load_private_key_from_pem,
    verify_crypto_package
)
import shutil
import os
import uuid
import hashlib
from server import watermark_template, watermark_template_len, public_key_pem, \
    private_key_pem, temp_dir, logger, app

v1_router = APIRouter(prefix="/api/v1")

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
        
        password_img = key_data.password_img
        password_wm = key_data.password_wm

        watermark_text = watermark_template.format(user_id=user_id)
        watermark_length = len(watermark_text)*8 - 1

        if not password_img or not password_wm:
            logger.error(f"password_img and password_wm are mandatary. password_img : {password_img}, password_wm : {password_wm}")
            raise ValueError(f"password_img and password_wm are mandatary. password_img : {password_img}, password_wm : {password_wm}")

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
        user.password_img = password_img
        user.password_wm = password_wm
        user.watermark_length = watermark_length

        db.commit()
        logger.debug("User public key updated in database")
        
        # Instead of returning the raw object, return the PEM string for json serialization
        logger.debug(f"Returning server public key PEM : {public_key_pem[:50]}...")
        
        return {"sp_public_key": public_key_pem}
    
    except ValueError as ve:
        logger.error(f"Validation error: {str(ve)}")
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Unexpected error during key exchange: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Key exchange failed: {str(e)}")

@v1_router.post("/watermark/")
async def embed_watermark_api(
    image: UploadFile = File(...),
    user_id: str = Form(...),
    crypto_package: str = Form(...),
    db: Session = Depends(get_db)
):
    """
    API to embed a watermark into an image with crypto package verification
    """
    input_path = os.path.join(temp_dir, image.filename)
    output_path = os.path.join(temp_dir, f"watermarked_{image.filename}")

    with open(input_path, "wb") as buffer:
        shutil.copyfileobj(image.file, buffer)

    # Get user's public key from database
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user or not user.user_public_key:
        raise HTTPException(status_code=404, detail="User not found or public key not set")

    # Use global SERVER_PRIVATE_KEY
    if not private_key_pem:
        raise HTTPException(status_code=500, detail="Server private key not initialized")

    logger.debug(f"Verifying crypto package for user {user_id}")
    # Convert private key to PEM format for verify_crypto_package
            
    logger.debug(f"crypto_package: {crypto_package}")  # Debugging line
    logger.debug(f"Server private key PEM: {private_key_pem}...")  # Debugging line
    is_valid = verify_crypto_package(
            crypto_package,
            private_key_pem,
            user.user_public_key,
            input_path
    )

    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid crypto package")

    # Create watermark text using template
    watermark_text = watermark_template.format(user_id=user_id)
        
    # Embed watermark with global passwords
    len = embed_watermark(input_path, watermark_text, output_path, user.password_img, user.password_wm)
    logger.debug(f"Watermark length: {len}")  # Debugging line

    return FileResponse(output_path, media_type="image/jpeg", filename=f"watermarked_{image.filename}")

@v1_router.post("/extract-watermark/")
async def extract_watermark_api(
    image: UploadFile = File(...),
    user_id: str = Form(...),
    db: Session = Depends(get_db)
):
    """
    API to extract a watermark from an image.
    """
    input_path = os.path.join(temp_dir, image.filename)

    # Save the uploaded image to the temp directory
    with open(input_path, "wb") as buffer:
        shutil.copyfileobj(image.file, buffer)
    
    # Get user's public key from database
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Extract the watermark with updated parameters
    logger.debug(f"extract_watermark inputs - input_path:{input_path}, password_img:{user.password_img}, password_wm:{user.password_wm}, len_wm:{user.watermark_length}")
    extracted_text = extract_watermark(input_path, user.password_img, user.password_wm, user.watermark_length)
    logger.debug(f"extracted_text: {extracted_text}")  # Debugging line

    # Return the extracted watermark text
    return JSONResponse(content={"watermark_text": extracted_text})

# Include the v1 router
app.include_router(v1_router)