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
from library.tsa import (
    create_rfc3161_timestamp_request,
    get_timestamp_from_freetsa,
    extract_timestamp_time,
    verify_tsr_matches_file
)
from library.evidence_jws import build_evidence_json, sign_evidence
import shutil
import os
import uuid
import hashlib
import base64
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
    워터마크 이미지 삽입 및 증거 토큰 생성 API

    Parameters
    ----------
    image : UploadFile
        워터마크를 삽입할 원본 이미지 파일
    user_id : str 
        인증된 사용자 ID
    crypto_package : str
        클라이언트가 생성한 암호화 패키지 (JSON)
    db : Session
        데이터베이스 세션

    Returns
    -------
    JSONResponse
        {
            "image": base64로 인코딩된 워터마크 이미지,
            "evidence_token": JWS 서명된 증거 토큰
        }

    Raises
    ------
    HTTPException(404)
        사용자를 찾을 수 없거나 공개키가 설정되지 않은 경우
    HTTPException(400) 
        잘못된 crypto_package
    HTTPException(500)
        서버 개인키가 초기화되지 않은 경우
    """
    # 1. 업로드된 이미지를 임시 파일로 저장
    input_path = os.path.join(temp_dir, image.filename)
    output_path = os.path.join(temp_dir, f"watermarked_{image.filename}")
    with open(input_path, "wb") as buffer:
        shutil.copyfileobj(image.file, buffer)

    # 2. 사용자 정보 검증
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user or not user.user_public_key:
        raise HTTPException(status_code=404, detail="User not found or public key not set")

    # 3. 서버 개인키 확인
    if not private_key_pem:
        raise HTTPException(status_code=500, detail="Server private key not initialized")

    # 4. 암호화 패키지 검증
    logger.debug(f"Verifying crypto package for user {user_id}")
    logger.debug(f"crypto_package: {crypto_package}")
    is_valid = verify_crypto_package(
            crypto_package,
            private_key_pem,
            user.user_public_key,
            input_path
    )
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid crypto package")

    # 5. 워터마크 텍스트 생성 및 삽입
    watermark_text = watermark_template.format(user_id=user_id)
    len = embed_watermark(input_path, watermark_text, output_path, 
                         user.password_img, user.password_wm)
    logger.debug(f"Watermark length: {len}")

    # 6. RFC 3161 타임스탬프 생성
    tsq_der = create_rfc3161_timestamp_request(output_path, request_path=None)
    tsr_data = get_timestamp_from_freetsa(tsq_der, response_path=None)
    gen_time = extract_timestamp_time(tsr_data)

    # 7. CA/TSA 인증서 경로
    ca_cert_path = os.path.join("resources", "cacert.pem")
    tsa_cert_path = os.path.join("resources", "tsa.pem")

    # 8. 워터마크 이미지 처리 및 해시 계산
    with open(output_path, "rb") as f:
        file_size = os.path.getsize(output_path)
        image_data = f.read()
        file_sha256 = hashlib.sha256(image_data).hexdigest()

    # 9. 증거 JSON 생성 및 JWS 서명
    evidence = build_evidence_json(
        user_id=user_id,
        watermarked_url=f"watermarked_{image.filename}",
        file_sha256=file_sha256,
        file_size=file_size,
        wm_text=watermark_text,
        tsq_der=tsq_der,
        tsr_der=tsr_data,
        tsa_pem=tsa_cert_path,
        cacert_pem=ca_cert_path,
        gen_time=gen_time.isoformat() + "Z"
    )
    evidence_token = sign_evidence(evidence, private_key_pem)

    # 10. 응답 데이터 구성
    response_data = {
        "image": base64.b64encode(image_data).decode('utf-8'),
        "evidence_token": evidence_token
    }

    return JSONResponse(content=response_data)

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