# Invisible Proof - Watermark Library

## Overview
This project provides functionality to embed and extract watermarks in images using the `blind_watermark` package.

## Requirements
- Python 3.x
- OpenCV (`pip install opencv-python`)
- blind_watermark (`pip install blind-watermark`)
- FastAPI (`pip install fastapi`)
- Uvicorn (`pip install uvicorn`)
- cryptography (`pip install cryptography`)

## How to Run

### Running the Server
1. Open a terminal in `c:\GitHub\invisible-proof`.
2. Run the server with:
   ```bash
   uvicorn server.server:app --reload --log-level debug
   ```
   This starts the FastAPI server at http://127.0.0.1:8000.

### Running the Client
1. Open a terminal in `c:\GitHub\invisible-proof\client`.
2. Run the client with:
   ```bash
   python client.py
   ```
   This opens the GUI where you can upload an image, embed a watermark, and extract it.

## Modifications
- Adjust input/output image names and watermark text directly in `library/watermark.py` as needed.
---
### Specific Design (Server)
#### 0. 환경변수
- `KEY_STORAGE_BACKEND`
   - `file`: pem 파일
   - `vault`: HashiCorp Vault 사용
#### 1. Server key 생성
- `python create_server_key.py` 실행하면 비밀키, 공개키 key 쌍을 생성 후 `KEY_STORAGE_BACKEND` 값에 따라 key들을 저장
#### 2. User 등록 (App과 Server간 key 교환)
- REST POST /user data {'user_id':'<user_id>'} response: {'app_key':'<app_key value>'}
  ```bash
  # Linux
  curl -X POST "http://localhost:8000/api/v1/user" \
       -H "Content-Type: application/json" \
       -d '{"user_id":"tiffanie"}'

  # Windows (PowerShell)
  curl.exe -X POST "http://localhost:8000/api/v1/user" -H "Content-Type: application/json" -d '{\"user_id\":\"tiffanie\"}'
  ```
- Client 화면 최상단에 api_key 입력 후 `서버와 Key 교환` 버튼 누르면 아래 수행
- Client에서 user_public_key, user_private_key 생성 및 pem 파일로 저장
- Client에서 server(sp) call REST PUT /user/{user_id} data {'app_key':'<app_key value>', 'user_public_key':'<user_public_key>'} response: {'sp_public_key':'<sp_public_key encryped by user_public_key>'}
- REST PUT 실행되면 User table user_public_key, update_dt update
- Client는 sp_public_key 를 복호화 해서 파일(pem)로 저장
#### 3. 거래 (App에서 이미지를 보내고 Server에서 watermark 처리 후 return)
- User : Image 생성
- User : Image file hash 생성
- User : gen symmetric key
- User : payload : encryp (ID + timestamp + file hash) with symmetric key
- User : signature : signature (ID + timestamp) with user_private_key
- User : encryp (symmetric key) with sp_public_key
- REST POST /image image_file, data {'user_id':'<user_id>', 'payload':'', 'signature':'', 'symmetric_key':''}
   response watermarked_image_file data {'return_code':1}


