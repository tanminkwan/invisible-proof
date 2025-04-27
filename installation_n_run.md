# 설치 및 실행 가이드 - Invisible Proof

## 사전 요구 사항
- Python 3.10+
- OpenSSL (암호화 작업용)
- 인터넷 연결 (FreeTSA 타임스탬프 발급용)

## 필수 Python 패키지
`pip`를 사용하여 필요한 패키지를 설치합니다:
```bash
pip install -r requirements.txt
```

## 환경 변수 설정
### 클라이언트 (`./client/.env`)
```bash
USER_ID=your-username
SERVER_URL=http://localhost:8000/api/v1
```

### 서버 (`./server/.env`)
- SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY는 없는 경우 서버 부팅 시 자동 생성됩니다.
```bash
DB_CONNECTION_STRING=sqlite:///./app.db
SERVER_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----...
SERVER_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----...
WATERMARK_TEMPLATE=Owned by {user_id}, certified by the Tanminkwan Foundation.
```

### 인증서
FreeTSA 인증서를 다운로드하여 저장합니다:
- [TSA 인증서](https://freetsa.org/files/tsa.crt)
- [CA 인증서](https://freetsa.org/files/cacert.pem)

이 파일들을 `resources` 디렉토리에 저장합니다:
```
resources/
  ├── tsa.crt
  ├── cacert.pem
```

---

## 서버 실행
1. 프로젝트 루트 디렉토리로 이동:
   ```bash
   cd c:\GitHub\invisible-proof
   ```
2. FastAPI 서버 시작:
   ```bash
   uvicorn server.server:app --reload
   ```

---

## 클라이언트 실행
1. 클라이언트 디렉토리로 이동:
   ```bash
   cd client
   ```
2. GUI 애플리케이션 실행:
   ```bash
   python client.py
   ```

---

## 워터마크 삽입 절차

### 1. 사용자 등록 및 키 교환
1. **사용자 등록**:
   - 클라이언트에서 API 키를 발급받습니다.
   ```bash
   curl -X POST "http://localhost:8000/api/v1/user" \
        -H "Content-Type: application/json" \
        -d '{"user_id":"your-username"}'
   ```
   - 서버는 사용자 ID와 함께 고유한 API 키를 반환합니다.

2. **키 교환**:
   - 클라이언트 GUI에서 발급받은 API 키를 입력하고 "서버와 Key 교환" 버튼을 클릭합니다.
   - 클라이언트는 RSA 키 쌍을 생성하고, 공개키를 서버로 전송합니다.
   - 서버는 사용자 공개키를 저장하고, 서버 공개키를 클라이언트로 반환합니다.
   - 클라이언트는 서버 공개키를 복호화하여 `.env` 파일에 저장합니다.

---

### 2. 워터마크 삽입 요청
1. **이미지 업로드**:
   - 클라이언트 GUI에서 "Upload Image" 버튼을 클릭하여 워터마크를 삽입할 이미지를 선택합니다.
   - 선택한 이미지는 클라이언트 애플리케이션에 표시됩니다.

2. **워터마크 삽입**:
   - "Embed WM" 버튼을 클릭하여 워터마크 삽입을 요청합니다.
   - 클라이언트는 다음 작업을 수행합니다:
     - 이미지 파일의 SHA-256 해시를 계산합니다.
     - 암호화 패키지(crypto_package)를 생성합니다.
     - 서버로 이미지 파일과 암호화 패키지를 전송합니다.

3. **서버 처리**:
   - 서버는 다음 작업을 수행합니다:
     - 클라이언트에서 전송된 암호화 패키지를 검증합니다.
     - 이미지에 워터마크를 삽입합니다.
     - RFC3161 타임스탬프를 생성하고 검증합니다.
     - 워터마크, 타임스탬프, 메타데이터를 포함한 Evidence JSON을 생성합니다.
     - Evidence JSON을 JWS 토큰으로 서명합니다.
     - 워터마크가 삽입된 이미지와 JWS 토큰을 클라이언트로 반환합니다.

4. **결과 확인**:
   - 클라이언트는 서버로부터 반환된 워터마크 이미지와 JWS 토큰을 저장합니다.
   - JWS 토큰의 서명을 검증하고, Evidence JSON의 내용을 로그로 출력합니다.

---

## 로그 확인 방법

### 클라이언트 로그
- 클라이언트 실행 중 발생하는 모든 로그는 터미널에 출력됩니다.
- 주요 로그:
  - **워터마크 삽입 요청 시작**: `Starting watermark embedding process`
    - 워터마크 삽입 프로세스가 시작되었음을 나타냅니다.
    - 클라이언트가 서버로 이미지를 업로드하고 암호화 패키지를 전송하기 직전 단계입니다.
  - **Evidence JSON 디코딩**: `Evidence Token Payload:`
    - 서버에서 반환된 JWS 토큰을 디코딩하여 Evidence JSON의 내용을 출력합니다.
    - Evidence JSON에는 워터마크 삽입과 관련된 모든 증거 데이터가 포함됩니다.
    - 주요 필드:
      - `iss`: 증거를 발급한 서버의 식별자입니다.
      - `sub`: 워터마크 삽입 요청을 보낸 사용자 ID입니다.
      - `iat`: 증거 토큰이 생성된 UNIX 타임스탬프입니다.
      - `evidence`: 워터마크와 관련된 증거 데이터가 포함된 객체입니다.
        - `file_sha256`: 워터마크가 삽입된 이미지의 SHA-256 해시 값입니다.
        - `file_size`: 워터마크가 삽입된 이미지의 크기(바이트)입니다.
        - `wm_algorithm`: 워터마크 삽입에 사용된 알고리즘입니다.
        - `wm_text`: 삽입된 워터마크 텍스트입니다.
        - `image_url`: 워터마크가 삽입된 이미지의 파일 이름입니다.
        - `timestamp`: 타임스탬프 관련 데이터입니다.
          - `tsq`: 타임스탬프 요청(Timestamp Query)의 Base64URL 인코딩 값입니다.
          - `tsr`: 타임스탬프 응답(Timestamp Response)의 Base64URL 인코딩 값입니다.
          - `tsa_pem`: 타임스탬프 발급 기관(TSA)의 인증서입니다.
          - `cacert_pem`: 타임스탬프 발급 기관의 루트 인증서입니다.
          - `gen_time`: 타임스탬프가 생성된 시간입니다.
  - **JWS 서명 검증 결과**: `Evidence Token Signature Valid: True`
    - 클라이언트가 서버의 공개키를 사용하여 JWS 토큰의 서명을 검증한 결과입니다.
    - `True`는 서명이 유효하며, Evidence JSON이 변조되지 않았음을 의미합니다.
    - 만약 `False`라면, 서버의 공개키가 잘못되었거나 데이터가 변조되었을 가능성이 있습니다.
  - **워터마크 이미지 저장 완료**: `Watermarked image saved successfully`
    - 서버에서 반환된 워터마크 이미지가 로컬 파일로 성공적으로 저장되었음을 나타냅니다.
    - 저장된 파일 이름은 Evidence JSON의 `image_url` 필드에 명시된 이름과 동일합니다.

---

### 서버 로그
- 서버 실행 중 발생하는 모든 로그는 터미널에 출력됩니다.
- 주요 로그:
  - **암호화 패키지 검증**: `Verifying crypto package for user {user_id}`
    - 클라이언트에서 전송된 암호화 패키지가 유효한지 검증합니다.
    - 암호화 패키지에는 클라이언트가 생성한 서명과 암호화된 데이터를 포함합니다.
    - 검증 실패 시, 서버는 HTTP 400 에러를 반환합니다.
  - **워터마크 삽입 완료**: `Watermark length: {len}`
    - 워터마크가 성공적으로 삽입되었음을 나타냅니다.
    - `{len}`은 삽입된 워터마크의 비트 길이를 나타냅니다.
  - **Evidence JSON 생성**: `Generated Evidence JSON for user {user_id}`
    - 워터마크, 타임스탬프, 메타데이터를 포함한 Evidence JSON이 생성되었음을 나타냅니다.
    - Evidence JSON은 클라이언트로 반환되기 전에 JWS 토큰으로 서명됩니다.
  - **JWS 서명 완료**: `Signed Evidence JSON with server private key`
    - 서버의 개인키를 사용하여 Evidence JSON에 대한 JWS 서명이 완료되었음을 나타냅니다.
    - 서명된 JWS 토큰은 클라이언트로 반환됩니다.

---

## 로그 예시

### 클라이언트 로그
```
[2025-04-27 13:00:48] INFO: Starting watermark embedding process
[2025-04-27 13:00:48] INFO: Evidence Token Payload:
{
  "iss": "copyright-tanminkwan.org",
  "sub": "tiffanie",
  "iat": 1745726448,
  "version": "1.0",
  "evidence": {
    "file_sha256": "088ccc0e828587baa80e9fdcabbea22e863801866a9bfb1ba8fd99180ae85e09",
    "file_size": 279264,
    "wm_algorithm": "blind_watermark-v1",
    "wm_text": "Owned by tiffanie, certified by the Tanminkwan Foundation.",
    "image_url": "watermarked_basket.jpg",
    "timestamp": {
      "tsq": "MDcCAQEwLzALBglghkgBZQMEAgEEIAiMzA6ChYe6qA6f3Ku-oi6GOAGGapv7G6j9mRgK6F4JAQH_",
      "tsr": "MIIVUDADAgEAMIIVRwYJKoZIhvcNAQcCoIIVODCCFTQCAQMxDzANBglghkgBZQMEAgMFADCCAYIG...",
      "tsa_pem": "-----BEGIN CERTIFICATE-----\nMIIIATCCBemgAwIBAgIJAMHphhYNqOmCMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYD...",
      "cacert_pem": "-----BEGIN CERTIFICATE-----\nMIIH/zCCBeegAwIBAgIJAMHphhYNqOmAMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYD...",
      "gen_time": "2025-04-27T03:59:49+00:00Z"
    }
  }
}
[2025-04-27 13:00:48] INFO: Evidence Token Signature Valid: True
[2025-04-27 13:00:48] INFO: Watermarked image saved successfully
```

### 서버 로그
```
[2025-04-27 13:00:48] DEBUG: Verifying crypto package for user tiffanie
[2025-04-27 13:00:48] DEBUG: Watermark length: 128
[2025-04-27 13:00:48] INFO: Generated Evidence JSON for user tiffanie
[2025-04-27 13:00:48] INFO: Signed Evidence JSON with server private key
```

---

## 문제 해결
- **의존성 누락**: 모든 필수 Python 패키지가 설치되었는지 확인하세요.
- **서버 실행 오류**: `.env` 파일에 누락되거나 잘못된 값이 없는지 확인하세요.
- **타임스탬프 오류**: `resources` 디렉토리에 FreeTSA 인증서가 올바르게 저장되었는지 확인하세요.

---

## 라이선스
MIT License


