## 📑 이미지 저작권 인증 대행 서비스 기획 보고서 v2  
> **업데이트 핵심** — 모든 증빙 자료를 “Evidence JSON + JWS 토큰” 하나로 패키징

---

### 1. 서비스 가치

| 문제 | 해결 방안 |
|------|-----------|
| 이미지 소유 시점 증명 어려움 | **블라인드 워터마크**로 소유자 식별 정보 삽입 |
| “언제 등록했나” 입증 | **RFC 3161 타임스탬프(TSA)**로 법적 시점 고정 |
| 자료 관리 복잡 | 워터마크·TSQ·TSR·인증서를 **Evidence JSON → JWS**로 묶어 문자열 하나로 전달·보존 |

---

### 2. 처리 흐름 요약

```
(1) 회원가입             -> api_key 발급
(2) 키 교환              -> 서버·사용자 RSA 키, 워터마크 비밀번호 저장
(3) 이미지 업로드        -> crypto_package 검증, 워터마크 삽입
(4) 타임스탬프 획득      -> TSQ → TSA → TSR 수신·검증
(5) Evidence JSON 작성   -> JWS(RS256) 서명
(6) 결과 반환            -> watermarked_image + evidence_jws
```

---

### 3. 핵심 데이터 구조

#### 3-1. Evidence JSON (payload)
```jsonc
{
  "iss": "copyright-server.example",
  "sub": "alice",
  "iat": 1714024800,
  "version": "1.0",
  "evidence": {
    "file_sha256": "ab34…",
    "file_size": 512034,
    "wm_algorithm": "blind_watermark-v1",
    "wm_text": "Owned by alice …",
    "image_url": "s3://…/watermarked_x.jpg",
    "timestamp": {
      "tsq": "<Base64-DER>",
      "tsr": "<Base64-DER>",
      "tsa_chain": "<PEM bundle>",
      "gen_time": "2025-04-25T11:22:33Z"
    }
  }
}
```

#### 3-2. JWS Compact 토큰
```
BASE64URL(header).BASE64URL(payload).BASE64URL(signature)
```
* header 예: `{"alg":"RS256","typ":"JWT","kid":"2025-04"}`  
* signature: **서버 개인키**로 RS256 서명  
→ 결과 길이 2-4 KB.

---

### 4. 주요 API 설계

| 단계 | 메서드 & 경로 | 입력 | 주요 로직 | 출력 |
|------|--------------|------|-----------|------|
| 사용자 등록 | **POST** `/api/v1/user` | `user_id` | api_key 생성 | `{user_id, api_key}` |
| 키 교환 | **PUT** `/api/v1/user/{id}` | `app_key`, `user_public_key`, `password_img`, `password_wm` | 사용자 검증, 비번·공개키 저장, **서버 공개키** 반환 | `{sp_public_key}` |
| 워터마크 등록 | **POST** `/api/v1/watermark` | `image`, `user_id`, `crypto_package` | crypto_package 검증 → 워터마크 삽입 → TSA 호출 → Evidence JSON → **JWS 서명** | `{image_url, evidence_jws}` |
| 워터마크 추출 | **POST** `/api/v1/extract-watermark` | `image`, `user_id` | 비밀번호·길이로 추출 | `{watermark_text}` |

---

### 5. 보안·컴플라이언스

| 계층 | 적용 |
|------|------|
| 전송 | API TLS 1.3, presigned URL 제한 메서드 |
| 저장 | S3 Object Lock(Compliance), 서버 개인키 → HSM/KMS |
| 암호·서명 | RSA-OAEP, AES-256-GCM, RSA-PSS, JWS-RS256 |
| 검증 | 파일 SHA-256 대조 + TSR 검증 + JWS 공개키 검증 |
| 키 유통 | `/jwks.json` JWKS, `kid` 버전·롤링 지원 |

---

### 6. 사용자·제3자 검증 절차

1. Evidence JWS 수신  
2. JWKS URL에서 서버 공개키 획득  
3. JWS 서명 검증 → 변조 여부 확인  
4. payload 열람 → 이미지 SHA-256, TSA gen_time 등 확인  
5. 필요 시 TSR DER을 `openssl ts -verify` 로 독립 검증

*(옵션) 기밀성 필요 시* — Evidence JSON을 먼저 JWE(A256GCM)로 암호화한 뒤 JWS 서명 → 열람하려면 수신자 개인키로 복호화 후 2-4단계 진행.

---

### 7. 장점 요약

| 구분 | 효과 |
|------|------|
| **단일 토큰** | 오프라인 제시·법원 제출이 간단 (QR·텍스트로도 전달) |
| **표준 JOSE** | 언어·플랫폼 불문 검증, 라이브러리 풍부 |
| **무결성 + 발행자 증명** | 서버 개인키 서명 → 공개키만으로 검증 |
| **확장성** | 다중 TSA, 추가 메타, 알고리즘 교체(JWS header) 쉽게 확장 |

---

### 8. 다음 단계

1. **PoC**  
   - `python-jose`로 JWS 생성/검증 로직 구현  
   - Evidence JSON 구조 체계화(버전 필드 포함)
2. **인프라**  
   - JWKS 자동 롤링·배포 파이프라인  
   - Object Lock 버킷·Lifecycle 정책 설정
3. **Dashboard / SDK**  
   - 사용자 워터마크 이력 표출, 증빙 다운로드  
   - 모바일·웹 SDK로 즉시 인증

---

> 이 설계를 기반으로 MVP 개발을 진행하고, 세부 스펙(파일 크기 제한, 과금 모델 등)은 별도 문서로 정의하면 됩니다. 추가 문의 환영합니다!