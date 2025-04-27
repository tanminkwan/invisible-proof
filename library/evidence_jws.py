"""
evidence_jws.py
---------------
워터마크·타임스탬프 정보를 JSON으로 묶은 뒤
서버 RSA 개인키로 RS256 서명(JWS Compact)하는 예제.
"""

import json, time, base64
from pathlib import Path                       # ← 폴더·파일 다루기 편리용
from jose import jws                           # python-jose
from cryptography.hazmat.primitives import serialization


# ─────────────────────────────────────────────────────────────
# 1) 유틸 – DER → Base64URL 변환
# ─────────────────────────────────────────────────────────────
def der_to_b64url(path: str | Path) -> str:
    """파일(DER/CRT 등)을 Base64URL(str) 로 반환"""
    raw = Path(path).read_bytes()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


# ─────────────────────────────────────────────────────────────
# 2) Evidence JSON 구성
# ─────────────────────────────────────────────────────────────
def build_evidence_json(user_id: str,
                        watermarked_url: str,
                        file_sha256: str,
                        file_size: int,
                        wm_text: str,
                        tsq_der: str | Path,
                        tsr_der: str | Path,
                        tsa_pem: str | Path,
                        cacert_pem: str | Path,
                        gen_time: str) -> dict:
    return {
        "iss": "copyright-server.example",
        "sub": user_id,
        "iat": int(time.time()),            # UNIX epoch
        "version": "1.0",
        "evidence": {
            "file_sha256":  file_sha256,
            "file_size":    file_size,
            "wm_algorithm": "blind_watermark-v1",
            "wm_text":      wm_text,
            "image_url":    watermarked_url,
            "timestamp": {
                "tsq":        der_to_b64url(tsq_der),
                "tsr":        der_to_b64url(tsr_der),
                "tsa_pem":    Path(tsa_pem).read_text(),
                "cacert_pem": Path(cacert_pem).read_text(),
                "gen_time":   gen_time
            }
        }
    }


# ─────────────────────────────────────────────────────────────
# 3) JWS 서명
# ─────────────────────────────────────────────────────────────
def sign_evidence(payload: dict,
                  server_priv_pem: str,
                  *,
                  kid: str = "2025-04") -> str:
    """
    Evidence JSON ➜ JWS Compact (RS256)

    Parameters
    ----------
    payload         : dict   Evidence JSON
    server_priv_pem : str    RSA **개인키** PEM 문자열
    kid             : str    JWKS Key-ID

    Returns
    -------
    str             JWS Compact token
    """
    # 1) 개인키 PEM 헤더 확인
    if not server_priv_pem.lstrip().startswith(
        ("-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----")
    ):
        raise ValueError("server_priv_pem must be an RSA PRIVATE KEY PEM string")

    # 2) 유효성 검사만 cryptography로 (오류 시 예외)
    serialization.load_pem_private_key(server_priv_pem.encode(), password=None)

    # 3) JWS 서명 – python-jose 는 PEM(str/bytes)을 직접 받게 한다
    headers = {"alg": "RS256", "typ": "JWT", "kid": kid}
    token   = jws.sign(payload, server_priv_pem, algorithm="RS256", headers=headers)
    return token


def decode_evidence_token(token: str) -> dict:
    """
    JWS Compact 토큰에서 payload를 추출하여 JSON으로 반환

    Parameters
    ----------
    token : str
        JWS Compact 토큰

    Returns
    -------
    dict
        디코딩된 payload JSON
    """
    # Base64URL-encoded payload 부분 추출 (두 번째 부분)
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWS token format")
    
    # Base64URL → JSON
    payload_json = base64.urlsafe_b64decode(
        parts[1] + '=' * (-len(parts[1]) % 4)
    ).decode('utf-8')
    
    return json.loads(payload_json)

def verify_evidence_token(token: str, server_pub_pem: str) -> bool:
    """
    JWS 토큰의 서명을 검증

    Parameters
    ----------
    token : str
        JWS Compact 토큰
    server_pub_pem : str
        서버의 RSA 공개키 PEM 문자열

    Returns
    -------
    bool
        서명이 유효하면 True

    Raises
    -------
    ValueError
        잘못된 키 형식이나 토큰 형식
    jose.exceptions.JWSError
        서명 검증 실패
    """
    # 공개키 PEM 헤더 확인
    if not server_pub_pem.lstrip().startswith("-----BEGIN PUBLIC KEY-----"):
        raise ValueError("server_pub_pem must be a PUBLIC KEY PEM string")

    # 유효성 검사 (오류 시 예외)
    serialization.load_pem_public_key(server_pub_pem.encode())

    try:
        # JWS 서명 검증
        payload = jws.verify(token, server_pub_pem, algorithms=["RS256"])
        return True
    except Exception as e:
        logger.error(f"Signature verification failed: {str(e)}")
        return False


# ─────────────────────────────────────────────────────────────
# 4) 실행 예시 (PoC)
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":

    import os
    from dotenv import load_dotenv
    # .env 파일 로드
    load_dotenv(dotenv_path='test.env')

    user_id        = os.getenv('USER_ID')
    server_priv_pem = os.getenv('SERVER_PRIVATE_KEY')
    wm_text = f'Owned by {user_id}, certified by the Tanminkwan Foundation.'  # 워터마크 텍스트
    wm_url  = "https://s3.example.com/lock/watermarked_abc.jpg"

    from asn1crypto import tsp
    import base64, binascii
    with open("request.tsq", "rb") as f:
        tsq_der = f.read()

    tsq = tsp.TimeStampReq.load(tsq_der)
    hashed_msg = tsq['message_imprint']['hashed_message'].native

    file_sha256 = binascii.hexlify(hashed_msg).decode()

    evidence = build_evidence_json(
        user_id          = user_id,
        watermarked_url  = wm_url,
        file_sha256      = file_sha256,
        file_size        = 512_034,
        wm_text          = wm_text,
        tsq_der          = "request.tsq",
        tsr_der          = "response.tsr",
        tsa_pem          = "../resources/tsa.pem",
        cacert_pem       = "../resources/cacert.pem",
        gen_time         = "2025-04-25T11:22:33Z"
    )

    token = sign_evidence(
        payload         = evidence,
        server_priv_pem = server_priv_pem,
        kid             = "tanminkwan-2025-04"
    )

    print("\n—— Evidence JWS ——")
    print(token)

    # Decode and verify test
    print("\n—— Decoded Payload ——")
    payload = decode_evidence_token(token)
    print(json.dumps(payload, indent=2))

    # Get server public key from environment
    server_pub_pem = os.getenv('SERVER_PUBLIC_KEY')
    is_valid = verify_evidence_token(token, server_pub_pem)
    print(f"\nSignature Valid: {is_valid}")