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
                  server_priv_pem: str | Path,
                  kid: str = "2025-04") -> str:
    """
    payload → JWS Compact (RS256).  kid 는 JWKS에서 키 식별용.
    """
    priv_key = Path(server_priv_pem).read_text()
    headers  = {"alg": "RS256", "typ": "JWT", "kid": kid}
    token    = jws.sign(payload, priv_key, algorithm="RS256", headers=headers)
    return token


# ─────────────────────────────────────────────────────────────
# 4) 실행 예시 (PoC)
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":

    import os
    from dotenv import load_dotenv
    # .env 파일 로드
    load_dotenv(dotenv_path='test.env')

    user_id        = os.getenv('USER_ID')
    server_pub_pem = os.getenv('SERVER_PUBLIC_KEY')
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
        server_priv_pem = server_pub_pem,
        kid             = "tanminkwan-2025-04"
    )

    print("—— Evidence JWS ——")
    print(token)