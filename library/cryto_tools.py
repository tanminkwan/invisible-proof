# cryto_tools.py

import os
import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# 대칭키 생성 함수
def generate_symmetric_key() -> bytes:
    return os.urandom(32)

# RSA 비밀키, 공개키 생성
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # 또는 보안을 위해 3072 또는 4096 사용 가능
    )
    public_key = private_key.public_key()
    return private_key, public_key

# 공개키/비밀키 로드 및 저장 함수
def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def load_private_key(filename):
    with open(filename, 'rb') as f:
        pem_data = f.read()
    private_key = serialization.load_pem_private_key(pem_data, password=None)
    return private_key

def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def load_public_key(filename):
    with open(filename, 'rb') as f:
        pem_data = f.read()
    public_key = serialization.load_pem_public_key(pem_data)
    return public_key

def convert_private_key_to_pem(private_key):
    """Convert private key to PEM format string"""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

def convert_public_key_to_pem(public_key):
    """Convert public key to PEM format string"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def load_private_key_from_pem(pem_string):
    """Load private key from PEM format string"""
    return serialization.load_pem_private_key(
        pem_string.encode(),
        password=None
    )

def load_public_key_from_pem(pem_string):
    """Load public key from PEM format string"""
    return serialization.load_pem_public_key(
        pem_string.encode()
    )

def encrypt_server_public_key(server_public_key, client_public_key_pem):
    """Encrypt server public key with client's public key"""
    client_public_key = load_public_key_from_pem(client_public_key_pem)
    sp_public_key_pem = convert_public_key_to_pem(server_public_key)
    
    encrypted_sp_key = client_public_key.encrypt(
        sp_public_key_pem.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_sp_key).decode()

def decrypt_server_public_key(encrypted_sp_key_base64, private_key):
    """Decrypt server public key using client's private key"""
    encrypted_sp_key = base64.b64decode(encrypted_sp_key_base64)
    return private_key.decrypt(
        encrypted_sp_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# AES-GCM 페이로드 암호화
def encrypt_payload_aes_gcm(payload: dict, symmetric_key: bytes) -> dict:
    raw = json.dumps(payload, sort_keys=True).encode('utf-8')
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(symmetric_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(raw) + encryptor.finalize()
    tag = encryptor.tag
    return {
        'enc_payload': base64.b64encode(ciphertext).decode('utf-8'),
        'iv':         base64.b64encode(iv).decode('utf-8'),
        'tag':        base64.b64encode(tag).decode('utf-8')
    }

def sign_message(data: bytes, private_key) -> str:
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

# 대칭키를 recipient의 public key로 암호화
def encrypt_symmetric_key(symmetric_key, recipient_public_key):
    encrypted_symmetric_key = recipient_public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_symmetric_key

def decrypt_symmetric_key(encrypted_sym_bytes: bytes, recipient_private_key) -> bytes:
    return recipient_private_key.decrypt(
        encrypted_sym_bytes,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# 암호화 키 파생 함수
def derive_key_from_password(password, salt):
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import base64

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

#대칭키 복호화: 자신의 비밀키로 암호화된 대칭키를 복호화합니다.
def decrypt_symmetric_key(encrypted_sym_bytes: bytes, recipient_private_key) -> bytes:
    # 수신된 암호화된 대칭키(바이트) 복호화
    return recipient_private_key.decrypt(
        encrypted_sym_bytes,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def calculate_file_hash(file_path):
    """
    SHA256 해시 값을 계산하여 반환합니다.
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            digest.update(chunk)
    return digest.finalize().hex()

def verify_file_integrity(file_path, original_hash):
    """
    파일의 무결성을 원래 해시와 비교하여 확인합니다.
    """
    current_hash = calculate_file_hash(file_path)
    if current_hash == original_hash:
        print("✅ 파일 무결성 검증 성공: 변조되지 않았습니다.")
        return True
    else:
        print("❌ 파일 무결성 검증 실패: 파일이 변경되었습니다.")
        print(f"원본 해시:   {original_hash}")
        print(f"현재 해시:   {current_hash}")
        return False

def prepare_crypto_package(
    image_path: str,
    user_id: str,
    priv_pem: str,
    server_pub_pem: str
) -> dict:
    """
    이미지 보안 패키지 생성:
      1. 파일 해시 계산 (SHA256)
      2. 대칭 키 생성
      3. payload 암호화 (AES-GCM)
      4. payload 서명 (RSA-PSS)
      5. 대칭 키 암호화 (RSA-OAEP)

    Returns:
        {
          'file_hash': str,
          'enc_payload': str,
          'iv': str,
          'tag': str,
          'signature': str,
          'enc_sym_key': str
        }
    """
    # 1. 키 로드
    user_priv = serialization.load_pem_private_key(
        priv_pem.encode('utf-8'),
        password=None
    )
    server_pub = serialization.load_pem_public_key(
        server_pub_pem.encode('utf-8')
    )

    # 2. 파일 해시
    file_hash = calculate_file_hash(image_path)

    # 3. timestamp
    timestamp = datetime.utcnow().isoformat()

    # 4. 대칭키 생성
    sym_key = generate_symmetric_key()

    # 5. payload 암호화 (AES-GCM)
    payload = {"user_id": user_id, "timestamp": timestamp, "file_hash": file_hash}
    enc = encrypt_payload_aes_gcm(payload, sym_key)

    # 6. payload 서명 (RSA-PSS)
    to_sign = f"{user_id}{timestamp}".encode('utf-8')
    signature = sign_message(to_sign, user_priv)

    # 7. 대칭키 암호화 (RSA-OAEP)
    encrypted_sym = encrypt_symmetric_key(sym_key, server_pub)
    enc_sym_key = base64.b64encode(encrypted_sym).decode('utf-8')

    return {
        'file_hash':   file_hash,
        'enc_payload': enc['enc_payload'],
        'iv':          enc['iv'],
        'tag':         enc['tag'],
        'signature':   signature,
        'enc_sym_key': enc_sym_key
    }

def serialize_crypto_package(package: dict) -> str:
    """
    crypto 패키지(dict)를 JSON 문자열로 직렬화합니다.
    """
    return json.dumps(package, sort_keys=True)


def deserialize_crypto_package(package_json: str) -> dict:
    """
    JSON 문자열로부터 crypto 패키지를 복원하여 dict로 반환합니다.
    """
    return json.loads(package_json)

def decrypt_payload_aes_gcm(enc: dict, symmetric_key: bytes) -> dict:
    iv = base64.b64decode(enc['iv'])
    tag = base64.b64decode(enc['tag'])
    ciphertext = base64.b64decode(enc['enc_payload'])
    decryptor = Cipher(
        algorithms.AES(symmetric_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    raw = decryptor.update(ciphertext) + decryptor.finalize()
    return json.loads(raw.decode('utf-8'))

def verify_signature(data: bytes, signature_b64: str, sender_public_key) -> bool:
    """
    data: 원본 바이트(예: f"{user_id}{timestamp}".encode())
    signature_b64: Base64 인코딩된 서명 문자열
    sender_public_key: 서명 검증에 사용할 공개키 객체
    """
    sig = base64.b64decode(signature_b64)
    try:
        sender_public_key.verify(
            sig,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def verify_crypto_package(
    package_json: str,
    recipient_priv_pem: str,
    sender_pub_pem: str,
    image_path: str
) -> bool:
    pkg = deserialize_crypto_package(package_json)
    recipient_priv = serialization.load_pem_private_key(recipient_priv_pem.encode(), password=None)
    sender_pub = serialization.load_pem_public_key(sender_pub_pem.encode())

    # 1. encrypted_sym_key는 base64이므로 디코딩 후 복호화
    enc_sym_b64 = pkg['enc_sym_key']
    enc_sym_bytes = base64.b64decode(enc_sym_b64)
    sym_key = decrypt_symmetric_key(enc_sym_bytes, recipient_priv)

    # 2. 페이로드 복호화
    payload = decrypt_payload_aes_gcm(pkg, sym_key)

    # 3. 서명 검증
    data = f"{payload['user_id']}{payload['timestamp']}".encode()
    if not verify_signature(data, pkg['signature'], sender_pub):
        return False

    # 4. 파일 해시 검증
    return calculate_file_hash(image_path) == payload['file_hash']

if __name__ == '__main__':

    from dotenv import load_dotenv
    # .env 파일 로드
    load_dotenv(dotenv_path='test.env')

    # 1. Client-Side
    user_id        = os.getenv('USER_ID')
    user_priv_pem  = os.getenv('USER_PRIVATE_KEY')
    server_pub_pem = os.getenv('SERVER_PUBLIC_KEY')
    
    # 이미지 경로
    image_path     = "../resources/basket.jpg"

    # 패키지 생성 및 테스트
    package = prepare_crypto_package(
        image_path,
        user_id,
        user_priv_pem,
        server_pub_pem
    )
    print('Prepared package:', package)

    # JSON 직렬화
    package_json = serialize_crypto_package(package)
    print('Serialized JSON:', package_json)

    # 2. image와 package_json을 Server에 전송

    # 3. Server-Side
    # 검증
    user_pub_pem  = os.getenv('USER_PUBLIC_KEY')
    server_priv_pem = os.getenv('SERVER_PRIVATE_KEY')

    valid = verify_crypto_package(package_json, server_priv_pem, user_pub_pem, image_path)
    print('Package valid:', valid)