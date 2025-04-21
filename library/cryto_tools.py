# tools.py

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

# 대칭키로 transaction 정보 암호화
def encrypt_transaction_data(transaction, symmetric_key, output_format='bytes'):
    """
    트랜잭션 데이터를 대칭키로 암호화하고 지정된 형식으로 반환합니다.

    :param transaction: 트랜잭션 객체
    :param symmetric_key: 대칭키 (bytes)
    :param output_format: 'bytes' 또는 'hex' 중 선택 (기본값: 'bytes')
    :return: 암호화된 데이터 딕셔너리
    """
    # 트랜잭션 데이터를 JSON으로 직렬화
    tx_data = json.dumps(transaction.to_dict(), sort_keys=True).encode('utf-8')
    # 대칭키 암호화 (AES-GCM 사용)
    iv = os.urandom(12)  # 초기화 벡터
    encryptor = Cipher(
        algorithms.AES(symmetric_key),
        modes.GCM(iv)
    ).encryptor()
    ciphertext = encryptor.update(tx_data) + encryptor.finalize()

    encrypted_data = {
        'ciphertext': ciphertext,
        'iv': iv,
        'tag': encryptor.tag
    }

    if output_format == 'hex':
        # 바이트 데이터를 헥스 문자열로 변환
        encrypted_data = {
            'ciphertext': ciphertext.hex(),
            'iv': iv.hex(),
            'tag': encryptor.tag.hex()
        }
    elif output_format != 'bytes':
        raise ValueError("output_format은 'bytes' 또는 'hex' 중 하나여야 합니다.")

    return encrypted_data

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

# recipient의 public key로 sender가 보낸 암호화된 대칭키를 recipient의 private key로 복호화
def decrypt_symmetric_key(encrypted_symmetric_key, recipient_private_key):
    symmetric_key = recipient_private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return symmetric_key

# sender의 대칭키로 transaction 복호화
def decrypt_transaction_data(encrypted_data, symmetric_key, input_format='bytes'):
    """
    대칭키로 암호화된 트랜잭션 데이터를 복호화하고, 트랜잭션 딕셔너리를 반환합니다.

    :param encrypted_data: 암호화된 데이터 딕셔너리 (ciphertext, iv, tag)
    :param symmetric_key: 대칭키 (bytes)
    :param input_format: 'bytes' 또는 'hex' 중 선택 (기본값: 'bytes')
    :return: 복호화된 트랜잭션 데이터 (dict)
    """
    if input_format == 'hex':
        # 헥스 문자열을 바이트로 변환
        iv = bytes.fromhex(encrypted_data['iv'])
        tag = bytes.fromhex(encrypted_data['tag'])
        ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
    elif input_format == 'bytes':
        iv = encrypted_data['iv']
        tag = encrypted_data['tag']
        ciphertext = encrypted_data['ciphertext']
    else:
        raise ValueError("input_format은 'bytes' 또는 'hex' 중 하나여야 합니다.")

    decryptor = Cipher(
        algorithms.AES(symmetric_key),
        modes.GCM(iv, tag)
    ).decryptor()
    tx_data = decryptor.update(ciphertext) + decryptor.finalize()
    return json.loads(tx_data.decode('utf-8'))

# 트랜잭션 서명 함수(RSA 키용)
def sign_transaction(private_key, transaction):
    # 서명에 사용할 트랜잭션 데이터 생성
    tx_data = {
        'sender_id': transaction.sender_id,
        'recipient_id': transaction.recipient_id,
        'amount': transaction.amount,
        'timestamp': transaction.timestamp,
    }
    # 트랜잭션 데이터를 JSON 문자열로 변환
    tx_string = json.dumps(tx_data, sort_keys=True)
    signature = private_key.sign(
        tx_string.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256()
    )
    transaction.signature = signature.hex()

# 서명 검증 함수 정의
def verify_signature(public_key, transaction):
    tx_data = {
        'sender_id': transaction.sender_id,
        'recipient_id': transaction.recipient_id,
        'amount': transaction.amount,
        'timestamp': transaction.timestamp,
    }
    tx_string = json.dumps(tx_data, sort_keys=True)
    try:
        public_key.verify(
            bytes.fromhex(transaction.signature),
            tx_string.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"서명 검증 실패: {e}")
        return False

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
def decrypt_symmetric_key(encrypted_symmetric_key, recipient_private_key):
    symmetric_key = recipient_private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return symmetric_key

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