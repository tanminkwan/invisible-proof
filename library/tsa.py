import hashlib
from asn1crypto import tsp, algos, core
import subprocess
import requests
from datetime import datetime, timezone

def create_rfc3161_timestamp_request(file_path, hash_algorithm='sha256'):
    # 파일 해시 생성
    with open(file_path, 'rb') as f:
        file_data = f.read()

    hash_func = getattr(hashlib, hash_algorithm)
    digest = hash_func(file_data).digest()

    # RFC3161 요청 객체 생성
    tsq = tsp.TimeStampReq({
        'version': 'v1',
        'message_imprint': {
            'hash_algorithm': {
                'algorithm': hash_algorithm,
                'parameters': None
            },
            'hashed_message': digest
        },
        'cert_req': True
    })

    # DER 형식으로 인코딩
    tsq_der = tsq.dump()

    # 파일로 저장
    with open('request.tsq', 'wb') as f:
        f.write(tsq_der)

    print("request.tsq 파일이 생성되었습니다.")
    return tsq_der

def get_timestamp_from_freetsa(tsq_der):
    headers = {'Content-Type': 'application/timestamp-query'}
    response = requests.post("https://freetsa.org/tsr", data=tsq_der, headers=headers, verify=False)
    response.raise_for_status()
    with open("response.tsr", "wb") as f:
        f.write(response.content)
    print("response.tsr 파일이 생성되었습니다.")

def verify_timestamp(request_file="request.tsq",
                     response_file="response.tsr",
                     ca_cert="cacert.pem",
                     tsa_cert="tsa.crt"):
    """
    Verify a RFC3161 timestamp token using OpenSSL.
    - 이 응답이 내가 보낸 요청에 대한 진짜 타임스탬프이고
    - TSA가 올바르게 서명했으며
    - 인증서도 신뢰할 만하다

    Parameters:
      - request_file: the .tsq file you sent
      - response_file: the .tsr file you received
      - ca_cert: the TSA CA bundle (root certificate)
      - tsa_cert: the TSA’s own certificate (intermediate, untrusted)
    Returns:
      - True if verification OK, False otherwise
      - details: the full OpenSSL stdout/stderr

    How to Get certis
      - wget https://freetsa.org/files/cacert.pem
      - wget https://freetsa.org/files/tsa.crt

    """
    cmd = [
        "openssl", "ts", "-verify",
        "-in", response_file,
        "-queryfile", request_file,
        "-CAfile", ca_cert,
        "-untrusted", tsa_cert
    ]
    # capture_output requires Python 3.7+
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout + result.stderr

    success = (result.returncode == 0 and "Verification: OK" in output)
    return success, output

def extract_timestamp_time(response_file="response.tsr") -> datetime:
    # 1) response.tsr 읽어서 파싱
    tsr = tsp.TimeStampResp.load(open(response_file, "rb").read())
    status = tsr['status']['status'].native
    if status != 'granted':
        raise ValueError(f"타임스탬프가 승인되지 않았습니다: {status}")

    # 2) SignedData → EncapsulatedContentInfo → ParsableOctetString
    signed_data = tsr['time_stamp_token']['content']
    encap_info  = signed_data['encap_content_info']
    octet_str   = encap_info['content']  # ParsableOctetString

    if octet_str is None:
        raise ValueError("TSTInfo가 응답에 포함되어 있지 않습니다.")

    # 3) parse() 로 바로 TSTInfo 객체 얻기
    tst_info = octet_str.parse(spec=tsp.TSTInfo)

    # 4) genTime 꺼내기
    gen_time = tst_info['gen_time'].native  # datetime 객체

    return gen_time

if __name__ == "__main__":
    image_path     = "../resources/basket.jpg"
    tsq_der = create_rfc3161_timestamp_request(image_path)
    get_timestamp_from_freetsa(tsq_der)
    rtn, output = verify_timestamp(ca_cert="../resources/cacert.pem", tsa_cert="../resources/tsa.crt")
    print(f"rtn : {rtn}, output : {output}")
    gen_time = extract_timestamp_time(response_file="response.tsr")
    print(f"gen_time : {gen_time}")