import hashlib
from asn1crypto import tsp, algos, core
import subprocess
import requests
import logging
import tempfile
import io
import sys
import os
from datetime import datetime, timezone

def create_rfc3161_timestamp_request(file_path, hash_algorithm='sha256', request_path='request.tsq'):
    """
    파일 해시를 기반으로 RFC3161 Time Stamp 요청을 생성하고, 옵션에 따라 요청을 파일로 저장합니다.

    Parameters:
        file_path (str): 입력 파일 경로
        hash_algorithm (str): 해시 알고리즘 이름 (기본 'sha256')
        request_path (str or None): 저장할 .tsq 파일 경로 (None이면 저장 안 함)

    Returns:
        bytes: DER로 인코딩된 TSQ 요청 데이터
    """
    # 1) 파일 해시 생성
    with open(file_path, 'rb') as f:
        file_data = f.read()
    hash_func = getattr(hashlib, hash_algorithm)
    digest = hash_func(file_data).digest()

    # 2) RFC3161 요청 객체 생성
    tsq = tsp.TimeStampReq({
        'version': 'v1',
        'message_imprint': {
            'hash_algorithm': {'algorithm': hash_algorithm, 'parameters': None},
            'hashed_message': digest
        },
        'cert_req': True
    })

    # 3) DER 형식으로 인코딩
    tsq_der = tsq.dump()

    # 4) 선택적 파일 저장
    if request_path is not None:
        with open(request_path, 'wb') as f:
            f.write(tsq_der)
        logging.info(f"TSQ 요청 파일 생성: {request_path}")
    else:
        logging.info("TSQ 요청 데이터 생성 완료 (파일 저장 안 함)")

    return tsq_der


def get_timestamp_from_freetsa(tsq_der, response_path='response.tsr'):
    """
    Freetsa.org TSA에 TSQ 요청을 전송하고, 지정된 경로에 TSR 응답을 저장합니다.

    Parameters:
        tsq_der (bytes): TimeStampReq 객체를 DER로 인코딩한 바이트
        response_path (str or None): 저장할 .tsr 파일 경로(None이면 저장 안 함)

    Returns:
        bytes: DER로 인코딩된 TSR 응답 데이터
    """
    logging.info("TSA 서버로 TSQ 요청 전송 중...")
    headers = {'Content-Type': 'application/timestamp-query'}
    response = requests.post(
        "https://freetsa.org/tsr", data=tsq_der,
        headers=headers, verify=False
    )
    response.raise_for_status()

    tsr_data = response.content
    logging.info("TSR 응답 데이터 수신 완료")

    # 선택적 파일 저장
    if response_path is not None:
        with open(response_path, 'wb') as f:
            f.write(tsr_data)
        logging.info(f"TSR 파일 생성: {response_path}")
    else:
        logging.info("TSR 데이터 저장 안 함")

    return tsr_data


def verify_timestamp(request_input, response_input,
                     ca_cert="cacert.pem", tsa_cert="tsa.crt"):
    """
    Verify a RFC3161 timestamp token using OpenSSL. 입력으로 파일 경로(str), 바이트(bytes), 또는 파일 객체(io.IOBase)를 지원합니다.

    Parameters:
        request_input (str, bytes, or IOBase): TSQ 요청 데이터 또는 파일 경로 또는 파일 객체
        response_input (str, bytes, or IOBase): TSR 응답 데이터 또는 파일 경로 또는 파일 객체
        ca_cert (str): CA 인증서 경로
        tsa_cert (str): TSA 인증서 경로

    Returns:
        tuple: (success: bool, output: str)
    """
    temp_paths = []
    try:
        # 요청 처리
        if isinstance(request_input, bytes):
            req_path = tempfile.NamedTemporaryFile(delete=False)
            req_path.write(request_input)
            req_path.flush()
            temp_paths.append(req_path.name)
            req_path = req_path.name
        elif hasattr(request_input, 'read'):
            data = request_input.read()
            tmp = tempfile.NamedTemporaryFile(delete=False)
            tmp.write(data)
            tmp.flush()
            temp_paths.append(tmp.name)
            req_path = tmp.name
        else:
            req_path = request_input

        # 응답 처리
        if isinstance(response_input, bytes):
            res_path = tempfile.NamedTemporaryFile(delete=False)
            res_path.write(response_input)
            res_path.flush()
            temp_paths.append(res_path.name)
            res_path = res_path.name
        elif hasattr(response_input, 'read'):
            data = response_input.read()
            tmp = tempfile.NamedTemporaryFile(delete=False)
            tmp.write(data)
            tmp.flush()
            temp_paths.append(tmp.name)
            res_path = tmp.name
        else:
            res_path = response_input

        logging.info("OpenSSL로 타임스탬프 검증 시작")
        cmd = [
            "openssl", "ts", "-verify",
            "-in", res_path,
            "-queryfile", req_path,
            "-CAfile", ca_cert,
            "-untrusted", tsa_cert
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout + result.stderr
        success = (result.returncode == 0 and "Verification: OK" in output)
        logging.info(f"검증 결과: {'OK' if success else 'FAILED'}")
        return success, output
    finally:
        # 임시 파일 정리
        for path in temp_paths:
            try:
                os.unlink(path)
            except OSError:
                pass

def extract_timestamp_time(tsr_data: bytes) -> datetime:
    """
    DER로 인코딩된 TSR 바이너리 데이터를 파싱하여 genTime을 추출합니다.
    """
    logging.info("TSR 데이터에서 genTime 추출 시작")
    tsr = tsp.TimeStampResp.load(tsr_data)
    status = tsr['status']['status'].native
    if status != 'granted':
        raise ValueError(f"타임스탬프가 승인되지 않았습니다: {status}")

    signed_data = tsr['time_stamp_token']['content']
    encap_info  = signed_data['encap_content_info']
    octet_str   = encap_info['content']

    if octet_str is None:
        raise ValueError("TSTInfo가 응답에 포함되어 있지 않습니다.")

    tst_info = octet_str.parse(spec=tsp.TSTInfo)
    gen_time = tst_info['gen_time'].native
    logging.info(f"genTime 추출 완료: {gen_time}")
    return gen_time

if __name__ == "__main__":

    # 로깅 설정 (stdout으로 출력되도록 설정)
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        stream=sys.stdout
    )

    print("=== RFC3161 타임스탬프 생성 및 검증 시작 ===")
    image_path = "../resources/basket.jpg"

    tsq_der = create_rfc3161_timestamp_request(image_path, request_path=None)

    tsr_data = get_timestamp_from_freetsa(tsq_der, response_path=None)

    rtn, output = verify_timestamp(
        request_input=tsq_der, response_input=tsr_data,
        ca_cert="../resources/cacert.pem",
        tsa_cert="../resources/tsa.crt"
    )
    print(f"Verification return: {rtn}")
    if not rtn:
        print(f"검증 오류 세부 정보: {output}")
        exit(1)

    gen_time = extract_timestamp_time(tsr_data)
    print(f"최종 gen_time: {gen_time}")
    print("=== 작업 완료 ===")