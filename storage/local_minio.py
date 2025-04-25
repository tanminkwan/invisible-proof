import logging
from minio import Minio
from minio.error import S3Error
from minio.retention import Retention
from minio.commonconfig import COMPLIANCE, GOVERNANCE
from typing import List, Optional
from datetime import datetime, timedelta

if __name__ == '__main__':
    from storage_interface import StorageInterface
else:
    from storage.storage_interface import StorageInterface

class MinIO(StorageInterface):

    def __init__(
            self,
            endpoint: str = None,
            access_key: str = None,
            secret_key: str = None,
            secure: bool = False
        ):
        self.client = Minio(
            endpoint=endpoint,
            access_key=access_key,
            secret_key=secret_key,
            secure=secure
        )
        
    def upload_file(
        self,
        bucket: str,
        object_name: str,
        local_file_path: str,
    ) -> None:
        """
        로컬 파일(local_file_path)을 지정된 bucket의 object_name으로 업로드하고,
        필요에 따라 Object Lock Retention을 설정합니다.

        :param bucket: 버킷 이름
        :param object_name: 업로드 될 객체 이름
        :param local_file_path: 로컬 파일 경로
        """

        try:
            # 파일 업로드
            self.client.fput_object(bucket, object_name, local_file_path)
            logging.info(
                f"Successfully uploaded '{local_file_path}' as '{object_name}' to bucket '{bucket}'."
            )
        except S3Error as err:
            logging.error(
                f"Failed to upload '{local_file_path}' as '{object_name}' to bucket '{bucket}': {err}"
            )
            raise

    def get_file_url(self, bucket: str, file_name: str) -> str:
        """
        객체에 대한 presigned URL을 반환합니다.
        """
        url = self.client.presigned_get_object(bucket, file_name, 
                                               expires=timedelta(days=1))
        return url

    def list_files_in_bucket(self, bucket: str, recursive: bool = True) -> List[str]:
        """
        버킷 내의 파일 목록을 문자열 리스트로 반환합니다.
        """
        try:
            objects = self.client.list_objects(bucket, recursive=recursive)
            return [obj.object_name for obj in objects]
        except S3Error as err:
            logging.error(f"Error listing objects in bucket '{bucket}': {err}")
            return []

    def delete_file(self, bucket: str, file_name: str) -> None:
        """
        버킷 내 특정 파일을 삭제합니다.
        """
        try:
            self.client.remove_object(bucket, file_name)
            logging.info(f"Deleted '{file_name}' from bucket '{bucket}'.")
        except S3Error as err:
            logging.error(f"Failed to delete '{file_name}' from bucket '{bucket}': {err}")
            raise

if __name__ == '__main__':

    import os
    import sys
    from dotenv import load_dotenv

    # 로깅 설정 (stdout으로 출력되도록 설정)
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        stream=sys.stdout
    )

    # .env 파일 로드
    load_dotenv(dotenv_path='test.env')

    S3_ENDPOINT = os.getenv("S3_ENDPOINT", "minio:9000")
    S3_ACCESS_KEY = os.getenv("S3_ACCESS_KEY", "minioadmin")
    S3_SECRET_KEY = os.getenv("S3_SECRET_KEY", "minioadmin")
    S3_SECURE = os.getenv("S3_SECURE", "false").lower() == "true"
    
    bucket_name = 'test'
    # 이미지 경로
    image_path     = "../resources/basket.jpg"

    storage = MinIO(
                    endpoint=S3_ENDPOINT,
                    access_key=S3_ACCESS_KEY,
                    secret_key=S3_SECRET_KEY,
                    secure=S3_SECURE
                )
    
    storage.upload_file(
            bucket=bucket_name,
            object_name='basket3.jpg',
            local_file_path=image_path,
        )

    url = storage.get_file_url(bucket_name, 'basket3.jpg')
    print(f"# pre-signed url : {url}")

    file_list = storage.list_files_in_bucket(bucket_name)
    print(f"# file list bf delete : {file_list}")

    storage.delete_file(bucket_name, 'basket3.jpg')

    file_list = storage.list_files_in_bucket(bucket_name)
    print(f"# file list af delete : {file_list}")




