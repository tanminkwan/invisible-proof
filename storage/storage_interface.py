from abc import ABC, abstractmethod
from typing import List, Dict
import numpy as np

class StorageInterface(ABC):

    @abstractmethod
    def upload_file(self, bucket: str, file_name: str) -> None:
        """
        파일을 Object Storage에 업로드합니다.
        """
        pass

    @abstractmethod
    def get_file_url(self, bucket: str, file_name: str) -> str:
        """
        객체에 대한 presigned URL을 반환합니다.
        """
        pass

    @abstractmethod
    def list_files_in_bucket(self, bucket: str, recursive: bool = True) -> List[str]:
        """
        버킷 내의 파일 목록을 문자열 리스트로 반환합니다.
        """
        pass

    @abstractmethod
    def delete_file(self, bucket: str, file_name: str)-> None:
        """
        버킷 내 특정 파일을 삭제합니다.
        """
        pass
