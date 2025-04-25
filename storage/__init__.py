from storage.storage_interface import StorageInterface

def storage_client(object_storage: str, **kwargs) -> StorageInterface:

    if object_storage == "MINIO":
        from storage.local_minio import MinIO
        storage = MinIO(
                    endpoint=kwargs.get('endpoint'),
                    access_key=kwargs.get('access_key'),
                    secret_key=kwargs.get('secret_key'),
                    secure=kwargs.get('secure', False)
                )
    else:
        raise ValueError("Invalid Storage value.")

    return storage
