import os
import hashlib
from typing import List
from .config import ENCRYPTED_BLOCK_SIZE, STORAGE_DIR

def calculate_file_hash_and_blocks(file_path: str) -> tuple[str, List[str]]:
    """Single-pass: calculates the full SHA-256 hash and 1MB block hashes."""
    full_sha256 = hashlib.sha256()
    block_hashes = []
    if not os.path.exists(file_path):
        return "", []
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(ENCRYPTED_BLOCK_SIZE)
            if not chunk:
                break
            full_sha256.update(chunk)
            block_hashes.append(hashlib.sha256(chunk).hexdigest())
    return full_sha256.hexdigest(), block_hashes

def is_safe_path(user_id: int, path: str) -> bool:
    """
    Prevents directory traversal attacks by verifying the path is within the user's root directory.
    """
    user_root = os.path.join(STORAGE_DIR, str(user_id))
    requested_path = os.path.abspath(os.path.join(user_root, path.lstrip("/\\")))
    return os.path.commonpath([user_root, requested_path]) == user_root
