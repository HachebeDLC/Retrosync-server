import sys
import os
import base64
import hashlib
import json
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# --- PROTOCOL CONSTANTS (Must match Android Native) ---
BLOCK_SIZE_PLAIN = 1024 * 1024
MAGIC_SIZE = 7
IV_SIZE = 16
PADDING_OVERHEAD = 16
ENCRYPTED_BLOCK_SIZE = MAGIC_SIZE + IV_SIZE + BLOCK_SIZE_PLAIN + PADDING_OVERHEAD # 1,048,615

def derive_master_key(password, email):
    # Matches Flutter ApiClient: sha256(password:email)
    bytes_in = f"{password}:{email}".encode('utf-8')
    digest = hashlib.sha256(bytes_in).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

def decrypt_file(input_data, master_key_b64):
    missing_padding = len(master_key_b64) % 4
    if missing_padding: master_key_b64 += '=' * (4 - missing_padding)
    key_bytes = base64.urlsafe_b64decode(master_key_b64)[:32]

    magic = b"NEOSYNC"
    output_data = bytearray()
    offset = 0
    
    if len(input_data) < 7 or input_data[0:7] != magic:
        print("ℹ️ No encryption magic detected. Processing as plain data.")
        return input_data

    while offset < len(input_data):
        # 1. Verify Header
        if input_data[offset:offset+7] != magic:
            print(f"⚠️ Warning: Magic mismatch at {offset}. Data may be truncated.")
            break
        
        # 2. Extract IV
        iv = input_data[offset+7:offset+23]
        
        # 3. Determine Block Boundary (Fixed Size vs Remaining)
        # We don't SEARCH for magic, we calculate where the next one SHOULD be.
        remaining_data = len(input_data) - offset
        current_block_size = min(ENCRYPTED_BLOCK_SIZE, remaining_data)
        
        encrypted_payload = input_data[offset+23 : offset+current_block_size]
        offset += current_block_size
        
        # 4. Decrypt
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        try:
            decrypted = decryptor.update(encrypted_payload) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plain = unpadder.update(decrypted) + unpadder.finalize()
            output_data.extend(plain)
        except Exception as e:
            print(f"❌ Decryption failed for block at offset {offset - current_block_size}: {e}")
            break
            
    return output_data

def run_verify(base_url, email, password, remote_path):
    print(f"🚀 Connecting to Apollo at {base_url}...")
    try:
        resp = requests.post(f"{base_url}/login", json={"email": email, "password": password})
        resp.raise_for_status()
        token = resp.json()['token']
        print("🔑 Login Successful")
    except Exception as e:
        print(f"❌ Auth failed: {e}")
        return

    print(f"📥 Downloading {remote_path}...")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.post(f"{base_url}/api/v1/download", json={"filename": remote_path}, headers=headers)
        resp.raise_for_status()
        raw_data = resp.content
        print(f"📦 Downloaded {len(raw_data)} bytes")
    except Exception as e:
        print(f"❌ Download failed: {e}")
        return

    master_key = derive_master_key(password, email)
    print(f"🔓 Decrypting using Fixed-Block Strategy...")
    plain_data = decrypt_file(raw_data, master_key)
    
    output_filename = "pc_verified_" + os.path.basename(remote_path)
    with open(output_filename, "wb") as f:
        f.write(plain_data)
    
    print(f"✅ VERIFICATION COMPLETE")
    print(f"📄 Saved to: {output_filename}")
    print(f"📊 Final Plain Size: {len(plain_data)} bytes")
    print(f"🔒 SHA256: {hashlib.sha256(plain_data).hexdigest()}")

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python3 verify_sync.py <base_url> <email> <password> <remote_path>")
    else:
        run_verify(sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3], sys.argv[4])
