import sys
import os
import base64
import hashlib
import json
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- PROTOCOL CONSTANTS ---
BLOCK_SIZE_PLAIN = 1024 * 1024
MAGIC = b"VAULTSYNC"
MAGIC_SIZE = len(MAGIC)
IV_SIZE = 16
PADDING_OVERHEAD = 16
# A full 1MiB block is 9 + 16 + 1,048,576 + 16 = 1,048,617
ENCRYPTED_BLOCK_SIZE = MAGIC_SIZE + IV_SIZE + BLOCK_SIZE_PLAIN + PADDING_OVERHEAD

def derive_master_key_pbkdf2(password, email):
    """New PBKDF2 derivation."""
    salt = email.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def derive_master_key_legacy(password, email):
    """Old SHA256 derivation."""
    bytes_in = f"{password}:{email}".encode('utf-8')
    return hashlib.sha256(bytes_in).digest()

def decrypt_block(block_data, key_bytes, use_padding=True):
    if len(block_data) < MAGIC_SIZE + IV_SIZE:
        return None
    
    magic = block_data[:MAGIC_SIZE]
    if magic != MAGIC:
        return None
        
    iv = block_data[MAGIC_SIZE : MAGIC_SIZE + IV_SIZE]
    ciphertext = block_data[MAGIC_SIZE + IV_SIZE:]
    
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    try:
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        if use_padding:
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(decrypted) + unpadder.finalize()
        return decrypted
    except Exception:
        return None

def run_verify(base_url, email, password, remote_path):
    print(f"🚀 Connecting to VaultSync at {base_url}...")
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

    # Try Key Derivations
    key_pbkdf2 = derive_master_key_pbkdf2(password, email)
    key_legacy = derive_master_key_legacy(password, email)
    
    print(f"🕵️ Testing Key Derivations...")
    
    # Peek at first block
    first_block_size = min(ENCRYPTED_BLOCK_SIZE, len(raw_data))
    first_block = raw_data[:first_block_size]
    
    active_key = None
    
    # 1. Try PBKDF2
    res = decrypt_block(first_block, key_pbkdf2)
    if res:
        print("✅ Key Match Found: PBKDF2 (New Standard)")
        active_key = key_pbkdf2
    else:
        # 2. Try Legacy
        res = decrypt_block(first_block, key_legacy)
        if res:
            print("⚠️ Key Match Found: Legacy SHA-256 (Old Format)")
            active_key = key_legacy
        else:
            print("❌ Error: Could not decrypt first block with either key.")
            print("   Possible causes: Wrong password/email, or file is corrupted.")
            # Deep Diagnostic: Try to decrypt without padding to see what the data looks like
            raw_dec = decrypt_block(first_block, key_pbkdf2, use_padding=False)
            if raw_dec:
                print(f"   Diagnostic Peek (PBKDF2): {raw_dec[:32].hex()}...")
            return

    # Full Decryption
    print(f"🔓 Decrypting file...")
    output_data = bytearray()
    offset = 0
    block_num = 0
    
    while offset < len(raw_data):
        remaining = len(raw_data) - offset
        # We need to find the magic to handle variable sized blocks if any
        if raw_data[offset : offset + MAGIC_SIZE] != MAGIC:
            print(f"❌ Critical: Magic mismatch at block {block_num} (offset {offset})")
            break
            
        # Determine this block's total size (9 + 16 + payload + padding)
        # For our protocol, every block is ENCRYPTED_BLOCK_SIZE except maybe the last
        current_block_size = min(ENCRYPTED_BLOCK_SIZE, remaining)
        
        block = raw_data[offset : offset + current_block_size]
        plain = decrypt_block(block, active_key)
        
        if plain is None:
            print(f"❌ Decryption failed at block {block_num}")
            break
            
        output_data.extend(plain)
        offset += current_block_size
        block_num += 1

    output_filename = "pc_verified_" + os.path.basename(remote_path)
    with open(output_filename, "wb") as f:
        f.write(output_data)
    
    print(f"✅ VERIFICATION COMPLETE")
    print(f"📄 Saved to: {output_filename}")
    print(f"📊 Final Plain Size: {len(output_data)} bytes")
    print(f"🔒 SHA256: {hashlib.sha256(output_data).hexdigest()}")

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python3 verify_sync.py <base_url> <email> <password> <remote_path>")
    else:
        run_verify(sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3], sys.argv[4])
