# VaultSync Server

RAM-safe, bit-perfect backend for the VaultSync synchronization platform.

## Features
- **FastAPI Core:** High-performance async Python backend.
- **Zero-Copy Patching:** Uses `f.seek()` for direct binary block updates, keeping memory usage near-constant.
- **PostgreSQL Meta-Sync:** Reliable file tracking and block manifest management.
- **Streaming Restoration:** Native `FileResponse` support for high-speed save downloads.
- **Cloudflare Compatible:** Standardized on Port 8080 for seamless proxying.

## Setup
VaultSync is designed to run in Docker for maximum reliability.

```bash
docker compose up --build -d
```

## Security
VaultSync is a Zero-Knowledge system. The server stores hardware-encrypted fragments (`AES-256-CBC`) and has no access to your local Master Key.

## Verification
Use the included `verify_sync.py` script to verify bit-perfect integrity from your PC:
```bash
python3 verify_sync.py <BASE_URL> <EMAIL> <PASSWORD> <REMOTE_PATH>
```
