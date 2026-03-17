import os
import json
import logging
import asyncio
import aiofiles
import hashlib
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, BackgroundTasks
from fastapi.responses import FileResponse, StreamingResponse

from ..config import STORAGE_DIR, ENCRYPTED_BLOCK_SIZE
from ..database import get_db
from ..models import FileRequest, RestoreRequest, BlockCheckRequest, BlockDownloadRequest, FinalizeRequest
from ..dependencies import get_current_user
from ..utils import is_safe_path, calculate_file_hash_and_blocks
from ..services.version_manager import version_manager
from .. import crud

logger = logging.getLogger("VaultSync")
router = APIRouter(prefix="/api/v1")

@router.get("/files")
def list_files(prefix: Optional[str] = None, current_user = Depends(get_current_user)):
    """
    Returns a list of all files synced by the current user, optionally filtered by path prefix.
    """
    with get_db() as conn:
        return {"files": crud.list_user_files(conn, current_user['id'], prefix=prefix)}

@router.get("/versions")
def list_versions(path: str, current_user = Depends(get_current_user)):
    """
    Lists all available historical versions for a specific file path.
    """
    if not is_safe_path(current_user['id'], path):
        raise HTTPException(status_code=403, detail="Forbidden: Path traversal detected")
    versions = version_manager.list_versions(current_user['id'], path)
    return {"path": path, "versions": versions}

@router.post("/versions/restore")
def restore_version(body: RestoreRequest, current_user = Depends(get_current_user)):
    """
    Restores a specific version of a file. The current version is backed up before restoration.
    """
    user_id = current_user['id']
    if not is_safe_path(user_id, body.path):
        raise HTTPException(status_code=403, detail="Forbidden")
    
    try:
        # Create a version of the current file before restoring
        with get_db() as conn:
            metadata = crud.get_file_metadata(conn, user_id, body.path)
            if metadata:
                version_manager.create_version(user_id, body.path, metadata['device_name'])
        
        version_manager.restore_version(user_id, body.path, body.version_id)
        
        # Update metadata to match the restored file
        user_root = os.path.join(STORAGE_DIR, str(user_id))
        safe_path = os.path.abspath(os.path.join(user_root, body.path.lstrip("/\\")))
        
        actual_hash, block_hashes = calculate_file_hash_and_blocks(safe_path)
        
        with get_db() as conn:
            crud.update_file_sync(
                conn, user_id, body.path, actual_hash, 
                os.path.getsize(safe_path), int(os.path.getmtime(safe_path) * 1000), 
                json.dumps(block_hashes)
            )
            conn.commit()
            
        return {"message": "Success", "hash": actual_hash}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Version not found")
    except Exception as e:
        logger.error(f"❌ Restore failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/files/manifest")
def get_file_manifest(path: str, current_user = Depends(get_current_user)):
    """
    Returns the block manifest (list of SHA-256 hashes) for a specific file.
    """
    if not is_safe_path(current_user['id'], path):
        raise HTTPException(status_code=403)
    with get_db() as conn:
        metadata = crud.get_file_metadata(conn, current_user['id'], path)
    if not metadata:
        raise HTTPException(status_code=404)
    return {"path": path, "blocks": json.loads(metadata['blocks']) if metadata['blocks'] else []}

@router.post("/blocks/check")
def check_blocks(body: BlockCheckRequest, current_user = Depends(get_current_user)):
    """
    Compares local block hashes with server block hashes and returns indices of missing/modified blocks.
    """
    if not is_safe_path(current_user['id'], body.path):
        raise HTTPException(status_code=403)
    with get_db() as conn:
        metadata = crud.get_file_metadata(conn, current_user['id'], body.path)
    server_blocks = json.loads(metadata['blocks']) if metadata and metadata['blocks'] else []
    return {"missing": [i for i, h in enumerate(body.blocks) if i >= len(server_blocks) or server_blocks[i] != h]}

@router.post("/blocks/download")
async def download_blocks(body: BlockDownloadRequest, current_user = Depends(get_current_user)):
    """
    Streams specific blocks of a file based on provided indices. Merges contiguous block reads for performance.
    """
    if not is_safe_path(current_user['id'], body.path):
        raise HTTPException(status_code=403)
    safe_path = os.path.abspath(os.path.join(STORAGE_DIR, str(current_user['id']), body.path.lstrip("/\\")))
    if not os.path.exists(safe_path):
        raise HTTPException(status_code=404)

    async def iter_blocks():
        if not body.indices:
            return
            
        # Group contiguous indices
        sorted_indices = sorted(body.indices)
        groups = []
        current_group = [sorted_indices[0]]
        
        for i in range(1, len(sorted_indices)):
            if sorted_indices[i] == current_group[-1] + 1:
                current_group.append(sorted_indices[i])
            else:
                groups.append(current_group)
                current_group = [sorted_indices[i]]
        if current_group:
            groups.append(current_group)

        async with aiofiles.open(safe_path, "rb") as f:
            for group in groups:
                start_offset = group[0] * ENCRYPTED_BLOCK_SIZE
                read_size = len(group) * ENCRYPTED_BLOCK_SIZE
                
                await f.seek(start_offset)
                
                # Stream the merged group in chunks to avoid blowing up memory if the group is huge
                bytes_left = read_size
                chunk_size = 1024 * 1024 * 4  # 4MB max per yield
                while bytes_left > 0:
                    chunk = await f.read(min(chunk_size, bytes_left))
                    if not chunk:
                        break
                    yield chunk
                    bytes_left -= len(chunk)
                    
    return StreamingResponse(iter_blocks(), media_type="application/octet-stream")

@router.post("/upload")
async def upload_fragment(request: Request, current_user = Depends(get_current_user)):
    """
    Uploads a file fragment at a specific offset. Used for both full uploads and delta patching.
    Requires 'x-vaultsync-path' and 'x-vaultsync-offset' headers.
    """
    headers = request.headers
    path = headers.get("x-vaultsync-path")
    offset = int(headers.get("x-vaultsync-offset") or 0)
    if not path or not is_safe_path(current_user['id'], path):
        raise HTTPException(status_code=403)
    
    user_id = current_user['id']
    safe_path = os.path.abspath(os.path.join(STORAGE_DIR, str(user_id), path.lstrip("/\\")))
    os.makedirs(os.path.dirname(safe_path), exist_ok=True)
    
    # Version before overwrite at offset 0
    if offset == 0 and os.path.exists(safe_path):
        with get_db() as conn:
            metadata = crud.get_file_metadata(conn, user_id, path)
            if metadata:
                version_manager.create_version(user_id, path, metadata['device_name'])
                
    hasher = hashlib.sha256()
    bytes_written = 0
    
    # Safely create the file without truncating if it doesn't exist to prevent concurrent upload races
    if not os.path.exists(safe_path):
        try:
            open(safe_path, "a").close()
        except Exception:
            pass
            
    async with aiofiles.open(safe_path, "r+b") as f:
        await f.seek(offset)
        async for chunk in request.stream():
            await f.write(chunk)
            hasher.update(chunk)
            bytes_written += len(chunk)
            
    # For smart delta hashing, if the upload matches a block size, we update the block hash.
    # If it's a full stream, we'll just fall back to full file hashing in finalize.
    if bytes_written <= ENCRYPTED_BLOCK_SIZE and bytes_written > 0:
        block_idx = offset // ENCRYPTED_BLOCK_SIZE
        block_hash = hasher.hexdigest()
        with get_db() as conn:
            metadata = crud.get_file_metadata(conn, user_id, path)
            if metadata and metadata.get('blocks'):
                blocks = json.loads(metadata['blocks'])
                if block_idx < len(blocks):
                    blocks[block_idx] = block_hash
                    crud.update_file_sync(conn, user_id, path, metadata['hash'], metadata['size'], metadata['updated_at'], json.dumps(blocks))
                    conn.commit()

    return {"message": "OK"}

@router.post("/upload/finalize")
async def finalize_upload(body: FinalizeRequest, current_user = Depends(get_current_user)):
    """
    Finalizes a file upload. Avoids reading the whole file if smart delta hashing can be used.
    """
    user_id = current_user['id']
    if not is_safe_path(user_id, body.path):
        raise HTTPException(status_code=403)
        
    safe_path = os.path.abspath(os.path.join(STORAGE_DIR, str(user_id), body.path.lstrip("/\\")))
    if not os.path.exists(safe_path):
        raise HTTPException(status_code=404)

    actual_hash = body.hash
    block_hashes = []
    
    with get_db() as conn:
        metadata = crud.get_file_metadata(conn, user_id, body.path)
        if metadata and metadata.get('blocks'):
            block_hashes = json.loads(metadata['blocks'])
            
        # If it's a completely new file or we don't have blocks, calculate the hard way
        if not block_hashes:
            actual_hash, block_hashes = await asyncio.to_thread(calculate_file_hash_and_blocks, safe_path)
            
        crud.upsert_file_metadata(
            conn, user_id, body.path, actual_hash, 
            body.size or os.path.getsize(safe_path), body.updated_at, 
            body.device_name, json.dumps(block_hashes)
        )
        conn.commit()
    return {"message": "Success", "hash": actual_hash}

@router.post("/download")
def download_file(body: FileRequest, current_user = Depends(get_current_user)):
    """
    Downloads a full file from the server.
    """
    if not is_safe_path(current_user['id'], body.filename):
        raise HTTPException(status_code=403)
    safe_path = os.path.abspath(os.path.join(STORAGE_DIR, str(current_user['id']), body.filename.lstrip("/\\")))
    if not os.path.exists(safe_path):
        raise HTTPException(status_code=404)
    return FileResponse(safe_path, media_type="application/octet-stream")
