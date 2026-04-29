from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from pydantic import BaseModel
import base64
import json

from app.database import get_db
from app.models import User, DataLog
from app.security import decode_access_token
from app.crypto_service import verify_signature
from app.crypto_service import decrypt_data


router = APIRouter(prefix="/data", tags=["Secure Data"])



# REQUEST SCHEMA

class SecureDataRequest(BaseModel):
    payload: dict
    signature: str



# MAIN ENDPOINT

@router.post("/send")
def send_secure_data(
    request: SecureDataRequest,
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
   
    # VERIFY JWT
   
    token = authorization.replace("Bearer ", "").strip()
    decoded = decode_access_token(token)

    if not decoded:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == decoded["user_id"]).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.public_key:
        raise HTTPException(status_code=400, detail="User has no public key")

    
    # PREPARE DATA FOR SIGNATURE CHECK
    
    payload_json = json.dumps(
        request.payload,
        sort_keys=True,
        separators=(",", ":")
    )
    data_bytes = payload_json.encode("utf-8")

    try:
        signature_bytes = base64.b64decode(request.signature)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid signature encoding")

    
    # VERIFY SIGNATURE
  
    is_valid = verify_signature(user.public_key, data_bytes, signature_bytes)


    # LOG DATA (IMPORTANT PART)
 
    log = DataLog(
        user_id=user.id,
        payload=json.dumps(request.payload),
        is_valid=is_valid
    )
    db.add(log)
    db.commit()

 
    # RETURN RESPONSE
    
    if not is_valid:
        raise HTTPException(status_code=400, detail="Fake or tampered data detected")

    return {"message": "Data accepted (valid signature)"}




class EncryptedDataRequest(BaseModel):
    encrypted_payload: str
    signature: str


@router.post("/send-encrypted")
def send_encrypted_data(
    request: EncryptedDataRequest,
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    token = authorization.replace("Bearer ", "").strip()
    decoded = decode_access_token(token)

    if not decoded:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == decoded["user_id"]).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.public_key:
        raise HTTPException(status_code=400, detail="User has no public key")

    encrypted_bytes = request.encrypted_payload.encode("utf-8")

    try:
        signature_bytes = base64.b64decode(request.signature)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid signature encoding")

    is_valid = verify_signature(user.public_key, encrypted_bytes, signature_bytes)

    if not is_valid:
        log = DataLog(
            user_id=user.id,
            payload=request.encrypted_payload,
            is_valid=False
        )
        db.add(log)
        db.commit()

        raise HTTPException(status_code=400, detail="Fake or tampered encrypted data detected")

    try:
        decrypted_payload = decrypt_data(request.encrypted_payload)
    except Exception:
        raise HTTPException(status_code=400, detail="Decryption failed")

    log = DataLog(
        user_id=user.id,
        payload=decrypted_payload,
        is_valid=True
    )
    db.add(log)
    db.commit()

    return {
        "message": "Encrypted data accepted",
        "decrypted_payload": decrypted_payload
    }