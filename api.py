from fastapi import FastAPI, Request
from pydantic import BaseModel
from lyn_encryption import encrypt, decrypt

app = FastAPI()

class EncryptRequest(BaseModel):
    plaintext: str
    key: str

class DecryptRequest(BaseModel):
    ciphertext: str
    key: str

@app.post("/encrypt")
def encrypt_endpoint(req: EncryptRequest):
    try:
        encrypted = encrypt(req.plaintext, req.key)
        return {"encrypted": encrypted}
    except Exception as e:
        return {"error": str(e)}

@app.post("/decrypt")
def decrypt_endpoint(req: DecryptRequest):
    try:
        decrypted = decrypt(req.ciphertext, req.key)
        return {"decrypted": decrypted}
    except Exception as e:
        return {"error": str(e)}

@app.get("/")
def root():
    return {"message": "LYN Encryption API is running."}
