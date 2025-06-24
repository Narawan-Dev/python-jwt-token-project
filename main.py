from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

import jwt
import datetime
import base64
import json

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EncodeData(BaseModel):
    payload: dict
    secret: str

class DecodeData(BaseModel):
    token: str

@app.get("/")
def read_root():
    return {"message": "JWT Encode/Decode API is running 🚀"}

@app.post("/encode")
def encode_token(data: EncodeData):
    payload = data.payload.copy()
    token = jwt.encode(payload, data.secret, algorithm="HS256")
    return {"token": token}

@app.post("/decode")
def decode_no_verify(data: DecodeData):
    try:
        parts = data.token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid token format")

        def b64decode(segment):
            padded = segment + '=' * (-len(segment) % 4)
            return json.loads(base64.urlsafe_b64decode(padded).decode('utf-8'))

        header = b64decode(parts[0])
        payload = b64decode(parts[1])

        return {
            "header": header,
            "payload": payload
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid token: {str(e)}")
