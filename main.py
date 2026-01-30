from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import re
from datetime import datetime

app = FastAPI()
@app.get("/")
def root():
    return {"status": "ok"}

import os
API_KEY = os.getenv("API_KEY")


class RequestModel(BaseModel):
    message: str

@app.post("/detect")
def detect(
    data: RequestModel,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    msg = data.message.lower()

    scam_keywords = ["won", "urgent", "upi", "click", "lottery", "account"]
    score = sum(1 for k in scam_keywords if k in msg)
    is_scam = score >= 2

    upi_ids = re.findall(r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}", data.message)
    links = re.findall(r"https?://\S+", data.message)
    banks = re.findall(r"\b\d{9,18}\b", data.message)

    return {
        "is_scam": is_scam,
        "confidence": round(min(0.6 + score * 0.1, 0.99), 2),
        "extracted_intelligence": {
            "upi_ids": upi_ids,
            "bank_accounts": banks,
            "phishing_links": links
        },
        "persona_used": "naive_user",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
