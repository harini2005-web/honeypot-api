from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import re
from datetime import datetime
import os

# -------------------------
# App initialization
# -------------------------
app = FastAPI()

# -------------------------
# Environment variable
# -------------------------
API_KEY = os.getenv("API_KEY")

# -------------------------
# Health check (required for GUVI tester)
# -------------------------
@app.get("/")
def root():
    return {"status": "ok"}

# -------------------------
# Request model
# -------------------------
class RequestModel(BaseModel):
    message: str

# -------------------------
# Shared logic functions
# -------------------------
def analyze_message(message: str):
    msg = message.lower()

    scam_keywords = ["won", "urgent", "upi", "click", "lottery", "account"]
    score = sum(1 for k in scam_keywords if k in msg)
    is_scam = score >= 2

    upi_ids = re.findall(r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}", message)
    links = re.findall(r"https?://\S+", message)
    banks = re.findall(r"\b\d{9,18}\b", message)

    return is_scam, score, upi_ids, banks, links


def build_response(is_scam, score, upi_ids, banks, links):
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

# -------------------------
# POST /detect (PRIMARY – evaluator uses this)
# -------------------------
@app.post("/detect")
def detect_post(
    data: RequestModel,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    is_scam, score, upi_ids, banks, links = analyze_message(data.message)
    return build_response(is_scam, score, upi_ids, banks, links)

# -------------------------
# GET /detect (fallback – GUVI tester compatibility)
# -------------------------
@app.get("/detect")
def detect_get(
    message: str = "",
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    is_scam, score, upi_ids, banks, links = analyze_message(message)
    return build_response(is_scam, score, upi_ids, banks, links)
