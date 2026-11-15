import os
import sys
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai_persona import analyze_scam_persona
from database import add_or_update_flag, get_intel_for_indicators, get_trending_threats, init_db
from image_qr_scanner import MAX_IMAGE_BYTES, scan_image
from upi_sms_scanner import scan_message

app = FastAPI(
    title="PhishGuard India API",
    description="AI-powered phishing, QR and Indian UPI/SMS scam analysis with community threat intelligence.",
    version="1.1.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_PATH = os.path.join(ROOT, "frontend", "index.html")


@app.on_event("startup")
def startup_event():
    init_db()


class AnalyzeRequest(BaseModel):
    message: Optional[str] = Field(default="", description="SMS, email, UPI text, or URL to analyze")
    sender: Optional[str] = Field(default=None, description="Optional SMS sender ID or phone number")


class FlagRequest(BaseModel):
    indicator_type: str
    indicator_value: str = Field(min_length=1, max_length=2048)
    scam_category: str = "General Phishing / Scam"
    is_safe: bool = False


def analyze_text(message: str, sender: Optional[str] = None) -> dict:
    message = message.strip()
    if not message:
        raise HTTPException(status_code=400, detail="Provide message text or a QR payload to analyze.")
    scan = scan_message(message, sender.strip() if sender and sender.strip() else None)
    indicators = [{"type": "msg_hash", "value": scan["msg_hash"]}]
    indicators.extend({"type": "upi_id", "value": value} for value in scan["upi"]["upi_ids"])
    indicators.extend({"type": "url", "value": value} for value in scan["urls"]["urls"])
    matched = get_intel_for_indicators(indicators)
    flags = sum(row.get("flag_count", 0) for row in matched)
    safe_votes = sum(row.get("safe_votes", 0) for row in matched)
    categories = list(dict.fromkeys(
        row["scam_category"] for row in matched
        if row.get("scam_category") and row["scam_category"] != "False Positive (Safe)"
    ))

    score = scan["base_score"] + min(30, flags * 5)
    if safe_votes > flags:
        score = max(5, score - min(35, (safe_votes - flags) * 8))
    score = max(3, min(99, score))
    if score >= 80:
        verdict, level = "CRITICAL THREAT", "CRITICAL"
    elif score >= 50:
        verdict, level = "HIGH RISK SCAM", "HIGH"
    elif score >= 25:
        verdict, level = "SUSPICIOUS ACTIVITY", "SUSPICIOUS"
    else:
        verdict, level = "SAFE / LOW RISK", "SAFE"

    flaggable = [{"type": "msg_hash", "value": scan["msg_hash"], "label": f"Message fingerprint · {scan['msg_hash']}"}]
    flaggable.extend({"type": "upi_id", "value": value, "label": f"UPI ID · {value}"} for value in scan["upi"]["upi_ids"])
    flaggable.extend({"type": "url", "value": value, "label": f"URL · {value}"} for value in scan["urls"]["urls"])
    return {
        "verdict": verdict,
        "risk_score": score,
        "risk_level": level,
        "primary_category": categories[0] if categories else scan["primary_category"],
        "msg_hash": scan["msg_hash"],
        "scanner_details": scan,
        "community_intel": {
            "has_prior_reports": flags > 0,
            "total_flags": flags,
            "total_safe_votes": safe_votes,
            "matched_indicators": matched,
            "community_categories": categories,
        },
        "ai_persona": analyze_scam_persona(message, scan),
        "flaggable_indicators": flaggable,
    }


@app.get("/")
def serve_dashboard():
    if not os.path.isfile(FRONTEND_PATH):
        raise HTTPException(status_code=404, detail="Dashboard frontend not found.")
    return FileResponse(FRONTEND_PATH, media_type="text/html")


@app.post("/analyze")
def analyze_threat(payload: AnalyzeRequest):
    return analyze_text(payload.message or "", payload.sender)


@app.post("/analyze-image")
async def analyze_image(file: UploadFile = File(...), sender: Optional[str] = Form(default=None)):
    suffix = os.path.splitext(file.filename or "")[1].lower()
    if suffix not in {".png", ".jpg", ".jpeg", ".webp"}:
        raise HTTPException(status_code=415, detail="Upload a PNG, JPG, JPEG, or WEBP image.")
    data = await file.read(MAX_IMAGE_BYTES + 1)
    if len(data) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail="Image is too large. Maximum upload size is 10 MB.")
    try:
        extracted = scan_image(data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    combined = "\n".join(part for part in [extracted["ocr_text"], *extracted["qr_payloads"]] if part)
    if not combined:
        raise HTTPException(status_code=422, detail=extracted["notice"] or "No readable text or QR code was found in the image.")
    report = analyze_text(combined, sender)
    report["image_findings"] = extracted
    return report


@app.post("/flag")
def flag_threat(payload: FlagRequest):
    valid_types = {"msg_hash", "upi_id", "url"}
    if payload.indicator_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"indicator_type must be one of {sorted(valid_types)}")
    if not payload.is_safe and not payload.scam_category.strip():
        raise HTTPException(status_code=400, detail="Select a scam category.")
    updated = add_or_update_flag(
        payload.indicator_type,
        payload.indicator_value,
        payload.scam_category,
        payload.is_safe,
    )
    return {"status": "success", "message": "Community report recorded.", "record": updated}


@app.get("/trending")
def trending_threats():
    threats = get_trending_threats(limit=5)
    return {"status": "success", "count": len(threats), "threats": threats}
