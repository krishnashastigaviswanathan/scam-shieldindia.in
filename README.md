# PhishGuard India

A FastAPI-powered phishing, UPI/SMS and QR screenshot analyzer with local Ollama persona analysis and a SQLite community threat feed.

## Run locally

```bash
python -m pip install -r requirements.txt
# Optional AI persona engine (the built-in rule-based analyzer works without Ollama)
ollama pull llama3.2
cd backend
python -m uvicorn main:app --reload
```

Open <http://127.0.0.1:8000>. The API docs are available at `/docs`. The database is initialized as `backend/threats.db` on startup. Message content is analyzed in memory; the community database stores a normalized message fingerprint and user-reported indicators, not the raw message.

For screenshot OCR, install the Tesseract OCR system binary separately and make it available on PATH. If it is missing, QR decoding still works and the API returns an OCR-unavailable notice. Image uploads are limited to PNG/JPEG/WEBP and 10 MB.

## API

- `POST /analyze` — JSON `{ "message": "...", "sender": "..." }`
- `POST /analyze-image` — multipart `file` and optional `sender`
- `POST /flag` — community scam report or safe vote
- `GET /trending` — top five community-reported indicators
