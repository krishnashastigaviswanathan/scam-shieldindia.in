import io
from typing import Any, Dict, List

from PIL import Image, UnidentifiedImageError

ALLOWED_FORMATS = {"PNG", "JPEG", "WEBP"}
MAX_IMAGE_BYTES = 10 * 1024 * 1024


def scan_image(image_bytes: bytes) -> Dict[str, Any]:
    """Decode QR codes and OCR screenshot text; OCR is optional at runtime."""
    if not image_bytes:
        raise ValueError("The uploaded image is empty.")
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise ValueError("Image is too large. Maximum upload size is 10 MB.")

    try:
        image = Image.open(io.BytesIO(image_bytes))
        image.verify()
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise ValueError("Please upload a valid PNG, JPG, JPEG, or WEBP image.") from exc

    if image.format not in ALLOWED_FORMATS and image.format is not None:
        raise ValueError("Please upload a PNG, JPG, JPEG, or WEBP image.")

    qr_payloads: List[str] = []
    qr_error = None
    try:
        import cv2
        import numpy as np

        detector = cv2.QRCodeDetector()
        image_array = np.array(image)
        decoded, points, _ = detector.detectAndDecode(image_array)
        if decoded:
            qr_payloads.append(decoded.strip())
        # Multi-code decoding is available only in some OpenCV builds.
        if hasattr(detector, "detectAndDecodeMulti"):
            result = detector.detectAndDecodeMulti(image_array)
            if result and result[0]:
                for value in result[1]:
                    value = value.strip()
                    if value and value not in qr_payloads:
                        qr_payloads.append(value)
    except Exception as exc:  # Keep screenshot OCR usable even if QR support fails.
        qr_error = f"QR decoding was unavailable: {exc}"

    ocr_text = ""
    ocr_available = True
    ocr_notice = None
    try:
        import pytesseract

        ocr_text = pytesseract.image_to_string(image).strip()
    except Exception:
        ocr_available = False
        ocr_notice = "OCR is unavailable because Tesseract is not installed or configured. QR scanning is still available."

    return {
        "qr_payloads": qr_payloads,
        "ocr_text": ocr_text,
        "ocr_available": ocr_available,
        "notice": ocr_notice or qr_error,
    }
