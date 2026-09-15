

"""
qr_utils.py — QR code decoding using OpenCV's built-in QRCodeDetector.

We use cv2.QRCodeDetector instead of pyzbar so the project has one less
system-level dependency (pyzbar needs the zbar shared library installed
on the OS, which complicates setup for a BCA project on Windows).

The uploaded image is decoded fully IN MEMORY — it is never written to
disk, so there is no temporary file to clean up or secure.
"""

import re

# Delay importing heavy native libraries until actually needed so the
# app can start even when OpenCV is not installed in the environment.
cv2 = None
np = None

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB

URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def decode_qr_from_bytes(file_bytes: bytes):
    """
    Returns (decoded_text:str|None, error:str|None).
    Never raises on a bad/garbled image — returns a friendly error instead.
    """
    if not file_bytes:
        return None, "The uploaded file is empty."

    if len(file_bytes) > MAX_UPLOAD_BYTES:
        return None, "The uploaded file is too large (max 5 MB)."

    global cv2, np
    try:
        import numpy as _np
        import cv2 as _cv2
        np = _np
        cv2 = _cv2
    except Exception:
        return None, "Server does not have OpenCV installed for QR decoding. Use the demo scan instead."

    try:
        np_arr = np.frombuffer(file_bytes, dtype=np.uint8)
        image = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    except Exception:
        return None, "Could not read the uploaded image."

    if image is None:
        return None, "Could not read the uploaded image. Please upload a valid PNG/JPG/WEBP file."

    detector = cv2.QRCodeDetector()
    try:
        data, points, _ = detector.detectAndDecode(image)
    except Exception:
        return None, "Failed to scan the QR code from this image."

    if not data:
        try:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            data, points, _ = detector.detectAndDecode(gray)
            if not data:
                enlarged = cv2.resize(gray, None, fx=1.8, fy=1.8, interpolation=cv2.INTER_CUBIC)
                data, points, _ = detector.detectAndDecode(enlarged)
            if not data:
                crisp = cv2.resize(gray, None, fx=4, fy=4, interpolation=cv2.INTER_NEAREST)
                data, points, _ = detector.detectAndDecode(crisp)
            if not data:
                _, binary = cv2.threshold(crisp, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
                data, points, _ = detector.detectAndDecode(binary)
            if not data:
                adaptive = cv2.adaptiveThreshold(
                    crisp, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                    cv2.THRESH_BINARY, 31, 5
                )
                data, points, _ = detector.detectAndDecode(adaptive)
            if not data and hasattr(detector, "detectAndDecodeMulti"):
                found, decoded_info, _, _ = detector.detectAndDecodeMulti(enlarged)
                if found and decoded_info:
                    data = next((value for value in decoded_info if value), "")
            if not data:
                bordered = cv2.copyMakeBorder(enlarged, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
                data, points, _ = detector.detectAndDecode(bordered)
        except Exception:
            return None, "Failed to scan the QR code from this image."

    if not data:
        return None, "No QR code could be detected in this image."

    return data, None


def classify_payload(data: str) -> str:
    if URL_RE.match(data.strip()):
        return "URL"
    if data.strip().upper().startswith("UPI:") or "upi://" in data.lower():
        return "UPI_PAYMENT"
    return "TEXT"