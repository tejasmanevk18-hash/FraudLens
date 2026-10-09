"""Lightweight, in-memory static analysis helpers for FraudLens scanners."""

import io
import mimetypes
import os
import re
import zipfile
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

MAX_EMAIL_CHARS = 100_000
MAX_FILE_BYTES = 5 * 1024 * 1024
SUPPORTED_FILE_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "txt", "zip",
    "png", "jpg", "jpeg", "gif", "webp",
}
SUPPORTED_MIME_TYPES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text/plain",
    "application/zip",
    "application/x-zip-compressed",
    "image/png", "image/jpeg", "image/gif", "image/webp",
}

RISKY_EMAIL_TERMS = [
    (r"\b(?:otp|one[- ]time password|verification code|2fa code)\b", "Credential or verification request"),
    (r"\b(?:password|passcode|pin)\s+(?:for|is|to|your|now)?\b", "Credential or password request"),
    (r"\b(?:urgent|immediately|right now|within\s+\d+\s+(?:hours|minutes)|act now|do not delay)\b", "Urgency or threat language"),
    (r"\b(?:click|visit|open|reply)\s+(?:[a-z0-9_:/.-]+|the\s+link)\b", "Call to action or link request"),
    (r"\b(?:pay|payment|transfer|bank account|invoice|renew|subscription|gift card|crypto)\b", "Payment or financial request"),
    (r"\b(?:confirm|verify|login|sign in|account suspended|account locked|malware|infected)\b", "Account or security threat"),
    (r"\b(?:prize|winner|cash|free money|unlock|claim reward)\b", "Too-good-to-be-true offer language"),
]
RISKY_URL_TERMS = ["bit.ly", "tinyurl", "t.co", "shorturl", "urlscan", "paste.ee", "youtu.be"]
SUSPICIOUS_HOST_TERMS = ["verify", "secure", "login", "bank", "update", "confirm", "account", "paypal", "micros0ft", "google"]
DANGEROUS_FILE_MARKERS = [
    b"MZ", b"\x7fELF", b"%PDF-", b"PK\x03\x04", b"\x89PNG\r\n\x1a\n",
]
SCRIPT_MARKERS = [
    "<script", "javascript:", "vbscript:", "eval(", "document.cookie",
    "onerror=", "onclick=", "powershell", "cmd.exe", "wscript", "cscript",
]


def _risk_level(score):
    if score >= 70:
        return "Dangerous", "danger"
    if score >= 40:
        return "Suspicious", "medium"
    return "Safe", "safe"


def _extract_urls(text):
    return re.findall(r"https?://[^\s<>'\"`]+|www\.[^\s<>'\"`]+", text, re.IGNORECASE)


def _domain_from_url(url):
    try:
        parsed = urlparse(url.strip())
        domain = parsed.hostname or ""
        return domain.lower().rstrip(".")
    except Exception:
        return ""


def _extract_email_fields(raw_bytes):
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    text_parts = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                try:
                    text_parts.append(part.get_payload(decode=True).decode("utf-8", "replace"))
                except Exception:
                    pass
    else:
        try:
            text_parts.append(message.get_payload(decode=True).decode("utf-8", "replace"))
        except Exception:
            pass
    return message, text_parts


def _first_header(message, name):
    value = message.get(name) if message else None
    return str(value) if value else ""


def analyze_email_text(content, source="paste"):
    text = (content or "").strip()
    if not text:
        return {"success": False, "message": "Please enter email content to analyze."}
    if len(text) > MAX_EMAIL_CHARS:
        return {"success": False, "message": "Email content is too large (maximum 100 KB)."}

    issues = []
    score = 0
    detected_urls = []
    for pattern, label in RISKY_EMAIL_TERMS:
        if re.search(pattern, text, re.IGNORECASE):
            issues.append(label)
            score += 15
    if re.search(r"\b(?:password|credential|otp|pin)\b", text, re.IGNORECASE):
        score += 10
    if re.search(r"(?:\b(?:pay|payment|transfer|bank)\b|\$\d|\d+\s*(?:usd|eur|gbp))", text, re.IGNORECASE):
        score += 10

    urls = _extract_urls(text)
    for url in urls:
        detected_urls.append(url.rstrip(".,;:)]}"))
        host = _domain_from_url(url)
        if any(term in host for term in RISKY_URL_TERMS):
            issues.append("Suspicious shortened or masked URL")
            score += 20
        elif any(term in host for term in SUSPICIOUS_HOST_TERMS):
            issues.append(f"Suspicious URL/domain indicator: {host}")
            score += 8
        elif host and not re.match(r"^[a-z0-9-]+\.[a-z]{2,}$", host):
            issues.append(f"Unusual URL domain: {host}")
            score += 8
        if any(term in url.lower() for term in ("http://", "ftp://")):
            issues.append("Non-HTTPS link detected")
            score += 8

    if urls and not issues:
        issues.append("Suspicious URL detected")
        score += 5

    score = min(score, 100)
    level, css_class = _risk_level(score)
    if not issues:
        issues = ["No strong phishing or fraud indicators detected"]
    parsed_headers = BytesParser(policy=policy.default).parsebytes(
        text.encode("utf-8", errors="replace")
    )
    return {
        "success": True,
        "status": level,
        "severity": css_class,
        "risk_score": score,
        "indicators": list(dict.fromkeys(issues)),
        "suspicious_urls": list(dict.fromkeys(detected_urls)),
        "email_metadata": {
            "sender": _first_header(parsed_headers, "From"),
            "reply_to": _first_header(parsed_headers, "Reply-To"),
            "subject": _first_header(parsed_headers, "Subject"),
        },
        "source": source,
        "recommendation": (
            "Review the sender and links carefully, and do not provide credentials or payment details."
            if level != "Safe"
            else "No strong phishing indicators were detected, but always verify unexpected requests through an official channel."
        ),
    }


def analyze_eml_file(file_bytes, filename):
    if not file_bytes:
        return {"success": False, "message": "The uploaded email file is empty."}
    if not filename.lower().endswith(".eml"):
        return {"success": False, "message": "Unsupported email file. Please upload a .eml file."}
    try:
        message, text_parts = _extract_email_fields(file_bytes)
        if not message:
            raise ValueError("Could not parse email")
        raw_text = "\n".join(text_parts)
        if not raw_text:
            raw_text = file_bytes.decode("utf-8", "replace")
        sender = _first_header(message, "From")
        reply_to = _first_header(message, "Reply-To")
        subject = _first_header(message, "Subject")
        headers_text = "\n".join(
            f"{key}: {value}" for key, value in message.raw_items()
        )
        content = "\n".join([sender, reply_to, subject, headers_text, raw_text])
        result = analyze_email_text(content, source="eml")
        result["email_metadata"] = {
            "sender": sender,
            "reply_to": reply_to,
            "subject": subject,
        }
        return result
    except Exception as exc:
        return {"success": False, "message": f"The email file could not be parsed: {exc}"}


def _safe_extension(filename):
    return os.path.splitext(filename or "")[1].lower().lstrip(".")


def _mime_from_magic(file_bytes):
    if file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if file_bytes.startswith((b"\xff\xd8\xff",)):
        return "image/jpeg"
    if file_bytes.startswith(b"GIF87a") or file_bytes.startswith(b"GIF89a"):
        return "image/gif"
    if file_bytes.startswith(b"RIFF") and file_bytes[8:12] == b"WEBP":
        return "image/webp"
    if file_bytes.startswith(b"%PDF-"):
        return "application/pdf"
    if file_bytes.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "application/zip"
    if file_bytes.startswith(b"MZ"):
        return "application/x-msdownload"
    if file_bytes.startswith(b"\x7fELF"):
        return "application/x-executable"
    return "application/octet-stream"


def _scan_zip(file_bytes):
    issues = []
    names = []
    content_snippets = []
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as archive:
            names = archive.namelist()
            for name in names[:50]:
                if name.lower().endswith((".exe", ".dll", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".scr")):
                    issues.append(f"Executable or script file inside archive: {name}")
                if any(marker in name.lower() for marker in ("macro", "vba", "auto_open", "script")):
                    issues.append(f"Potential macro or script artifact: {name}")
                try:
                    member = archive.open(name)
                    data = member.read(100_000)
                    content_snippets.append(data)
                except Exception:
                    continue
    except Exception:
        issues.append("Archive structure could not be read safely")
    text = "\n".join(
        str(name) for name in names
    ) + "\n" + "\n".join(
        data.decode("utf-8", "replace") for data in content_snippets
        if isinstance(data, bytes)
    )
    for marker in SCRIPT_MARKERS:
        if marker.lower() in text.lower():
            issues.append(f"Script-like content detected: {marker}")
            break
    return issues, text


def analyze_uploaded_file(filename, file_bytes, mime_type=None):
    if not filename or not file_bytes:
        return {"success": False, "message": "Please select a file to scan."}
    if len(file_bytes) > MAX_FILE_BYTES:
        return {"success": False, "message": "File is too large (maximum 5 MB)."}
    extension = _safe_extension(filename)
    if extension not in SUPPORTED_FILE_EXTENSIONS:
        return {"success": False, "message": f"Unsupported file type: {extension or 'unknown'}. Supported formats are PDF, DOC, DOCX, XLS, XLSX, TXT, ZIP, PNG, JPG, GIF and WEBP."}

    detected_mime = mime_type or _mime_from_magic(file_bytes)
    detected_mime = detected_mime.lower().split(";", 1)[0]
    if detected_mime not in SUPPORTED_MIME_TYPES and detected_mime != "application/octet-stream":
        return {"success": False, "message": "The file type could not be safely identified."}
    issues = []
    score = 0
    if extension in {"docx", "xlsx"} and detected_mime == "application/zip":
        pass
    elif extension in {"doc", "xls"} and detected_mime not in SUPPORTED_MIME_TYPES:
        issues.append("File extension does not match detected type")
        score += 10
    elif extension in {"pdf"} and detected_mime != "application/pdf":
        issues.append("File extension does not match detected type")
        score += 10
    elif extension in {"txt"} and detected_mime not in {"text/plain", "application/octet-stream"}:
        issues.append("File extension does not match detected type")
        score += 10
    elif extension in {"jpg", "jpeg", "png", "gif", "webp"} and not detected_mime.startswith("image/"):
        issues.append("File extension does not match detected type")
        score += 10

    if len(file_bytes) > 10 * 1024 * 1024:
        issues.append("Large file size may increase review risk")
        score += 10
    if any(token in filename.lower() for token in ("invoice", "payment", "password", "credential", "urgent", "verify", "bank")):
        issues.append("Filename contains potentially suspicious terms")
        score += 5
    if file_bytes.startswith(b"MZ") or file_bytes.startswith(b"\x7fELF"):
        issues.append("Executable or binary content detected")
        score += 45
    if extension == "zip":
        zip_issues, text = _scan_zip(file_bytes)
        issues.extend(zip_issues)
        score += sum(20 if "Executable" in issue or "script" in issue.lower() else 8 for issue in zip_issues)
    else:
        text = ""
        if detected_mime.startswith("text/") or extension == "txt":
            try:
                text = file_bytes.decode("utf-8", "replace")
            except UnicodeDecodeError:
                pass
        elif extension in {"docx", "xlsx"} and detected_mime == "application/zip":
            zip_issues, text = _scan_zip(file_bytes)
            issues.extend(zip_issues)
            score += sum(20 if "Executable" in issue or "script" in issue.lower() else 8 for issue in zip_issues)
        elif extension == "pdf":
            text = file_bytes.decode("latin-1", "replace")

    if text:
        urls = _extract_urls(text)
        for url in urls:
            host = _domain_from_url(url)
            if any(term in host for term in RISKY_URL_TERMS):
                issues.append("Suspicious shortened URL found in file")
                score += 25
            elif host and not re.match(r"^[a-z0-9-]+\.[a-z]{2,}$", host):
                issues.append(f"Unusual URL domain found in file: {host}")
                score += 10
        for marker in SCRIPT_MARKERS:
            if marker.lower() in text.lower():
                issues.append(f"Script-like content detected in file: {marker}")
                score += 20
                break
        if re.search(r"\b(?:password|credential|otp|api[_-]?key|secret)\b", text, re.IGNORECASE):
            issues.append("Credential-like content detected")
            score += 10
        if re.search(r"\b(?:macro|vbaProject|auto_open|openxml)\b", text, re.IGNORECASE):
            issues.append("Macro or document-code indicator detected")
            score += 15

    score = min(score, 100)
    level, css_class = _risk_level(score)
    if not issues:
        issues = ["No strong static security indicators detected"]
    return {
        "success": True,
        "status": level,
        "severity": css_class,
        "risk_score": score,
        "file_name": filename,
        "file_type": extension.upper() or detected_mime,
        "file_size": len(file_bytes),
        "mime_type": detected_mime,
        "indicators": list(dict.fromkeys(issues)),
        "suspicious_urls": list(dict.fromkeys(_extract_urls(text))),
        "recommendation": (
            "No strong static indicators were detected. Continue to review the file with trusted software and authorities."
            if level == "Safe"
            else "Do not open or execute the file from untrusted sources. Verify its source and use trusted security tools."
        ),
    }
