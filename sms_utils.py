

"""
sms_utils.py — SMS text cleaning + rule-based indicator extraction.

Kept deliberately separate from the ML model: the model gives a
Spam/Ham prediction + confidence, and this module independently flags
human-readable reasons ("indicators") using simple keyword rules. The
two are combined in app.py to produce the final risk score.
"""

import re

INDICATOR_RULES = [
    (r"\burgent\b|\bimmediately\b|\bwithin\s+\d+\s*(hour|hr)s?\b", "Urgent language"),
    (r"\botp\b|\bone[\s-]?time\s+password\b", "OTP request"),
    (r"\bbank\b|\baccount\b.*\b(verify|update|confirm)\b|\bkyc\b", "Bank/account verification request"),
    (r"\bwon\b|\bwinner\b|\bcongratulations\b|\bprize\b|\blucky draw\b|\breward\b", "Prize/reward claim"),
    (r"\bsuspend|\bblock|\bdeactivat|\bclose\b.*\baccount\b", "Account suspension threat"),
    (r"https?://|www\.|bit\.ly|tinyurl|t\.co", "Suspicious URL"),
    (r"\bpassword\b|\bpin\b|\bcvv\b|\bcard number\b", "Request for sensitive information"),
    (r"\bpay(ment)?\b.*\bimmediately\b|\bfine\b|\bpenalty\b|\blegal action\b", "Payment/legal threat"),
    (r"\bfree\b.*\b(recharge|gift|cash)\b", "Too-good-to-be-true offer"),
]


def clean_text(text: str) -> str:
    text = str(text).lower()
    text = re.sub(r"http\S+|www\.\S+", " URL ", text)
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def extract_indicators(raw_text: str) -> list[str]:
    lowered = raw_text.lower()
    found = []
    for pattern, label in INDICATOR_RULES:
        if re.search(pattern, lowered) and label not in found:
            found.append(label)
    return found


def combine_risk_score(model_confidence: float, prediction: str, indicator_count: int) -> int:
    """
    Blend the ML model's confidence with the number of rule-based
    indicators into a single 0-100 application-level risk score.

    This is an application-level indicator, not a guaranteed measurement.
    """
    base = model_confidence * 100 if prediction == "spam" else (1 - model_confidence) * 100
    bonus = min(indicator_count * 4, 20)
    score = base * 0.75 + bonus
    return int(max(0, min(100, round(score))))


def risk_level(score: int) -> str:
    if score <= 30:
        return "Safe"
    if score <= 60:
        return "Suspicious"
    return "Scam"


def recommendation_for(level: str) -> str:
    return {
        "Safe": "This message does not show strong scam patterns. Still, never share OTPs or passwords over SMS.",
        "Suspicious": "This message shows some risky language. Avoid clicking any links and verify with the sender directly.",
        "Scam": "This message shows strong signs of a scam. Do not click any links, reply, or share personal information.",
    }[level]