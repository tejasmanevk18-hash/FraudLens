

"""
link_utils.py — Defensive, rule-based URL risk analysis.

IMPORTANT: this module NEVER makes a network request to the submitted
URL. It only inspects the text of the URL itself (scheme, host,
structure). This is intentional — visiting or fetching a possibly
malicious URL server-side would be unsafe.
"""

import re
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy"}
SUSPICIOUS_KEYWORDS = ["verify", "secure", "update", "confirm", "login", "account",
                        "bank", "payment", "kyc", "reward", "gift", "claim", "urgent"]
SUSPICIOUS_TLDS = {".top", ".xyz", ".info", ".click", ".gq", ".tk", ".work", ".loan"}

IP_HOST_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def analyze_url(raw_url: str):
    """Returns (risk_score:int, indicators:list[str])."""
    indicators = []
    score = 8

    url = raw_url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        # Normalize for parsing but still flag missing scheme as risky-ish
        parse_target = "http://" + url
    else:
        parse_target = url

    parsed = urlparse(parse_target)
    host = (parsed.hostname or "").lower()
    full_lower = url.lower()

    if parsed.scheme == "http":
        indicators.append("Not using HTTPS")
        score += 15

    if IP_HOST_RE.match(host):
        indicators.append("Uses a raw IP address instead of a domain name")
        score += 20

    if any(host == s or host.endswith("." + s) for s in SHORTENERS):
        indicators.append("Shortened / masked link")
        score += 18

    subdomain_count = max(host.count(".") - 1, 0)
    if subdomain_count >= 3:
        indicators.append("Excessive subdomains")
        score += 10

    if len(url) > 75:
        indicators.append("Unusually long URL")
        score += 8

    if host.count("-") >= 2:
        indicators.append("Multiple hyphens in domain")
        score += 8

    if host.startswith("xn--") or ".xn--" in host:
        indicators.append("Punycode / internationalized domain (possible spoof)")
        score += 15

    if any(tld in host for tld in SUSPICIOUS_TLDS):
        indicators.append("Uncommon or high-risk top-level domain")
        score += 10

    if any(kw in full_lower for kw in SUSPICIOUS_KEYWORDS):
        indicators.append("Suspicious keyword in URL (e.g. verify/login/account)")
        score += 10

    if re.search(r"\d{5,}", host):
        indicators.append("Unusual numeric pattern in domain")
        score += 6

    if "@" in url:
        indicators.append("Contains '@' — may hide the real destination")
        score += 15

    score = int(max(0, min(97, score)))
    if not indicators:
        indicators.append("No strong risk indicators detected")

    return score, indicators


def risk_level(score: int) -> str:
    if score <= 30:
        return "Safe"
    if score <= 60:
        return "Suspicious"
    return "High Risk"


def recommendation_for(level: str) -> str:
    return {
        "Safe": "This link looks reasonably safe. As always, verify the sender before entering credentials.",
        "Suspicious": "This link shows some risky traits. Avoid entering personal or banking information.",
        "High Risk": "This link shows strong signs of phishing. Do not open it or enter any information.",
    }[level]