"""HTTP Security Headers & Transport Posture Auditor."""
from __future__ import annotations
from typing import Any, Mapping

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS", 25),
    ("Content-Security-Policy", "CSP", 30),
    ("X-Frame-Options", "Clickjacking Defense", 15),
    ("X-Content-Type-Options", "MIME Sniffing Defense", 15),
    ("Referrer-Policy", "Referrer Leaks Defense", 10),
    ("Permissions-Policy", "Browser Feature Permissions", 5),
]

def audit_security_headers(headers: Mapping[str, str]) -> dict[str, Any]:
    """Calculate defense score and identify missing HTTP security headers."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    score = 0
    present_headers: dict[str, str] = {}
    missing_headers: list[str] = []

    for header_name, desc, weight in SECURITY_HEADERS:
        val = lower_headers.get(header_name.lower())
        if val:
            score += weight
            present_headers[header_name] = val
        else:
            missing_headers.append(header_name)

    # Determine letter grade
    if score >= 85:
        grade = "A"
    elif score >= 65:
        grade = "B"
    elif score >= 40:
        grade = "C"
    elif score >= 20:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": score,
        "grade": grade,
        "present_headers": present_headers,
        "missing_headers": missing_headers,
    }
