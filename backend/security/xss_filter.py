# FILE: backend/security/xss_filter.py
# PURPOSE: Demonstrates unfiltered HTML output vs. bleach-sanitised safe output
# SECURITY NOTE: render_raw() returns user content verbatim — intentional XSS demo

import bleach

ALLOWED_TAGS: list[str] = ["b", "i", "em", "strong", "p"]
ALLOWED_ATTRS: dict = {}


def render_raw(text: str) -> str:
    # VULNERABLE: returns content as-is, allowing script injection
    return text


def render_safe(text: str) -> str:
    # SECURE: strips all disallowed HTML tags via bleach
    return bleach.clean(text, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
