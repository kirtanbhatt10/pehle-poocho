"""Detectors for Indian personal data.

The detectors favour precision. Identifiers with a checksum (Aadhaar, card
numbers) are validated, and bare digit strings that could be anything, such
as order ids or timestamps, are reported only when the field name, nearby
text or the formatting says what they are.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Iterator
from urllib.parse import unquote

# Verhoeff tables (dihedral group D5), used by UIDAI for the Aadhaar check digit.
_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)

PAN_ENTITIES = {
    "A": "association of persons",
    "B": "body of individuals",
    "C": "company",
    "F": "firm or LLP",
    "G": "government",
    "H": "Hindu undivided family",
    "J": "artificial juridical person",
    "L": "local authority",
    "P": "individual",
    "T": "trust",
}

UPI_HANDLES = frozenset(
    """
    abfspay airtel apl axisb axisbank axl barodampay boi cnrb dbs fbl federal
    freecharge hdfcbank hsbc ibl icici idbi idfcbank idfcfirst ikwik indianbank
    indus jupiteraxis kmbl kotak mahb naviaxis okaxis okhdfcbank okicici oksbi
    paytm pingpay pnb ptaxis pthdfc ptsbi ptyes rbl sbi sib slice superyes
    tapicici timecosmos uco unionbank upi utbi waaxis wahdfcbank waicici wasbi
    yapl ybl yesbank yesbankltd
    """.split()
)

KIND_LABELS = {
    "aadhaar": "Aadhaar number",
    "pan": "PAN",
    "email": "email address",
    "phone": "mobile number",
    "upi": "UPI ID",
    "card": "card number",
    "custom": "test value",
}
KIND_LABELS_HI = {
    "aadhaar": "आधार नंबर",
    "pan": "पैन नंबर",
    "email": "ईमेल पता",
    "phone": "मोबाइल नंबर",
    "upi": "UPI आईडी",
    "card": "कार्ड नंबर",
    "custom": "टेस्ट वैल्यू",
}

_HINTS = {
    "aadhaar": ("aadhaar", "aadhar", "adhaar", "uidai"),
    "phone": ("phone", "mobile", "msisdn", "whatsapp", "contact", "mob", "tel", "ph", "cell"),
    "card": ("cardnumber", "ccnum", "card", "cc"),
}

EMAIL_RE = re.compile(r"(?<![\w.%+-])[\w.%+-]{1,64}@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}(?![\w-])")
UPI_RE = re.compile(r"(?<![\w.-])[\w.-]{2,256}@([A-Za-z]{2,64})(?![\w.-])")
PAN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]{3}[ABCFGHJLPT][A-Z][0-9]{4}[A-Z](?![A-Za-z0-9])")
AADHAAR_RE = re.compile(r"(?<!\d)(?<!\d[ -])([2-9]\d{3})([ -]?)(\d{4})\2(\d{4})(?![ -]?\d)")
PHONE_RE = re.compile(r"(?<![\d+])(\+?91[ -]?|0)?([6-9]\d{9})(?!\d)")
CARD_RE = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?!\d)")
_CARD_GROUPED = re.compile(r"\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}")
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{16,}={0,2}")
_IMAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico")


@dataclass(frozen=True)
class Hit:
    """One piece of personal data found in a value."""

    kind: str
    value: str
    encoding: str = "plain"
    key: str = ""


@dataclass(frozen=True)
class Needle:
    """A form of a tester-supplied seed value to look for."""

    text: str
    encoding: str
    kind: str
    case_sensitive: bool
    source: str


def verhoeff_valid(digits: str) -> bool:
    check = 0
    for i, ch in enumerate(reversed(digits)):
        check = _D[check][_P[i % 8][int(ch)]]
    return check == 0


def verhoeff_check_digit(digits: str) -> str:
    check = 0
    for i, ch in enumerate(reversed(digits)):
        check = _D[check][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[check])


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _has_hint(kind: str, key: str) -> bool:
    if not key:
        return False
    low = key.lower()
    tokens = set(re.split(r"[^a-z0-9]+", low))
    compact = re.sub(r"[^a-z0-9]", "", low)
    return any(h in tokens or (len(h) >= 5 and h in compact) for h in _HINTS[kind])


def _context_hint(kind: str, text: str, start: int) -> bool:
    window = text[max(0, start - 32):start].lower()
    return any(len(h) >= 5 and h in window for h in _HINTS[kind])


def _try_json(text: str):
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        return json.loads(stripped)
    except ValueError:
        return None


def _flatten(obj, prefix: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _flatten(v, f"{prefix}[{i}]")
    elif obj is not None and not isinstance(obj, bool):
        yield prefix, str(obj)


def _b64decode(token: str) -> str | None:
    body = token.rstrip("=")
    if len(body) % 4 == 1:
        return None
    body = body.replace("-", "+").replace("_", "/")
    try:
        text = base64.b64decode(body + "=" * (-len(body) % 4), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if len(text) < 6:
        return None
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    return text if printable >= 0.95 * len(text) else None


def _expand(value: str, key: str, depth: int) -> Iterator[tuple[str, str, str]]:
    """Yield (text, encoding, key) views of a value: URL-decoded, JSON-flattened, base64-decoded."""
    for _ in range(3):
        if "%" not in value:
            break
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    parsed = _try_json(value) if depth < 4 else None
    if parsed is not None:
        for inner_key, inner in _flatten(parsed, key):
            yield from _expand(inner, inner_key, depth + 1)
        return
    yield value, "plain", key
    if depth < 4:
        for token in _B64_RE.findall(value):
            text = _b64decode(token)
            if text:
                for t, _encoding, k in _expand(text, key, depth + 1):
                    yield t, "base64", k


def _scan_text(text: str, key: str, encoding: str) -> Iterator[Hit]:
    for m in EMAIL_RE.finditer(text):
        if not m.group(0).lower().endswith(_IMAGE_EXT):
            yield Hit("email", m.group(0), encoding, key)
    for m in UPI_RE.finditer(text):
        if m.group(1).lower() in UPI_HANDLES:
            yield Hit("upi", m.group(0), encoding, key)
    for m in PAN_RE.finditer(text):
        yield Hit("pan", m.group(0), encoding, key)
    for m in AADHAAR_RE.finditer(text):
        digits = m.group(1) + m.group(3) + m.group(4)
        if verhoeff_valid(digits) and (
            m.group(2) or _has_hint("aadhaar", key) or _context_hint("aadhaar", text, m.start())
        ):
            yield Hit("aadhaar", digits, encoding, key)
    for m in PHONE_RE.finditer(text):
        if "+" in (m.group(1) or "") or _has_hint("phone", key) or _context_hint("phone", text, m.start()):
            yield Hit("phone", m.group(2), encoding, key)
    for m in CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_valid(digits) and (
            _CARD_GROUPED.fullmatch(m.group(0)) or _has_hint("card", key) or _context_hint("card", text, m.start())
        ):
            yield Hit("card", digits, encoding, key)


def scan_value(value: str, key: str = "") -> list[Hit]:
    """Find personal data in one value. `key` is the field name it came from, if any."""
    hits: list[Hit] = []
    seen: set[tuple[str, str]] = set()
    for text, encoding, inner_key in _expand(value, key, 0):
        for hit in _scan_text(text, inner_key, encoding):
            if (hit.kind, hit.value) not in seen:
                seen.add((hit.kind, hit.value))
                hits.append(hit)
    return hits


def seed_kind(seed: str) -> str:
    s = seed.strip()
    if "@" in s and EMAIL_RE.fullmatch(s):
        return "email"
    digits = re.sub(r"\D", "", s)
    if re.fullmatch(r"[\d\s()+-]+", s) and (len(digits) == 10 or (len(digits) == 12 and digits.startswith("91"))):
        return "phone"
    return "custom"


def seed_needles(seed: str) -> list[Needle]:
    """Every form of a seed value worth searching for: plain, md5, sha1, sha256, base64."""
    s = seed.strip()
    if not s:
        return []
    kind = seed_kind(s)
    if kind == "email":
        plains = {s.lower()}
    elif kind == "phone":
        national = re.sub(r"\D", "", s)[-10:]
        plains = {national, "91" + national, "+91" + national, "0" + national}
    else:
        plains = {s, s.lower(), s.upper()}
    needles = []
    for plain in sorted(plains):
        raw = plain.encode("utf-8")
        needles.append(Needle(plain, "plain", kind, kind == "custom", plain))
        for name in ("md5", "sha1", "sha256"):
            needles.append(Needle(hashlib.new(name, raw).hexdigest(), name, kind, False, plain))
        if len(raw) >= 6:
            needles.append(Needle(base64.b64encode(raw).decode().rstrip("="), "base64", kind, True, plain))
            needles.append(Needle(base64.urlsafe_b64encode(raw).decode().rstrip("="), "base64", kind, True, plain))
    return needles


def search_seeds(text: str, needles: list[Needle]) -> list[Needle]:
    """Return the needles found in text, one per (kind, encoding)."""
    lowered = text.lower()
    found: dict[tuple[str, str], Needle] = {}
    for needle in needles:
        haystack = text if needle.case_sensitive else lowered
        target = needle.text if needle.case_sensitive else needle.text.lower()
        if target in haystack:
            found.setdefault((needle.kind, needle.encoding), needle)
    return list(found.values())


def mask(kind: str, value: str) -> str:
    """Show enough of a value to recognise it, never the whole thing."""
    if kind in ("email", "upi"):
        local, _, domain = value.partition("@")
        return (local[:1] or "*") + "***@" + domain
    if kind == "pan" and len(value) == 10:
        return "***" + value[3] + "*****" + value[-1]
    if kind in ("aadhaar", "phone", "card"):
        digits = re.sub(r"\D", "", value)
        return "*" * (len(digits) - 4) + digits[-4:]
    return (value[:1] or "*") + "***"
