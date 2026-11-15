"""Turn HAR requests into findings, a score and a grade."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from .detect import KIND_LABELS, KIND_LABELS_HI, PAN_ENTITIES, Hit, mask, scan_value, search_seeds, seed_needles
from .har import Request, display_url, load, parse_time
from .trackers import CATEGORY_SEVERITY, match_tracker, registrable_domain

SEVERITIES = ("critical", "high", "medium", "low")
PENALTY = {"critical": 35, "high": 15, "medium": 6, "low": 2}
GRADES = ("A+", "A", "B", "C", "D", "F")

RULES = {
    "PP001": {
        "name": "tracker-before-consent",
        "title": "Tracker loaded before consent",
        "title_hi": "सहमति से पहले ट्रैकर लोड हुआ",
        "help": (
            "The page contacted a known tracking service before the visitor agreed to it. Under the "
            "DPDP Act, 2023, personal data may be processed only for a purpose the person has given "
            "free, specific and informed consent to (Section 6). Load this tag only after the visitor "
            "opts in, and keep it off when they decline."
        ),
        "help_hi": (
            "पेज ने विज़िटर की मंज़ूरी से पहले ही एक ट्रैकिंग सेवा से संपर्क किया। DPDP एक्ट, 2023 की धारा 6 "
            "के अनुसार निजी डेटा का इस्तेमाल सिर्फ़ उसी काम के लिए हो सकता है जिसके लिए व्यक्ति ने अपनी मर्ज़ी "
            "से, साफ़ और पूरी जानकारी के साथ सहमति दी हो। यह टैग सहमति मिलने के बाद ही लोड करें, और मना करने "
            "पर बंद रखें।"
        ),
    },
    "PP002": {
        "name": "third-party-cookie-before-consent",
        "title": "Third-party cookie set before consent",
        "title_hi": "सहमति से पहले थर्ड-पार्टी कुकी सेट हुई",
        "help": (
            "A third-party server set a cookie before the visitor made a choice. Identifier cookies "
            "let that company recognise the same browser across sites. Hold back the request that "
            "sets it until consent is given."
        ),
        "help_hi": (
            "विज़िटर के फ़ैसले से पहले ही किसी थर्ड-पार्टी सर्वर ने कुकी सेट कर दी। ऐसी पहचान वाली कुकी से वह "
            "कंपनी अलग-अलग वेबसाइटों पर उसी ब्राउज़र को पहचान सकती है। कुकी सेट करने वाली रिक्वेस्ट को सहमति "
            "मिलने तक रोकें।"
        ),
    },
    "PP003": {
        "name": "personal-data-to-third-party",
        "title": "Personal data sent to a third party",
        "title_hi": "निजी जानकारी थर्ड-पार्टी को भेजी गई",
        "help": (
            "A request to another company carried personal data. Whoever runs that server now holds "
            "it, and the DPDP Act makes you, the Data Fiduciary, answerable for what your processors "
            "do with it (Section 8). Strip the field before it leaves the page, or send it only to a "
            "processor under contract and only for the purpose the person agreed to."
        ),
        "help_hi": (
            "दूसरी कंपनी को गई एक रिक्वेस्ट में निजी जानकारी थी। अब वह जानकारी उस सर्वर को चलाने वाले के पास "
            "है, और DPDP एक्ट की धारा 8 के तहत इसके लिए आप, यानी डेटा फ़िड्यूशरी, ज़िम्मेदार हैं। पेज से बाहर "
            "भेजने से पहले यह फ़ील्ड हटाएँ, या इसे सिर्फ़ अनुबंध वाले प्रोसेसर को और सिर्फ़ उसी काम के लिए "
            "भेजें जिसकी सहमति मिली है।"
        ),
    },
    "PP004": {
        "name": "personal-data-in-url",
        "title": "Personal data in a URL",
        "title_hi": "URL में निजी जानकारी",
        "help": (
            "Personal data appeared in a URL on your own site. URLs end up in server and proxy logs, "
            "browser history, analytics reports, and in the Referer header and page-URL fields that "
            "tags send to third parties. Send it in a POST body instead."
        ),
        "help_hi": (
            "आपकी अपनी साइट के एक URL में निजी जानकारी दिखी। URL सर्वर और प्रॉक्सी लॉग, ब्राउज़र हिस्ट्री, "
            "एनालिटिक्स रिपोर्ट, और थर्ड-पार्टी टैग को जाने वाले Referer हेडर और पेज-URL फ़ील्ड में पहुँच जाते "
            "हैं। इसे URL की जगह POST बॉडी में भेजें।"
        ),
    },
    "PP005": {
        "name": "hashed-identifier-to-third-party",
        "title": "Hashed or encoded identifier sent to a third party",
        "title_hi": "हैश या एनकोड की हुई पहचान थर्ड-पार्टी को भेजी गई",
        "help": (
            "A value you typed into the site (passed with --seed) left for a third party hashed or "
            "encoded. Hashing an email or phone number does not anonymise it: the receiver can match "
            "it against its own users, which is what ad platforms do with it. Treat it as personal "
            "data and send it only with consent."
        ),
        "help_hi": (
            "आपने साइट में जो वैल्यू डाली थी (--seed), वह हैश या एनकोड होकर थर्ड-पार्टी को गई। ईमेल या फ़ोन "
            "नंबर को हैश करने से वह गुमनाम नहीं होता: पाने वाला उसे अपने यूज़र्स से मिला सकता है, और विज्ञापन "
            "प्लेटफ़ॉर्म यही करते हैं। इसे निजी डेटा मानें और सिर्फ़ सहमति के साथ भेजें।"
        ),
    },
    "PP006": {
        "name": "personal-data-over-http",
        "title": "Personal data sent without encryption",
        "title_hi": "निजी जानकारी बिना एन्क्रिप्शन के भेजी गई",
        "help": (
            "Personal data travelled over plain HTTP, readable by anyone on the same Wi-Fi or network "
            "path. The DPDP Act requires reasonable security safeguards to prevent a personal data "
            "breach (Section 8(5)). Serve this endpoint over HTTPS only and turn on HSTS."
        ),
        "help_hi": (
            "निजी जानकारी सादे HTTP पर गई, जिसे उसी वाई-फ़ाई या नेटवर्क पर कोई भी पढ़ सकता है। DPDP एक्ट की "
            "धारा 8(5) के तहत डेटा लीक रोकने के लिए उचित सुरक्षा उपाय ज़रूरी हैं। इस एंडपॉइंट को सिर्फ़ HTTPS "
            "पर चलाएँ और HSTS चालू करें।"
        ),
    },
}

_KIND_SEVERITY = {"aadhaar": "critical", "card": "critical"}
_WHERE_HI = {
    "query": "क्वेरी पैरामीटर",
    "body": "रिक्वेस्ट बॉडी",
    "path": "URL पाथ",
    "referer": "Referer हेडर",
    "cookie": "कुकी",
}


class AuditError(Exception):
    """The audit options do not fit the recording."""


@dataclass
class Finding:
    rule: str
    severity: str
    host: str
    url: str
    request: int
    summary: str
    summary_hi: str
    count: int = 1
    fingerprint: str = ""


@dataclass
class Report:
    har: str
    page: str | None
    first_party: list[str]
    consent: str
    total_requests: int
    third_party_requests: int
    third_party_hosts: list[str]
    findings: list[Finding] = field(default_factory=list)
    score: int = 100
    grade: str = "A+"


def _where(loc: str, key: str) -> tuple[str, str]:
    key = key if len(key) <= 40 else key[:37] + "..."
    if loc == "query":
        return f"query parameter '{key}'", f"{_WHERE_HI[loc]} '{key}'"
    if loc == "body":
        return (f"request body field '{key}'", f"{_WHERE_HI[loc]} '{key}'") if key else ("request body", _WHERE_HI[loc])
    if loc == "cookie":
        return f"cookie '{key}'", f"{_WHERE_HI[loc]} '{key}'"
    return {"path": "URL path", "referer": "Referer header"}[loc], _WHERE_HI[loc]


def _label(kind: str, value: str) -> tuple[str, str]:
    en, hi = KIND_LABELS[kind], KIND_LABELS_HI[kind]
    if kind == "pan" and len(value) == 10 and value[3] in PAN_ENTITIES:
        en = f"PAN ({PAN_ENTITIES[value[3]]})"
    return en, hi


def _locations(req: Request, third: bool):
    for key, value in req.query:
        yield "query", key, value
    if req.path not in ("", "/"):
        yield "path", "", unquote(req.path)
    if third or req.scheme == "http":
        if req.body_params:
            for key, value in req.body_params:
                yield "body", key, value
        elif req.body:
            yield "body", "", req.body
    if third:
        if req.headers.get("referer"):
            yield "referer", "", req.headers["referer"]
        for part in req.headers.get("cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if value:
                yield "cookie", name, value


def _seed_chunks(req: Request):
    body = req.body or "&".join(f"{k}={v}" for k, v in req.body_params)
    for loc, text in (
        ("query", unquote(req.raw_query)),
        ("path", unquote(req.path)),
        ("body", body),
        ("referer", unquote(req.headers.get("referer", ""))),
        ("cookie", req.headers.get("cookie", "")),
    ):
        if text:
            yield loc, text


def _consent_boundary(requests: list[Request], after: str | None, at: str | None) -> tuple[int, str]:
    if after:
        for pos, req in enumerate(requests):
            if after in req.url:
                return pos, f"from the first request containing '{after}' (request {req.index})"
        raise AuditError(f"no request URL contains '{after}'; check --consent-after")
    if at:
        moment = parse_time(at)
        if moment is None:
            raise AuditError(f"cannot read --consent-time '{at}'; use ISO 8601, e.g. 2026-11-15T19:05:01Z")
        for pos, req in enumerate(requests):
            if req.started and req.started >= moment:
                return pos, f"from {moment.isoformat()}"
        return len(requests), f"from {moment.isoformat()} (after the last request)"
    return len(requests), "none given; the whole recording is treated as before consent"


def _grade(findings: list[Finding]) -> tuple[int, str]:
    if not findings:
        return 100, "A+"
    score = max(0, 100 - sum(PENALTY[f.severity] for f in findings))
    grade = "F"
    for threshold, letter in ((90, "A"), (80, "B"), (65, "C"), (50, "D")):
        if score >= threshold:
            grade = letter
            break
    if any(f.severity == "critical" for f in findings) and GRADES.index(grade) < GRADES.index("D"):
        grade = "D"
    return score, grade


def audit(path, first_party=(), consent_after=None, consent_time=None, seeds=()) -> Report:
    requests, page = load(path)
    parties = sorted({registrable_domain(d) for d in first_party if d.strip()})
    if not parties and page and urlsplit(page).hostname:
        parties = [registrable_domain(urlsplit(page).hostname)]
    boundary, consent_text = _consent_boundary(requests, consent_after, consent_time)
    needles = [n for seed in seeds for n in seed_needles(seed)]
    found: dict[tuple, Finding] = {}

    def add(key: tuple, rule: str, severity: str, req: Request, summary: str, summary_hi: str) -> Finding:
        if key in found:
            found[key].count += 1
            return found[key]
        fingerprint = hashlib.sha256("|".join(map(str, key)).encode()).hexdigest()[:16]
        found[key] = Finding(rule, severity, req.host, req.display_url, req.index, summary, summary_hi, 1, fingerprint)
        return found[key]

    third_hosts: set[str] = set()
    third_count = 0
    for pos, req in enumerate(requests):
        site = registrable_domain(req.host)
        third = site not in parties
        if third:
            third_count += 1
            third_hosts.add(req.host)

        if third and pos < boundary:
            tracker = match_tracker(req.host)
            if tracker:
                add(
                    ("PP001", tracker.vendor), "PP001", CATEGORY_SEVERITY[tracker.category], req,
                    f"{tracker.vendor} ({tracker.category}) at {req.host}",
                    f"{tracker.vendor} ({tracker.category}) — {req.host}",
                )
            if req.set_cookies:
                names = ", ".join(req.set_cookies[:5]) + (" ..." if len(req.set_cookies) > 5 else "")
                add(
                    ("PP002", site), "PP002", "medium", req,
                    f"{req.host} set cookie {names}", f"{req.host} ने कुकी सेट की: {names}",
                )

        leaked: set[tuple[str, str]] = set()
        for loc, outer_key, value in _locations(req, third):
            for hit in scan_value(value, outer_key):
                _report_hit(add, req, site, third, loc, hit)
                leaked.add((hit.kind, loc))

        if third and needles:
            for loc, text in _seed_chunks(req):
                for needle in search_seeds(text, needles):
                    label, label_hi = KIND_LABELS[needle.kind], KIND_LABELS_HI[needle.kind]
                    where, where_hi = _where(loc, "") if loc != "query" else ("query string", "क्वेरी स्ट्रिंग")
                    shown = mask(needle.kind, needle.source)
                    if needle.encoding != "plain":
                        add(
                            ("PP005", needle.kind, site), "PP005", "high", req,
                            f"{label} {shown} as {needle.encoding} in {where} to {req.host}",
                            f"{label_hi} {shown} ({needle.encoding}) → {req.host} ({where_hi})",
                        )
                    elif not any(kind == needle.kind for kind, _loc in leaked) and ("PP003", needle.kind, site) not in found:
                        add(
                            ("PP003", needle.kind, site), "PP003", _KIND_SEVERITY.get(needle.kind, "high"), req,
                            f"{label} {shown} in {where} to {req.host}",
                            f"{label_hi} {shown} → {req.host} ({where_hi})",
                        )

    findings = sorted(found.values(), key=lambda f: (SEVERITIES.index(f.severity), f.rule, f.host, f.summary))
    score, grade = _grade(findings)
    return Report(
        har=str(path),
        page=display_url(page) if page else None,
        first_party=parties,
        consent=consent_text,
        total_requests=len(requests),
        third_party_requests=third_count,
        third_party_hosts=sorted(third_hosts),
        findings=findings,
        score=score,
        grade=grade,
    )


def _report_hit(add, req: Request, site: str, third: bool, loc: str, hit: Hit) -> None:
    label, label_hi = _label(hit.kind, hit.value)
    where, where_hi = _where(loc, hit.key)
    shown = mask(hit.kind, hit.value)
    if hit.encoding != "plain":
        where, where_hi = f"{where} ({hit.encoding})", f"{where_hi} ({hit.encoding})"
    if req.scheme == "http":
        add(
            ("PP006", hit.kind, req.host), "PP006", _KIND_SEVERITY.get(hit.kind, "high"), req,
            f"{label} {shown} in {where} over http://{req.host}",
            f"{label_hi} {shown} — http://{req.host} ({where_hi})",
        )
    if third:
        add(
            ("PP003", hit.kind, site), "PP003", _KIND_SEVERITY.get(hit.kind, "high"), req,
            f"{label} {shown} in {where} to {req.host}",
            f"{label_hi} {shown} → {req.host} ({where_hi})",
        )
    elif loc in ("query", "path"):
        add(
            ("PP004", hit.kind, where), "PP004", "medium", req,
            f"{label} {shown} in {where} on {req.host}",
            f"{label_hi} {shown} — {req.host} ({where_hi})",
        )
