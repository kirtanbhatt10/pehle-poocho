"""Render an audit report as text, Markdown, JSON or SARIF."""
from __future__ import annotations

import json
import textwrap

from . import __version__
from .analyze import RULES, SEVERITIES, Report

HOMEPAGE = "https://github.com/kirtanbhatt10/pehle-poocho"
SEVERITY_HI = {"critical": "गंभीर", "high": "ऊँचा", "medium": "मध्यम", "low": "कम"}
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SECURITY_SEVERITY = {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "2.0"}


def to_dict(report: Report) -> dict:
    return {
        "tool": "pehle-poocho",
        "version": __version__,
        "har": report.har,
        "page": report.page,
        "first_party": report.first_party,
        "consent": report.consent,
        "requests": {
            "total": report.total_requests,
            "third_party": report.third_party_requests,
            "third_party_hosts": report.third_party_hosts,
        },
        "score": report.score,
        "grade": report.grade,
        "findings": [
            {
                "rule": f.rule,
                "name": RULES[f.rule]["name"],
                "severity": f.severity,
                "title": RULES[f.rule]["title"],
                "summary": f.summary,
                "summary_hi": f.summary_hi,
                "host": f.host,
                "url": f.url,
                "request": f.request,
                "count": f.count,
                "fingerprint": f.fingerprint,
            }
            for f in report.findings
        ],
    }


def render_json(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False) + "\n"


def _wrap(text: str, indent: str) -> list[str]:
    return textwrap.wrap(text, width=96, initial_indent=indent, subsequent_indent=indent)


def render_text(report: Report, lang: str = "en") -> str:
    en, hi = lang in ("en", "both"), lang in ("hi", "both")
    out = [f"pehle-poocho {__version__}: {report.har}", ""]
    out.append(f"  Page         {report.page or 'unknown'}")
    out.append(f"  First party  {', '.join(report.first_party) or 'unknown'}")
    out.append(f"  Consent      {report.consent}")
    out.append(
        f"  Requests     {report.total_requests} total, {report.third_party_requests} to "
        f"{len(report.third_party_hosts)} third-party hosts"
    )
    out.append("")
    if en:
        out.append(f"  Grade {report.grade}  (score {report.score}/100)")
    if hi:
        out.append(f"  ग्रेड {report.grade}  (स्कोर {report.score}/100)")
    if not report.findings:
        out.append("")
        if en:
            out.append("  No findings: nothing this tool looks for left the page.")
        if hi:
            out.append("  कोई समस्या नहीं मिली।")
        return "\n".join(out) + "\n"

    out.append("")
    for f in report.findings:
        rule = RULES[f.rule]
        times = f" (x{f.count})" if f.count > 1 else ""
        if en:
            out.append(f"  {f.severity.upper():<9} {f.rule}  {rule['title']}")
            out.append(f"            {f.summary}{times}")
        if hi:
            prefix = f"  {SEVERITY_HI[f.severity]:<9} {f.rule}  " if not en else "            "
            out.append(f"{prefix}{rule['title_hi']}: {f.summary_hi}{times}")
        out.append(f"            {f.url}")
    out.append("")
    out.append("  How to fix" if en else "  कैसे ठीक करें")
    for rule_id in sorted({f.rule for f in report.findings}):
        rule = RULES[rule_id]
        out.append("")
        if en:
            out.append(f"  {rule_id}  {rule['title']}")
            out.extend(_wrap(rule["help"], "        "))
        if hi:
            if not en:
                out.append(f"  {rule_id}  {rule['title_hi']}")
            out.extend(_wrap(rule["help_hi"], "        "))
    return "\n".join(out) + "\n"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: Report, lang: str = "en") -> str:
    en, hi = lang in ("en", "both"), lang in ("hi", "both")
    out = [f"## pehle-poocho: grade {report.grade} ({report.score}/100)", ""]
    out += [
        "| | |",
        "|---|---|",
        f"| Recording | `{_cell(report.har)}` |",
        f"| Page | {_cell(report.page or 'unknown')} |",
        f"| First party | {_cell(', '.join(report.first_party) or 'unknown')} |",
        f"| Consent boundary | {_cell(report.consent)} |",
        f"| Requests | {report.total_requests} total, {report.third_party_requests} to "
        f"{len(report.third_party_hosts)} third-party hosts |",
        "",
    ]
    if not report.findings:
        out.append("No findings: nothing this tool looks for left the page.")
        return "\n".join(out) + "\n"
    counts = {s: sum(f.severity == s for f in report.findings) for s in SEVERITIES}
    out.append(" · ".join(f"**{counts[s]}** {s}" for s in SEVERITIES if counts[s]))
    out += ["", "| Severity | Rule | Finding | Request |", "|---|---|---|---|"]
    for f in report.findings:
        rule = RULES[f.rule]
        parts = []
        if en:
            parts.append(f"**{rule['title']}**: {f.summary}")
        if hi:
            parts.append(f"**{rule['title_hi']}**: {f.summary_hi}")
        times = f" (x{f.count})" if f.count > 1 else ""
        out.append(f"| {f.severity} | {f.rule} | {_cell('<br>'.join(parts))}{times} | `{_cell(f.url)}` |")
    out += ["", "### How to fix", ""]
    for rule_id in sorted({f.rule for f in report.findings}):
        rule = RULES[rule_id]
        if en:
            out += [f"**{rule_id} · {rule['title']}.** {rule['help']}", ""]
        if hi:
            out += [f"**{rule_id} · {rule['title_hi']}।** {rule['help_hi']}", ""]
    return "\n".join(out)


def render_sarif(report: Report) -> str:
    uri = report.har.replace("\\", "/")
    rules = []
    for rule_id, rule in RULES.items():
        rules.append(
            {
                "id": rule_id,
                "name": rule["name"],
                "shortDescription": {"text": rule["title"]},
                "fullDescription": {"text": rule["help"]},
                "help": {"text": rule["help"] + "\n\n" + rule["help_hi"]},
                "helpUri": f"{HOMEPAGE}#rules",
                "properties": {"tags": ["privacy", "dpdp", "security"]},
            }
        )
    results = []
    for f in report.findings:
        results.append(
            {
                "ruleId": f.rule,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f"{RULES[f.rule]['title']}: {f.summary} ({f.url})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [{"name": f.host, "kind": "host"}],
                    }
                ],
                "partialFingerprints": {"pehlePoocho/v1": f.fingerprint},
                "properties": {"security-severity": _SECURITY_SEVERITY[f.severity], "count": f.count},
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pehle-poocho",
                        "version": __version__,
                        "informationUri": HOMEPAGE,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"
