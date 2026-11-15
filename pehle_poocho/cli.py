"""Command-line entry point."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .analyze import GRADES, AuditError, audit
from .har import HarError
from .report import render_json, render_markdown, render_sarif, render_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pehle-poocho",
        description=(
            "Audit a HAR recording for trackers, cookies and personal data (Aadhaar, PAN, UPI, phone, "
            "email) that a website sends out before the visitor consents."
        ),
        epilog="Exit codes: 0 ok, 1 grade worse than --min-grade, 2 usage or input error.",
    )
    parser.add_argument("har", help="HAR file saved from the browser's Network panel")
    parser.add_argument("-f", "--format", choices=("text", "markdown", "json", "sarif"), default="text")
    parser.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    parser.add_argument(
        "--lang", choices=("en", "hi", "both"), default="en", help="language of text and Markdown reports"
    )
    parser.add_argument(
        "--first-party",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="a domain that belongs to the site (repeatable); default: the recorded page's domain",
    )
    consent = parser.add_mutually_exclusive_group()
    consent.add_argument(
        "--consent-after",
        metavar="TEXT",
        help="requests from the first URL containing TEXT onward count as after consent",
    )
    consent.add_argument(
        "--consent-time", metavar="ISO8601", help="requests at or after this time count as after consent"
    )
    parser.add_argument(
        "--seed",
        action="append",
        default=[],
        metavar="VALUE",
        help="a test email, phone number or other value you typed into the site; "
        "found even when hashed (md5, sha1, sha256) or base64-encoded (repeatable)",
    )
    parser.add_argument(
        "--min-grade", choices=GRADES, metavar="GRADE", help="exit 1 if the grade is worse (A+, A, B, C, D, F)"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _write_stdout(text: str) -> None:
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        sys.stdout.flush()
        sys.stdout.buffer.write(text.encode("utf-8"))
    sys.stdout.flush()


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = audit(
            args.har,
            first_party=args.first_party,
            consent_after=args.consent_after,
            consent_time=args.consent_time,
            seeds=args.seed,
        )
    except (HarError, AuditError) as exc:
        print(f"pehle-poocho: error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        text = render_json(report)
    elif args.format == "sarif":
        text = render_sarif(report)
    elif args.format == "markdown":
        text = render_markdown(report, args.lang)
    else:
        text = render_text(report, args.lang)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
        except OSError as exc:
            print(f"pehle-poocho: error: cannot write {args.output}: {exc.strerror or exc}", file=sys.stderr)
            return 2
    else:
        _write_stdout(text)

    if args.min_grade and GRADES.index(report.grade) > GRADES.index(args.min_grade):
        print(f"pehle-poocho: grade {report.grade} is worse than the required {args.min_grade}", file=sys.stderr)
        return 1
    return 0
