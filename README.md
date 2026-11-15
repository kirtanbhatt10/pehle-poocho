# pehle-poocho

**पहले पूछो — "ask first."** See what your website sends to trackers before the visitor says yes.

[![CI](https://github.com/kirtanbhatt10/pehle-poocho/actions/workflows/ci.yml/badge.svg)](https://github.com/kirtanbhatt10/pehle-poocho/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

You record a page load in your browser and save it as a HAR file. pehle-poocho reads that recording and tells you:

- which **trackers** loaded and which **third-party cookies** were set before the visitor agreed to anything;
- which **personal data** left the page for another company: Aadhaar, PAN, UPI IDs, mobile numbers, emails and card numbers, including when they are URL-encoded, buried in JSON or **base64-encoded**;
- whether your test email or phone number went out **hashed** (sha256, sha1, md5), the way ad pixels send "advanced matching" data;
- whether personal data travelled over **plain HTTP** or sat in a **URL**, where it ends up in logs and analytics.

Each finding is explained in **English and Hindi**, mapped to the relevant section of the DPDP Act, and graded from A+ to F. Output as text, Markdown, JSON or SARIF, with a GitHub Action for CI.

It is pure Python with no dependencies, it makes no network requests, and it never prints a personal value in full.

## Why

India's Digital Personal Data Protection Rules were notified on 13 November 2025, and the substantive obligations (consent, notices, security safeguards, breach reporting) apply from **13 May 2027**. Most consent problems are not in a privacy policy. They are in the network tab: an analytics tag that fires on page load, a pixel that receives the checkout URL with the customer's email in it, an SDK that base64-encodes a phone number and posts it to an attribution service.

Code scanners look at your source. pehle-poocho looks at what the deployed page actually sends.

## Install

```bash
pip install git+https://github.com/kirtanbhatt10/pehle-poocho
```

Or run it straight from a clone, with nothing to install:

```bash
git clone https://github.com/kirtanbhatt10/pehle-poocho
cd pehle-poocho
python -m pehle_poocho examples/before-consent.har
```

## Record a HAR file

1. Open a fresh incognito window so no earlier consent is remembered.
2. Open DevTools (F12) → **Network**, tick **Preserve log**.
3. Load your site. **Do not touch the cookie banner.** If you want to test a form, fill it with test data (for example a test email you will pass as `--seed`).
4. Optionally click "Accept" at the end, so you can mark the consent point with `--consent-after`.
5. Right-click the request list → **Save all as HAR** (or the download icon).

Recent Chrome versions may save a *sanitized* HAR that drops cookies and auth headers. That is fine for every rule except PP002 (cookies before consent), which needs the `Set-Cookie` headers; export with sensitive data if you want that rule, and keep that file private.

## Use

```bash
pehle-poocho site.har
pehle-poocho site.har --lang both                           # English and Hindi
pehle-poocho site.har --seed test@yourmail.in --seed 9876543210
pehle-poocho site.har --consent-after /api/consent          # requests from here on are post-consent
pehle-poocho site.har --first-party mybrand.in --first-party mybrand-cdn.com
pehle-poocho site.har --format sarif --output pehle-poocho.sarif
pehle-poocho site.har --min-grade B                         # exit 1 if worse than B
```

Output on the bundled sample recording (`examples/before-consent.har`, synthetic data), shortened:

```text
pehle-poocho 0.1.0: examples/before-consent.har

  Page         https://shop.kirana.example/checkout
  First party  kirana.example
  Consent      none given; the whole recording is treated as before consent
  Requests     13 total, 9 to 9 third-party hosts

  Grade F  (score 0/100)

  CRITICAL  PP006  Personal data sent without encryption
            Aadhaar number ********2346 in request body field 'aadhaar' over http://forms.kirana.example
            http://forms.kirana.example/kyc
  HIGH      PP001  Tracker loaded before consent
            Microsoft Clarity (session-replay) at www.clarity.ms
            https://www.clarity.ms/tag/kiranaq7
  HIGH      PP003  Personal data sent to a third party
            PAN (individual) ***P*****K in request body field 'data.pan' (base64) to api2.branch.io
            https://api2.branch.io/v1/open
  HIGH      PP003  Personal data sent to a third party
            email address p***@mail.example in query parameter 'dl' to www.google-analytics.com
            https://www.google-analytics.com/g/collect
  HIGH      PP005  Hashed or encoded identifier sent to a third party
            email address p***@mail.example as sha256 in query string to www.facebook.com
            https://www.facebook.com/tr/
  ...
```

With `--lang hi`:

```text
  गंभीर     PP006  निजी जानकारी बिना एन्क्रिप्शन के भेजी गई: आधार नंबर ********2346 — http://forms.kirana.example (रिक्वेस्ट बॉडी 'aadhaar')
```

### Options

| Option | What it does |
|---|---|
| `-f, --format` | `text` (default), `markdown`, `json` or `sarif` |
| `-o, --output FILE` | Write the report to a file |
| `--lang` | `en` (default), `hi` or `both` for text and Markdown |
| `--first-party DOMAIN` | Domains that belong to you (repeatable). Default: the recorded page's domain |
| `--consent-after TEXT` | Requests from the first URL containing TEXT onward count as after consent |
| `--consent-time ISO8601` | Same, by timestamp |
| `--seed VALUE` | A test value you typed into the site; found plain, hashed or base64-encoded (repeatable) |
| `--min-grade GRADE` | Exit 1 if the grade is worse than GRADE |

Exit codes: `0` ok, `1` grade worse than `--min-grade`, `2` usage or input error.

## Rules

| ID | Finding | Severity |
|---|---|---|
| PP001 | Known tracker contacted before consent | high for advertising, session replay and attribution; medium for analytics and marketing; low for tag managers and error monitoring |
| PP002 | Third-party cookie set before consent | medium |
| PP003 | Personal data sent to a third party (query, path, body, Referer, cookie) | critical for Aadhaar and card numbers, high otherwise |
| PP004 | Personal data in a URL on your own site | medium |
| PP005 | A `--seed` value sent to a third party hashed or encoded | high |
| PP006 | Personal data sent over plain HTTP | critical for Aadhaar and card numbers, high otherwise |

Rules PP001 and PP002 respect the consent boundary. The others apply to the whole recording, because sending personal data to the wrong place is a problem whether or not a banner was clicked.

**Grading.** The score starts at 100 and loses 35 per critical, 15 per high, 6 per medium and 2 per low finding (repeats of the same issue count once). A+ means no findings, A is 90+, B 80+, C 65+, D 50+, F below 50. Any critical finding caps the grade at D.

## How detection works

The goal is findings you can act on, not a wall of maybes.

- **Aadhaar**: 12 digits starting 2–9 with a valid **Verhoeff** check digit, and either 4-4-4 formatting or a field name or nearby text such as `aadhaar`. A bare 12-digit order id is not flagged.
- **PAN**: the `AAAAA9999A` shape with a valid fourth letter (entity type: P individual, C company, H HUF, F firm and so on), which the report spells out.
- **UPI ID**: `name@handle` where the handle is a known UPI handle (`oksbi`, `ybl`, `paytm`, `okhdfcbank`, ...), so emails are not mistaken for UPI IDs.
- **Mobile number**: Indian 10-digit numbers starting 6–9, only with a `+91` prefix or a field name such as `mobile`, `phone`, `msisdn`. Timestamps and ids stay quiet.
- **Card number**: 13–19 digits passing **Luhn**, grouped in fours or under a field name such as `card`.
- **Email**: standard shape, ignoring retina image names like `logo@2x.png`.
- **Decoding**: values are URL-decoded (also when double-encoded), JSON bodies are flattened (`data.user.mobile`), and base64 tokens are decoded and scanned again.
- **Seeds**: for each `--seed`, the tool searches for the plain value, its md5, sha1 and sha256 (lowercased email; phone as 10 digits, `91…`, `+91…` and `0…`) and its base64 forms.
- **Third party**: a host whose registrable domain differs from the page's (with India-aware suffixes such as `.co.in` and `.gov.in`), unless you list it with `--first-party`.
- **Trackers**: a curated list of 56 domains (Google Analytics and Ads, Meta Pixel, Microsoft Clarity, Hotjar, TikTok, LinkedIn, Branch, AppsFlyer, MoEngage, CleverTap, WebEngage, Netcore and others). Pull requests welcome.

## GitHub Action

Record a HAR in your end-to-end tests (Playwright can save one with `recordHar`), then:

```yaml
name: Consent audit
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      # ... run your e2e tests that write recordings/home.har ...
      - id: consent
        uses: kirtanbhatt10/pehle-poocho@v0.1.0
        with:
          har: recordings/home.har
          min-grade: B
          consent-after: /api/consent
          seeds: ${{ secrets.TEST_USER_EMAIL }}
          lang: both
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: pehle-poocho.sarif
```

The Action writes a Markdown report to the job summary, a SARIF file for code scanning, and the outputs `grade` and `score`.

## Privacy of the tool itself

- No network access, no telemetry, no dependencies.
- Every personal value is masked in every output format (`********2346`, `p***@mail.example`, `***P*****K`). URLs in reports drop the query string and hide path segments that look like identifiers.
- HAR files can contain session cookies and tokens. Record with a test account, keep real recordings out of git (the bundled `.gitignore` ignores `*.har`), and delete them when done.

## Limits

- It sees one recording. A tracker that only fires on another page, after a scroll, or on a slow network will not be in it.
- The tracker list and the registrable-domain logic are heuristics, not the full Public Suffix List.
- It checks what was sent, not what the receiver does with it, and it cannot tell whether you have a valid contract with a processor.
- **This is a technical audit, not legal advice or a compliance certificate.** Use it to find problems early and talk to counsel about what they mean for you.

## Development

```bash
python -m unittest discover -s tests -v
```

The sample recording in `examples/` is synthetic: the names, numbers, Aadhaar and PAN are made up (the Aadhaar has a valid checksum so the detector can be tested).

## License

MIT © Kirtan Bhatt
