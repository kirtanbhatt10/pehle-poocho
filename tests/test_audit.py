import hashlib
import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from pehle_poocho.analyze import AuditError, audit
from pehle_poocho.cli import main
from pehle_poocho.detect import verhoeff_check_digit
from pehle_poocho.har import HarError
from pehle_poocho.report import render_json, render_markdown, render_sarif, render_text

SAMPLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "examples", "before-consent.har")
EMAIL = "priya.sharma@mail.example"
PHONE = "9876543210"
PAN = "ABCPS1234K"
AADHAAR = "23412341234" + verhoeff_check_digit("23412341234")


def rule_hosts(report, rule):
    return {f.host for f in report.findings if f.rule == rule}


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


def write_har(directory, entries, name="clean.har"):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"log": {"version": "1.2", "entries": entries}}, fh)
    return path


class SampleRecording(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = audit(SAMPLE, seeds=[EMAIL, PHONE])

    def test_first_party_comes_from_the_page(self):
        self.assertEqual(self.report.first_party, ["kirana.example"])
        self.assertEqual(self.report.page, "https://shop.kirana.example/checkout")

    def test_grade(self):
        self.assertEqual(self.report.grade, "F")
        self.assertEqual({f.rule for f in self.report.findings}, {"PP001", "PP002", "PP003", "PP004", "PP005", "PP006"})

    def test_trackers_but_not_the_font_cdn(self):
        hosts = rule_hosts(self.report, "PP001")
        for host in ("www.google-analytics.com", "connect.facebook.net", "www.clarity.ms", "api2.branch.io"):
            self.assertIn(host, hosts)
        self.assertNotIn("fonts.gstatic.com", hosts)

    def test_cookies_before_consent(self):
        self.assertEqual(
            rule_hosts(self.report, "PP002"),
            {"www.facebook.com", "www.clarity.ms", "googleads.g.doubleclick.net"},
        )

    def test_page_url_leaks_through_analytics(self):
        ga = [f for f in self.report.findings if f.rule == "PP003" and f.host == "www.google-analytics.com"]
        self.assertEqual(len(ga), 2)
        self.assertTrue(all("query parameter 'dl'" in f.summary for f in ga))

    def test_base64_payload_is_decoded(self):
        branch = [f for f in self.report.findings if f.rule == "PP003" and f.host == "api2.branch.io"]
        self.assertEqual(len(branch), 3)
        self.assertTrue(all("(base64)" in f.summary for f in branch))

    def test_hashed_seeds_to_meta(self):
        pp005 = [f for f in self.report.findings if f.rule == "PP005"]
        self.assertEqual(len(pp005), 2)
        self.assertTrue(all(f.host == "www.facebook.com" and "sha256" in f.summary for f in pp005))

    def test_no_seeds_no_pp005(self):
        self.assertNotIn("PP005", {f.rule for f in audit(SAMPLE).findings})

    def test_aadhaar_over_http_is_critical(self):
        pp006 = {f.severity for f in self.report.findings if f.rule == "PP006" and "Aadhaar" in f.summary}
        self.assertEqual(pp006, {"critical"})
        self.assertEqual(self.report.grade, "F")

    def test_retina_image_is_not_flagged(self):
        self.assertFalse(any("logo" in f.url for f in self.report.findings))

    def test_consent_boundary(self):
        after = audit(SAMPLE, consent_after="/api/consent")
        self.assertIn("analytics.tiktok.com", rule_hosts(self.report, "PP001"))
        self.assertNotIn("analytics.tiktok.com", rule_hosts(after, "PP001"))
        self.assertIn("www.clarity.ms", rule_hosts(after, "PP001"))

    def test_consent_time(self):
        after = audit(SAMPLE, consent_time="2026-11-15T19:05:02.750Z")
        self.assertNotIn("analytics.tiktok.com", rule_hosts(after, "PP001"))
        with self.assertRaises(AuditError):
            audit(SAMPLE, consent_time="yesterday")

    def test_unknown_consent_marker(self):
        with self.assertRaises(AuditError):
            audit(SAMPLE, consent_after="/no-such-path")

    def test_first_party_override(self):
        report = audit(SAMPLE, first_party=["kirana.example", "facebook.com", "facebook.net"])
        hosts = {f.host for f in report.findings}
        self.assertNotIn("www.facebook.com", hosts)
        self.assertNotIn("connect.facebook.net", hosts)

    def test_reports_never_show_raw_personal_data(self):
        secrets = [EMAIL, PHONE, PAN, AADHAAR, AADHAAR[:4] + " " + AADHAAR[4:8], hashlib.sha256(EMAIL.encode()).hexdigest()]
        for text in (
            render_text(self.report, "both"),
            render_markdown(self.report, "both"),
            render_json(self.report),
            render_sarif(self.report),
        ):
            for secret in secrets:
                self.assertNotIn(secret, text)

    def test_sarif_shape(self):
        data = json.loads(render_sarif(self.report))
        self.assertEqual(data["version"], "2.1.0")
        run = data["runs"][0]
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertEqual(len(run["results"]), len(self.report.findings))
        for result in run["results"]:
            self.assertIn(result["ruleId"], rule_ids)
            self.assertIn(result["level"], ("error", "warning", "note"))
            self.assertTrue(result["partialFingerprints"]["pehlePoocho/v1"])

    def test_markdown_keeps_masked_values_in_code_spans(self):
        text = render_markdown(self.report, "both")
        outside = re.sub(r"`[^`]*`", "", text).replace("**", "")
        self.assertNotIn("@", outside)
        self.assertNotIn("*", outside)
        self.assertIn("`p***@oksbi`", text)
        self.assertIn("`***P*****K`", text)

    def test_hindi(self):
        self.assertIn("निजी जानकारी", render_text(self.report, "hi"))
        both = render_markdown(self.report, "both")
        self.assertIn("Personal data sent to a third party", both)
        self.assertIn("थर्ड-पार्टी", both)


class Cli(unittest.TestCase):
    def test_min_grade(self):
        code, _out, err = run_cli(SAMPLE, "--min-grade", "C")
        self.assertEqual(code, 1)
        self.assertIn("worse than the required C", err)
        self.assertEqual(run_cli(SAMPLE, "--min-grade", "F")[0], 0)

    def test_json_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "report.json")
            self.assertEqual(run_cli(SAMPLE, "-f", "json", "-o", target)[0], 0)
            with open(target, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["grade"], "F")

    def test_bad_input(self):
        self.assertEqual(run_cli("/no/such/file.har")[0], 2)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x.har")
            with open(path, "w") as fh:
                fh.write("{}")
            code, _out, err = run_cli(path)
            self.assertEqual(code, 2)
            self.assertIn("log.entries", err)
            with self.assertRaises(HarError):
                audit(path)

    def test_clean_recording(self):
        entry = {
            "startedDateTime": "2026-11-15T10:00:00Z",
            "request": {"method": "GET", "url": "https://www.kirana.example/", "headers": []},
            "response": {"status": 200, "headers": [], "content": {"mimeType": "text/html"}},
        }
        cdn = {
            "startedDateTime": "2026-11-15T10:00:01Z",
            "request": {"method": "GET", "url": "https://cdn.jsdelivr.net/npm/x.js", "headers": []},
            "response": {"status": 200, "headers": []},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = write_har(tmp, [entry, cdn])
            code, out, _err = run_cli(path, "--min-grade", "A+")
            self.assertEqual(code, 0)
            self.assertIn("Grade A+", out)


if __name__ == "__main__":
    unittest.main()
