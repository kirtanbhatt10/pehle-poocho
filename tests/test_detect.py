import base64
import hashlib
import json
import unittest

from pehle_poocho.detect import (
    luhn_valid,
    mask,
    scan_value,
    search_seeds,
    seed_kind,
    seed_needles,
    verhoeff_check_digit,
    verhoeff_valid,
)

AADHAAR = "23412341234" + verhoeff_check_digit("23412341234")


def kinds(hits):
    return sorted({h.kind for h in hits})


class Checksums(unittest.TestCase):
    def test_verhoeff_reference_value(self):
        self.assertEqual(verhoeff_check_digit("236"), "3")
        self.assertTrue(verhoeff_valid("2363"))
        self.assertFalse(verhoeff_valid("2364"))

    def test_verhoeff_catches_typos_and_swaps(self):
        self.assertTrue(verhoeff_valid(AADHAAR))
        typo = AADHAAR[:5] + str((int(AADHAAR[5]) + 1) % 10) + AADHAAR[6:]
        swap = AADHAAR[:3] + AADHAAR[4] + AADHAAR[3] + AADHAAR[5:]
        self.assertFalse(verhoeff_valid(typo))
        self.assertFalse(verhoeff_valid(swap))

    def test_luhn(self):
        self.assertTrue(luhn_valid("4111111111111111"))
        self.assertFalse(luhn_valid("4111111111111112"))


class Aadhaar(unittest.TestCase):
    def test_formatted_number_is_found(self):
        spaced = f"{AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}"
        self.assertEqual(kinds(scan_value(f"id proof {spaced}")), ["aadhaar"])

    def test_bare_digits_need_a_field_name(self):
        self.assertEqual(kinds(scan_value(AADHAAR, "order_id")), [])
        self.assertEqual(kinds(scan_value(AADHAAR, "aadhaar_no")), ["aadhaar"])

    def test_bad_checksum_is_ignored(self):
        wrong = AADHAAR[:-1] + str((int(AADHAAR[-1]) + 1) % 10)
        self.assertEqual(kinds(scan_value(wrong, "aadhaar")), [])

    def test_card_number_is_not_read_as_aadhaar(self):
        self.assertNotIn("aadhaar", kinds(scan_value("4111 1111 1111 1111")))


class OtherIdentifiers(unittest.TestCase):
    def test_pan_and_entity_letter(self):
        self.assertEqual(kinds(scan_value("PAN ABCPS1234K")), ["pan"])
        self.assertEqual(kinds(scan_value("ABCDE1234F")), [])

    def test_upi_and_email_do_not_collide(self):
        hits = scan_value("pay priya@oksbi or mail priya@mail.example")
        self.assertEqual({(h.kind, h.value) for h in hits}, {("upi", "priya@oksbi"), ("email", "priya@mail.example")})
        self.assertEqual(kinds(scan_value("someone@unknownhandle")), [])

    def test_retina_image_name_is_not_an_email(self):
        self.assertEqual(kinds(scan_value("/static/logo@2x.png")), [])

    def test_phone_needs_context(self):
        self.assertEqual(kinds(scan_value("9876543210", "id")), [])
        self.assertEqual(kinds(scan_value("call 9876543210")), [])
        self.assertEqual(kinds(scan_value("9876543210", "mobile")), ["phone"])
        self.assertEqual(kinds(scan_value("+919876543210")), ["phone"])
        self.assertEqual(kinds(scan_value("next=/a?mobile=9876543210")), ["phone"])

    def test_card_needs_grouping_or_field_name(self):
        self.assertEqual(kinds(scan_value("4111 1111 1111 1111")), ["card"])
        self.assertEqual(kinds(scan_value("4111111111111111", "ts")), [])
        self.assertEqual(kinds(scan_value("4111111111111111", "card_number")), ["card"])

    def test_timestamps_and_ids_stay_quiet(self):
        self.assertEqual(kinds(scan_value("1731697501234", "random")), [])
        self.assertEqual(kinds(scan_value("1731697500.1700000000", "cid")), [])


class Decoding(unittest.TestCase):
    def test_url_encoding_is_peeled(self):
        hits = scan_value("https%3A%2F%2Fx.example%2F%3Femail%3Dpriya%2540mail.example")
        self.assertEqual(kinds(hits), ["email"])

    def test_base64_json_payload(self):
        inner = base64.b64encode(json.dumps({"mobile": "9876543210", "pan": "ABCPS1234K"}).encode()).decode()
        hits = scan_value(json.dumps({"data": inner}))
        self.assertEqual(kinds(hits), ["pan", "phone"])
        self.assertTrue(all(h.encoding == "base64" for h in hits))
        self.assertIn("data.mobile", {h.key for h in hits})


class Seeds(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(seed_kind("Priya@Mail.example"), "email")
        self.assertEqual(seed_kind("+91 98765 43210"), "phone")
        self.assertEqual(seed_kind("Priya Sharma"), "custom")

    def test_hashed_email_found_in_any_case(self):
        digest = hashlib.sha256(b"priya@mail.example").hexdigest().upper()
        found = search_seeds(f"ud[em]={digest}", seed_needles(" Priya@Mail.example "))
        self.assertEqual([(n.kind, n.encoding) for n in found], [("email", "sha256")])

    def test_phone_hashed_with_country_code(self):
        digest = hashlib.sha256(b"919876543210").hexdigest()
        found = search_seeds(digest, seed_needles("98765 43210"))
        self.assertEqual([(n.kind, n.encoding, n.source) for n in found], [("phone", "sha256", "919876543210")])

    def test_base64_seed(self):
        token = base64.b64encode(b"priya@mail.example").decode()
        found = search_seeds(f"u={token}", seed_needles("priya@mail.example"))
        self.assertIn(("email", "base64"), {(n.kind, n.encoding) for n in found})


class Masking(unittest.TestCase):
    def test_masks(self):
        self.assertEqual(mask("aadhaar", AADHAAR), "********" + AADHAAR[-4:])
        self.assertEqual(mask("email", "priya@mail.example"), "p***@mail.example")
        self.assertEqual(mask("pan", "ABCPS1234K"), "***P*****K")
        self.assertEqual(mask("phone", "+919876543210"), "********3210")


if __name__ == "__main__":
    unittest.main()
