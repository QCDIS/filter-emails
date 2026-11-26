from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from pathlib import Path
import tempfile
import unittest

from filter_emls import (
    filter_eml_fields,
    find_keywords,
    process_eml_files,
    redact_secrets,
    sanitize_email,
)

from detect_secrets.core.scan import scan_line

class RedactSecretsTests(unittest.TestCase):
    def test_find_keywords_case_insensitively_as_whole_words(self):
        message = EmailMessage()
        message["Subject"] = "Password reset"
        message.set_content("Voer wachtwoord in; secretive is not a match.\n")

        self.assertEqual(
            find_keywords(message),
            [
                ("Subject: Password reset", ["password"]),
                ("Voer wachtwoord in; secretive is not a match.", ["wachtwoord"]),
            ],
        )

    def test_redacts_detected_secret_and_preserves_surrounding_text(self):
        secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        text = f"before\npassword: {secret}\nafter\n"

        result = redact_secrets(text)

        self.assertNotIn(secret, result)
        self.assertIn("[REDACTED SECRET]", result)
        self.assertTrue(result.startswith("before\n"))
        self.assertTrue(result.endswith("after\n"))

    def test_redacts_private_key_block(self):
        text = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIE_fake_private_key_material\n"
            "-----END PRIVATE KEY-----\n"
        )

        result = redact_secrets(text)

        self.assertNotIn("MIIE_fake_private_key_material", result)
        self.assertEqual(result.count("[REDACTED SECRET]"), 3)

    def test_processes_input_eml_files_and_redacts_detected_secrets(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        message = EmailMessage()
        message["From"] = "Example <sender@example.org>"
        message["To"] = "recipient@example.org"
        message["Subject"] = "Credentials"
        message["Date"] = "Tue, 25 Nov 2026 10:00:00 +0000"
        message.set_content(f"AWS_ACCESS_KEY_ID={secret}\n", cte="base64")

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source_directory = root / "source"
            destination_directory = root / "results"
            source_directory.mkdir()
            destination_directory.mkdir()
            input_path = source_directory / "matched.eml"
            input_path.write_bytes(message.as_bytes(policy=policy.default))

            secret_findings, keyword_findings = process_eml_files(
                [input_path],
                destination_directory,
            )

            result = (destination_directory / "matched.eml").read_bytes()

        self.assertNotIn(secret.encode(), result)
        self.assertIn(b"[REDACTED SECRET]", result)
        self.assertEqual(
            secret_findings,
            [(
                "Credentials",
                "Example <sender@example.org>",
                "Wed, 25 Nov 2026 10:00:00 +0000",
                "matched.eml",
            )],
        )
        self.assertEqual(keyword_findings, [])

    def test_reports_keywords_even_when_no_secret_is_detected(self):
        message = EmailMessage()
        message["From"] = "sender@example.org"
        message["Subject"] = "Account update"
        message.set_content("Verander uw wachtwoord.\n")

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source_directory = root / "source"
            destination_directory = root / "results"
            source_directory.mkdir()
            destination_directory.mkdir()
            input_path = source_directory / "keyword.eml"
            input_path.write_bytes(
                message.as_bytes(policy=policy.default)
            )

            secret_findings, keyword_findings = process_eml_files(
                [input_path],
                destination_directory,
            )

        self.assertEqual(secret_findings, [])
        self.assertEqual(
            keyword_findings,
            [(
                "Account update",
                "sender@example.org",
                "(unknown date)",
                "keyword.eml",
                [("Verander uw wachtwoord.", ["wachtwoord"])],
            )],
        )

    def test_serializes_text_part_with_multipart_payload_after_redaction(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        message = EmailMessage()
        message["From"] = "sender@example.org"
        message["Subject"] = "Nested content"
        child = EmailMessage()
        child.set_content(f"AWS_ACCESS_KEY_ID={secret}\n")
        message.set_payload([child])

        self.assertTrue(sanitize_email(message))
        serialized = message.as_bytes(policy=policy.default)

        self.assertNotIn(secret.encode(), serialized)
        self.assertIn(b"multipart/mixed", serialized)
        self.assertIn(b"[REDACTED SECRET]", serialized)

    def test_uses_utf8_when_redacted_content_exceeds_original_charset(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        message = BytesParser(policy=policy.default).parsebytes(
            b"From: sender@example.org\r\n"
            b"Content-Type: text/plain; charset=gb2312\r\n"
            b"Content-Transfer-Encoding: 8bit\r\n"
            b"\r\n"
            + b"unrepresentable: \xff\n"
            + f"AWS_ACCESS_KEY_ID={secret}\n".encode()
        )

        self.assertTrue(sanitize_email(message))
        content = message.get_content()

        self.assertEqual(message.get_content_charset(), "utf-8")
        self.assertIn("[REDACTED SECRET]", content)
        self.assertIn("\ufffd", content)

    def test_filter_eml_fields_keeps_requested_headers_and_content(self):
        message = EmailMessage()
        message["From"] = "sender@example.org"
        message["To"] = "recipient@example.org"
        message["Subject"] = "Relevant subject"
        message["Message-ID"] = "<message@example.org>"
        message["In-Reply-To"] = "<previous@example.org>"
        message["References"] = "<root@example.org>"
        message["Date"] = "Wed, 25 Nov 2026 10:00:00 +0000"
        message["X-Private-Header"] = "remove me"
        message.set_content("Keep this email content.\n")

        filter_eml_fields(message)

        self.assertEqual(
            {name.lower() for name, _ in message.items()},
            {
                "from",
                "to",
                "subject",
                "message-id",
                "in-reply-to",
                "references",
                "content-type",
                "content-transfer-encoding",
                "mime-version",
                "date",
            },
        )
        self.assertEqual(message.get_content(), "Keep this email content.\n")

if __name__ == "__main__":
    unittest.main()
