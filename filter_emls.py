import argparse
import re
import shutil
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path

from detect_secrets.core.scan import scan_line
from detect_secrets.settings import default_settings

KEYWORDS = ("password", "wachtwoord", "secret")


def filter_eml_fields(message: Message) -> None:
    retained_headers = {
        "from",
        "in-reply-to",
        "message-id",
        "references",
        "subject",
        "to",
        "date",
    }

    for header_name in dict.fromkeys(name for name, _ in message.items()):
        normalized_name = header_name.lower()
        if normalized_name in retained_headers or normalized_name.startswith("content-"):
            continue
        if normalized_name == "mime-version":
            continue
        del message[header_name]


def _redact_secrets(text: str) -> str:
    redacted_lines = []
    in_private_key = False

    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        line_ending = line[len(content):]

        if in_private_key:
            redacted_lines.append(f"[REDACTED SECRET]{line_ending}")
            if "-----END " in content.upper() and "PRIVATE KEY-----" in content.upper():
                in_private_key = False
            continue

        findings = [
            finding
            for finding in scan_line(content)
            if finding.type not in {"Base64 High Entropy String", "Hex High Entropy String"}
            or len(finding.secret_value) >= 16
        ]
        if not findings:
            redacted_lines.append(line)
            continue

        if "-----BEGIN " in content.upper() and "PRIVATE KEY-----" in content.upper():
            in_private_key = True

        redacted_lines.append(f"[REDACTED SECRET]{line_ending}")

    return "".join(redacted_lines)


def redact_secrets(text: str) -> str:
    with default_settings():
        return _redact_secrets(text)


def sanitize_email(message: Message) -> bool:
    changed = False

    with default_settings():
        for part in message.walk():
            if part.is_multipart() or part.get_content_maintype() != "text":
                continue

            content = part.get_content()
            if not isinstance(content, str):
                continue

            sanitized_content = _redact_secrets(content)
            if sanitized_content == content:
                continue

            params = {
                name: value
                for name, value in (part.get_params()[1:] if part.get_params() else [])
                if name.lower() != "charset"
            }
            content_options = {"subtype": part.get_content_subtype(), "params": params}
            charset = part.get_content_charset()
            if charset:
                content_options["charset"] = charset
            part.set_content(sanitized_content, **content_options)
            changed = True

        if changed:
            for part in message.walk():
                if part.is_multipart() and part.get_content_maintype() == "text":
                    part.set_type("multipart/mixed")

    return changed


def find_keywords(message: Message) -> list[tuple[str, list[str]]]:
    lines = []
    for name, value in message.items():
        lines.extend(f"{name}: {line}" for line in str(value).splitlines())

    for part in message.walk():
        if part.is_multipart() or part.get_content_maintype() != "text":
            continue
        content = part.get_content()
        if isinstance(content, str):
            lines.extend(content.splitlines())

    matches = []
    for line in lines:
        found_keywords = [
            keyword
            for keyword in KEYWORDS
            if re.search(rf"\b{re.escape(keyword)}\b", line, re.IGNORECASE)
        ]
        if found_keywords:
            matches.append((line, found_keywords))
    return matches


def process_eml_files(
    src_dir: Path,
    dst_dir: Path,
    lowercase_target_senders: list[str],
) -> tuple[
    list[tuple[str, str, str, str]],
    list[tuple[str, str, str, str, list[tuple[str, list[str]]]]],
]:
    secret_findings = []
    keyword_findings = []

    for eml_path in src_dir.glob("*.eml"):
        with eml_path.open("rb") as source:
            message = BytesParser(policy=policy.default).parse(source)

        from_header = (message.get("From") or "").lower()
        if not any(sender in from_header for sender in lowercase_target_senders):
            continue

        subject = str(message.get("Subject") or "(no subject)")
        sender = str(message.get("From") or "(unknown sender)")
        date = str(message.get("Date") or "(unknown date)")
        found_keywords = find_keywords(message)
        filter_eml_fields(message)
        found_secrets = sanitize_email(message)
        destination = dst_dir / eml_path.name
        if found_secrets:
            secret_findings.append((
                subject,
                sender,
                date,
                eml_path.name,
            ))
            destination.write_bytes(message.as_bytes(policy=policy.default))
        else:
            shutil.copy2(eml_path, destination)
        if found_keywords:
            keyword_findings.append((
                subject,
                sender,
                date,
                eml_path.name,
                found_keywords,
            ))

    return secret_findings, keyword_findings


def main() -> int:
    script_dir = Path(__file__).parent
    dst_dir = script_dir / "results"
    dst_dir.mkdir(exist_ok=True)

    with (script_dir / "input/from_email_adresses.txt").open() as sender_file:
        target_senders = sender_file.read().splitlines()
    lowercase_target_senders = [sender.lower() for sender in target_senders]

    parser = argparse.ArgumentParser()
    parser.add_argument("source_directory", help="Directory to process")
    args = parser.parse_args()

    print(f"Source directory: {args.source_directory}")
    src_dir = Path(args.source_directory)
    if not any(src_dir.glob("*.eml")):
        print(f"No .eml files found in the {src_dir=}.")
        return 1

    secret_findings, keyword_findings = process_eml_files(
        src_dir,
        dst_dir,
        lowercase_target_senders,
    )
    if secret_findings:
        print("Secrets found in these emails (values are not shown):")
        for subject, sender, date, filename in secret_findings:
            print(
                f"  File: {filename} | Subject: {subject} | "
                f"Sender: {sender} | Date: {date}"
            )
    else:
        print("No secrets found in matching emails.")

    if keyword_findings:
        print(f"Watchlist words found ({', '.join(KEYWORDS)}):")
        for subject, sender, date, filename, keyword_matches in keyword_findings:
            print(
                f"  File: {filename} | Subject: {subject} | "
                f"Sender: {sender} | Date: {date}"
            )
            for line, found_keywords in keyword_matches:
                print(f"    Words: {', '.join(found_keywords)} | Line: {line}")
    else:
        print(f"No watchlist words found ({', '.join(KEYWORDS)}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
