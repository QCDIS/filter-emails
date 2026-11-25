from email import policy
from email.parser import BytesParser
from pathlib import Path
import shutil
import argparse

dst_dir = Path(__file__).parent / "results"
dst_dir.mkdir(exist_ok=True)

def check_that_directory_contains_eml_files(directory: Path) -> bool:
    return any(directory.glob("*.eml"))

with open('input/from_email_adresses.txt') as f:
    target_senders = f.read().splitlines()

parser = argparse.ArgumentParser()
parser.add_argument("source_directory", help="Directory to process")
args = parser.parse_args()

print(f"Source directory: {args.source_directory}")
src_dir = Path(args.source_directory)

if not check_that_directory_contains_eml_files(src_dir):
    print(f"No .eml files found in the {src_dir=}.")
    exit(1)

lowercase_target_senders = [sender.lower() for sender in target_senders]

for eml_path in src_dir.glob("*.eml"):
    with eml_path.open("rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    from_header = (msg.get("From") or "").lower()
    if any(target_sender in from_header for target_sender in lowercase_target_senders):
        shutil.copy2(eml_path, dst_dir / eml_path.name)

