# filter-emails

Create the project environment and install dependencies with:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Run the filter using that same environment:

```sh
.venv/bin/python filter_emls.py <source_directory>
```

If you activate `.venv` first (`source .venv/bin/activate`), you can instead use
`python -m pip install -r requirements.txt` and `python filter_emls.py <source_directory>`.

Emails from senders listed in `input/from_email_adresses.txt` are copied to `results/`.
Before saving, the script scans email headers and decoded text MIME parts with
[detect-secrets](https://github.com/Yelp/detect-secrets) and replaces detected values with
`[REDACTED SECRET]`. It prints the subject, sender, date, and `.eml` filename for each
matching email where it found secrets, without printing the secret values. Other messages
are not copied. Secret scanners are heuristic and cannot guarantee detection of every secret.