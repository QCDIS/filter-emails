# filter-emails

Create the project environment and install dependencies with:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Run the filter using that same environment:

```sh
.venv/bin/python filter_emls.py <source_directory> <subdirectory, e.g. Virtual_lab_support>
```

If you activate `.venv` first (`source .venv/bin/activate`), you can instead use
`python -m pip install -r requirements.txt` and `python filter_emls.py <source_directory>`.

Before scanning, it removes unrelated top-level headers, keeping `From` (the sender),
`To`, `Subject`, `Message-ID`, `In-Reply-To`, and `References`, along with the MIME
headers needed to preserve the message content. It then scans email headers and decoded
text MIME parts with
[detect-secrets](https://github.com/Yelp/detect-secrets) and replaces detected values with
`[REDACTED SECRET]`. It prints the subject, sender, date, and `.eml` filename for each
matching email where it found secrets, without printing the secret values. Other messages
are not copied. It also reports matching emails containing the whole words `password`,
`wachtwoord`, or `secret` (case-insensitively), printing each complete matching line.
Those lines may contain sensitive information. Secret scanners are heuristic and cannot
guarantee detection of every secret.

### Run tests

```sh
 .venv/bin/python -m unittest -v && .venv/bin/python -m py_compile filter_emls.py test_filter_emls.py
```