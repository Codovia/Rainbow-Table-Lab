# Rainbow Table Attack — Virtual Lab (Fullstack)

A small Flask + JavaScript web app demonstrating a rainbow table attack on
MD5 hashes of 4-letter lowercase passwords.

## Architecture

- **Backend (`app.py`)** — owns ALL the algorithm logic: hashing, the
  reduction function, building the rainbow tables, and cracking a hash.
  The frontend never computes any of this itself.
- **Frontend (`templates/index.html`, `static/`)** — sends your inputs to
  the backend and displays whatever it returns. No algorithm logic lives
  in the browser.

Every starting password used to build a chain is sampled **without
repeats** from the full 456,976-word combination space (enumerated via
`index_to_pw`), so no password is ever used as a chain start twice.

## Setup

```bash
# 1. (Recommended) create a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the app
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

## Using it

1. Click **"Build rainbow table"** — builds 4 rainbow tables server-side
   (takes a few seconds; progress isn't streamed, so the button just shows
   "Building…" until it's done).
2. Type any 4-letter lowercase word (e.g. `amit`, `nand`, `test`) and click
   **"Compute MD5 hash"**.
3. Click **"Run attack"** — the server searches its tables and returns a
   condensed result: one summary line per table searched, plus a trimmed
   view of the winning chain (first and last few steps only — not the
   full, potentially very long, step-by-step path).
4. Use **"Try a password in the table"** for a guaranteed successful demo.

## Why it sometimes fails to crack a password

Rainbow tables trade completeness for storage savings. With 4 tables of
10,000 chains × 100 steps each, roughly 96% of random 4-letter passwords
are recoverable — not 100%. This is expected, correct behavior, not a bug,
and is worth mentioning in a report: it's the real trade-off this
technique makes.
