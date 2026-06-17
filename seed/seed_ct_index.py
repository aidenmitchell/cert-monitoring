"""Seed certstream's recovery index (ct_index.json) at the CURRENT TIP of every
CT log, so enabling recovery resumes from "now" instead of backfilling from 0.

certstream keys its index map by the log URL with scheme + trailing slash
stripped (internal normalizeCtlogURL): RFC6962 logs by `url`, tiled logs by
`monitoring_url`. The stored value is the last-processed index; seeding it with
the log's current size makes the worker start at the next new entry.

Idempotent: if the index file already exists and is non-empty, we leave it alone
(certstream maintains it via its own 30s checkpoint), so a restart resumes from
the real saved position rather than resetting to the tip.
"""

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
INDEX_FILE = os.environ.get("CT_INDEX_FILE", "/state/ct_index.json")
STATE_DIR = os.path.dirname(INDEX_FILE)
TIMEOUT = float(os.environ.get("SEED_TIMEOUT", "15"))
WORKERS = int(os.environ.get("SEED_WORKERS", "12"))
RETRIES = int(os.environ.get("SEED_RETRIES", "5"))

_ctx = ssl.create_default_context()


def _get(url: str) -> bytes:
    """GET with retries on 429 / transient errors. Any log we ultimately fail
    to reach is left unseeded — and would then backfill from 0 — so we try hard.
    Genuinely dead logs (e.g. retired) also exhaust retries here, but certstream
    skips those too, so missing them is harmless."""
    req = urllib.request.Request(url, headers={"User-Agent": "ct-index-seeder/1.0"})
    last = None
    for attempt in range(RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ctx) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code == 429:  # rate limited — honor Retry-After, then back off
                ra = exc.headers.get("Retry-After")
                try:                       # Retry-After may be seconds...
                    wait = float(ra) if ra else 0
                except ValueError:         # ...or an HTTP-date we don't parse
                    wait = 0
                time.sleep(wait or min(2 ** attempt, 20))
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last = exc
            time.sleep(min(2 ** attempt, 20))  # transient network — retry
    raise last


def normalize(url: str) -> str:
    for scheme in ("https://", "http://"):
        if url.startswith(scheme):
            url = url[len(scheme):]
            break
    return url.rstrip("/")


def rfc6962_tip(url: str) -> int:
    """GET <url>/ct/v1/get-sth -> tree_size."""
    sth = json.loads(_get(url.rstrip("/") + "/ct/v1/get-sth"))
    return int(sth["tree_size"])


def tiled_tip(monitoring_url: str) -> int:
    """GET <monitoring_url>/checkpoint -> size (line 2 of the signed note)."""
    body = _get(monitoring_url.rstrip("/") + "/checkpoint").decode("utf-8", "replace")
    return int(body.splitlines()[1])


def collect_targets(log_list: dict):
    """Yield (key, fetch_fn) for every log in the list (a superset of what
    certstream watches — extra keys are harmless, missing keys cause backfill)."""
    for operator in log_list.get("operators", []):
        for log in operator.get("logs", []):
            url = log.get("url")
            if url:
                yield normalize(url), (lambda u=url: rfc6962_tip(u)), log.get("description", url)
        for log in operator.get("tiled_logs", []):
            mon = log.get("monitoring_url")
            if mon:
                yield normalize(mon), (lambda m=mon: tiled_tip(m)), log.get("description", mon)


def main() -> int:
    # Merge semantics: keep any indices already in the file (certstream maintains
    # them via its 30s checkpoint) and only fetch tips for logs that are MISSING.
    # This makes the seeder self-healing — re-running fills gaps left by earlier
    # failures without resetting logs certstream has already advanced.
    index: dict[str, int] = {}
    if os.path.exists(INDEX_FILE):
        try:
            with open(INDEX_FILE) as f:
                index = json.load(f)
        except (json.JSONDecodeError, OSError):
            index = {}

    print(f"[seed] fetching log list: {LOG_LIST_URL}")
    log_list = json.loads(_get(LOG_LIST_URL))
    targets = [(key, fn, desc) for key, fn, desc in collect_targets(log_list)
               if key not in index]

    if not targets:
        print(f"[seed] all {len(index)} logs already seeded — nothing to do.")
        return 0
    print(f"[seed] {len(index)} already seeded; querying tip of {len(targets)} new logs ...")

    failed = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(fn): (key, desc) for key, fn, desc in targets}
        for fut in as_completed(futures):
            key, desc = futures[fut]
            try:
                index[key] = fut.result()
            except Exception as exc:
                failed += 1
                print(f"[seed]   skip {desc}: {exc}", file=sys.stderr)

    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = INDEX_FILE + ".seedtmp"
    with open(tmp, "w") as f:
        json.dump(index, f, indent=1)
    os.replace(tmp, INDEX_FILE)

    # certstream runs as uid 10001 and must be able to rewrite this file +
    # its .tmp in this dir on every 30s checkpoint.
    try:
        os.chmod(STATE_DIR, 0o777)
        os.chmod(INDEX_FILE, 0o666)
    except OSError as exc:
        print(f"[seed]   warning: could not relax permissions: {exc}", file=sys.stderr)

    print(f"[seed] wrote {len(index)} log tips to {INDEX_FILE} "
          f"({len(targets) - failed} newly seeded, {failed} failed/skipped).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
