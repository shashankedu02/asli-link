"""Enumerate registrable .bank.in domains from public Certificate Transparency logs (via crt.sh).

Writes data/registry/observed_bank_in.json. Run by the "Refresh .bank.in snapshot" GitHub Actions
workflow (manual trigger), because it needs network access. Everything it records is public: CT logs
list every TLS certificate issued by a publicly trusted certificate authority.

Only the registrable domain is kept (www.sbi.bank.in -> sbi.bank.in). The snapshot is evidence that
a domain exists in the restricted namespace; it is not a list of bank names.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from asli.psl import load as load_psl  # noqa: E402

QUERY_URL = "https://crt.sh/?q=%25.bank.in&output=json&exclude=expired"
OUT = ROOT / "data" / "registry" / "observed_bank_in.json"


def fetch(url: str, attempts: int = 4, timeout: int = 180) -> list[dict]:
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "asli-link-registry-builder"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:  # crt.sh is busy at times; retry with backoff
            last = exc
            print(f"attempt {attempt} failed: {exc}", file=sys.stderr)
            time.sleep(15 * attempt)
    raise SystemExit(f"crt.sh query failed after {attempts} attempts: {last}")


def registrable_bank_in(names: list[str]) -> set[str]:
    psl = load_psl()
    found: set[str] = set()
    for raw in names:
        name = raw.strip().lower().rstrip(".")
        if name.startswith("*."):
            name = name[2:]
        if not name.endswith(".bank.in") or any(c.isspace() for c in name):
            continue
        parts = psl.split(name)
        if parts.suffix == "bank.in" and parts.registrable:
            found.add(parts.registrable)
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="use a saved crt.sh JSON response instead of querying")
    args = parser.parse_args()

    rows = json.loads(args.input.read_text(encoding="utf-8")) if args.input else fetch(QUERY_URL)
    names: list[str] = []
    for row in rows:
        names.extend(str(row.get("name_value", "")).splitlines())
        names.append(str(row.get("common_name", "")))
    domains = sorted(registrable_bank_in(names))
    if len(domains) < 20:
        raise SystemExit(f"only {len(domains)} domains found; refusing to write a suspiciously small snapshot")

    OUT.write_text(
        json.dumps(
            {
                "source": "crt.sh Certificate Transparency search for %.bank.in (unexpired certificates)",
                "query": QUERY_URL,
                "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "certificates_seen": len(rows),
                "count": len(domains),
                "domains": domains,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(domains)} domains from {len(rows)} certificates to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
