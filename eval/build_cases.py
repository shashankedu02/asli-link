"""Builds eval/cases.csv deterministically. Run: python eval/build_cases.py

Every case carries its provenance, because where a case comes from decides how much a result on it means:

- registry_official   official domains taken from the registry. A consistency check, not a test of detection.
- synthetic_impostor  generated from the registry with documented mutation rules. These mirror the signals the
                      checker looks for, so results on them are OPTIMISTIC and are reported separately.
- handwritten         written by hand to be awkward: benign links that contain brand words, deep lookalikes,
                      shorteners, and phishing the checker is not built to catch.

Ground truth classes: official, impostor, benign, hidden (shortener), out_of_scope (phishing with no link to any
known entity: undetectable by design, reported as abstention and never as a catch).
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(__file__).resolve().parent / "cases.csv"
FIELDS = ["id", "text", "truth", "category", "provenance", "note"]


def typo(label: str) -> str:
    """Swap the last two characters of a label (a one-edit typo)."""
    return label[:-2] + label[-1] + label[-2] if len(label) > 3 else label + label[-1]


def homoglyph(label: str) -> str | None:
    for a, b in (("o", "0"), ("l", "1"), ("i", "1"), ("s", "5")):
        if a in label:
            return label.replace(a, b, 1)
    return None


def build() -> list[dict]:
    data = json.loads((ROOT / "data/registry/entities.json").read_text(encoding="utf-8"))
    rows: list[dict] = []

    def add(text, truth, category, provenance, note=""):
        rows.append(
            {
                "id": f"C{len(rows) + 1:04d}",
                "text": text,
                "truth": truth,
                "category": category,
                "provenance": provenance,
                "note": note,
            }
        )

    for e in data["entities"]:
        for d in e.get("bank_in", []) + e.get("other_official", []):
            add(f"Open https://{d}/login to continue", "official", "official_domain", "registry_official", e["id"])
    for e in data["entities"]:
        official = (e.get("bank_in") or e.get("other_official") or [None])[0]
        tok = e["tokens"][0]
        add(f"https://{tok}-kyc-update.com/verify", "impostor", "brand_in_hyphen_domain", "synthetic_impostor", e["id"])
        add(f"http://{tok}.secure-login.xyz/", "impostor", "brand_as_subdomain", "synthetic_impostor", e["id"])
        if official:
            label = official.split(".")[0]
            add(
                f"https://{official}@secure-check.example/login",
                "impostor",
                "userinfo_trick",
                "synthetic_impostor",
                e["id"],
            )
            add(f"https://{official}.verify-now.com/", "impostor", "deceptive_suffix", "synthetic_impostor", e["id"])
            # Not under .bank.in: that namespace is restricted to authorised banks, so a typo inside it is not an impostor.
            add(f"https://{typo(label)}.co.in/", "impostor", "typo_of_official", "synthetic_impostor", e["id"])
            g = homoglyph(label)
            if g:
                add(f"https://{g}.bank.in.example.com/", "impostor", "homoglyph_label", "synthetic_impostor", e["id"])
        add(f"https://{tok}.bankin.com/", "impostor", "namespace_lookalike", "synthetic_impostor", e["id"])

    hand = [
        ("https://www.python.org/downloads/", "benign", "plain_benign"),
        ("https://en.wikipedia.org/wiki/State_Bank_of_India", "benign", "benign_with_brand_in_path"),
        ("Read about HDFC history at https://en.wikipedia.org/wiki/HDFC_Bank", "benign", "benign_with_brand_in_path"),
        ("https://github.com/shashankedu02/asli-link", "benign", "plain_benign"),
        ("https://www.rbi.org.in/", "official", "official_domain"),
        ("http://sbi.com.verify-account.in/x", "impostor", "brand_then_tld_trick"),
        ("SBI alert: your account is blocked. Update PAN at http://hdfc-help.top", "impostor", "claim_mismatch"),
        ("Dear customer, income tax refund pending. Claim http://refund-claim.top/in", "impostor", "claim_mismatch"),
        ("https://sbi.bank.in.account-review.top/signin", "impostor", "deceptive_suffix"),
        ("http://xn--sb-pia.bank.in.example/", "impostor", "punycode_lookalike"),
        (
            "Your electricity will be cut tonight. Pay now http://secure-login-portal.xyz/auth",
            "out_of_scope",
            "unbranded_phishing",
        ),
        ("You won a prize! Collect at http://winner-prize-claim.top/x", "out_of_scope", "unbranded_phishing"),
        ("Pay the courier fee at http://delivery-fee-pay.live/c", "out_of_scope", "unbranded_phishing"),
        ("http://bit.ly/3xYz9Ab", "hidden", "shortener"),
        ("Verify here: https://tinyurl.com/yk2w9", "hidden", "shortener"),
    ]
    for text, truth, cat in hand:
        add(text, truth, cat, "handwritten")
    return rows


def main() -> None:
    rows = build()
    with OUT.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} cases to {OUT}")


if __name__ == "__main__":
    main()
