"""Lookalike detection: scripts, confusable characters and edit distance.

The confusable map is a deliberately small, reviewed subset aimed at characters that
render like Latin letters in common fonts (Cyrillic, Greek, a few Latin variants and
digit swaps). It is used only to *raise* signals, never to declare a domain official.
"""

from __future__ import annotations

import unicodedata

# Non-Latin or decorated characters that commonly impersonate Latin letters.
_UNICODE_TO_LATIN = {
    # Cyrillic
    "а": "a",
    "в": "b",
    "е": "e",
    "ё": "e",
    "һ": "h",
    "і": "i",
    "ї": "i",
    "ј": "j",
    "к": "k",
    "ӏ": "l",
    "м": "m",
    "н": "h",
    "о": "o",
    "р": "p",
    "с": "c",
    "т": "t",
    "у": "y",
    "х": "x",
    "ԁ": "d",
    "ԛ": "q",
    "ԝ": "w",
    "ѕ": "s",
    "ь": "b",
    "ɡ": "g",
    # Greek
    "α": "a",
    "β": "b",
    "ε": "e",
    "η": "n",
    "ι": "i",
    "κ": "k",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "χ": "x",
    "ω": "w",
    # Latin look-alikes that NFKC keeps
    "ı": "i",
    "ł": "l",
    "ø": "o",
    "đ": "d",
    "ħ": "h",
}

# ASCII tricks used in typosquats. Multi-character sequences are applied first.
_ASCII_SEQUENCES = (("rn", "m"), ("vv", "w"), ("cl", "d"))
_ASCII_CHARS = {"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s", "!": "i", "|": "l"}


def scripts(text: str) -> set[str]:
    """Unicode scripts of the letters in `text` (digits, hyphens and dots are ignored)."""
    found: set[str] = set()
    for ch in text:
        if not ch.isalpha():
            continue
        name = unicodedata.name(ch, "")
        found.add(name.split(" ")[0] if name else "UNKNOWN")
    return found


def is_mixed_script(label: str) -> bool:
    return len(scripts(label)) > 1


def skeleton(text: str) -> str:
    """A rough visual skeleton: strip accents, map confusables and digit swaps to Latin letters.

    Two strings with the same skeleton may look alike to a reader. Hyphens are removed so that
    "hdfc-bank" and "hdfcbank" compare equal."""
    text = unicodedata.normalize("NFKD", text.lower())
    out: list[str] = []
    for ch in text:
        if unicodedata.combining(ch):
            continue
        out.append(_UNICODE_TO_LATIN.get(ch, ch))
    result = "".join(out).replace("-", "").replace("_", "")
    for seq, rep in _ASCII_SEQUENCES:
        result = result.replace(seq, rep)
    return "".join(_ASCII_CHARS.get(ch, ch) for ch in result)


def edit_distance(a: str, b: str, limit: int | None = None) -> int:
    """Optimal-string-alignment distance (Levenshtein plus adjacent transpositions).

    Stops early and returns limit + 1 once the distance must exceed `limit`."""
    if a == b:
        return 0
    if limit is not None and abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if limit is not None and min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def distance_limit(length: int) -> int:
    """How many edits still count as a lookalike. Short names get no fuzzy matching at all,
    because 'sbi' is one edit away from hundreds of unrelated words."""
    if length < 5:
        return 0
    if length < 9:
        return 1
    return 2
