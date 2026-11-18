"""Public Suffix List handling: find the registrable domain of a hostname.

The vendored list (data/psl/public_suffix_list.dat, MPL-2.0) decides where the
"owner" part of a hostname starts. For India this matters: ``bank.in``, ``gov.in``
and ``nic.in`` are public suffixes, so ``sbi.bank.in`` and ``hdfc.bank.in`` are two
different registrable domains, not two subdomains of one ``bank.in`` site.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DEFAULT_PSL_PATH = Path(__file__).resolve().parent.parent / "data" / "psl" / "public_suffix_list.dat"


@dataclass(frozen=True)
class DomainParts:
    """A hostname split by the Public Suffix List."""

    host: str
    suffix: str  # e.g. "bank.in"
    registrable: str | None  # e.g. "sbi.bank.in"; None when the host is itself a suffix
    subdomain: str  # e.g. "www" for www.sbi.bank.in, "" when absent

    @property
    def label(self) -> str | None:
        """The owner's label: "sbi" for sbi.bank.in, "hdfcbank" for netbanking.hdfcbank.com."""
        if self.registrable is None:
            return None
        return self.registrable[: -len(self.suffix) - 1]


class PublicSuffixList:
    def __init__(self, rules: set[str], exceptions: set[str], wildcards: set[str]) -> None:
        self._rules = rules
        self._exceptions = exceptions
        self._wildcards = wildcards

    @classmethod
    def from_text(cls, text: str) -> PublicSuffixList:
        rules: set[str] = set()
        exceptions: set[str] = set()
        wildcards: set[str] = set()
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0].lower()
            if rule.startswith("!"):
                exceptions.add(rule[1:])
            elif rule.startswith("*."):
                wildcards.add(rule[2:])
            else:
                rules.add(rule)
        return cls(rules, exceptions, wildcards)

    def suffix_of(self, host: str) -> str:
        """Longest matching public suffix (PSL algorithm, including * and ! rules).

        Unknown TLDs fall back to the last label, as the PSL algorithm specifies."""
        labels = host.split(".")
        best = labels[-1]
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in self._exceptions:
                return ".".join(labels[i + 1 :])
            if candidate in self._rules:
                return candidate
            parent = ".".join(labels[i + 1 :])
            if parent and parent in self._wildcards:
                return candidate
        return best

    def is_listed(self, suffix: str) -> bool:
        """True when `suffix` is an explicit PSL entry (or matches a wildcard rule), not the unknown-TLD fallback."""
        parent = suffix.partition(".")[2]
        return suffix in self._rules or (bool(parent) and parent in self._wildcards)

    def split(self, host: str) -> DomainParts:
        host = host.lower().rstrip(".")
        suffix = self.suffix_of(host)
        if host == suffix:
            return DomainParts(host=host, suffix=suffix, registrable=None, subdomain="")
        head = host[: -len(suffix) - 1]
        head_labels = head.split(".")
        registrable = f"{head_labels[-1]}.{suffix}"
        subdomain = ".".join(head_labels[:-1])
        return DomainParts(host=host, suffix=suffix, registrable=registrable, subdomain=subdomain)


@lru_cache(maxsize=4)
def load(path: Path = DEFAULT_PSL_PATH) -> PublicSuffixList:
    return PublicSuffixList.from_text(path.read_text(encoding="utf-8"))
