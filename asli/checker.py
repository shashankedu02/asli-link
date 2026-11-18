"""Turn a link (or a whole message) into a verdict with evidence.

Verdicts, in the order they are decided:

1. cannot_check            - a link shortener hides the destination; nothing is opened to find out.
2. official                - the link's registrable domain is inside a restricted namespace
                             (.bank.in, .gov.in, .nic.in) or is a curated official domain.
3. impersonation_signals   - the link is not official but carries at least one impersonation signal.
4. not_recognised          - the default. It means "no claim could be established", never "safe".

"official" says who owns the domain. It does not say the page is harmless: official sites can be
compromised, and an official domain does not make a request for an OTP or PIN legitimate.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from enum import StrEnum

from . import lookalike
from .psl import DomainParts, PublicSuffixList
from .psl import load as load_psl
from .registry import Entity, Registry, default_registry
from .urls import Link, LinkError, find_links, parse_link


class Verdict(StrEnum):
    CANNOT_CHECK = "cannot_check"
    OFFICIAL = "official"
    IMPERSONATION = "impersonation_signals"
    NOT_RECOGNISED = "not_recognised"


# Lower number = more serious, used to pick the headline verdict for a message.
_SEVERITY = {Verdict.IMPERSONATION: 0, Verdict.CANNOT_CHECK: 1, Verdict.NOT_RECOGNISED: 2, Verdict.OFFICIAL: 3}

# Signals that, on a non-official link, make the verdict impersonation_signals.
IMPERSONATION_SIGNALS = {
    "userinfo_trick",
    "deceptive_suffix",
    "namespace_lookalike",
    "brand_token",
    "lookalike_label",
    "mixed_script",
    "claim_mismatch",
}

_NAMESPACE_LOOKALIKES = ("bankin", "bank-in", "bank_in", "govin", "gov-in", "gov_in", "nicin", "nic-in")


@dataclass
class Signal:
    id: str
    message: str
    evidence: dict = field(default_factory=dict)


@dataclass
class LinkResult:
    link: str
    host: str
    registrable: str | None
    verdict: Verdict
    headline: str
    official_for: str | None = None  # entity or namespace the domain officially belongs to
    official_basis: str | None = None
    signals: list[Signal] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        return data


@dataclass
class MessageResult:
    verdict: Verdict | None  # None when no link was found
    headline: str
    claims: list[str]  # entity names the message text mentions
    links: list[LinkResult]
    registry_version: str

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value if self.verdict else None,
            "headline": self.headline,
            "claims": self.claims,
            "links": [r.to_dict() for r in self.links],
            "registry_version": self.registry_version,
        }


class Checker:
    def __init__(self, registry: Registry | None = None, psl: PublicSuffixList | None = None) -> None:
        self.registry = registry or default_registry()
        self.psl = psl or load_psl()
        self._official_labels = self.registry.official_labels
        self._claim_patterns = [
            (entity, re.compile(r"(?<![a-z0-9])" + re.escape(alias) + r"(?![a-z0-9])", re.IGNORECASE))
            for entity in self.registry.entities
            for alias in entity.claims
        ]

    # ------------------------------------------------------------------ public API

    def check_message(self, text: str) -> MessageResult:
        found = [
            (link, span) for link, span in find_links(text) if link.scheme or link.is_ip or self._known_suffix(link)
        ]
        # Brand names inside a link are evidence about the link, not a claim made by the message text.
        prose = text
        for _, (start, end) in sorted((item for item in found), key=lambda item: -item[1][0]):
            prose = prose[:start] + " " + prose[end:]
        claims = self.claimed_entities(prose)
        links = [link for link, _ in found]
        results = [self._check(link, claims) for link in links]
        if not results:
            return MessageResult(
                None, "No link found in the text.", [e.name for e in claims], [], self.registry.version
            )
        worst = min(results, key=lambda r: _SEVERITY[r.verdict])
        headline = (
            worst.headline if len(results) == 1 else f"{len(results)} links checked. Most serious: {worst.headline}"
        )
        return MessageResult(worst.verdict, headline, [e.name for e in claims], results, self.registry.version)

    def check_link(self, raw: str, claims: list[Entity] | None = None) -> LinkResult:
        return self._check(parse_link(raw), claims or [])

    def claimed_entities(self, text: str) -> list[Entity]:
        """Entities whose names appear in the message text (e.g. "SBI", "Income Tax")."""
        found: list[Entity] = []
        for entity, pattern in self._claim_patterns:
            if entity not in found and pattern.search(text):
                found.append(entity)
        return found

    # ------------------------------------------------------------------ internals

    def _known_suffix(self, link: Link) -> bool:
        """Bare host-like words in prose ("file.txt") are only checked when their suffix is a real one."""
        return self.psl.is_listed(self.psl.suffix_of(link.ascii_host))

    def _check(self, link: Link, claims: list[Entity]) -> LinkResult:
        if link.is_ip:
            result = LinkResult(
                link.raw,
                link.host,
                None,
                Verdict.NOT_RECOGNISED,
                "Not recognised: the link points to a bare IP address, not a named website.",
            )
            result.signals.append(
                Signal(
                    "raw_ip", "Banks and government sites use named domains, not bare IP addresses.", {"ip": link.host}
                )
            )
            self._apply_claims(result, link, None, claims)
            if any(sig.id in IMPERSONATION_SIGNALS for sig in result.signals):
                result.verdict = Verdict.IMPERSONATION
                names = ", ".join(
                    sorted({sig.evidence["entity"] for sig in result.signals if "entity" in sig.evidence})
                )
                result.headline = (
                    f"Impersonation signals: the message mentions {names}, but the link is a bare IP "
                    "address, not an official domain."
                )
            return self._finish(result, link)

        parts = self.psl.split(link.ascii_host)
        result = LinkResult(link.raw, link.host, parts.registrable, Verdict.NOT_RECOGNISED, "")

        if parts.registrable and parts.registrable in self.registry.shorteners:
            result.verdict = Verdict.CANNOT_CHECK
            result.headline = f"Cannot check: {parts.registrable} is a link shortener that hides the real destination."
            result.notes.append(
                "Asli Link does not open links. Ask the sender for the full address, or go to the "
                "bank or department's site yourself instead of using this link."
            )
            if claims:
                result.notes.append(
                    f"The message mentions {', '.join(e.name for e in claims)}; a shortened link is "
                    "not how you should reach them."
                )
            return self._finish(result, link)

        official = self._official(parts)
        if official:
            result.verdict = Verdict.OFFICIAL
            result.official_for, result.official_basis, headline, notes = official
            result.headline = headline
            result.notes.extend(notes)
            if link.has_userinfo:
                result.notes.append(
                    "The address contains text before an '@'. Browsers ignore that part; the site "
                    "actually opened is the one shown here."
                )
            mismatched = [e for e in claims if not self._is_official_for(parts, e)]
            if mismatched and result.official_basis in {"bank_in", "bank_namespace", "legacy_bank"}:
                result.notes.append(
                    f"The message mentions {', '.join(e.name for e in mismatched)}, but this domain "
                    f"belongs to {result.official_for}."
                )
            return self._finish(result, link)

        self._impersonation_signals(result, link, parts)
        self._apply_claims(result, link, parts, claims)
        if any(s.id in IMPERSONATION_SIGNALS for s in result.signals):
            result.verdict = Verdict.IMPERSONATION
            targets = sorted({s.evidence["entity"] for s in result.signals if "entity" in s.evidence})
            who = f" {', '.join(targets)}" if targets else " an official bank or government site"
            result.headline = (
                f"Impersonation signals: this looks like{who}, but {parts.registrable or link.host} "
                "is not an official domain."
            )
            lures = self._lure_words(link)
            if lures:
                result.signals.append(
                    Signal(
                        "lure_words",
                        f"The address also uses words common in phishing lures: {', '.join(lures)}.",
                        {"words": lures},
                    )
                )
        else:
            result.headline = (
                f"Not recognised: {parts.registrable or link.host} is not a bank or government domain "
                "that Asli Link knows. This does not mean it is safe."
            )
        return self._finish(result, link)

    def _finish(self, result: LinkResult, link: Link) -> LinkResult:
        if link.scheme == "http":
            result.notes.append("The link uses http:// (not encrypted).")
        return result

    def _official(self, parts: DomainParts) -> tuple[str, str, str, list[str]] | None:
        if parts.registrable is None:
            return None
        curated = self.registry.entity_for_domain(parts.registrable)
        if curated:
            entity, how = curated
            if how == "bank_in":
                return (
                    entity.name,
                    "bank_in",
                    f"Official: {parts.registrable} is {entity.name}'s .bank.in domain.",
                    ["Only RBI-regulated banks can register .bank.in domains."],
                )
            if entity.kind == "bank":
                return (
                    entity.name,
                    "legacy_bank",
                    f"Official (older domain): {parts.registrable} is an official {entity.name} domain.",
                    [
                        "RBI asked banks to move to .bank.in by 31 October 2025. Prefer the bank's .bank.in address "
                        "or its official app."
                    ],
                )
            return (
                entity.name,
                "curated",
                f"Official: {parts.registrable} is the official domain of {entity.name}.",
                [],
            )

        namespace = self.registry.namespace_for(parts.suffix)
        if namespace is None:
            return None
        if namespace.kind == "bank":
            note = [f"{namespace.label}: {namespace.basis}."]
            if self.registry.observed_bank_in:
                if parts.registrable in self.registry.observed_bank_in:
                    note.append("This domain appears in public Certificate Transparency logs.")
                else:
                    note.append(
                        "This domain was not in our latest Certificate Transparency snapshot. The namespace "
                        "is still restricted, but check the bank name carefully."
                    )
            return (
                "a bank (name not in Asli Link's list)",
                "bank_namespace",
                f"Official bank domain: {parts.registrable} is inside the RBI-restricted .bank.in namespace.",
                note,
            )
        return (
            namespace.label,
            "government_namespace",
            f"Official government domain: {parts.registrable} is under .{namespace.suffix}.",
            [
                f"{namespace.label}: {namespace.basis}.",
                "Government sites can still be compromised; never share an OTP or PIN because a page asks for it.",
            ],
        )

    def _is_official_for(self, parts: DomainParts | None, entity: Entity) -> bool:
        if parts is None or parts.registrable is None:
            return False
        curated = self.registry.entity_for_domain(parts.registrable)
        if curated and curated[0].id == entity.id:
            return True
        if entity.kind == "government":
            namespace = self.registry.namespace_for(parts.suffix)
            return namespace is not None and namespace.kind == "government"
        return False

    def _impersonation_signals(self, result: LinkResult, link: Link, parts: DomainParts) -> None:
        host = link.ascii_host
        unicode_host = link.host

        if link.has_userinfo:
            result.signals.append(
                Signal(
                    "userinfo_trick",
                    "The address hides its real host after an '@'. Everything before the '@' is "
                    "ignored by the browser.",
                    {"real_host": host},
                )
            )

        # Official-looking namespace text in the wrong place: sbi.bank.in.secure-login.xyz, incometax.gov.in-refund.com
        for ns in self.registry.namespaces:
            marker = f".{ns.suffix}"
            index = f".{host}".find(f"{marker}.")
            index_dash = f".{host}".find(f"{marker}-")
            if index != -1 or index_dash != -1:
                result.signals.append(
                    Signal(
                        "deceptive_suffix",
                        f"The address contains '{ns.suffix}' in the middle, but it really ends in "
                        f".{parts.suffix} and belongs to {parts.registrable}.",
                        {"namespace": ns.suffix, "real_domain": parts.registrable},
                    )
                )
                break

        flat_labels = host.replace("_", "-").split(".")
        if not any(s.id == "deceptive_suffix" for s in result.signals):
            for label in flat_labels:
                hit = next((m for m in _NAMESPACE_LOOKALIKES if m in label), None)
                if hit:
                    result.signals.append(
                        Signal(
                            "namespace_lookalike",
                            f"'{label}' imitates an official namespace such as .bank.in or .gov.in.",
                            {"label": label},
                        )
                    )
                    break

        # Brand names of banks, departments and institutions used inside someone else's domain.
        parts_by_hyphen = {p for label in flat_labels for p in label.split("-") if p}
        squashed_labels = [label.replace("-", "") for label in flat_labels]
        for entity in self.registry.entities:
            for token in entity.tokens:
                plain = token.replace("-", "")
                matched = (
                    (plain in parts_by_hyphen) if len(plain) <= 3 else any(plain in lbl for lbl in squashed_labels)
                )
                if matched:
                    result.signals.append(
                        Signal(
                            "brand_token",
                            f"The address uses the name '{token}' of {entity.name}, "
                            f"but {parts.registrable} is not {entity.name}'s domain.",
                            {"entity": entity.name, "token": token},
                        )
                    )
                    break

        # Typosquats and visual lookalikes of curated official domain labels (hdfcbnak, onlinesbl, icicibamk).
        label = parts.label or ""
        if label:
            skel = lookalike.skeleton(label)
            for official_label, entity in self._official_labels.items():
                if any(s.id == "brand_token" and s.evidence.get("entity") == entity.name for s in result.signals):
                    continue
                official_skel = lookalike.skeleton(official_label)
                limit = lookalike.distance_limit(len(official_label))
                if skel == official_skel and label != official_label:
                    dist = 0
                elif limit:
                    dist = lookalike.edit_distance(skel, official_skel, limit)
                    if dist > limit:
                        continue
                else:
                    continue
                result.signals.append(
                    Signal(
                        "lookalike_label",
                        f"'{label}' looks like '{official_label}' ({entity.name}).",
                        {"entity": entity.name, "looks_like": official_label, "edits": dist},
                    )
                )

        # Internationalised (Unicode) names: mixed scripts are a classic homoglyph trick.
        if link.is_idn:
            mixed = [lbl for lbl in unicode_host.split(".") if lookalike.is_mixed_script(lbl)]
            if mixed:
                result.signals.append(
                    Signal(
                        "mixed_script",
                        "The address mixes writing systems (for example Latin and "
                        "Cyrillic letters), a common way to imitate a known name.",
                        {"labels": mixed, "punycode": host},
                    )
                )
            else:
                result.notes.append(f"This is an internationalised domain name (shown as {host} in punycode).")
            unicode_label = unicode_host.split(".")[-len(parts.registrable.split(".")) if parts.registrable else -1]
            skel = lookalike.skeleton(unicode_label)
            for entity in self.registry.entities:
                if any(len(t) > 3 and t.replace("-", "") in skel for t in entity.tokens):
                    if not any(s.evidence.get("entity") == entity.name for s in result.signals):
                        result.signals.append(
                            Signal(
                                "lookalike_label",
                                f"'{unicode_label}' reads like a name of "
                                f"{entity.name} once look-alike letters are "
                                "replaced.",
                                {"entity": entity.name, "skeleton": skel},
                            )
                        )
                    break

    def _apply_claims(self, result: LinkResult, link: Link, parts: DomainParts | None, claims: list[Entity]) -> None:
        for entity in claims:
            if self._is_official_for(parts, entity):
                continue
            already = any(s.evidence.get("entity") == entity.name for s in result.signals)
            if not already:
                domain = (parts.registrable if parts else None) or link.host
                result.signals.append(
                    Signal(
                        "claim_mismatch",
                        f"The message mentions {entity.name}, but this link "
                        f"goes to {domain}, which is not {entity.name}'s "
                        "official domain.",
                        {"entity": entity.name},
                    )
                )

    def _lure_words(self, link: Link) -> list[str]:
        words = set(re.split(r"[^a-z0-9]+", f"{link.ascii_host} {link.path}".lower()))
        return sorted(words & self.registry.lure_keywords)


def check_text(text: str) -> MessageResult:
    """Convenience wrapper using the bundled registry."""
    return Checker().check_message(text)


__all__ = ["Checker", "LinkError", "LinkResult", "MessageResult", "Signal", "Verdict", "check_text"]
