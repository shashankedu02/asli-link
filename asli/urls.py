"""Find links in pasted text and normalise their hostnames.

Nothing here touches the network: links are parsed, never opened.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

import idna

MAX_TEXT_CHARS = 5000
MAX_LINKS = 20

# Characters people paste around links in SMS/WhatsApp text.
_TRAILING = ".,;:!?)]}>'\"’”"
_LEADING = "([{<'\"‘“"

# Explicit URLs, plus bare host-like tokens such as "sbi-kyc.top/verify" or "www.example.in".
_CANDIDATE = re.compile(
    r"""(?ix)
    (?:\b[a-z][a-z0-9+.\-]{1,15}://[^\s<>"']+)       # scheme://...
    |
    (?:(?<![@\w.\-])(?:[\w\-]+\.)+[\w\-]{2,}(?::\d{1,5})?(?:/[^\s<>"']*)?)  # bare host[/path]
    """
)


class LinkError(ValueError):
    """The text does not contain a usable link."""


@dataclass(frozen=True)
class Link:
    raw: str  # exactly as found in the text
    scheme: str  # "https", "http", or "" for a bare host
    host: str  # lower-case, Unicode form (punycode decoded), no trailing dot
    ascii_host: str  # lower-case ASCII (punycode) form
    is_ip: bool
    has_userinfo: bool  # e.g. https://sbi.bank.in@evil.example/ - the real host is after the @
    port: int | None
    path: str

    @property
    def is_idn(self) -> bool:
        return self.host != self.ascii_host


def _strip_punctuation(token: str) -> str:
    token = token.lstrip(_LEADING)
    while token and token[-1] in _TRAILING:
        token = token[:-1]
    return token


def _decode_host(host: str) -> tuple[str, str]:
    """Return (unicode_host, ascii_host). Raises LinkError on hosts that are not valid domain names."""
    host = unicodedata.normalize("NFKC", host).lower().rstrip(".")
    if not host or len(host) > 253:
        raise LinkError("missing or over-long host name")
    labels = host.split(".")
    if any(not label for label in labels):
        raise LinkError("empty label in host name")
    ascii_labels: list[str] = []
    unicode_labels: list[str] = []
    for label in labels:
        try:
            if label.isascii():
                ascii_label = label
                unicode_label = idna.decode(label) if label.startswith("xn--") else label
            else:
                ascii_label = idna.encode(label, uts46=True).decode("ascii")
                unicode_label = idna.decode(ascii_label)
        except idna.IDNAError as exc:
            # Mixed-script or otherwise invalid IDN labels are still worth reporting, so keep the raw label
            # rather than rejecting the link: an attacker's label does not have to be valid IDNA 2008.
            try:
                ascii_label = label.encode("idna").decode("ascii") if not label.isascii() else label
            except UnicodeError:
                raise LinkError(f"host label cannot be encoded: {exc}") from exc
            unicode_label = label if not label.startswith("xn--") else _legacy_decode(label)
        ascii_labels.append(ascii_label)
        unicode_labels.append(unicode_label.lower())
    return ".".join(unicode_labels), ".".join(ascii_labels)


def _legacy_decode(label: str) -> str:
    try:
        return label.encode("ascii").decode("idna")
    except UnicodeError:
        return label


def parse_link(raw: str) -> Link:
    """Parse one link-like string. Bare hosts ("example.in/path") are accepted."""
    token = _strip_punctuation(raw.strip())
    if not token:
        raise LinkError("empty link")
    has_scheme = "://" in token
    parts = urlsplit(token if has_scheme else f"//{token}")
    scheme = parts.scheme.lower() if has_scheme else ""
    if has_scheme and scheme not in {"http", "https"}:
        raise LinkError(f"unsupported scheme: {scheme}")
    netloc = parts.netloc
    if not netloc:
        raise LinkError("no host name")
    has_userinfo = "@" in netloc
    hostport = netloc.rsplit("@", 1)[-1]
    try:
        port = parts.port
    except ValueError as exc:
        raise LinkError("invalid port") from exc
    host = parts.hostname or ""
    if hostport.startswith("["):  # IPv6 literal
        return Link(raw, scheme, host, host, True, has_userinfo, port, parts.path)
    try:
        ipaddress.ip_address(host)
        return Link(raw, scheme, host, host, True, has_userinfo, port, parts.path)
    except ValueError:
        pass
    unicode_host, ascii_host = _decode_host(host)
    if "." not in ascii_host:
        raise LinkError("host has no domain suffix")
    return Link(raw, scheme, unicode_host, ascii_host, False, has_userinfo, port, parts.path)


def find_links(text: str) -> list[tuple[Link, tuple[int, int]]]:
    """Find up to MAX_LINKS distinct links in free text, with their character spans, in order."""
    if len(text) > MAX_TEXT_CHARS:
        raise LinkError(f"text is longer than {MAX_TEXT_CHARS} characters")
    found: list[tuple[Link, tuple[int, int]]] = []
    seen: set[tuple[str, str]] = set()
    for match in _CANDIDATE.finditer(text):
        try:
            link = parse_link(match.group(0))
        except LinkError:
            continue
        if not link.scheme and not link.is_ip and not _looks_like_bare_link(match.group(0), link.ascii_host):
            continue  # e.g. "Rs.500", "e.g" or "customer.Click" (a missing space after a full stop) in prose
        key = (link.ascii_host, link.path)
        if key in seen:
            continue
        seen.add(key)
        found.append((link, match.span()))
        if len(found) >= MAX_LINKS:
            break
    return found


def extract_links(text: str) -> list[Link]:
    """Find up to MAX_LINKS distinct links in free text, in order of appearance."""
    return [link for link, _ in find_links(text)]


_TLD_LIKE = re.compile(r"^(?:[a-z]{2,24}|xn--[a-z0-9\-]{2,59})$")


def _looks_like_bare_link(raw: str, ascii_host: str) -> bool:
    """A bare host without http(s):// is only taken as a link when it is written like one: links are
    lower-case in practice, while "word.Next" is usually a sentence break with a missing space."""
    if not _looks_like_domain(ascii_host):
        return False
    token = _strip_punctuation(raw)
    host_part = token.split("/", 1)[0].split(":", 1)[0]
    if token.lower().startswith("www.") or "/" in token:
        return True
    return host_part.rsplit(".", 1)[-1].islower()


def _looks_like_domain(ascii_host: str) -> bool:
    labels = ascii_host.split(".")
    return len(labels) >= 2 and bool(_TLD_LIKE.match(labels[-1])) and not labels[-2].isdigit()
