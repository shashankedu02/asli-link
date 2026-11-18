"""The official-domain registry: curated entities plus restricted namespaces.

Data lives in data/registry/. The loader validates structure and refuses to start on a
malformed file (fail closed): a checker with a broken registry must not quietly call
everything "not recognised".
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

DEFAULT_REGISTRY_DIR = Path(__file__).resolve().parent.parent / "data" / "registry"
KINDS = {"bank", "government", "institution"}


class RegistryError(RuntimeError):
    """The registry data is missing or malformed."""


@dataclass(frozen=True)
class Namespace:
    suffix: str
    kind: str
    label: str
    basis: str


@dataclass(frozen=True)
class Entity:
    id: str
    kind: str
    name: str
    bank_in: tuple[str, ...]
    other_official: tuple[str, ...]
    tokens: tuple[str, ...]
    claims: tuple[str, ...]


@dataclass(frozen=True)
class Registry:
    version: str
    sha256: str
    namespaces: tuple[Namespace, ...]
    entities: tuple[Entity, ...]
    observed_bank_in: frozenset[str]  # registrable .bank.in domains seen in Certificate Transparency logs
    observed_source: str | None
    shorteners: frozenset[str]
    lure_keywords: frozenset[str]
    _by_domain: dict[str, tuple[Entity, str]] = field(default_factory=dict, repr=False, compare=False)

    def namespace_for(self, suffix: str) -> Namespace | None:
        return next((ns for ns in self.namespaces if ns.suffix == suffix), None)

    def entity_for_domain(self, registrable: str) -> tuple[Entity, str] | None:
        """(entity, "bank_in" | "other_official") for a curated official registrable domain."""
        return self._by_domain.get(registrable)

    def entity(self, entity_id: str) -> Entity:
        return next(e for e in self.entities if e.id == entity_id)

    @property
    def official_labels(self) -> dict[str, Entity]:
        """Owner labels of every curated official domain ("hdfcbank" -> HDFC Bank), for lookalike checks."""
        labels: dict[str, Entity] = {}
        for domain, (entity, _) in self._by_domain.items():
            labels.setdefault(domain.split(".")[0], entity)
        return labels


def _clean_domain(value: str, where: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip().lower() or "/" in value or "." not in value:
        raise RegistryError(f"{where}: invalid domain {value!r}")
    return value


def _str_tuple(item: dict, key: str, where: str) -> tuple[str, ...]:
    value = item.get(key)
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise RegistryError(f"{where}: '{key}' must be a list of non-empty strings")
    return tuple(v.strip().lower() for v in value)


def load_registry(directory: Path = DEFAULT_REGISTRY_DIR) -> Registry:
    path = directory / "entities.json"
    try:
        raw = path.read_bytes()
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"cannot read {path.name}: {exc}") from exc
    if data.get("schema") != 1:
        raise RegistryError("unsupported registry schema")

    namespaces = []
    for i, ns in enumerate(data.get("namespaces", [])):
        if ns.get("kind") not in {"bank", "government"}:
            raise RegistryError(f"namespace {i}: unknown kind")
        namespaces.append(Namespace(ns["suffix"], ns["kind"], ns["label"], ns["basis"]))
    if not namespaces:
        raise RegistryError("no namespaces defined")

    entities: list[Entity] = []
    by_domain: dict[str, tuple[Entity, str]] = {}
    ids: set[str] = set()
    for i, item in enumerate(data.get("entities", [])):
        where = f"entity {i} ({item.get('id', '?')})"
        if item.get("kind") not in KINDS or not item.get("id") or not item.get("name"):
            raise RegistryError(f"{where}: needs id, name and a known kind")
        if item["id"] in ids:
            raise RegistryError(f"{where}: duplicate id")
        ids.add(item["id"])
        bank_in = tuple(_clean_domain(d, where) for d in _str_tuple(item, "bank_in", where))
        if any(not d.endswith(".bank.in") or d.count(".") != 2 for d in bank_in):
            raise RegistryError(f"{where}: bank_in entries must look like <name>.bank.in")
        other = tuple(_clean_domain(d, where) for d in _str_tuple(item, "other_official", where))
        entity = Entity(
            item["id"],
            item["kind"],
            item["name"],
            bank_in,
            other,
            _str_tuple(item, "tokens", where),
            _str_tuple(item, "claims", where),
        )
        for domain, how in [(d, "bank_in") for d in bank_in] + [(d, "other_official") for d in other]:
            if domain in by_domain:
                raise RegistryError(f"{where}: {domain} already belongs to {by_domain[domain][0].id}")
            by_domain[domain] = (entity, how)
        entities.append(entity)

    observed: frozenset[str] = frozenset()
    observed_source = None
    observed_path = directory / "observed_bank_in.json"
    if observed_path.exists():
        try:
            obs = json.loads(observed_path.read_text(encoding="utf-8"))
            observed = frozenset(_clean_domain(d, "observed_bank_in") for d in obs["domains"])
            observed_source = obs.get("source")
        except (KeyError, json.JSONDecodeError, TypeError) as exc:
            raise RegistryError(f"observed_bank_in.json is malformed: {exc}") from exc

    return Registry(
        version=str(data.get("registry_version", "unknown")),
        sha256=hashlib.sha256(raw).hexdigest(),
        namespaces=tuple(namespaces),
        entities=tuple(entities),
        observed_bank_in=observed,
        observed_source=observed_source,
        shorteners=frozenset(d.lower() for d in data.get("shorteners", [])),
        lure_keywords=frozenset(k.lower() for k in data.get("lure_keywords", [])),
        _by_domain=by_domain,
    )


@lru_cache(maxsize=1)
def default_registry() -> Registry:
    return load_registry()
