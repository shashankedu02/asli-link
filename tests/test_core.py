"""Core behaviour: parsing, lookalikes, registry and verdicts. No network, no web framework."""

import json

import pytest

from asli import lookalike
from asli.checker import Checker, Verdict
from asli.psl import load as load_psl
from asli.registry import RegistryError, load_registry
from asli.urls import MAX_TEXT_CHARS, LinkError, extract_links, parse_link


@pytest.fixture(scope="module")
def checker():
    return Checker()


def verdict_of(checker, text):
    result = checker.check_message(text)
    assert result.links, f"no link found in {text!r}"
    return result.links[0]


# ------------------------------------------------------------------ Public Suffix List


@pytest.mark.parametrize(
    ("host", "registrable", "suffix"),
    [
        ("sbi.bank.in", "sbi.bank.in", "bank.in"),
        ("www.kotak.bank.in", "kotak.bank.in", "bank.in"),
        ("incometax.gov.in", "incometax.gov.in", "gov.in"),
        ("eportal.incometax.gov.in", "incometax.gov.in", "gov.in"),
        ("netbanking.hdfcbank.com", "hdfcbank.com", "com"),
        ("sbi.bank.in.secure-login.xyz", "secure-login.xyz", "xyz"),
        ("example.co.in", "example.co.in", "co.in"),
    ],
)
def test_registrable_domain(host, registrable, suffix):
    parts = load_psl().split(host)
    assert (parts.registrable, parts.suffix) == (registrable, suffix)


def test_bank_in_is_a_public_suffix():
    # If this ever fails, every bank would share one registrable domain and the checker would be wrong.
    psl = load_psl()
    assert psl.is_listed("bank.in") and psl.is_listed("gov.in") and psl.is_listed("nic.in")
    assert psl.split("bank.in").registrable is None


# ------------------------------------------------------------------ link parsing


def test_extracts_links_from_sms_text():
    text = "Dear customer, update KYC at https://sbi-kyc.top/login. Or visit www.example.in, call 1930."
    hosts = [link.ascii_host for link in extract_links(text)]
    assert hosts == ["sbi-kyc.top", "www.example.in"]


@pytest.mark.parametrize("text", ["Rs.500 credited", "e.g. this one", "Dear customer.Your account", "v2.0 released"])
def test_prose_is_not_mistaken_for_links(text):
    assert extract_links(text) == []


def test_trailing_punctuation_is_stripped():
    assert parse_link("(https://kotak.bank.in/login).").ascii_host == "kotak.bank.in"


def test_userinfo_is_detected():
    link = parse_link("https://sbi.bank.in@evil.example/path")
    assert link.has_userinfo and link.ascii_host == "evil.example"


def test_idn_is_decoded():
    link = parse_link("https://xn--xisbank-1fg.com")
    assert link.is_idn and link.host != link.ascii_host


@pytest.mark.parametrize("raw", ["javascript:alert(1)", "ftp://files.example.com", "https://", "https://localhost"])
def test_rejects_unusable_links(raw):
    with pytest.raises(LinkError):
        parse_link(raw)


def test_text_length_limit():
    with pytest.raises(LinkError):
        extract_links("a" * (MAX_TEXT_CHARS + 1))


# ------------------------------------------------------------------ lookalike primitives


def test_edit_distance():
    assert lookalike.edit_distance("hdfcbank", "hdfcbnak") == 1  # transposition counts once
    assert lookalike.edit_distance("onlinesbi", "onlinesbl") == 1
    assert lookalike.edit_distance("abc", "xyz", limit=1) == 2


def test_skeleton_maps_confusables():
    assert lookalike.skeleton("аxisbank") == "axisbank"  # Cyrillic 'а'
    assert lookalike.skeleton("icicibarnk") == "icicibamk"  # 'rn' reads as 'm'
    assert lookalike.skeleton("hdfc-bank") == "hdfcbank"


def test_mixed_script():
    assert lookalike.is_mixed_script("аxisbank")
    assert not lookalike.is_mixed_script("axisbank")


def test_short_names_get_no_fuzzy_matching():
    assert lookalike.distance_limit(3) == 0  # "sbi" would otherwise match hundreds of words


# ------------------------------------------------------------------ verdicts: official


@pytest.mark.parametrize(
    ("link", "basis"),
    [
        ("https://kotak.bank.in/personal", "bank_in"),
        ("https://abc.bank.in", "bank_namespace"),
        ("https://www.onlinesbi.sbi/", "legacy_bank"),
        ("https://www.incometax.gov.in/iec/foportal/", "government_namespace"),
        ("https://www.india.nic.in", "government_namespace"),
        ("https://www.rbi.org.in", "curated"),
    ],
)
def test_official_domains(checker, link, basis):
    result = verdict_of(checker, link)
    assert result.verdict is Verdict.OFFICIAL
    assert result.official_basis == basis


def test_official_never_claims_safety(checker):
    for link in ["https://kotak.bank.in", "https://incometax.gov.in"]:
        result = verdict_of(checker, link)
        text = (result.headline + " ".join(result.notes)).lower()
        assert "safe" not in text and "genuine" not in text


def test_userinfo_before_official_host_is_still_the_official_host(checker):
    result = verdict_of(checker, "https://login@kotak.bank.in/")
    assert result.verdict is Verdict.OFFICIAL


# ------------------------------------------------------------------ verdicts: impersonation


@pytest.mark.parametrize(
    ("text", "signal"),
    [
        ("https://sbi-kyc-update.top/login", "brand_token"),
        ("sbi.bank.in.secure-verify.xyz", "deceptive_suffix"),
        ("https://incometax.gov.in-refund.com", "deceptive_suffix"),
        ("https://hdfc-bank-in.com", "namespace_lookalike"),
        ("https://onlinesbl.com", "lookalike_label"),
        ("https://iclcibank.com", "lookalike_label"),  # 'l' for 'i', and no brand token present
        ("https://аxisbank.com/login", "mixed_script"),
        ("https://sbi.bank.in@evil-site.com/", "userinfo_trick"),
        ("Your HDFC card is blocked, verify: https://random-shop.in/x", "claim_mismatch"),
        ("SBI alert: verify at http://192.168.1.10/kyc", "claim_mismatch"),
    ],
)
def test_impersonation_signals(checker, text, signal):
    result = verdict_of(checker, text)
    assert result.verdict is Verdict.IMPERSONATION
    assert signal in [s.id for s in result.signals]


def test_impersonation_names_the_target(checker):
    result = verdict_of(checker, "https://hdfcbnak.com/netbanking")
    assert "HDFC Bank" in result.headline


def test_lure_words_are_reported_as_extra_evidence(checker):
    result = verdict_of(checker, "https://sbi-kyc-update.top/login")
    lure = next(s for s in result.signals if s.id == "lure_words")
    assert {"kyc", "update", "login"} <= set(lure.evidence["words"])


# ------------------------------------------------------------------ verdicts: default and unknowns


@pytest.mark.parametrize(
    "link",
    [
        "https://random-shop.in/offers",
        "https://www.wikipedia.org/wiki/Bank",
        "https://sbiz.example.com",  # contains 'sbi' but not as a separate word
        "https://subbing.in",  # 'sbi'-like letters inside a word
    ],
)
def test_unrelated_domains_are_not_recognised(checker, link):
    result = verdict_of(checker, link)
    assert result.verdict is Verdict.NOT_RECOGNISED
    assert "does not mean it is safe" in result.headline


def test_shortener_cannot_be_checked(checker):
    result = verdict_of(checker, "Your parcel is held. India Post: https://bit.ly/3xyzAbc")
    assert result.verdict is Verdict.CANNOT_CHECK
    assert any("India Post" in note for note in result.notes)


def test_brand_in_link_is_not_a_message_claim(checker):
    result = checker.check_message("https://sbi.bank.in@evil-site.com/")
    assert result.claims == []


def test_message_headline_uses_most_serious_link(checker):
    result = checker.check_message("Official: https://kotak.bank.in . Also https://kotak-kyc.top/verify")
    assert result.verdict is Verdict.IMPERSONATION
    assert len(result.links) == 2


def test_no_link(checker):
    result = checker.check_message("Hello, your OTP is 123456. Do not share it.")
    assert result.verdict is None and result.links == []


def test_results_are_json_serialisable(checker):
    payload = checker.check_message("Update KYC: https://sbi-kyc.top").to_dict()
    assert json.loads(json.dumps(payload))["verdict"] == "impersonation_signals"


# ------------------------------------------------------------------ registry integrity (fail closed)


def test_bundled_registry_loads():
    registry = load_registry()
    assert registry.entity_for_domain("kotak.bank.in")[0].name == "Kotak Mahindra Bank"
    assert len(registry.sha256) == 64


def _write(tmp_path, data):
    (tmp_path / "entities.json").write_text(json.dumps(data), encoding="utf-8")
    return tmp_path


def _minimal():
    return {
        "schema": 1,
        "namespaces": [{"suffix": "bank.in", "kind": "bank", "label": "x", "basis": "y"}],
        "entities": [
            {
                "id": "a",
                "kind": "bank",
                "name": "A",
                "bank_in": ["a.bank.in"],
                "other_official": [],
                "tokens": ["abank"],
                "claims": ["a bank"],
            }
        ],
    }


def test_minimal_registry_is_valid(tmp_path):
    assert load_registry(_write(tmp_path, _minimal())).entity_for_domain("a.bank.in")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(schema=2),
        lambda d: d.update(namespaces=[]),
        lambda d: d["entities"][0].update(kind="shop"),
        lambda d: d["entities"][0].update(bank_in=["a.com"]),
        lambda d: d["entities"][0].update(bank_in=["x.y.bank.in"]),
        lambda d: d["entities"].append(dict(d["entities"][0])),  # duplicate id
        lambda d: d["entities"][0].update(tokens="abank"),
    ],
)
def test_malformed_registry_is_rejected(tmp_path, mutate):
    data = _minimal()
    mutate(data)
    with pytest.raises(RegistryError):
        load_registry(_write(tmp_path, data))


def test_missing_registry_is_rejected(tmp_path):
    with pytest.raises(RegistryError):
        load_registry(tmp_path)


def test_curated_bank_in_domains_are_confirmed_by_the_ct_snapshot():
    registry = load_registry()
    if not registry.observed_bank_in:
        pytest.skip("no Certificate Transparency snapshot in data/registry")
    curated = {d for e in registry.entities for d in e.bank_in}
    missing = sorted(curated - registry.observed_bank_in)
    assert not missing, f"curated .bank.in domains not seen in CT logs: {missing}"


def test_bank_in_domain_outside_curated_list_mentions_the_snapshot(checker):
    registry = load_registry()
    unnamed = sorted(registry.observed_bank_in - {d for e in registry.entities for d in e.bank_in})[0]
    result = verdict_of(checker, f"https://{unnamed}")
    assert result.official_basis == "bank_namespace"
    assert any("Certificate Transparency" in note for note in result.notes)
