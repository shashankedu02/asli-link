# Rules and design decisions

This is the reference for how Asli Link reaches a verdict. The code is in `asli/checker.py`; every rule
has tests in `tests/test_core.py`.

## Order of decisions

1. **Shortener** (`data/registry/entities.json` → `shorteners`) → `cannot_check`. The link is never expanded.
2. **Official**, checked by registrable domain (Public Suffix List):
   - curated `.bank.in` domain → named bank (`bank_in`);
   - curated other official domain → older bank domain (`legacy_bank`) or institution (`curated`);
   - any other `<name>.bank.in` → official bank namespace, bank not named (`bank_namespace`);
   - any `<name>.gov.in` / `<name>.nic.in` → government namespace (`government_namespace`).
3. **Impersonation signals** on a non-official link → `impersonation_signals`.
4. Otherwise → `not_recognised`.

The message-level verdict is the most serious one across its links:
impersonation > cannot check > not recognised > official.

## Signals

| Id | Fires when | Notes |
|---|---|---|
| `userinfo_trick` | The URL has `user@host`. | Browsers open `host`; the text before `@` is decoration. |
| `deceptive_suffix` | `.bank.in.`, `.gov.in.`, `.nic.in.` (or the same followed by `-`) appears inside the host, but the host does not end in that suffix. | `incometax.gov.in.refund-status.co`. |
| `namespace_lookalike` | A label contains `bankin`, `bank-in`, `govin`, `gov-in`, `nicin` or `nic-in`. | Skipped when `deceptive_suffix` already fired. |
| `brand_token` | A curated token appears in the host. | Tokens of 3 characters or fewer must be a whole hyphen/dot-separated part; longer tokens may appear anywhere in a label (hyphens ignored). |
| `lookalike_label` | The owner label's visual skeleton equals, or is within a small edit distance of, the label of a curated official domain. Also fires for Unicode labels whose skeleton contains a brand token. | Distance limit: 0 below 5 characters, 1 for 5–8, 2 for 9+. Skipped for an entity already named by `brand_token`. |
| `mixed_script` | An internationalised label mixes scripts (e.g. Latin and Cyrillic). | Single-script IDNs (e.g. a Hindi domain) only get an informational note. |
| `claim_mismatch` | The message text (with the links removed) names a curated entity, and the link is not that entity's official domain. | For government entities, any `.gov.in` / `.nic.in` domain counts as official. |
| `raw_ip` | The host is an IP address. | Informational; becomes impersonation only together with `claim_mismatch`. |
| `lure_words` | Host or path contains words like `kyc`, `verify` or `refund`. | Evidence only. It is added only when there is already an impersonation signal. |

## Decisions

- **Precision first.** A false *Impersonation* on a legitimate business is costly, so short tokens need word
  boundaries, short labels get no fuzzy matching, and the default is *Not recognised*, not *suspicious*.
- **Never "safe".** No verdict describes a link as safe or genuine. *Not recognised* states explicitly that it does
  not mean safe, and *Official* names the owner without calling the page trustworthy (tested in
  `test_official_never_claims_safety`).
- **No network in the checker.** Links are parsed, not opened: this keeps the tool private, fast, and safe to run
  on attacker-supplied input.
- **Fail closed.** A malformed registry raises `RegistryError` and the server refuses to start.
- **Brand evidence never confers trust.** Tokens and message aliases can raise signals but can never make a
  domain official; only namespaces and curated official domains do.
- **Colour.** *Official* is blue, not green, so it does not read as a safety badge.
