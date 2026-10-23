# IAS conformance toolkit 1.6.0: file manifest

Toolkit for checking TEFCA Individual Access Services (IAS) artifacts against the Exchange Purpose Implementation SOP: Individual Access Services (IAS) v3.0. From 1.5.0 it also applies TEFCA QHIN Compliance Bulletin No. 2 v1.0, and 1.6.0 adds the claim-value clarifications from the RCE IAS workgroup of October 22, 2026. Version 1.6.0 was built on October 22, 2026; the changes from 1.4.0 are listed under Version history. It is unofficial: the schemas and checks encode one reading of the source documents, and nothing here is RCE guidance.

**Keep all ten program and schema files in one folder.** RUN_GUIDE.md explains how to install and run them. The checker loads the schema files from its own folder, or from `--schema-dir`, and the schemas reference each other by `$id`.

**Requirements:**
- Python 3.8 or later; 3.10 or later recommended. The 54 tests pass on Python 3.8.20 and 3.13.16.
- `cryptography`, for signature and x5c checks and for the fixture generator.
- `jsonschema>=4.18`, which includes `referencing`, for the schema cross-check.
- Everything else uses the standard library.

```
pip install cryptography "jsonschema>=4.18"
python3 ias_sop_checker.py --token-file id_token.jwt --expected-aud urn:oid:<IAS Provider HCID>
python3 test_ias_toolkit.py -v
```

## Files

| File | Kind | Purpose | Change in 1.6.0 |
|---|---|---|---|
| `ias_sop_checker.py` | Python CLI | The conformance and troubleshooting checker | Changed |
| `make_ias_test_fixtures.py` | Python CLI | Generates synthetic test artifacts (fictitious people) | Changed |
| `test_ias_toolkit.py` | Python unittest | Regression suite, 54 tests | Changed |
| `oidc-core-1.0.schema.json` | JSON Schema 2020-12 | Generic OpenID Connect / JOSE layer | Unchanged |
| `oauth2-core.schema.json` | JSON Schema 2020-12 | Generic OAuth 2.0 layer | Unchanged |
| `hl7-udap-security-1.1.0.schema.json` | JSON Schema 2020-12 | HL7 SSRAA (UDAP) STU1.1 layer | Unchanged |
| `tefca-facilitated-fhir-v2.schema.json` | JSON Schema 2020-12 | TEFCA Facilitated FHIR SOP v2.0 layer | Unchanged |
| `tefca-ias-sop-v3.schema.json` | JSON Schema 2020-12 | IAS SOP v3.0 MUST layer | Changed |
| `tefca-ias-sop-v3.recommended.schema.json` | JSON Schema 2020-12 | IAS SOP v3.0 SHOULD / RECOMMENDED layer | Changed |
| `tefca-qhin-bulletin-2.schema.json` | JSON Schema 2020-12 | QHIN Compliance Bulletin No. 2 claims layer | Unchanged (new in 1.5.0) |
| `MANIFEST.md` | Markdown | This file | Changed |
| `RUN_GUIDE.md` | Markdown | Step-by-step guide: setup, practice runs, real artifacts, options, reading results, troubleshooting | Changed |

## ias_sop_checker.py

This is the main tool. It checks IAS artifacts and prints PASS, FAIL, PENDING, WARN, INFO, SKIP and MANUAL findings. Each finding cites the clause it rests on: an IAS SOP section, a Bulletin 2 section (written `B2 §…`), a QTF requirement, an FF or SSRAA section, or an OIDC or RFC section.

**Inputs.** Any combination, at least one required:
- An IAL2 Claims Token: `--token` or `--token-file`. The file may be a JSON token response containing `id_token`.
- Decoded claims: `--payload`. This runs payload and profile checks only, with no signature, discovery or expiry checks.
- Captured XCPD, XCA Query and XCA Retrieve requests: `--soap`. These may be raw XML, MTOM or HTTP captures.
- An XCPD response: `--xcpd-response`.
- Facilitated FHIR and UDAP artifacts: `--fhir-auth`, `--udap-registration` and `--oauth-response`.
- A FHIR base URL to probe for `/.well-known/udap`: `--fhir-base`.
- Offline discovery and JWKS files: `--discovery-file` and `--jwks-file`.

**What it checks.**
- **Tokens:**
  - The IAS §4.9 token rules: Tables 1–3, the RS256 signature verified against the CSP JWKS, the version claim and the RCE claim namespace.
  - Issuer discovery and JWKS, including §4.3(d)–(f).
  - The minimum demographics (§4.4(d)) and the comparison of token values with the XCPD body (§4.4(e)).
  - That the token is present in PD, DQ, DR and FHIR authentication requests (§4.4(f), §4.9(d)).
  - The SAML attribute carrying the token (§4.9(e)).
  - The claim values clarified by the RCE IAS workgroup on October 22, 2026:
    - aud: an upper- or mixed-case `urn:oid:` prefix is a WARN, not a FAIL. RFC 8141 makes the prefix case-insensitive, but the FHIR oid data type, which the workgroup recommends following, needs lower case. `--expected-aud` is compared by URN-equivalence.
    - country: must be one of the 249 assigned ISO 3166-1 alpha-2 codes, in upper case. So `UK` (use `GB`) and unassigned pairs fail.
    - region: the upper-case ISO 3166-2 subdivision code without the country prefix.
  - For a CSP token response, whether it carries a refresh_token, and any lifetime field it gives. This is reported as INFO, because the SOP is silent on refresh tokens.
- **Exchange:**
  - XP code T-IAS (§4.1, with QTF-604/605).
  - QTF-501 signature algorithms, depending on the hop.
  - Facilitated FHIR and SSRAA artifacts.
  - XCPD response analysis.
- **Not machine-testable:** process obligations are listed as MANUAL attestation items.

**Rule sets.**
- **`--bulletin2 auto|on|off`.** The default, `auto`, applies QHIN Compliance Bulletin No. 2 when `--as-of` is on or after 2026-10-13, the Bulletin's Issue Date. Today's UTC date is used if `--as-of` is not given. With the Bulletin applied:
  - `tefca_ial2claims_version` must be the string `"3.0"` (§2(a)).
  - The email / phone_number verification rules apply (§3(a)–(f)).
  - `historical_address` may be an Address object or an array of them (§4).
  - `aud` may be a string or a one-element array (§5).
  - `off` gives the SOP-text reading used in 1.4.0.
- **`--b2-3g-notice DATE`.** This is the date of the RCE notice that ends the temporary §3(b)/(c) permissions. From that date, an unverified email or phone_number fails (§3(g); IAS §4.9(a)(iii)). Setting a date on or before `--as-of` also reproduces the production "no unverified data" decision.
- **`--as-of DATE`.** Compliance dates are applied as of this date. A violation whose compliance date has not yet arrived (from the IAS §4.8 table and the SSRAA adoption dates) is reported as PENDING, not FAIL.
- **`--at TIME`.** This is the instant used for `exp` and `iat`, typically the capture time.

**Schema cross-check.**
- Each decoded artifact is validated against the schema layers below, and the result is compared field by field with the hand-written checks.
- Any disagreement is reported as a `*.drift` WARN.
- `--obligations text|csv` prints the obligation and precedence table built from the schema annotations.

**Output.**
- A text report with a requirement roll-up, and optionally a JSON report via `--json-report`.
- The JSON report includes `rule_set`, which says whether Bulletin 2 was applied and on what basis.
- Demographics are masked unless `--show-phi` is given.
- Exit code 0 means no FAIL, 1 means at least one FAIL, and 2 means a usage or input error.

`python3 ias_sop_checker.py --help` lists every option with examples. The module docstring at the top of the file explains the precedence model, the production decision and the Bulletin 2 behaviour.

## Schema layers

All seven schemas are JSON Schema draft 2020-12 and are marked UNOFFICIAL. They carry custom annotation keywords:
- `x-obligation`, `x-source`, `x-precedence`, `x-not-expressible`.
- `x-field` (new in 1.5.0): names the member that a cross-field rule is reported against.

Draft 2020-12 validators keep unknown keywords as annotations. Ajv in strict mode needs `addKeyword` for each of them.

| File | `$id` | Source | References |
|---|---|---|---|
| `oidc-core-1.0.schema.json` | `urn:x-oidc:core-1.0:schema` | OIDC Core 1.0 and Discovery 1.0 incorporating errata set 2; RFC 7515, 7517, 7518, 7519 | none |
| `oauth2-core.schema.json` | `urn:x-oauth2:core:schema` | RFC 6749, 7521, 7523, 7591, 7636 | none |
| `hl7-udap-security-1.1.0.schema.json` | `urn:x-hl7-udap-security:1.1.0:schema` | HL7 SSRAA STU1.1 (the version the Facilitated FHIR SOP v2.0 pins; STU2 differs) | oauth2-core |
| `tefca-facilitated-fhir-v2.schema.json` | `urn:x-tefca-facilitated-fhir:2.0:schema` | TEFCA Facilitated FHIR SOP v2.0 (effective March 8, 2026), applied to IAS through IAS §4.2(b) | hl7-udap-security, oauth2-core |
| `tefca-ias-sop-v3.schema.json` | `urn:x-tefca-ias-sop:3.0:schema` | IAS SOP v3.0 (effective August 3, 2026): MUST / SHALL items | oidc-core, tefca-facilitated-fhir |
| `tefca-ias-sop-v3.recommended.schema.json` | `urn:x-tefca-ias-sop:3.0:recommended` | IAS SOP v3.0 SHOULD / RECOMMENDED items, plus heuristics | oidc-core, tefca-ias-sop-v3 |
| `tefca-qhin-bulletin-2.schema.json` | `urn:x-tefca-qhin-bulletin-2:1.0:schema` | QHIN Compliance Bulletin No. 2 v1.0 (issued October 13, 2026) | oidc-core, tefca-ias-sop-v3, tefca-ias-sop-v3.recommended |

### oidc-core-1.0.schema.json

This is the generic, framework-neutral OIDC layer.
- **Required items:** `joseHeader`, `idTokenClaims` (the file's root), `standardClaims`, `address`, `jwk`, `publicJwk`, `jwks`, `publishedJwks`, `discovery`.
- **RECOMMENDED items:** the `*Recommended` definitions hold only these, and are reported as warnings.

### oauth2-core.schema.json

This layer covers generic OAuth 2.0 artifacts:
- token request, response and error;
- JWT client-assertion claims;
- dynamic client registration request, response and error.

Form-encoded requests are represented as JSON objects of their parameters.

### hl7-udap-security-1.1.0.schema.json

This layer covers the SSRAA (UDAP) artifacts:
- JWT headers;
- UDAP metadata and `signed_metadata` claims;
- software statement, certification and Authentication JWT claims;
- registration request;
- the `hl7-b2b` extension;
- client_credentials and authorization_code token requests, and the token response.

It is not TEFCA-specific.

### tefca-facilitated-fhir-v2.schema.json

This is the TEFCA profile of SSRAA and OAuth. It covers:
- the XP code;
- the `hl7-b2b` and `tefca_ias` extensions;
- client assertion, certification and software statement;
- registration;
- UDAP metadata for an IAS responder;
- token response and error.

For TEFCA IAS FHIR Endpoints, the FF SSRAA deadlines are superseded by IAS §4.6, with a date of July 1, 2027.

### tefca-ias-sop-v3.schema.json

This is the IAS SOP v3.0 MUST layer.
- **Definitions:** `oidUrn`, `iso3166Alpha2`, `jwt`, `idTokenHeader`, `address` (Table 3), `idTokenClaimsCore`, `idTokenClaims`, `idTokenClaimsStrict`, `decodedIdToken`, `jwks`, `discovery`, `tefcaIasExtension`, `iasHl7B2b`, `iasClientCredentialsAssertion`.
- **1.6.0:**
  - `oidUrn` accepts the `urn:oid:` prefix in any case (RFC 3061; RFC 8141 §3.1).
  - `address.country` must be one of the 249 assigned ISO 3166-1 alpha-2 codes, held in `iso3166Alpha2`.
- **1.5.0 restructure:**
  - `idTokenClaimsCore` holds the constraints shared by both readings.
  - `idTokenClaims` is now the SOP-text reading only: aud is one string, historical_address is one object, and the `*_verified` flags may only be true.
- **Root:** the file's root still points to the SOP-text `idTokenClaims`. To validate under the Bulletin, use the root of `tefca-qhin-bulletin-2.schema.json`.

### tefca-ias-sop-v3.recommended.schema.json

This is the IAS SOP v3.0 SHOULD / RECOMMENDED layer. Errors that appear only here are warnings.
- **Definitions:** `address`, `idTokenClaims`, `idTokenHeader`, `jwks`, `discovery`, `tefcaIasExtension`, `fhirOid`.
- **New in 1.6.0:** `fhirOid` is the FHIR oid form, with a lower-case prefix. `idTokenClaimsDelta` applies it to aud, as a string or as the element of a one-element array.
- **New in 1.5.0:** `addressDelta` and `idTokenClaimsDelta` hold the SHOULD items without the MUST layer, so the same items apply under both rule sets. `idTokenClaimsDelta` also recommends omitting a `*_verified` flag when its claim is absent (`dependentRequired`).

### tefca-qhin-bulletin-2.schema.json (new)

This layer replaces the SOP-text `idTokenClaims` when the Bulletin applies, following Bulletin §1(b): the Bulletin governs where the SOP is ambiguous and prevails where they conflict. It reuses `idTokenClaimsCore`, `address` and `oidUrn` from the SOP layer.

| Definition | What it encodes |
|---|---|
| `aud` | A string, or an array containing exactly one string. The string is an RFC 3061 HCID URI (§5) |
| `historicalAddress` | An Address object, or an array of one or more, each per IAS Table 3 (§4) |
| `verifiedContact` | At least one of email and phone_number present and not flagged `false` (§3(a)–(f)) |
| `idTokenClaims` | The Bulletin reading; the file's root. Also requires `tefca_ial2claims_version` to be `"3.0"` (§2(a)) |
| `idTokenClaimsStrict` | `idTokenClaims` with unknown claims rejected |
| `idTokenClaimsRecommended` | The Bulletin reading plus the OIDC and TEFCA SHOULD items |
| `decodedIdToken` | `{header, payload}` wrapper |

**What it cannot express** (listed under `x-not-expressible`):
- The §3(g) notice that ends the temporary permissions.
- That an email or phone was verified per IAS §4.3.
- That aud is the intended recipient's HCID.
- That recipients treat the two aud forms as equivalent.
- The QHIN processing and compliance dates.

### How the checker uses the layers for ID token claims

| Rule set | MUST layers | SHOULD layers |
|---|---|---|
| SOP text (`--bulletin2 off`, or `--as-of` before 2026-10-13) | `oidc-core#idTokenClaims` + `tefca-ias-sop-v3#idTokenClaims` | `oidc-core#idTokenClaimsRecommended` + `tefca-ias-sop-v3.recommended#idTokenClaims` |
| Bulletin 2 (default from 2026-10-13) | `oidc-core#idTokenClaims` + `tefca-qhin-bulletin-2#idTokenClaims` | `oidc-core#idTokenClaimsRecommended` + `tefca-ias-sop-v3.recommended#idTokenClaimsDelta` |

`--schema-strict` swaps in the `idTokenClaimsStrict` definitions. The check names are the same in both rule sets: `schema.idTokenClaims` and `schema.idTokenClaims.recommended`, or `schema.idTokenClaimsStrict…` in strict mode.

**If a schema file is missing:**
- Without `oidc-core-1.0.schema.json` or `tefca-ias-sop-v3.schema.json`, the cross-check is skipped. It is reported as FAIL when `--schema-dir` was given, and SKIP otherwise.
- The other layers are optional. When the Bulletin applies and `tefca-qhin-bulletin-2.schema.json` is missing, the claims cross-check is skipped with a WARN.

## make_ias_test_fixtures.py

This generates synthetic artifacts for the checker and the regression suite. All people, addresses and phone numbers are fictitious.

```
python3 make_ias_test_fixtures.py --output-dir DIR [--issuer URL] [--fhir-base URL] [--force]
```

**How it writes:**
- Output goes to `--output-dir`, by default `./ias_fixtures`. The generator refuses a non-empty directory unless `--force` is given, and `--help` writes nothing.
- Each run makes fresh keys, so its tokens verify only against that run's `jwks.json`.
- ID tokens expire 10 minutes after generation. Check them later with `--at` or `--ignore-expiry`.

**What it produces:** 54 files, of which the generated `manifest.json` lists 50 with their intended result:
- **CSP side:** `jwks.json`, `disc.json`, and signed tokens (`good.jwt`, `bad.jwt`, `tok_*.jwt`).
- **Decoded payloads:** in `payloads/`. These include:
  - the revision-memo cases;
  - nine `b2-*` Bulletin 2 cases (new in 1.5.0);
  - three `wg-*` cases from the October 22 workgroup (new in 1.6.0): an upper-case aud prefix, country `UK`, and a lower-case region.
- **CSP token response:** `csp_token_response_refresh.json`, which carries a refresh_token (new in 1.6.0).
- **SOAP captures:**
  - PD requests: `pd*.xml`, including `pd_b2_unverified_email.xml`.
  - DQ and DR requests: `dq.xml` and `dr.mtom`.
  - The XCPD response `resp.xml`.
- **UDAP / Facilitated FHIR:**
  - a test PKI;
  - client assertions (`fhir_*.txt` / `.jwt`);
  - registrations (`reg*.json`) and token responses (`token_*.json`);
  - UDAP metadata under `srv/`, which the test suite serves over a local HTTP server.

In 1.5.0 the manifest notes for the three memo fixtures named `invalid-…array` and `temp-valid-…` now say that they are valid under Bulletin 2 and fail only under the SOP-text reading.

## test_ias_toolkit.py

This is the unittest regression suite, 54 tests:

```
python3 test_ias_toolkit.py -v
```

**How it runs:**
- It runs the generator into a temporary directory and serves the generated UDAP metadata from a local HTTP server.
- It then runs the checker as a subprocess, with a JSON report for each run.
- Every run asserts specific named findings. Unless a test deliberately loosens a schema, it also asserts that no `*.drift` WARN appeared.
- It takes about a minute.

| Tests | Area |
|---|---|
| 00–03 | Generator CLI safety, schema meta-validation and `$ref` resolution across all seven files, obligations vocabulary |
| 10 | Full good suite: no FAIL, no drift |
| 20–22 | UDAP certification claims |
| 30–33 | SAML PurposeOfUse element, namespace and code system |
| 40–42 | QTF-501 algorithm rule by hop |
| 50–51 | `hl7-b2b` organization_id forms |
| 60–62 | SSRAA protocol axis vs adoption date |
| 70 | x5c chain with an impostor intermediate |
| 80–85 | Bad ID token, FHIR assertion, registration, token response, SOAP coverage, UDAP metadata |
| 90–92 | Drift detection in the SHOULD, MUST and certification layers |
| 100–110 | Revision-memo cases under the SOP-text reading (`--bulletin2 off` where the Bulletin changes the outcome) |
| 120–128 | QHIN Compliance Bulletin No. 2 (new in 1.5.0) |
| 130–133 | RCE IAS workgroup, October 22, 2026: aud prefix case, ISO 3166-1 country, region forms, refresh-token reporting (new in 1.6.0) |

The Bulletin 2 tests (120–128) cover:
- the date gate;
- aud arrays;
- historical_address arrays;
- unverified email or phone;
- the §3(g) notice;
- the version claim;
- the XCPD body comparison;
- strict mode and a missing schema layer;
- drift detection in the Bulletin layer.

## Integrity

SHA-256 of each file in this release (MANIFEST.md and RUN_GUIDE.md excluded):

```
31fafcf897ead5b5fb77e582dfbd9edc9b59469acce5f4485273f8e676b94dbf  ias_sop_checker.py
a77b8043391ea8e17828ff7d6de6117137d4d16bc80498f90d1737e63ec05eb1  make_ias_test_fixtures.py
612562552bd79c48ec5f4d0666da1f1fac75b9e43c94186aa023cc9d1aaaf9e0  test_ias_toolkit.py
26953d219b6a409ea5b925edeba8dc1e4b7adac05b09a1e0b14e8ad5261476ed  oidc-core-1.0.schema.json
624b8a49a7f1e8abc9de3167a946791b410b4b31a78726dc6b990890b72b4d12  oauth2-core.schema.json
88dcf1d502863b1e673b9d1dd3b30be4b1d393e8abcd5436de7f33bc941f7acf  hl7-udap-security-1.1.0.schema.json
d2298909a3d97d60d9649b93f8f79a61cc9c44555065408e937fb626242812f5  tefca-facilitated-fhir-v2.schema.json
98110b1308abf2a5c79584792586e37b74dbee6340ade09c13141413883d5590  tefca-ias-sop-v3.schema.json
47310b1510b71982cefd94c0cec8532b4d06a156366a88d65187187ee5273799  tefca-ias-sop-v3.recommended.schema.json
8afdb110f4b7bb94fde80d6865c6301e38e0778a415e65950b35d543040bd301  tefca-qhin-bulletin-2.schema.json
```

Check with `sha256sum -c` after saving the block above to a file.

## Version history

- **1.6.0 (October 22, 2026).** Claim-value clarifications from the RCE IAS workgroup of October 22, 2026:
  - An upper- or mixed-case `urn:oid:` prefix in aud is a WARN (`aud.case`), not a FAIL. RFC 3061's own example is `URN:OID:0.9.2342.19200300.100.4`, and RFC 8141 §3.1 compares the prefix case-insensitively. The lower-case FHIR oid form is a SHOULD.
  - `--expected-aud` is compared by URN-equivalence.
  - country is checked against the ISO 3166-1 alpha-2 list.
  - region failures cite the clarification.
  - A refresh_token in a CSP token response is reported as INFO.
  - New open-question items: token and refresh-token lifetimes, refined aud language, and sunset dates for the Bulletin 2 temporary measures.
  - 4 new tests; 3 new payload fixtures and one token-response fixture.
- **1.5.0 (October 22, 2026).** QHIN Compliance Bulletin No. 2:
  - `--bulletin2` and `--b2-3g-notice`.
  - The new layer `tefca-qhin-bulletin-2.schema.json`.
  - The SOP and SHOULD layers restructured into `idTokenClaimsCore` and the `*Delta` definitions.
  - 9 new tests.
- **1.4.0.** Production decision: tefca_ial2claims_version required as "3.0".
