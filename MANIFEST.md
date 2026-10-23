# IAS conformance toolkit 1.6.5: file manifest

Toolkit for checking TEFCA Individual Access Services (IAS) artifacts against the Exchange Purpose Implementation SOP: Individual Access Services (IAS) v3.0. From 1.5.0 it also applies TEFCA QHIN Compliance Bulletin No. 2 v1.0, 1.6.0 adds the claim-value clarifications from the RCE IAS workgroup of October 22, 2026, 1.6.1 decodes tokens that are not base64url instead of stopping, 1.6.2 corrects the gender comparison with the XCPD body, 1.6.3 reports how long before issue the person last signed in at the CSP, 1.6.4 checks captures with a repeated XML declaration, and 1.6.5 checks the XCPD gender code. Version 1.6.5 was built on October 23, 2026; the changes from 1.4.0 are listed under Version history. It is unofficial: the schemas and checks encode one reading of the source documents, and nothing here is RCE guidance.

**Keep all ten program and schema files in one folder.** RUN_GUIDE.md explains how to install and run them. The checker loads the schema files from its own folder, or from `--schema-dir`, and the schemas reference each other by `$id`.

**Requirements:**
- Python 3.8 or later; 3.10 or later recommended. The 69 tests pass on Python 3.8.20 and 3.13.16.
- `cryptography`, for signature and x5c checks and for the fixture generator.
- `jsonschema>=4.18`, which includes `referencing`, for the schema cross-check.
- Everything else uses the standard library.

```
pip install cryptography "jsonschema>=4.18"
python3 ias_sop_checker.py --token-file id_token.jwt --expected-aud urn:oid:<IAS Provider HCID>
python3 test_ias_toolkit.py -v
```

## Files

| File | Kind | Purpose | Change in 1.6.5 |
|---|---|---|---|
| `ias_sop_checker.py` | Python CLI | The conformance and troubleshooting checker | Changed |
| `make_ias_test_fixtures.py` | Python CLI | Generates synthetic test artifacts (fictitious people) | Changed |
| `test_ias_toolkit.py` | Python unittest | Regression suite, 69 tests | Changed |
| `oidc-core-1.0.schema.json` | JSON Schema 2020-12 | Generic OpenID Connect / JOSE layer | Unchanged |
| `oauth2-core.schema.json` | JSON Schema 2020-12 | Generic OAuth 2.0 layer | Unchanged |
| `hl7-udap-security-1.1.0.schema.json` | JSON Schema 2020-12 | HL7 SSRAA (UDAP) STU1.1 layer | Unchanged |
| `tefca-facilitated-fhir-v2.schema.json` | JSON Schema 2020-12 | TEFCA Facilitated FHIR SOP v2.0 layer | Unchanged |
| `tefca-ias-sop-v3.schema.json` | JSON Schema 2020-12 | IAS SOP v3.0 MUST layer | Unchanged (changed in 1.6.0) |
| `tefca-ias-sop-v3.recommended.schema.json` | JSON Schema 2020-12 | IAS SOP v3.0 SHOULD / RECOMMENDED layer | Unchanged (changed in 1.6.0) |
| `tefca-qhin-bulletin-2.schema.json` | JSON Schema 2020-12 | QHIN Compliance Bulletin No. 2 claims layer | Unchanged (new in 1.5.0) |
| `MANIFEST.md` | Markdown | This file | Changed |
| `RUN_GUIDE.md` | Markdown | Step-by-step guide: setup, practice runs, real artifacts, options, reading results, troubleshooting | Changed |

## ias_sop_checker.py

This is the main tool. It checks IAS artifacts and prints PASS, FAIL, PENDING, WARN, INFO, SKIP and MANUAL findings. Each finding cites the clause it rests on: an IAS SOP section, a Bulletin 2 section (written `B2 §…`), a QTF requirement, an FF or SSRAA section, or an OIDC or RFC section.

**Inputs.** Any combination, at least one required:
- An IAL2 Claims Token: `--token` or `--token-file`. The file may be a JSON token response containing `id_token`.
- Decoded claims: `--payload`. This runs payload and profile checks only, with no signature, discovery or expiry checks.
- Captured XCPD, XCA Query and XCA Retrieve requests: `--soap`. These may be raw XML, MTOM or HTTP captures. From 1.6.4, a capture with a repeated XML declaration at the top is checked after a WARN (`xml.decl`) instead of stopping.
- An XCPD response: `--xcpd-response`.
- Facilitated FHIR and UDAP artifacts: `--fhir-auth`, `--udap-registration` and `--oauth-response`.
- A FHIR base URL to probe for `/.well-known/udap`: `--fhir-base`.
- Offline discovery and JWKS files: `--discovery-file` and `--jwks-file`.

**What it checks.**
- **Tokens:**
  - The IAS §4.9 token rules: Tables 1–3, the RS256 signature verified against the CSP JWKS, the version claim and the RCE claim namespace.
  - Issuer discovery and JWKS, including §4.3(d)–(f).
  - The minimum demographics (§4.4(d)) and the comparison of token values with the XCPD body (§4.4(e)). From 1.6.2 a token gender of `female` or `F` matches body code F, and `male` or `M` matches M. From 1.6.4 a token birthdate that is not a full YYYY-MM-DD date is not compared (INFO); it already fails `birthdate.format`. From 1.6.5 an XCPD gender code other than F, M or UN is a WARN (`pd.gender.code`); a spelled-out `MALE` or `FEMALE` is still compared as M or F.
  - That the token is present in PD, DQ, DR and FHIR authentication requests (§4.4(f), §4.9(d)).
  - The SAML attribute carrying the token (§4.9(e)).
  - The claim values clarified by the RCE IAS workgroup on October 22, 2026:
    - aud: an upper- or mixed-case `urn:oid:` prefix is a WARN, not a FAIL. RFC 8141 makes the prefix case-insensitive, but the FHIR oid data type, which the workgroup recommends following, needs lower case. `--expected-aud` is compared by URN-equivalence.
    - country: must be one of the 249 assigned ISO 3166-1 alpha-2 codes, in upper case. So `UK` (use `GB`) and unassigned pairs fail.
    - region: the upper-case ISO 3166-2 subdivision code without the country prefix.
  - For a CSP token response, whether it carries a refresh_token, and any lifetime field it gives. This is reported as INFO, because the SOP is silent on refresh tokens.
  - Token encoding (new in 1.6.1). A part that is not base64url is a FAIL (`token.b64url`; RFC 7515). If the part uses the standard-base64 alphabet or `=` padding, the checker still decodes it and runs every other check. It then tries the signature both over the token as received and over its base64url form. `sig.b64-source` reports which verified: whether the CSP signed the non-standard text, or the token was converted after signing. A token wrapped in quotation marks is unwrapped with a WARN (`token.quoted`). Any other character still stops the token checks.
  - gender value (new in 1.6.2). A token gender that abbreviates or changes the case of `female` or `male`, such as `F`, is a WARN (`gender.value`). OIDC Core §5.1 defines those two values and allows others only when neither applies, and §4.9(a) requires OIDC conformance.
  - auth_time age (new in 1.6.3). When the token carries auth_time, an INFO (`auth_time.age`) says how long before iat the person last authenticated at the CSP. Within 10 minutes, the authorization-code lifetime RFC 6749 §4.1.2 recommends, it reads as a sign-in for this token. Longer means the token came from a refresh token or an existing CSP session, because OIDC Core §12.2 keeps the original auth_time on a refreshed ID Token. It is not judged, because the workgroup set no lifetime. auth_time after iat is a WARN (`auth_time.order`), and a non-numeric auth_time is a FAIL (`auth_time.type`).
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

**What it produces:** 64 files, of which the generated `manifest.json` lists 60 with their intended result:
- **CSP side:** `jwks.json`, `disc.json`, and signed tokens (`good.jwt`, `bad.jwt`, `tok_*.jwt`). Since 1.6.1 these include four encoding cases:
  - `tok_b64_converted.jwt`: converted to standard base64 after signing;
  - `tok_b64_std_signed.jwt`: signed in standard base64;
  - `tok_quoted.txt`: wrapped in quotation marks;
  - `tok_b64_junk.jwt`: contains `%`.
- **Decoded payloads:** in `payloads/`. These include:
  - the revision-memo cases;
  - nine `b2-*` Bulletin 2 cases (new in 1.5.0);
  - three `wg-*` cases from the October 22 workgroup (new in 1.6.0): an upper-case aud prefix, country `UK`, and a lower-case region.
- **CSP token response:** `csp_token_response_refresh.json`, which carries a refresh_token (new in 1.6.0).
- **SOAP captures:**
  - PD requests: `pd*.xml`, including `pd_b2_unverified_email.xml` and, since 1.6.2, three gender cases: `pd_gender_female.xml` (matches), `pd_gender_letter.xml` (token `F`: WARN, still matches) and `pd_gender_mismatch.xml` (FAIL). Since 1.6.4 also `pd_double_xml_decl.xml` (two XML declarations: WARN, then checked) and `pd_birthdate_not_iso.xml` (token birthdate `2/29/80`: one FAIL, not compared with the body). Since 1.6.5 also `pd_gender_spelled_out.xml` (token `Male`, body code `MALE`: two WARNs, no mismatch).
  - DQ and DR requests: `dq.xml` and `dr.mtom`.
  - The XCPD response `resp.xml`.
- **UDAP / Facilitated FHIR:**
  - a test PKI;
  - client assertions (`fhir_*.txt` / `.jwt`);
  - registrations (`reg*.json`) and token responses (`token_*.json`);
  - UDAP metadata under `srv/`, which the test suite serves over a local HTTP server.

In 1.5.0 the manifest notes for the three memo fixtures named `invalid-…array` and `temp-valid-…` now say that they are valid under Bulletin 2 and fail only under the SOP-text reading.

## test_ias_toolkit.py

This is the unittest regression suite, 69 tests:

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
| 140–144 | Token encoding: converted after signing, signed in standard base64, quoted, undecodable, conforming token unchanged (new in 1.6.1) |
| 150–152 | Gender: `female` matches XCPD F; `F` is a WARN but matches; a real mismatch still fails (new in 1.6.2) |
| 160–162 | auth_time: long before iat reads as a refresh; just before reads as a sign-in; after iat, or not a number (new in 1.6.3) |
| 170–172 | Captures: repeated XML declaration, NameFormat of a mis-named token attribute, non-ISO birthdate fails once (new in 1.6.4) |
| 180 | XCPD gender code `MALE`: WARN, compared as M (new in 1.6.5) |

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
8941be6ae5a590602c0dded8274e2dfadec1b446681e81670d5dfa0f0dbf7e64  ias_sop_checker.py
87ad289861358e44a511d0bc87453f317d0f387e7713d6bcb788ff513cf31026  make_ias_test_fixtures.py
1814c456627d2109d9a5245e484a4a998f702c718c3e315e7ccbca684d979ab0  test_ias_toolkit.py
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

- **1.6.5 (October 23, 2026).** XCPD gender code, prompted by a captured XCPD request:
  - A livingSubjectAdministrativeGender code other than F, M or UN (HL7 AdministrativeGender) is a WARN (`pd.gender.code`).
  - A spelled-out `MALE` or `FEMALE`, in any case, is compared with the token as M or F. Before, token `Male` and body `MALE` were reported as a mismatch (FAIL).
  - 1 new test; 1 new PD fixture.
- **1.6.4 (October 23, 2026).** Prompted by a captured XCPD request:
  - A capture with more than one XML declaration before the root element used to stop with `xml.parse`. The extra declarations are now removed with a WARN (`xml.decl`) and the message is checked.
  - When the token is in a mis-named SAML attribute, the attribute's NameFormat is now checked as well (`saml.id_token.nameformat`).
  - A token birthdate that is not YYYY-MM-DD is no longer also reported as a mismatch with the XCPD body, FHIR patient_information or an XCPD response; the comparison is INFO. Before, `1/15/11` and `20110115` were reported as different although they are the same day.
  - 3 new tests; 2 new PD fixtures.
- **1.6.3 (October 23, 2026).** auth_time:
  - New INFO `auth_time.age`: how long before iat the person last authenticated at the CSP, and whether that reads as a sign-in for this token or a refresh. Prompted by a captured CLEAR token issued almost seven days after its auth_time.
  - New WARN `auth_time.order` (auth_time after iat); a non-numeric auth_time is now a FAIL (`auth_time.type`), in line with the OIDC schema layer.
  - 3 new tests; no new fixtures.
- **1.6.2 (October 23, 2026).** Gender:
  - Fixed a false FAIL: a token gender of `F` or `M` was compared with the XCPD body as `UN`, so `pd.vs.token.gender` failed even when the body carried the same code. Found on a captured XCPD request.
  - A token gender such as `F` that is not an OIDC value is now a WARN (`gender.value`); before, it was a PASS noted as non-standard.
  - 3 new tests; 3 new PD fixtures.
- **1.6.1 (October 23, 2026).** Token encoding:
  - A token part that is not base64url is still a FAIL, but standard-base64 characters and `=` padding are now decoded so that the remaining checks run.
  - The signature is tried over the received text and over its base64url form, and `sig.b64-source` says which one verified.
  - Quotation marks around a token are removed with a WARN.
  - 5 new tests; 4 new token fixtures.
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
