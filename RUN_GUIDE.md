# IAS conformance toolkit 1.6.5: run guide

This guide takes you from the zip file to checking real TEFCA IAS artifacts. It is written for someone comfortable with a terminal who has not used the toolkit before. A first practice run takes about 15 minutes.

The toolkit checks IAS artifacts against IAS SOP v3.0 and, from October 13, 2026, QHIN Compliance Bulletin No. 2. The artifacts are:
- IAL2 Claims Tokens;
- captured XCPD, XCA Query and XCA Retrieve traffic;
- Facilitated FHIR / UDAP artifacts.

MANIFEST.md describes every file in the zip. This guide covers how to run them.

Commands are shown for macOS and Linux. On Windows they are the same with `py` in place of `python3`, and with `.venv\Scripts\activate` to activate the virtual environment.

> **Long commands are split across lines.** A `\` at the end of a line means "the command continues on the next line". Paste such a command exactly as shown, or type it on one line without the `\` characters. A blank line, or a space after a `\`, ends the command early. The checker then runs with only the options before the break, and the shell reports the rest as errors such as `zsh: command not found: --discovery-file`. Some viewers add blank lines when you copy; if that happens, use the one-line form.

---

## 1. Set up (once)

### 1.1 What you need

- Python 3.10 or later is recommended. Check with `python3 --version`.
  - The toolkit also runs on Python 3.8 and 3.9: the 69 tests pass on 3.8.20 with cryptography 47.0.0 and jsonschema 4.23.0. On 3.8, cryptography prints a `CryptographyDeprecationWarning` at start-up; it is harmless, but future cryptography releases will not install on 3.8.
  - On macOS, `python3` may be an old system version. Install a current Python from python.org or Homebrew (`brew install python@3.12`), then create the virtual environment with it, for example `python3.12 -m venv .venv`.
- Two packages: `cryptography`, used for signature checks and the fixture generator, and `jsonschema` 4.18 or later, used for the schema cross-check.
- Network access to the CSP's issuer **only** if you want the checker to fetch discovery documents and JWKS live. Everything can also run offline (section 3.3).

### 1.2 Unzip into one folder

```bash
mkdir ias-work && cd ias-work
unzip ias_toolkit_1.6.5.zip -d ias_toolkit
```

Keep all the files together in `ias_toolkit/`. The checker loads the seven `*.schema.json` files from its own folder; to keep them elsewhere, pass `--schema-dir DIR`.

### 1.3 Create a virtual environment and install the packages

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography "jsonschema>=4.18"
```

Run `source .venv/bin/activate` again in each new terminal.

### 1.4 Run the self-test

```bash
cd ias_toolkit
python3 test_ias_toolkit.py
cd ..
```

Expect `Ran 69 tests ... OK` after about a minute. The suite generates its own fixtures in a temporary folder and starts a local web server on a free port, so it needs no network access. If any test fails, stop there: the installation or the files are not as shipped. To confirm the files are as shipped, check the SHA-256 list in MANIFEST.md with `sha256sum -c`.

---

## 2. Practice on synthetic fixtures

The generator writes a set of fictitious tokens, payloads, SOAP captures and UDAP artifacts. Some are deliberately bad, and each file's intended result is listed in the generated `manifest.json`.

### 2.1 Generate the practice set

```bash
python3 ias_toolkit/make_ias_test_fixtures.py --output-dir practice
cd practice
```

The generator refuses to write into a folder that is not empty; add `--force` to overwrite. Each run creates new signing keys, so a token verifies only against the `jwks.json` from the same run.

> **The generated ID tokens expire 10 minutes after generation.** If you run a token check later, add `--ignore-expiry`, or `--at` with a time inside the token's lifetime (section 4). Otherwise the result will include an `exp.expired` FAIL.

From here on, run every command from inside `practice/`.

The practice issuer, `https://id.csp.example`, does not exist on the internet. That is why the practice commands pass `--discovery-file disc.json --jwks-file jwks.json`. Without those options, the checker tries to fetch discovery live and reports a `discovery.fetch` FAIL (DNS lookup failed).

### 2.2 Check a good token (offline)

```bash
python3 ../ias_toolkit/ias_sop_checker.py --token-file good.jwt \
    --discovery-file disc.json --jwks-file jwks.json \
    --expected-aud urn:oid:2.16.840.1.113883.3.9999.1 --no-manual
```

The same command on one line:

```bash
python3 ../ias_toolkit/ias_sop_checker.py --token-file good.jwt --discovery-file disc.json --jwks-file jwks.json --expected-aud urn:oid:2.16.840.1.113883.3.9999.1 --no-manual
```

What to expect:
- Exit code 0.
- `FAIL=0` in the totals.
- `sig.verify` reports `RS256 signature VALID`.
- One WARN, `discovery.recommended`, because the practice discovery document leaves out some RECOMMENDED metadata.
- The verdict `CONFORMANT WITH WARNINGS / PENDING`.

The report starts like this:

```
IAS SOP checker v1.6.5 -- Exchange Purpose Implementation SOP: Individual Access Services (IAS) v3.0
Evaluated as of 2026-10-22  |  token clock now  |  PHI masked
Rule set: IAS SOP v3.0 + QHIN Compliance Bulletin No. 2 v1.0 (evaluation date 2026-10-22 >= issue date; ...)
```

### 2.3 Check a bad token and read the fixes

```bash
python3 ../ias_toolkit/ias_sop_checker.py --token-file bad.jwt \
    --discovery-file disc.json --jwks-file jwks.json --problems-only --no-manual
```

What to expect:
- Exit code 1.
- About a dozen FAILs. They include:
  - typ missing;
  - a bare-OID aud;
  - an HL7-format birthdate;
  - `US-TN` and `USA` in the address;
  - a numeric version claim;
  - an unknown kid;
  - an RSA-PSS signature labelled RS256.
- Each problem prints the reason (`why:`) and the remedy (`fix:`) on the lines beneath it.

### 2.4 Check decoded claims (payload mode)

Use payload mode when you have the claims as JSON but not a signed token, for example a vendor's sample.

```bash
python3 ../ias_toolkit/ias_sop_checker.py \
    --payload payloads/valid-baseline-v3.json payloads/b2-invalid-both-unverified.json --no-manual
```

Payload mode checks the claim structure and the IAS and Bulletin rules. It does **not** check the signature, the key, discovery or expiry against the current time. The second file fails under Bulletin 2 §3(d) because email and phone_number are both unverified.

A payload file may hold the bare claims object, or `{"header": {...}, "payload": {...}}` to check the JOSE header as well.

### 2.5 Check captured exchange traffic

```bash
python3 ../ias_toolkit/ias_sop_checker.py --soap pd.xml dq.xml dr.mtom --xcpd-response resp.xml \
    --hop qhin-qhin --discovery-file disc.json --jwks-file jwks.json \
    --expected-aud urn:oid:2.16.840.1.113883.3.9999.1 --problems-only --no-manual
```

The checker reads the token out of each request's SAML assertion and checks it once. It then checks:
- PurposeOfUse, the SAML signature algorithms, and the XCPD body against the token (§4.4(d)–(e));
- the XCPD response;
- whether the token was relayed in every request type (§4.4(f)).

`dr.mtom` deliberately leaves the token out, so expect `saml.id_token` and `coverage.DR` FAILs and exit code 1.

### 2.6 Check Facilitated FHIR / UDAP artifacts

The generated UDAP metadata has to be served over HTTP. Start a local server in a second terminal, from inside `practice/`:

```bash
python3 -m http.server 8765 --bind 127.0.0.1 --directory srv
```

Then run the check:

```bash
python3 ../ias_toolkit/ias_sop_checker.py --fhir-auth fhir_cc.txt --udap-registration reg.json \
    --oauth-response token_resp.json token_err.json --fhir-base http://127.0.0.1:8765/fhir \
    --token-endpoint https://as.responder.example/token \
    --registration-endpoint https://as.responder.example/register \
    --discovery-file disc.json --jwks-file jwks.json \
    --expected-aud urn:oid:2.16.840.1.113883.3.9999.1 --problems-only --no-manual
```

Expect no FAILs and two WARNs. One is the same `discovery.recommended` WARN as in 2.2. The other is `udap.ctype`, because Python's simple server sends the metadata file as `application/octet-stream`; a real FHIR server should send `application/json`. Stop the server with Ctrl+C when you are done.

The generator's default `--fhir-base` is `http://127.0.0.1:8765/fhir`. If you serve the metadata on another port, regenerate the fixtures with a matching `--fhir-base`, because the server certificate and `signed_metadata` name that URL.

---

## 3. Check real artifacts

### 3.1 What to collect

| Artifact | Where it comes from | Option |
|---|---|---|
| IAL2 Claims Token (compact JWT) | The CSP's token response (`id_token`), or the SAML attribute `urn:ietf:params:oauth:token-type:id_token` in an IAS request | `--token-file` or `--token` |
| CSP token response JSON | The CSP's token endpoint response; the checker extracts `id_token` | `--token-file` |
| Decoded claims | A vendor sample, or a decoded token | `--payload` |
| XCPD / XCA Query / XCA Retrieve requests | Gateway or QHIN captures (raw XML, MTOM or HTTP capture) | `--soap` |
| XCPD response | Captured PRPA_IN201306UV02 | `--xcpd-response` |
| UDAP client assertion, token request body, or JSON with `extensions` | Facilitated FHIR client traffic | `--fhir-auth` |
| UDAP registration request | Registration traffic | `--udap-registration` |
| OAuth token response or error | Authorization server responses | `--oauth-response` |
| Discovery document and JWKS | `<iss>/.well-known/openid-configuration` and its `jwks_uri` | fetched live, or `--discovery-file` / `--jwks-file` |
| IAS Provider HCID | The RCE Directory entry of the IAS Provider the token was issued for | `--expected-aud urn:oid:...` |

Tokens and captures contain real demographics. Handle them under your organisation's PHI rules. The checker masks demographic values in its output unless you pass `--show-phi`.

### 3.2 A CSP token, fetching discovery and JWKS live

```bash
python3 ias_toolkit/ias_sop_checker.py --token-file <id_token.jwt> \
    --expected-aud urn:oid:<IAS Provider HCID>
```

The checker reads `iss` from the token. It then fetches `<iss>/.well-known/openid-configuration` and the JWKS without credentials, as the SOP requires them to be public (§4.3(d), (f)), and verifies the RS256 signature.

- **Behind a proxy:** set `HTTPS_PROXY` in the environment; Python's HTTP client reads it.
- **Private or intercepting CA:** point `SSL_CERT_FILE` at the CA bundle.
- **`--insecure`** skips TLS verification. Use it only to confirm that TLS is the problem, never for a conformance result.

To paste a token straight in instead of using a file, run `--token "$(cat <id_token.jwt>)"`.

If the file is the CSP's whole token response, the checker uses `id_token`. If the response also carries a `refresh_token`, the checker reports it, with any lifetime field, as INFO. The SOP says nothing about refresh tokens, and the workgroup has not set a lifetime.

A refresh also shows in the ID token itself. When the token carries auth_time, `auth_time.age` (INFO) says how long before issue the person last signed in at the CSP. More than 10 minutes means the token came from a refresh token or an existing CSP session, not a new sign-in.

### 3.3 Offline (no network)

```bash
python3 ias_toolkit/ias_sop_checker.py --token-file <id_token.jwt> \
    --discovery-file <openid-configuration.json> --jwks-file <jwks.json> \
    --expected-aud urn:oid:<IAS Provider HCID> --no-network
```

With `--no-network` and no discovery or JWKS files, the discovery, JWKS and signature checks are reported as SKIP, not FAIL.

### 3.4 Captured IAS traffic, replayed at capture time

```bash
python3 ias_toolkit/ias_sop_checker.py --soap <pd.xml> <dq.xml> <dr.xml> --xcpd-response <pd_resp.xml> \
    --at 2026-10-22T14:03:00Z --hop qhin-qhin --expected-aud urn:oid:<IAS Provider HCID>
```

- **`--at`** is the capture time. Without it, a captured token is judged against the current clock and will usually show as expired.
- **`--hop`** tells the checker which link the capture came from:

| `--hop` value | Effect on QTF-501 signature-algorithm violations |
|---|---|
| `qhin-qhin` | FAIL |
| `participant-qhin` | INFO, because QTF-501 does not govern that hop |
| `unknown` (default) | WARN |

### 3.5 Production and non-production issuers (§4.3(e))

```bash
python3 ias_toolkit/ias_sop_checker.py --token-file <id_token.jwt> \
    --prod-issuer https://<prod issuer> --nonprod-issuer https://<sandbox issuer> \
    --environment production
```

This fails if the two issuers are the same, or if a token from one environment is used in the other. Without these options, the check is listed as a MANUAL item.

### 3.6 Facilitated FHIR / UDAP

```bash
python3 ias_toolkit/ias_sop_checker.py --fhir-auth <token_request.txt> --udap-registration <reg.json> \
    --oauth-response <token_resp.json> --fhir-base https://<fhir base> \
    --token-endpoint https://<as>/token --registration-endpoint https://<as>/register \
    --requested-scope "system/Patient.rs"
```

If an IAL2 token is embedded in the `tefca_ias` extension, it is extracted and checked like any other token.

Two options apply when the run does not make things clear:
- **`--grant-type`:** set it when the artifacts do not show the grant type themselves.
- **`--ssraa-in-use yes|no`:** set it when the OAuth artifacts' membership in an SSRAA transaction is not evident from the same run.

### 3.7 Several inputs in one run

The input options can be combined freely. The checker deduplicates tokens: the same token seen in a CSP response, a PD request and a FHIR request is fully checked once and cross-referenced in the others.

---

## 4. Choose the rule set and the clock

| Option | What it does | When to use it |
|---|---|---|
| `--bulletin2 auto` (default) | Applies QHIN Compliance Bulletin No. 2 when the evaluation date is on or after 2026-10-13 | Normal use |
| `--bulletin2 off` | IAS SOP v3.0 text reading only: aud one string, historical_address one object, `*_verified` flags true only | Comparing with pre-Bulletin results (toolkit 1.4.0) |
| `--bulletin2 on` | Applies the Bulletin whatever the date | Re-running an old capture under today's rules |
| `--as-of YYYY-MM-DD` | The date compliance dates are judged against (default: today, UTC). Before an IAS §4.8 compliance date a violation is PENDING, not FAIL | Reproducing a past or future evaluation |
| `--b2-3g-notice YYYY-MM-DD` | The date of the RCE notice ending the temporary Bulletin §3(b)/(c) permissions. From then, any unverified email or phone_number FAILs | Once the RCE gives notice; or, with a date on or before `--as-of`, to apply the production "no unverified data" decision |
| `--allow-missing-claims-version` | Does not FAIL a missing `tefca_ial2claims_version` | Analysis of old tokens only; Bulletin §2(a) requires the claim |
| `--at <ISO time>` | The instant used for `exp`, `iat` and `nbf` | Captured artifacts |
| `--ignore-expiry` | Reports an expired token as INFO | Practice fixtures; old samples |
| `--clock-skew <seconds>` | Allowed clock difference (default 300) | Clocks known to drift |
| `--max-lifetime <seconds>` | WARN when `exp` minus `iat` exceeds this (default 3600) | The SOP sets no number for "short-lived"; agree one with the program |
| `--schema-strict` | Cross-checks the claims against the strict schema definitions, which reject claims that are not OIDC, SOP-named or RCE-namespaced; the checker reports such claims as WARN (`claim.unknown`) | Tightest profile check |

The second header line of every report states the rule set that was applied, and the JSON report records it under `rule_set`.

---

## 5. Read the results

**Layout.**
- **Header:** the toolkit version, the evaluation date, the token clock, whether PHI is masked, and the rule set.
- **Artifact sections:** one per artifact checked, such as `## IAL2 token #1 (...)`, `## SOAP pd.xml` or `## XCPD response ...`.
- **Requirement roll-up:** the worst status for each cited requirement. IAS SOP sections are shown as `§…`; Bulletin 2 sections as `B2 §…`; QTF, FF and SSRAA by name.
- **Totals and verdict.**

Each finding line reads `[STATUS] reference  check-name  message`.

**Statuses.**

| Status | Meaning |
|---|---|
| FAIL | A MUST / SHALL is violated and in force on the evaluation date |
| PENDING | Would FAIL, but the compliance date is after the evaluation date |
| WARN | A SHOULD is not met, a probable defect, or an interoperability risk |
| PASS | Checked and met |
| INFO | Context, such as a Bulletin 2 temporary permission in use, or a form the recipient must treat as equivalent |
| SKIP | Not evaluated; the message says why (for example, no network and no JWKS file) |
| MANUAL | Cannot be tested from artifacts. Most form an attestation checklist at the end of the report, listing the evidence to request; `--no-manual` hides that checklist |

**Detail.** FAIL, PENDING and WARN findings print `evidence:`, `why:` and `fix:` lines. Add `-v` to print them for every finding. `--problems-only` hides PASS, INFO, SKIP and MANUAL lines.

**Verdict and exit code.**

| Exit code | Meaning |
|---|---|
| 0 | No FAIL |
| 1 | At least one FAIL |
| 2 | Usage or input error, such as no input given |

The verdict covers machine-testable items only.

**JSON report.** `--json-report report.json` writes `tool`, `sop`, `as_of`, `rule_set` and `findings`. Each finding has `ref`, `check`, `status`, `message`, `artifact`, `level`, `evidence`, `why` and `fix`.

**Schema cross-check lines.**
- Lines whose check name starts with `schema.` compare the hand-written checks with the JSON Schema layers.
- A `*.drift` WARN means the two disagree about a field. On the shipped files that should not happen: report it with the artifact.
- `schema.load` WARN, FAIL or SKIP lines mean a schema file is missing or invalid (section 8).

**Seeing the token.**
- `--dump-token` prints the decoded header and claims, with demographics masked.
- `--show-phi` unmasks them. Use it only where PHI is allowed.
- `--debug` logs HTTP requests, parsing and decisions to stderr.

---

## 6. Use it in a script or pipeline

```bash
python3 ias_toolkit/ias_sop_checker.py --token-file <id_token.jwt> \
    --discovery-file <disc.json> --jwks-file <jwks.json> \
    --json-report report.json --no-manual --no-color > report.txt
echo "exit code: $?"

python3 -c "import json; r = json.load(open('report.json'))
for f in r['findings']:
    if f['status'] in ('FAIL', 'PENDING'):
        print(f['status'], f['ref'], f['check'], '-', f['message'])"
```

Pin `--as-of` (and `--at` for captured artifacts) in automated runs, so that a result does not change on its own when a compliance date passes.

To export the obligation table built from the schema annotations, write it to a file. Piping it into `head` stops Python with a broken-pipe error.

```bash
python3 ias_toolkit/ias_sop_checker.py --obligations csv > obligations.csv
```

---

## 7. Validate claims with the schemas alone

To validate JSON claims inside another tool, load all seven schema files into one registry and validate against the definition for the rule set you want. Save the script below as `validate_claims.py`:

```python
import glob, json, sys
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

schema_dir, claims_file = sys.argv[1], sys.argv[2]
docs = [json.load(open(p, encoding="utf-8")) for p in glob.glob(f"{schema_dir}/*.schema.json")]
registry = Registry().with_resources((d["$id"], Resource.from_contents(d)) for d in docs)
target = "urn:x-tefca-qhin-bulletin-2:1.0:schema#/$defs/idTokenClaims"  # Bulletin 2 reading
validator = Draft202012Validator({"$ref": target}, registry=registry)
claims = json.load(open(claims_file, encoding="utf-8"))
errors = sorted(validator.iter_errors(claims), key=lambda e: list(e.absolute_path))
for e in errors:
    where = "/".join(map(str, e.absolute_path)) or "<root>"
    rule = e.schema.get("x-source") if isinstance(e.schema, dict) and "x-field" in e.schema else None
    print(where, "-", rule or e.message[:120])
print("valid" if not errors else f"{len(errors)} error(s)")
sys.exit(1 if errors else 0)
```

Run it on a claims file:

```bash
python3 validate_claims.py ias_toolkit <claims.json>
```

Other targets:
- **SOP-text reading:** `urn:x-tefca-ias-sop:3.0:schema#/$defs/idTokenClaims`.
- **Strict:** `...#/$defs/idTokenClaimsStrict` in either file.
- **Bulletin reading plus the SHOULD items:** `urn:x-tefca-qhin-bulletin-2:1.0:schema#/$defs/idTokenClaimsRecommended`. Treat the errors that appear only here as warnings.

Schemas cannot check signatures, the current time or the RCE Directory, or anything listed under `x-not-expressible`. Use the checker for those.

---

## 8. Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| `exp.expired` FAIL on a capture or practice token | The token is judged against the current time | Add `--at <capture time>`, or `--ignore-expiry` |
| `iat.future` FAIL | The CSP's clock is ahead, or `--at` is earlier than the capture | Check the capture time; widen `--clock-skew` only if the clocks are known to drift |
| `sig.kid` FAIL: kid not found in JWKS | Wrong JWKS file, a token from the other environment's issuer, or a key rotation not yet published | Fetch the JWKS from the token's own `iss`; compare with `--prod-issuer` / `--nonprod-issuer` |
| TLS or DNS errors fetching discovery or JWKS | Proxy, private CA, firewall, or a typo in `iss` | Read the hint in the message; set `HTTPS_PROXY` or `SSL_CERT_FILE`; or run offline with saved files |
| `aud.type` FAIL on a one-element array, or `historical_address.type` FAIL on an array | The run used the SOP-text reading (`--bulletin2 off`, or `--as-of` before 2026-10-13) | Check the `Rule set:` header line |
| `email_verified` / `phone_number_verified` false reported as INFO (`b2.3b`, `b2.3c`) | Bulletin §3(b)/(c) temporary permission | Expected; add `--b2-3g-notice` once the RCE ends it |
| WARN `schema.idTokenClaims`: cross-check skipped, `tefca-qhin-bulletin-2.schema.json` not found | Schema files separated from the checker | Keep all files together, or pass `--schema-dir` |
| SKIP `schema.load`: schema file not found | Same, without `--schema-dir` | Same |
| SKIP or WARN about `jsonschema` or `cryptography` not installed | Packages missing in the active Python | Activate the virtual environment; `pip install cryptography "jsonschema>=4.18"` |
| `*.drift` WARN | The schemas and the checker disagree on a field | Not expected with the shipped files; check whether a schema was edited, and report it with the artifact |
| `udap.ctype` WARN in the practice run | Python's simple HTTP server's content type | Expected in practice only |
| `BrokenPipeError` after `--obligations ... \| head` | Python stops writing when `head` closes the pipe | Write to a file instead |
| Exit code 2 and a usage message | No input option, or an invalid option value | Give at least one input; see `--help` |
| `token.b64url` FAIL followed by `token.b64.lenient` | A token part uses standard-base64 characters (`+`, `/`) or `=` padding, which RFC 7515 does not allow | The other checks still ran on the decoded token. Read `sig.b64-source`: it says whether the CSP signed it that way or it was converted after signing, which tells you whom to ask for a fix |
| `token.b64url` FAIL with "cannot be decoded" and no other token findings | The token contains characters that are not base64 at all, such as `%` from URL-encoding | Get the token as the CSP issued it |
| `gender.value` WARN | The token's gender is `F`, `M` or another short form, not `female` or `male` | Ask the CSP to send the OIDC values. The XCPD comparison still treats `F` as female and `M` as male |
| `pd.gender.code` WARN | The XCPD body's livingSubjectAdministrativeGender code is not F, M or UN, for example `MALE` | Ask the sender to use the HL7 codes. A spelled-out `MALE` or `FEMALE` is still compared with the token |
| `auth_time.order` WARN | The token says the person authenticated after the token was issued | Check the CSP's clock and how it sets auth_time. Both times come from the token, so `--at` does not affect this |
| `xml.decl` WARN | The capture has two or more `<?xml ...?>` declarations at the top, which is not well-formed XML | The checker removed the extra ones and carried on. Find out whether the sender sent it that way or the capture tool added it; only the first is a sender problem |
| `xml.parse` FAIL | The capture is not well-formed XML for another reason: truncated, an unescaped `&` or `<`, or an undeclared namespace prefix | Take the capture again, or extract the whole SOAP Envelope |
| `pd.vs.token.birthdate` INFO "Not compared" | The token birthdate is not YYYY-MM-DD, which `birthdate.format` already fails | Fix the token's format; the comparison runs again once it is YYYY-MM-DD |
| `aud.case` WARN for `URN:OID:...` | The `urn:oid:` prefix is not lower case. It is still a valid OID URN (RFC 3061, RFC 8141), so this is not a FAIL, but the FHIR oid form the RCE IAS workgroup recommends is lower case | Ask the CSP to emit `urn:oid:` in lower case |
| `address.country` FAIL for `UK` or another two-letter value | country must be an assigned ISO 3166-1 alpha-2 code in upper case (RCE IAS workgroup clarification, October 22, 2026) | Use the assigned code, for example `GB` for the United Kingdom |
| `zsh: command not found: --discovery-file` (or another option), and the report ignores options you typed | A multi-line command was cut short by a blank line or a space after `\` | Re-run it on one line, or paste it again without blank lines |
| `discovery.fetch` FAIL with a DNS error for `id.csp.example` in practice | The offline options are missing, so the checker tried to reach the fictitious practice issuer | Add `--discovery-file disc.json --jwks-file jwks.json` |
| `CryptographyDeprecationWarning: Python 3.8 is no longer supported` | Python 3.8 in the virtual environment | Harmless today; rebuild the virtual environment with Python 3.10 or later |

---

## 9. Command reference

```bash
# help and every option
python3 ias_toolkit/ias_sop_checker.py --help

# self-test (from ias_toolkit/)
python3 test_ias_toolkit.py -v

# practice fixtures
python3 ias_toolkit/make_ias_test_fixtures.py --output-dir practice [--force]

# token: live / offline / payload only
python3 ias_toolkit/ias_sop_checker.py --token-file t.jwt --expected-aud urn:oid:<HCID>
python3 ias_toolkit/ias_sop_checker.py --token-file t.jwt --discovery-file d.json --jwks-file j.json --no-network
python3 ias_toolkit/ias_sop_checker.py --payload claims.json

# captured traffic at capture time
python3 ias_toolkit/ias_sop_checker.py --soap pd.xml dq.xml dr.xml --xcpd-response resp.xml --at <ISO time> --hop qhin-qhin

# rule set
python3 ias_toolkit/ias_sop_checker.py --payload claims.json --bulletin2 off
python3 ias_toolkit/ias_sop_checker.py --payload claims.json --as-of 2026-12-02 --b2-3g-notice 2026-12-01

# output
python3 ias_toolkit/ias_sop_checker.py ... --problems-only --no-manual
python3 ias_toolkit/ias_sop_checker.py ... -v --json-report report.json
python3 ias_toolkit/ias_sop_checker.py --obligations csv > obligations.csv
```
