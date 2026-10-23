# Hand-off brief: IAS token validation in the XDS Toolkit

Written October 23, 2026 and updated the same day for release 1.6.5. This is the starting point for the Java work. Read it together with `MANIFEST.md` and `RUN_GUIDE.md` in this repository. Nothing below has been checked against the XDS Toolkit source yet; section 5 lists what to find out first.

## 1. Goal

Add TEFCA IAS IAL2 Claims Token validation to the XDS Toolkit (`usnistgov/iheos-toolkit2`, release 7.13.0). When the toolkit receives or sends an XCPD, XCA Query or XCA Retrieve request, it should:
- find the IAL2 Claims Token;
- check it as `ias_sop_checker.py` does;
- report the findings in the toolkit's normal validation output.

## 2. Where things live

| What | Where | Role |
|---|---|---|
| Python checker, schemas, fixture generator, tests | `matt-blackmon/ias-toolkit` (private), tag `v1.6.5` | **Reference implementation and source of truth for the rules.** Development continues here. The seven schema files are identical in `v1.6.0` and `v1.6.5`; 1.6.1–1.6.5 changed only the checker, the fixtures and the tests. |
| XDS Toolkit | `usnistgov/iheos-toolkit2`, release 7.13.0 | Upstream, read-only. NIST is retiring its health IT tools; IHE USA is taking the toolkit over. |
| Java work | A fork of `iheos-toolkit2`, on a branch such as `ias-token-validator` cut from 7.13.0 | Where the integration is built. The fork's owner (IHE USA organization or Matt's account) is still to be decided. |

Real tokens and captures can contain PHI. Never commit them to either repository; use the generated fixtures.

## 3. Design agreed so far

1. **One source of rules.** The Java validator loads the seven JSON Schema files from a pinned `ias-toolkit` release, through a git submodule or a copied resource folder with the version recorded. It does not keep its own copy of the rules. When the Python side changes a rule, the toolkit picks it up by moving to the next tag.
2. **Same behaviour, checked by shared test vectors.**
   - `make_ias_test_fixtures.py` generates the inputs.
   - `ias_sop_checker.py --json-report` gives the expected findings for each input.
   - The Java tests assert the same `(check, status)` pairs for the token-scoped checks.
   - Keeping the Python check names (section 4) makes this a direct comparison.
3. **Same rule-set switches.**
   - `--bulletin2 auto|on|off` (default `auto`, which applies the Bulletin from 2026-10-13).
   - `--b2-3g-notice DATE`.
   - `--as-of` and `--at`.
   - The schema layer plan: SOP text versus Bulletin 2. See "How the checker uses the layers" in `MANIFEST.md`.
4. **Same finding model.** Each finding carries `ref`, `check`, `status` (FAIL, PENDING, WARN, PASS, INFO, SKIP, MANUAL), `message`, `why` and `fix`. These map onto whatever the toolkit uses to report validation results.

**Decision open:** port the checks to Java (recommended), or have the toolkit call the Python checker as an external process. Calling Python is faster to wire up, but it adds a Python runtime to every toolkit deployment.

## 4. What to port, in order

Check names are as in `ias_sop_checker.py` 1.6.5. The function is in brackets. Items new since 1.6.0 are marked *(1.6.x)*.

**Stage 1. Token structure and claims.** These need no network access.

| Area | Python checks |
|---|---|
| Token input (RFC 7515 compact form) [`_normalize_token`] | `token.empty`, `token.bearer`, `token.quoted` *(1.6.1)*, `token.whitespace`, `token.jwe`, `token.double-b64`, `token.format`, `token.b64url`, `token.b64.lenient` *(1.6.1)*, `token.unsigned` |
| JOSE header (Table 1) [`_check_header`] | `hdr.alg`, `hdr.kid`, `hdr.typ`, `hdr.crit`, `hdr.x5c`, `hdr.extra` |
| Core claims (Table 2) [`_check_claims`] | `iss`, `sub`, `iat`, `iat.future`, `exp`, `exp.order`, `exp.lifetime`, `exp.expired`, `nbf`, `jti`, `gender`, `gender.value` *(1.6.2)*, `auth_time.age`, `auth_time.order` *(1.6.3)*, `<time claim>.type` and `.units` (now also for auth_time), `csp_issued_identifier` |
| aud (Table 2, footnote 13, Bulletin 2 §5, Oct 22 workgroup) [`_check_aud`] | `aud`, `aud.type`, `aud.form`, `aud.format`, `aud.case`, `aud.whitespace`, `aud.expected` |
| Names and birthdate [`_check_name`, `_check_birthdate`] | `<claim>.type`, `.trim`, `.space`, `.delim`; `birthdate.format`, `.value`, `.partial`, `.future`, `.age` |
| Address and historical_address (Table 3, Bulletin 2 §4) [`_check_address`] | `<label>.street_address`, `.locality`, `.region`, `.postal_code`, `.country`, `.formatted`, `.extra`, `.type`, `.encoding`; `historical_address.form` and `.type` |
| Email and phone (Table 2, Bulletin 2 §3) [`_check_contact`, `_check_contact_b2`] | `email\|phone_number`, `email.addrspec`, `email.format`, `phone_number.e164`, `phone_number.digits`, `email_verified.type`, `email_verified.orphan`, `b2.3b`, `b2.3c`, `b2.3g` |
| Version claim (§4.9(a)(iv), Bulletin 2 §2(a)) | `tefca_ial2claims_version`, `.required`, `.value` |
| Claim names (§4.9(c)) [`_check_claim_names`] | `claim.ns`, `claim.unknown`, `claim.lang` |
| Minimum demographics (§4.4(d)) | `token.min-demographics` |
| Schema cross-check | `schema.idTokenHeader`, `schema.idTokenClaims` and their `.recommended` and `.drift` checks |

**Stage 2. Issuer, keys and signature.**

| Area | Python checks |
|---|---|
| Discovery (§4.3(f)) [`get_discovery`, `_validate_discovery`] | `discovery.fetch`, `.offline`, `.issuer`, `.required`, `.recommended`, `.rs256`, `jwks_uri` |
| JWKS (§4.3(d), §4.9(a)(i)) [`get_jwks`, `_validate_jwks`] | `jwks.fetch`, `jwks.bare`, `jwks.kid`, `jwks.kid.dup`, `jwks.rsa`, `jwks.size`, `jwks.private`, `jwks.use`, `jwks.alg` |
| Signature (§4.9(a)(ii)) [`_verify_signature`] | `sig.verify`, `sig.kid`, `sig.kid-mismatch`, `sig.pss`, `sig.decode` |
| Production and non-production issuers (§4.3(e)) [`_check_issuer_env`] | `issuer.distinct`, `issuer.env`, `issuer.heuristic` |

**Stage 3. Message level (where the toolkit adds most).**

| Area | Python checks |
|---|---|
| SAML attribute carrying the token (§4.9(e)) [`_check_saml`] | `saml.id_token`, `.name`, `.nameformat`, `.values`, `.multi`, `.xsitype`, `.children`; `aud.vs.saml-hcid` |
| XCPD body versus token (§4.4(d)–(e)) [`_check_pd_body`] | `pd.min-demographics`, `pd.vs.token`, `pd.vs.token.<field>` |
| Token in every request type (§4.4(f)) [`coverage`] | `coverage.PD`, `coverage.DQ`, `coverage.DR`, `jti.unique` |

**Out of scope at first:** Facilitated FHIR, UDAP and SSRAA artifacts, unless the toolkit already handles them.

## 5. First tasks for the Java session

Look through 7.13.0 before writing code, and report:

1. **Build basics:** the Java source and target level, the Maven module layout, and how to build and run the tests.
2. **Where SAML is handled:** where the toolkit handles inbound and outbound SAML assertions on XCPD and XCA. This includes `StsSamlValidator` and its `EnhancedKeySelector`, where an earlier key-resolution fix was made. That is where a hook to extract and validate the token belongs.
3. **How validation results are reported:** the classes, the levels, and how results reach the UI and the logs.
4. **Testing:** the existing test frameworks and fixtures.
5. **Dependencies:** choose libraries that work at the toolkit's Java level, bearing in mind the earlier POM audit, which found outdated OpenSAML, xmlsec, Jackson, Axis2 and Spring 4. Candidates to evaluate, not yet decided:
   - for JSON Schema draft 2020-12, the networknt `json-schema-validator`;
   - for JWS/JWK, Nimbus JOSE+JWT.

Then propose where the module sits and a test plan using the shared vectors, before implementing Stage 1.

## 6. Rules to keep in mind

The detail is in the Python checker's docstring and in `RUN_GUIDE.md` section 4.

- **Bulletin 2 v1.0:** issued 2026-10-13; QHINs must comply by 5:00 pm ET, 2026-10-26. It requires `tefca_ial2claims_version` to be "3.0". It allows aud as a string or a one-element array, and historical_address as an object or an array. An unverified email or phone is allowed only beside a verified other one, and only until the RCE gives notice.
- **RCE IAS workgroup, 2026-10-22:**
  - an upper-case `URN:OID:` prefix is a WARN, not a FAIL, and aud is compared by URN-equivalence;
  - country must be an ISO 3166-1 alpha-2 code;
  - region must be the ISO 3166-2 subdivision code without the country prefix;
  - token and refresh-token lifetimes are still undecided.
- **Production decision (v1.4.0):** the version claim "3.0" is required from 2026-10-01.
