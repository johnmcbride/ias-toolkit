#!/usr/bin/env python3
"""
ias_sop_checker.py -- Conformance + troubleshooting checker for the TEFCA
"Exchange Purpose (XP) Implementation SOP: Individual Access Services (IAS)" v3.0
(effective 2026-08-03; source PDF: SOP-IAS-XP-v3_June2026_Clean_-5081.pdf).

WHAT IT CHECKS (machine-testable items)
  §4.1        XP code T-IAS in SAML purposeofuse / FHIR purpose_of_use
  §4.3(d)     CSP JWKS reachable without authentication (jwks_uri)
  §4.3(e)     Distinct prod / non-prod issuer URLs            (enforced 2026-10-01)
  §4.3(f)     OIDC Discovery doc at <iss>/.well-known/openid-configuration
  §4.4(d)     Minimum demographics in the IAS Query (token + XCPD body)
  §4.4(e)     ALL verified token demographics carried in the XCPD request body
  §4.4(f)     Token present in PD, DQ, DR and FHIR authentication requests
  §4.6        XCPD response analysis (Mode 2.1.1 identifier evidence)
  §4.7(a)     Demographics Double-Check *aid* (advisory)       (enforced 2027-01-01)
  §4.9(a)(i)  Bare JWKS (optionally with x5c), key hygiene
  §4.9(a)(ii) RS256 signature -- verified cryptographically against the JWKS
  §4.9(a)(iii-v) Claims: Tables 1/2/3, unverified-claim detection,
              tefca_ial2claims_version, csp_issued_identifier (MAY)
  QHIN Compliance Bulletin No. 2 §2-§5 (from 2026-10-13): version "3.0", email/phone
              verification rules, historical_address arrays, aud one-element arrays
  §4.9(c)     Additional claims namespaced http://rce.sequoiaproject.org/OIDC/claim/
  §4.9(d)/(e) SAML Attribute Name/NameFormat; FHIR tefca_ias.id_token
  §4.6 1.2/2.3 SSRAA discovery (/.well-known/udap?community=...) (enforced 2027-07-01)
  Via §4.2(a) -- QTF v2.1: QTF-501 SAML signature algorithms, QTF-604/605 coded XP
  Via §4.2(b) -- Facilitated FHIR SOP v2.0 + HL7 SSRAA STU1.1: UDAP JWT headers (x5c
              leaf+intermediate, algorithms, signature), Authentication JWT claims,
              hl7-b2b (Table 2), tefca_ias (Table 4) incl. patient_information vs
              IAL2 token, token request/response/error, registration (software
              statement SAN/XP, basic-app certification), UDAP metadata, signed_metadata

QHIN COMPLIANCE BULLETIN No. 2 (v1.5.0)
  TEFCA QHIN Compliance Bulletin No. 2 v1.0, "Interim Technical Direction on IAS Claims
  Token Verification in TEFCA" (Issue Date October 13, 2026; header Effective Date
  October 26, 2026). Its introduction: effective October 13, 2026 QHINs must process IAS
  Claims Tokens under the Bulletin; a QHIN not compliant as of 5:00 pm ET, October 26,
  2026 may face consequences; in effect until further notice. Bulletin §1(b): the SOP is
  read consistently with the Bulletin, and the Bulletin prevails where they conflict.
  --bulletin2 auto (default) applies it when --as-of is on or after 2026-10-13; on / off
  force it. When applied:
    §2(a)  tefca_ial2claims_version SHALL be present with the string value "3.0".
    §3     at least one of email / phone_number present and verified; a claim counts as
           verified unless its *_verified flag is false (§3(e)-(f)). An unverified email
           (email_verified=false) is allowed only with a verified phone_number (§3(b)), and
           vice versa (§3(c)); never both (§3(d)). These §3(b)/(c) permissions are
           temporary (§3(g)): --b2-3g-notice DATE models the RCE notice that ends them,
           after which any unverified email/phone FAILs (IAS §4.9(a)(iii)). An unverified
           value is not an IAL2-verified demographic, so it is not counted for §4.4(d)(viii)
           or expected in the XCPD body (§4.4(e)).
    §4     historical_address: one Address object, or an array of one or more, each per
           Table 3.
    §5     aud: a string, or an array containing exactly one string; the string is the IAS
           Provider HCID as urn:oid:<oid>. Both forms are compared with --expected-aud as
           equivalent (§5(c)).
  Schema layer: tefca-qhin-bulletin-2.schema.json replaces the SOP-text idTokenClaims.

RCE IAS WORKGROUP, OCTOBER 22, 2026 (v1.6.0)
  Slides "Claims Values", "Whose HCID in the aud Claim", "Token Lifetime", "Review of the
  Bulletin". Applied:
    aud    the 'urn:oid:' prefix is case-insensitive (RFC 8141 §3.1; RFC 3061's own example
           is URN:OID:...), so an upper- or mixed-case prefix is a valid OID URN: aud.case is
           now a WARN (it was a FAIL), citing the recommendation that the value comply with
           the FHIR oid data type (lower case). --expected-aud is compared by RFC 8141
           URN-equivalence (prefix case-insensitive, OID exact).
    country  ISO 3166-1 alpha-2, upper case: checked against the 249 assigned codes, so 'UK'
           (use GB), 'XX' and other unassigned pairs now FAIL. IAS Table 3 itself says
           "ISO 3166-2" for country; the workgroup slide clarifies 3166-1 alpha-2.
    region the ISO 3166-2 subdivision part without the country prefix, upper case, no full
           names: already enforced; findings now cite the clarification.
  Recorded, not enforced (no decision yet): recommended lifetimes for the IAL2 Claims
  Token and the CSP refresh token (the token-response check reports a refresh_token and any
  lifetime field), refined aud language, sunset dates for the Bulletin 2 temporary measures.

PRODUCTION DECISION (v1.4.0; supersedes the v1.3.2 baseline note)
  For production, the implementation group decided, keyed to the IAS SOP §4.8 compliance
  date for IAL2 Claims Tokens (October 1, 2026), that tefca_ial2claims_version MUST be
  present with the value "3.0" and that the CSP-issued token carries no unverified data.
  An absent claim is a FAIL (tefca_ial2claims_version.required; PENDING before
  2026-10-01). The SOP-text reading (§4.9(a)(iv): SHOULD; omitted means "1.0") is still
  reported as a separate WARN, and --allow-missing-claims-version restores it for
  analysis of pre-decision tokens. Bulletin 2 §2(a) now states the version requirement.
  Its §3(b)/(c) temporary permissions relax the "no unverified data" part; to keep that
  part, use --b2-3g-notice with a date on or before the evaluation date. Without the
  Bulletin (--bulletin2 off) aud must be one string, historical_address one object and
  the *_verified flags true (SOP-text reading of IAS Table 2).

PRECEDENCE MODEL (v1.3.1)
  Requirements are cumulative where compatible. The IAS SOP v3.0 defines IAS-specific
  content; QTF is inherited via IAS §4.2(a); the Facilitated FHIR SOP and SSRAA via
  §4.2(b). A TEFCA profile may compatibly tighten a base rule (profile-tightened).
  Explicit overrides: IAS footnote 13 (aud = IAS Provider HCID), IAS §4.2(b)
  (FF deadlines superseded for IAS FHIR Endpoints -> July 1, 2027) and, from 2026-10-13,
  QHIN Compliance Bulletin No. 2 §1(b) (the Bulletin prevails over the SOP; §2-§5). Genuine conflicts
  are marked unresolved-conflict and never settled by picking the "stricter" text
  (e.g. hl7-b2b organization_id: FF Table 2 relative form vs SSRAA URI).

TWO AXES FOR SSRAA / FF ARTIFACTS
  Protocol axis: an artifact that is present (token response, metadata, registration,
  JWT) must conform to SSRAA/FF now. Adoption axis: whether an IAS FHIR endpoint must
  support/publish SSRAA at all is date-gated (PENDING before July 1, 2027).
  --ssraa-in-use says whether an OAuth artifact belongs to an SSRAA transaction.

QTF-501 HOP CONTEXT
  --hop qhin-qhin makes QTF-501 algorithm violations a FAIL; participant-qhin reports
  INFO (QTF-501 does not govern that hop); unknown (default) reports WARN.
  Process / contractual items (CSP approval, AAL2, breach steps, ...) are listed
  as MANUAL attestation items with the evidence to request.

INPUTS (combine freely; every input is optional, at least one required)
  --token / --token-file   raw JWT, or a JSON CSP token response containing "id_token"
  --payload FILE...        decoded token payload(s): payload/profile checks only (no signature,
                           discovery, JWKS or current-time expiry)
  --soap FILE...           captured XCPD / XCA DQ / XCA DR requests (raw XML, MTOM,
                           or HTTP captures -- the SOAP Envelope is extracted)
  --xcpd-response FILE     captured PRPA_IN201306UV02 response
  --fhir-auth FILE         UDAP client assertion JWT, token-request form body, or JSON
  --fhir-base URL          FHIR base to probe for SSRAA /.well-known/udap
  --oauth-response FILE    OAuth token response or error response JSON
  --udap-registration FILE UDAP registration request JSON
  --discovery-file / --jwks-file   offline copies (no network needed)

SEVERITY MODEL
  FAIL     MUST / SHALL violated (and in force on --as-of date)
  PENDING  would FAIL, but the §4.8 compliance date has not arrived yet
  WARN     SHOULD violated, probable defect, or interoperability risk
  PASS / INFO / SKIP / MANUAL
  Exit code: 0 = no FAIL, 1 = at least one FAIL, 2 = usage / input error

PHI: token and XCPD demographics are masked in all output unless --show-phi.

Notes on sources
  * Requirement text is from the IAS SOP v3.0. Items that depend on other
    documents (QTF SAML PurposeOfUse structure, the XP code-system OID, the
    Facilitated FHIR tefca_ias object, SSRAA/UDAP metadata) are labelled as such
    and are configurable or WARN-level, because this SOP does not define them.

JSON SCHEMA CROSS-CHECK (v1.2) -- layers loaded from this script's directory
  (or --schema-dir):
    oidc-core-1.0.schema.json                  generic OIDC: REQUIRED defs + *Recommended deltas
    tefca-ias-sop-v3.schema.json               TEFCA MUST layer (profile of the base)
    tefca-ias-sop-v3.recommended.schema.json   TEFCA SHOULD / RECOMMENDED layer (optional file)
    tefca-qhin-bulletin-2.schema.json          QHIN Compliance Bulletin No. 2 claims layer (v1.5.0;
                                               needed for the claims cross-check when the Bulletin applies)
  Every decoded artifact (JOSE header, claims, JWKS, discovery, tefca_ias) is validated
  against all layers. MUST-layer violations are labelled [OIDC base] / [TEFCA profile];
  SHOULD-layer ones [OIDC recommended] / [TEFCA recommended]. Each layer's verdict is
  compared with the hand-written checks at the matching severity (FAIL vs MUST layer,
  WARN vs SHOULD layer); any disagreement is a "drift" WARN.
  The comparison is field-level (top-level member of the artifact).
  --obligations [text|csv] prints the x-obligation / x-source annotation table.

Requires: Python 3.8+, `cryptography` (signature/x5c checks) and `jsonschema>=4.18`
          (schema cross-check); everything else runs on the standard library.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import logging
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False

try:
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import best_match
    from referencing import Registry, Resource

    HAVE_JSONSCHEMA = True
except ImportError:  # pragma: no cover
    HAVE_JSONSCHEMA = False

VERSION = "1.6.0"
SOP_NAME = "Exchange Purpose Implementation SOP: Individual Access Services (IAS) v3.0"
B2_NAME = "TEFCA QHIN Compliance Bulletin No. 2 v1.0 (Interim Technical Direction on IAS Claims Token Verification)"
# Issue Date; the introduction says "Effective October 13, 2026, QHINs must process IAS Claims Tokens under the
# interim technical direction in this Bulletin". The header's "Effective Date: October 26, 2026" matches the
# non-compliance deadline (5:00 pm ET, October 26, 2026).
B2_ISSUED = dt.date(2026, 10, 13)
B2_DEADLINE = "5:00 pm ET, October 26, 2026"

log = logging.getLogger("ias_sop_checker")

# --------------------------------------------------------------------------- #
# SOP constants
# --------------------------------------------------------------------------- #
# §4.8 compliance dates. Key -> (date, label). "sop" = SOP effective date.
COMPLIANCE_DATES: Dict[str, Tuple[dt.date, str]] = {
    "sop": (dt.date(2026, 8, 3), "SOP v3.0 effective date"),
    "4.3e": (dt.date(2026, 10, 1), "§4.8 distinct prod/non-prod issuer URLs"),
    "4.9": (dt.date(2026, 10, 1), "§4.8 IAL2 Claims Tokens + SAML claim updates"),
    "4.7": (dt.date(2027, 1, 1), "§4.8 Demographics Double-Check"),
    "ssraa": (dt.date(2027, 7, 1), "IAS §4.8 Modes 1.2/2.3 SSRAA support (supersedes the Facilitated FHIR SOP "
                                   "§6.2 Q1-2027 date for TEFCA IAS FHIR Endpoints, per IAS §4.2(b))"),
}

ID_TOKEN_ATTR_NAME = "urn:ietf:params:oauth:token-type:id_token"           # §4.9(e)
ID_TOKEN_ATTR_NAMEFORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"  # §4.9(e)
RCE_CLAIM_PREFIX = "http://rce.sequoiaproject.org/OIDC/claim/"             # §4.9(c)
XP_CODE = "T-IAS"                                                          # §4.1
# Not defined in the IAS SOP -- QTF v2.1 (QTF-602..605) via IAS §4.2(a).
POU_ATTR_NAME = "urn:oasis:names:tc:xspa:1.0:subject:purposeofuse"
HCID_ATTR_NAME = "urn:nhin:names:saml:homeCommunityId"
DEFAULT_XP_CODE_SYSTEM = "2.16.840.1.113883.3.7204.1.5.2.1"   # QTF-604 (applies via IAS §4.2(a))
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
HL7_V3_NS = "urn:hl7-org:v3"                    # IHE XUA PurposeOfUse element namespace
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"

OIDC_REGISTERED_CLAIMS = {
    # OIDC Core §2 (ID Token) and §5.1 (Standard Claims) + common JWT claims
    "iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp",
    "at_hash", "c_hash", "sid", "jti", "nbf",
    "name", "given_name", "family_name", "middle_name", "nickname",
    "preferred_username", "profile", "picture", "website", "email",
    "email_verified", "gender", "birthdate", "zoneinfo", "locale",
    "phone_number", "phone_number_verified", "address", "updated_at",
}
SOP_BARE_CLAIMS = {  # claims the SOP itself names without the RCE prefix
    "historical_address", "suffix", "tefca_ial2claims_version", "csp_issued_identifier",
}
OIDC_ADDRESS_MEMBERS = {"formatted", "street_address", "locality", "region", "postal_code", "country"}

# §4.3(b) demographics a CSP must be capable of verifying -> token claim used
CSP_VERIFIABLE = [
    ("First Name", "given_name"), ("Middle Name/Initial", "middle_name"),
    ("Last Name", "family_name"), ("Suffix", "suffix"), ("Date of Birth", "birthdate"),
    ("Street Address", "address.street_address"), ("City", "address.locality"),
    ("State", "address.region"), ("Zip Code", "address.postal_code"),
    ("Email", "email"), ("Mobile Phone", "phone_number"),
    ("State ID/Driver's License", None),
]

# ISO 3166-1 alpha-2: the 249 officially assigned codes (ISO 3166 Maintenance Agency list, as packaged in pycountry
# 26.2.16). IAS Table 3 says country uses "the 2-letter codes defined in ISO 3166-2"; the RCE IAS workgroup
# (October 22, 2026, "Claims Values") clarified: the ISO 3166-1 alpha-2 country code, upper case (e.g. US).
ISO3166_1_ALPHA2 = frozenset("""
    AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY
    BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK
    FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR
    IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK
    ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM
    PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF
    TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
""".split())
# Exceptionally reserved or transitional codes that are not assigned country codes -> the assigned code, if one
ISO3166_NOT_ASSIGNED = {"UK": "GB", "FX": "FR", "EL": "GR", "EU": None, "EZ": None, "UN": None, "SU": None,
                        "AC": "SH", "CP": None, "DG": "IO", "EA": "ES", "IC": "ES", "TA": "SH"}
WG_2026_10_22 = "RCE IAS workgroup (October 22, 2026)"
# ISO 3166-2:US subdivision codes (without the "US-" prefix)
US_REGIONS = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas", "CA": "California",
    "CO": "Colorado", "CT": "Connecticut", "DE": "Delaware", "FL": "Florida", "GA": "Georgia",
    "HI": "Hawaii", "ID": "Idaho", "IL": "Illinois", "IN": "Indiana", "IA": "Iowa",
    "KS": "Kansas", "KY": "Kentucky", "LA": "Louisiana", "ME": "Maine", "MD": "Maryland",
    "MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota", "MS": "Mississippi",
    "MO": "Missouri", "MT": "Montana", "NE": "Nebraska", "NV": "Nevada",
    "NH": "New Hampshire", "NJ": "New Jersey", "NM": "New Mexico", "NY": "New York",
    "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio", "OK": "Oklahoma",
    "OR": "Oregon", "PA": "Pennsylvania", "RI": "Rhode Island", "SC": "South Carolina",
    "SD": "South Dakota", "TN": "Tennessee", "TX": "Texas", "UT": "Utah", "VT": "Vermont",
    "VA": "Virginia", "WA": "Washington", "WV": "West Virginia", "WI": "Wisconsin",
    "WY": "Wyoming", "DC": "District of Columbia", "AS": "American Samoa", "GU": "Guam",
    "MP": "Northern Mariana Islands", "PR": "Puerto Rico",
    "UM": "United States Minor Outlying Islands", "VI": "Virgin Islands, U.S.",
}
US_REGION_BY_NAME = {v.lower(): k for k, v in US_REGIONS.items()}
USPS_MILITARY = {"AA", "AE", "AP"}

OID_URN_RE = re.compile(r"^urn:oid:[0-2](\.(0|[1-9][0-9]*))+$")  # FHIR oid data type form (lower-case prefix)
OID_URN_ANYCASE_RE = re.compile(r"^[uU][rR][nN]:[oO][iI][dD]:[0-2](\.(0|[1-9][0-9]*))+$")  # RFC 3061 + RFC 8141
BARE_OID_RE = re.compile(r"^[0-2](\.[0-9]+)+$")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")

BASE_SCHEMA_ID = "urn:x-oidc:core-1.0:schema"
PROFILE_SCHEMA_ID = "urn:x-tefca-ias-sop:3.0:schema"
REC_SCHEMA_ID = "urn:x-tefca-ias-sop:3.0:recommended"
OAUTH_SCHEMA_ID = "urn:x-oauth2:core:schema"
UDAP_SCHEMA_ID = "urn:x-hl7-udap-security:1.1.0:schema"
FF_SCHEMA_ID = "urn:x-tefca-facilitated-fhir:2.0:schema"
B2_SCHEMA_ID = "urn:x-tefca-qhin-bulletin-2:1.0:schema"
SCHEMA_FILES = {BASE_SCHEMA_ID: "oidc-core-1.0.schema.json", PROFILE_SCHEMA_ID: "tefca-ias-sop-v3.schema.json",
                REC_SCHEMA_ID: "tefca-ias-sop-v3.recommended.schema.json",
                OAUTH_SCHEMA_ID: "oauth2-core.schema.json", UDAP_SCHEMA_ID: "hl7-udap-security-1.1.0.schema.json",
                FF_SCHEMA_ID: "tefca-facilitated-fhir-v2.schema.json", B2_SCHEMA_ID: "tefca-qhin-bulletin-2.schema.json"}
CORE_SCHEMAS = (BASE_SCHEMA_ID, PROFILE_SCHEMA_ID)  # the rest are optional layers
LAYER_NAME = {BASE_SCHEMA_ID: "OIDC base", PROFILE_SCHEMA_ID: "TEFCA IAS MUST", REC_SCHEMA_ID: "TEFCA IAS SHOULD",
              OAUTH_SCHEMA_ID: "OAuth 2.0", UDAP_SCHEMA_ID: "HL7 SSRAA", FF_SCHEMA_ID: "TEFCA Facilitated FHIR",
              B2_SCHEMA_ID: "QHIN Bulletin 2"}
B_, P_, Q_, O_, U_, F_ = (BASE_SCHEMA_ID, PROFILE_SCHEMA_ID, REC_SCHEMA_ID, OAUTH_SCHEMA_ID, UDAP_SCHEMA_ID, FF_SCHEMA_ID)
P2_ = B2_SCHEMA_ID
# artifact -> (MUST layers, SHOULD/RECOMMENDED layers); each layer = (schema id, $def, label). Order = precedence of
# attribution: an error is reported under the FIRST layer that produces it (generic first, profile last).
SCHEMA_PLAN = {
    "idTokenHeader": ([(B_, "joseHeader", "OIDC base"), (P_, "idTokenHeader", "TEFCA IAS")],
                      [(Q_, "idTokenHeader", "TEFCA IAS")]),
    "idTokenClaims": ([(B_, "idTokenClaims", "OIDC base"), (P_, "idTokenClaims", "TEFCA IAS")],
                      [(B_, "idTokenClaimsRecommended", "OIDC"), (Q_, "idTokenClaims", "TEFCA IAS")]),
    "idTokenClaimsStrict": ([(B_, "idTokenClaims", "OIDC base"), (P_, "idTokenClaimsStrict", "TEFCA IAS")],
                            [(B_, "idTokenClaimsRecommended", "OIDC"), (Q_, "idTokenClaims", "TEFCA IAS")]),
    # QHIN Compliance Bulletin No. 2 (v1.5.0): the Bulletin layer replaces the SOP-text claims definition; the
    # SHOULD layer uses only the TEFCA delta, so it adds no SOP-text MUST rules the Bulletin relaxes.
    "idTokenClaimsB2": ([(B_, "idTokenClaims", "OIDC base"), (P2_, "idTokenClaims", "TEFCA IAS + Bulletin 2")],
                        [(B_, "idTokenClaimsRecommended", "OIDC"), (Q_, "idTokenClaimsDelta", "TEFCA IAS")]),
    "idTokenClaimsStrictB2": ([(B_, "idTokenClaims", "OIDC base"), (P2_, "idTokenClaimsStrict", "TEFCA IAS + Bulletin 2")],
                              [(B_, "idTokenClaimsRecommended", "OIDC"), (Q_, "idTokenClaimsDelta", "TEFCA IAS")]),
    "discovery": ([(B_, "discovery", "OIDC base"), (P_, "discovery", "TEFCA IAS")],
                  [(B_, "discoveryRecommended", "OIDC"), (Q_, "discovery", "TEFCA IAS")]),
    "jwks": ([(B_, "publishedJwks", "OIDC base"), (P_, "jwks", "TEFCA IAS")],
             [(B_, "jwksRecommended", "OIDC"), (Q_, "jwks", "TEFCA IAS")]),
    "tefcaIasExtension": ([(F_, "tefcaIasExtension", "Facilitated FHIR"), (P_, "tefcaIasExtension", "TEFCA IAS")], []),
    "hl7-b2b": ([(U_, "b2bExtension", "SSRAA"), (F_, "b2bExtension", "Facilitated FHIR"), (P_, "iasHl7B2b", "TEFCA IAS")], []),
    "udapJwtHeader": ([(U_, "jwtHeader", "SSRAA"), (F_, "jwtHeader", "Facilitated FHIR")],
                      [(U_, "jwtHeaderRecommended", "SSRAA"), (F_, "jwtHeaderRecommended", "Facilitated FHIR")]),
    "authJwtClaims": ([(O_, "clientAssertionClaims", "OAuth 2.0"), (U_, "authenticationJwtClaims", "SSRAA")], []),
    "udapMetadata": ([(U_, "udapMetadata", "SSRAA"), (F_, "udapMetadataIasResponder", "Facilitated FHIR")],
                     [(U_, "udapMetadataRecommended", "SSRAA")]),
    "signedMetadata": ([(U_, "signedMetadataClaims", "SSRAA")], []),
    "softwareStatement": ([(O_, "clientRegistrationRequest", "OAuth 2.0"), (U_, "softwareStatementClaims", "SSRAA")], []),
    "registrationRequest": ([(U_, "registrationRequest", "SSRAA"), (F_, "registrationRequest", "Facilitated FHIR")], []),
    "certificationBase": ([(U_, "certificationJwtClaims", "UDAP C&E")], []),
    "certification": ([(U_, "certificationJwtClaims", "UDAP C&E"), (F_, "certificationJwtClaims", "Facilitated FHIR")], []),
    "tokenResponse": ([(O_, "tokenResponse", "OAuth 2.0"), (U_, "tokenResponse", "SSRAA")],
                      [(O_, "tokenResponseRecommended", "OAuth 2.0"), (F_, "tokenResponseRecommended", "Facilitated FHIR")]),
    "tokenError": ([(O_, "tokenErrorResponse", "OAuth 2.0"), (F_, "tokenErrorResponse", "Facilitated FHIR")], []),
    "tokenRequestCC": ([(O_, "tokenRequest", "OAuth 2.0"), (U_, "tokenRequestClientCredentials", "SSRAA")], []),
    "tokenRequestAC": ([(O_, "tokenRequest", "OAuth 2.0"), (U_, "tokenRequestAuthorizationCode", "SSRAA")], []),
}
# Hand-check name prefixes for non-token artifacts: "<prefix>.<top-level member>[.detail]"
ARTIFACT_PREFIXES = ("b2b", "tefca_ias", "udapjwt", "authjwt", "udapmeta", "sigmeta", "softstmt", "regreq", "cert",
                     "tokresp", "tokerr", "tokreq")
TEFCA_COMMUNITY_URI = "urn:oid:2.16.840.1.113883.3.7204.1.5"          # FF §6.11(1)
BASIC_APP_CERT_URI = "https://rce.sequoiaproject.org/udap/profiles/basic-app-certification"  # FF §6.11(2)-(3)
BASIC_APP_CERT_NAME = "TEFCA Basic App Certification"                   # FF §6.11(6)
XP_CODE_SYSTEM_URN = "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1"         # QTF-604, FF §6.4
JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"   # RFC 7523 §2.2
FF_ALGS = ("RS256", "ES256", "ES384", "RS384")                          # FF §6.10(4)
# hand-written WARN checks that mirror the SHOULD/RECOMMENDED schema layer
REC_CHECK_NAMES = {"tefca_ial2claims_version",
                   "email.format", "phone_number.e164", "discovery.recommended", "discovery.token_endpoint",
                   "jwks.kid"}
REC_CHECK_NAMES |= {"udapjwt.alg", "udapmeta.registration_endpoint_jwt_signing_alg_values_supported",
                    "tokresp.expires_in"}
REC_CHECK_NAMES |= {"email_verified.orphan", "phone_number_verified.orphan"}  # v1.5.0: SHOULD-layer dependentRequired
REC_CHECK_NAMES |= {"aud.case"}  # v1.6.0: FHIR oid lower-case prefix is a SHOULD (RCE IAS workgroup recommendation)
REC_CHECK_SUFFIXES = (".delim", ".space", ".extra", ".formatted", ".postal_code.zip4")


def is_rec_check(name: str) -> bool:
    return name in REC_CHECK_NAMES or name.endswith(REC_CHECK_SUFFIXES)


# Field-level drift: map hand-written check names to the top-level member of the artifact they concern.
HAND_FIELD = {
    "email|phone_number": "<root>", "token.min-demographics": None, "fhir.tefca_ias": "<root>",
    "fhir.id_token": "id_token", "xp.fhir": "purpose_of_use",
    "discovery.rs256": "id_token_signing_alg_values_supported", "discovery.scopes": "scopes_supported",
    "discovery.subject_types": "subject_types_supported", "discovery.token_endpoint": "token_endpoint",
    "jwks_uri": "jwks_uri",
    # v1.5.0: a *_verified flag without its claim is a whole-token (dependentRequired) rule
    "email_verified.orphan": "<root>", "phone_number_verified.orphan": "<root>",
}


def hand_fields(f: Finding) -> List[str]:
    c = f.check
    head = c.split(".", 1)[0]
    if head in ARTIFACT_PREFIXES:
        parts = c.split(".")
        return [parts[1]] if len(parts) > 1 and parts[1] else ["<root>"]
    if c in HAND_FIELD:
        return [HAND_FIELD[c]] if HAND_FIELD[c] else []
    if c in ("discovery.required", "discovery.recommended"):
        return re.findall(r"'([^']+)'", f.message)
    if c == "discovery.types":
        return [f.message.split(" ", 1)[0]]
    if c.startswith("jwks."):
        return ["keys"]
    if c.startswith("hdr."):
        return [c[4:].split(".")[0]]
    if c.startswith("claim."):
        m = re.search(r"'([^']+)'", f.message)
        return [m.group(1)] if m else []
    m = re.match(r"^(address|historical_address)(?:\[\d+\])?\.([A-Za-z_]+)", c)
    if m:
        sub = m.group(2)
        if sub in ("type", "encoding", "shape"):
            return [m.group(1)]
        return [f"{m.group(1)}/{'{names}' if sub == 'extra' else sub}"]
    return [re.split(r"[.\[]", c)[0]]


NESTED_FIELDS = ("address", "historical_address")


def schema_fields(e: Any) -> List[str]:
    if isinstance(e.schema, dict) and isinstance(e.schema.get("x-field"), str):
        return [e.schema["x-field"]]  # cross-field rule that names the member it is reported against (v1.5.0)
    if (e.validator in ("oneOf", "anyOf") and e.context and not list(e.absolute_path)
            and all(c.validator == "required" for c in e.context)):
        return ["<root>"]  # "one of these members is required" (e.g. email|phone_number) is a root-level rule
    if e.validator in ("oneOf", "anyOf") and e.context:  # same branch choice as the error formatter
        informative = [c for c in e.context if c.validator != "type"]
        e = best_match(informative or e.context)
    path = [x for x in e.absolute_path if not isinstance(x, int)]
    req = re.match(r"'(.+?)' is a required property", e.message) if e.validator == "required" else None
    if path and path[0] in NESTED_FIELDS:
        if "propertyNames" in e.schema_path:
            return [f"{path[0]}/{{names}}"]
        if len(path) > 1:
            return [f"{path[0]}/{path[1]}"]
        if req:
            return [f"{path[0]}/{req.group(1)}"]
        return [str(path[0])]
    if path:
        return [str(path[0])]
    if req:
        return [req.group(1)]
    if e.validator in ("unevaluatedProperties", "additionalProperties"):
        return re.findall(r"'([^']+)'", e.message) or ["<root>"]
    return ["<root>"]
# Hand-written checks a JSON Schema cannot express; excluded from schema-vs-checker drift comparison.
NON_SCHEMA_CHECKS = {
    "exp.expired", "exp.lifetime", "exp.order", "iat.future", "nbf", "aud.expected", "jti.unique",
    "birthdate.value", "birthdate.future", "birthdate.age", "unverified.attest", "csp.demographics",
    "discovery.issuer", "discovery.token_endpoint", "jwks.size", "jwks.x5c", "jwks.x5c.validity",
    "jwks.kid.dup", "jwks.rsa", "phone_number.digits",
    # UDAP / OAuth artifacts: cryptographic, cross-document or cross-field rules
    "udapjwt.format", "udapjwt.sig", "udapjwt.chain", "udapjwt.x5c.der", "udapjwt.validity",
    "authjwt.issub", "authjwt.aud.match", "authjwt.exp.lifetime", "authjwt.exp.expired", "authjwt.extensions.grant",
    "b2b.purpose_of_use.multi",
    "udapmeta.community", "sigmeta.alg", "sigmeta.x5c", "sigmeta.iss.base", "sigmeta.iss.san", "sigmeta.sub.eq",
    "sigmeta.exp.lifetime", "sigmeta.endpoint.mismatch", "sigmeta.sig", "sigmeta.format",
    "softstmt.iss.san", "softstmt.iss.xp", "softstmt.sub.eq", "softstmt.aud.match", "softstmt.exp.lifetime",
    "cert.xp.match", "cert.format", "regreq.certifications.basic", "tokresp.refresh_token.grant",
    "tokresp.scope.compare", "tokerr.meaning",
    "cert.exp.expired", "cert.iat.future", "cert.exp.order", "cert.sub.san", "cert.selfsigned",
    # v1.5.0: QHIN Compliance Bulletin No. 2 §3(g) depends on an RCE notice date, not on the token
    "b2.3g",
}
LANG_TAGGED_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)#[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*$")

STATUS_RANK = {"FAIL": 0, "PENDING": 1, "WARN": 2, "MANUAL": 3, "PASS": 4, "INFO": 5, "SKIP": 6}


# --------------------------------------------------------------------------- #
# Small utilities
# --------------------------------------------------------------------------- #
def b64url_decode(seg: str) -> bytes:
    """Strict-ish base64url decode (RFC 7515: no padding expected)."""
    seg = seg.strip()
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def lname(tag: Any) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def nsname(tag: str) -> str:
    return tag[1:].split("}", 1)[0] if tag.startswith("{") else ""


def iter_local(elem: ET.Element, name: str):
    return (e for e in elem.iter() if lname(e.tag) == name)


def children_local(elem: Optional[ET.Element], name: str) -> List[ET.Element]:
    if elem is None:
        return []
    return [c for c in list(elem) if lname(c.tag) == name]


def first_local(elem: Optional[ET.Element], *path: str) -> Optional[ET.Element]:
    cur = elem
    for p in path:
        if cur is None:
            return None
        nxt = children_local(cur, p)
        cur = nxt[0] if nxt else None
    return cur


def text_of(e: Optional[ET.Element]) -> str:
    return "".join(e.itertext()).strip() if e is not None else ""


def norm_text(s: Any) -> str:
    s = str(s or "").casefold()
    s = re.sub(r"[.,'\"`\-]", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def norm_tokens(s: Any) -> List[str]:
    return [t for t in norm_text(s).split(" ") if t]


def digits(s: Any) -> str:
    return re.sub(r"\D", "", str(s or ""))


def urn_equivalent(a: str, b: str) -> bool:
    """RFC 8141 §3.1 URN-equivalence for OID URNs: lower-case the 'urn' scheme and the NID, compare the NSS (the OID)
    exactly (RFC 3061 lexical equivalence). Percent-encoding does not occur in OID URNs."""
    def key(x: str) -> Tuple[str, ...]:
        m = re.match(r"^([A-Za-z]{3}):([^:]+):(.*)$", x.strip())
        return (m.group(1).lower(), m.group(2).lower(), m.group(3)) if m else (x.strip(),)
    return key(a) == key(b)


def short(s: Any, n: int = 120) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 3] + "..."


def utc(ts: float) -> str:
    try:
        return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return f"<unrepresentable {ts}>"


def norm_url(u: str) -> str:
    p = urllib.parse.urlsplit(u.strip())
    return urllib.parse.urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path.rstrip("/"), p.query, ""))


# --------------------------------------------------------------------------- #
# Findings / report model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    ref: str
    check: str
    status: str
    message: str
    artifact: str = ""
    level: str = "MUST"
    evidence: str = ""
    why: str = ""
    fix: str = ""


class Report:
    def __init__(self, as_of: dt.date, show_phi: bool):
        self.findings: List[Finding] = []
        self.as_of = as_of
        self.show_phi = show_phi
        self.artifact = ""
        self.artifact_order: List[str] = []
        self.profile: Dict[str, Any] = {}  # rule set in force (QHIN Compliance Bulletin No. 2), for header / JSON

    def set_artifact(self, name: str) -> None:
        self.artifact = name
        if name not in self.artifact_order:
            self.artifact_order.append(name)

    def add(self, ref: str, check: str, status: str, message: str, *, level: str = "MUST",
            evidence: str = "", why: str = "", fix: str = "", when: str = "sop",
            artifact: Optional[str] = None) -> Finding:
        if status == "FAIL" and when in COMPLIANCE_DATES:
            d, label = COMPLIANCE_DATES[when]
            if self.as_of < d:
                status = "PENDING"
                message = f"{message}  [enforced from {d.isoformat()}: {label}]"
        art = artifact if artifact is not None else self.artifact
        if art and art not in self.artifact_order:
            self.artifact_order.append(art)
        f = Finding(ref, check, status, message, art, level, evidence, why, fix)
        self.findings.append(f)
        log.debug("finding %-7s %-16s %-28s %s", status, ref, check, message)
        return f

    # convenience wrappers
    def ok(self, ref, check, msg, **kw):
        return self.add(ref, check, "PASS", msg, **kw)

    def fail(self, ref, check, msg, **kw):
        return self.add(ref, check, "FAIL", msg, **kw)

    def warn(self, ref, check, msg, **kw):
        kw.setdefault("level", "SHOULD")
        return self.add(ref, check, "WARN", msg, **kw)

    def info(self, ref, check, msg, **kw):
        kw.setdefault("level", "INFO")
        return self.add(ref, check, "INFO", msg, **kw)

    def skip(self, ref, check, msg, **kw):
        kw.setdefault("level", "INFO")
        return self.add(ref, check, "SKIP", msg, **kw)

    def manual(self, ref, check, msg, **kw):
        return self.add(ref, check, "MANUAL", msg, **kw)

    def phi(self, v: Any) -> str:
        """Mask PHI/PII unless --show-phi."""
        if v is None:
            return "<absent>"
        s = v if isinstance(v, str) else json.dumps(v)
        if self.show_phi:
            return repr(s) if isinstance(v, str) else s
        if len(s) <= 2:
            return "*" * len(s)
        return f"'{s[0]}{'*' * min(len(s) - 2, 12)}{s[-1]}' (len={len(s)})"


# --------------------------------------------------------------------------- #
# HTTP layer (stdlib only, verbose diagnostics)
# --------------------------------------------------------------------------- #
@dataclass
class HttpResult:
    url: str
    final_url: str = ""
    status: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str = ""
    hint: str = ""
    elapsed_ms: int = 0


def _diagnose_net_error(reason: Any, url: str) -> str:
    host = urllib.parse.urlsplit(url).hostname or "?"
    if isinstance(reason, ssl.SSLCertVerificationError):
        return (f"TLS certificate verification failed for {host}: {getattr(reason, 'verify_message', reason)}. "
                "Common causes: incomplete chain (server not sending intermediates), hostname not in SAN, "
                "expired cert, or a private CA. Re-run with --insecure ONLY to isolate whether TLS is the "
                "sole problem; validators in production will not skip verification.")
    if isinstance(reason, ssl.SSLError):
        return (f"TLS handshake error with {host}: {reason}. Check TLS version (1.2+), cipher suites, SNI, "
                "or a TLS-intercepting proxy on your network.")
    if isinstance(reason, socket.gaierror):
        return f"DNS resolution failed for '{host}'. Check the issuer/jwks_uri hostname for typos and DNS."
    if isinstance(reason, ConnectionRefusedError):
        return f"Connection refused by {host}. Wrong port, service down, or firewall/ACL."
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return f"Timed out connecting to {host}. Firewall egress rule, IP allow-listing, or slow service."
    return f"Network error contacting {host}: {reason!r}"


def http_get(url: str, timeout: float = 15.0, insecure: bool = False) -> HttpResult:
    """GET with NO credentials (the SOP requires discovery/JWKS to be public)."""
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={
        "Accept": "application/json, application/jwk-set+json;q=0.9, */*;q=0.1",
        "User-Agent": f"ias-sop-checker/{VERSION}",
    })
    t0 = time.monotonic()
    res = HttpResult(url)
    log.debug("HTTP GET %s (timeout=%ss, insecure=%s)", url, timeout, insecure)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            res.final_url = r.geturl()
            res.status = r.status
            res.headers = {k.lower(): v for k, v in r.headers.items()}
            res.body = r.read()
    except urllib.error.HTTPError as e:
        res.final_url = getattr(e, "url", url) or url
        res.status = e.code
        res.headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        try:
            res.body = e.read()
        except Exception:  # noqa: BLE001
            res.body = b""
        res.error = f"HTTP {e.code} {e.reason}"
    except urllib.error.URLError as e:
        res.error = f"{type(e.reason).__name__}: {e.reason}"
        res.hint = _diagnose_net_error(e.reason, url)
    except (socket.timeout, TimeoutError) as e:
        res.error = f"timeout after {timeout}s"
        res.hint = _diagnose_net_error(e, url)
    except Exception as e:  # noqa: BLE001
        res.error = f"{type(e).__name__}: {e}"
        res.hint = _diagnose_net_error(e, url)
    res.elapsed_ms = int((time.monotonic() - t0) * 1000)
    log.debug("HTTP %s -> status=%s final=%s bytes=%d %dms err=%s ctype=%s",
              url, res.status, res.final_url, len(res.body), res.elapsed_ms, res.error or "-",
              res.headers.get("content-type", "-"))
    if res.body:
        log.debug("HTTP body (first 400 bytes): %r", res.body[:400])
    return res


# --------------------------------------------------------------------------- #
# JWS / X.509 helpers for UDAP artifacts (x5c-based keys, not jwks_uri)
# --------------------------------------------------------------------------- #
def decode_jws(tok: str) -> Tuple[dict, dict, bytes, bytes]:
    p = tok.strip().split(".")
    if len(p) != 3:
        raise ValueError(f"expected 3 dot-separated segments, found {len(p)}")
    hdr = json.loads(b64url_decode(p[0]))
    claims = json.loads(b64url_decode(p[1]))
    if not isinstance(hdr, dict) or not isinstance(claims, dict):
        raise ValueError("header or payload is not a JSON object")
    return hdr, claims, f"{p[0]}.{p[1]}".encode("ascii"), b64url_decode(p[2])


def cert_from_x5c(entry: str) -> Any:
    return x509.load_der_x509_certificate(base64.b64decode(entry, validate=True))


def cert_san_uris(cert: Any) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return list(ext.value.get_values_for_type(x509.UniformResourceIdentifier))
    except x509.ExtensionNotFound:
        return []


def verify_jws(alg: str, pub: Any, signing_input: bytes, sig: bytes) -> Tuple[Optional[bool], str]:
    """RS*/PS*/ES* verification with a public key object. (None, reason) when not checkable."""
    if not HAVE_CRYPTO:
        return None, "cryptography not installed"
    hmap = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
    try:
        h = hmap[alg[-3:]]()
        if alg.startswith("RS"):
            pub.verify(sig, signing_input, padding.PKCS1v15(), h)
        elif alg.startswith("PS"):
            pub.verify(sig, signing_input, padding.PSS(mgf=padding.MGF1(h), salt_length=padding.PSS.AUTO), h)
        elif alg.startswith("ES"):
            n = {"256": 32, "384": 48, "512": 66}[alg[-3:]]
            if len(sig) != 2 * n:
                return False, f"ECDSA signature is {len(sig)} bytes; JWS ES{alg[-3:]} needs raw r||s of {2 * n} bytes " \
                              "(a DER-encoded signature here is a common bug)"
            der = asym_utils.encode_dss_signature(int.from_bytes(sig[:n], "big"), int.from_bytes(sig[n:], "big"))
            pub.verify(der, signing_input, ec.ECDSA(h))
        else:
            return None, f"alg {alg!r} not supported by this tool"
        return True, ""
    except (KeyError, IndexError):
        return None, f"alg {alg!r} not supported by this tool"
    except InvalidSignature:
        return False, "signature does not verify with the x5c leaf certificate key"
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


# --------------------------------------------------------------------------- #
# JSON Schema layer (generic OIDC base + TEFCA IAS profile)
# --------------------------------------------------------------------------- #
class SchemaSet:
    """Loads every available schema layer into one registry so cross-file $refs resolve."""

    def __init__(self, schema_dir: str, explicit: bool, rep: Report):
        self.ok = False
        self.docs: Dict[str, dict] = {}
        self.validators: Dict[Tuple[str, str], Any] = {}
        rep.set_artifact("JSON Schema cross-check")
        if not HAVE_JSONSCHEMA:
            rep.skip("schema", "schema.load", "jsonschema/referencing not installed -- schema cross-check skipped.",
                     fix="pip install 'jsonschema>=4.18'")
            return
        missing_optional = []
        for sid, fname in SCHEMA_FILES.items():
            path = f"{schema_dir.rstrip('/')}/{fname}"
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    doc = json.load(fh)
            except OSError:
                if sid not in CORE_SCHEMAS:
                    missing_optional.append(fname)
                    continue
                (rep.fail if explicit else rep.skip)("schema", "schema.load", f"Schema file not found: {path}"
                                                     + ("" if explicit else " -- cross-check skipped (use --schema-dir)."))
                return
            except json.JSONDecodeError as e:
                rep.fail("schema", "schema.load", f"{path} is not valid JSON: {e}")
                return
            if doc.get("$id") != sid:
                rep.fail("schema", "schema.id", f"{path} has $id {doc.get('$id')!r}, expected {sid!r}.")
                return
            try:
                Draft202012Validator.check_schema(doc)
            except Exception as e:  # noqa: BLE001
                rep.fail("schema", "schema.meta", f"{path} is not a valid 2020-12 schema: {short(e, 200)}")
                return
            self.docs[sid] = doc
            log.debug("Loaded schema %s from %s", sid, path)
        self.registry = Registry().with_resources([(sid, Resource.from_contents(d)) for sid, d in self.docs.items()])
        self.ok = True
        if missing_optional:
            rep.info("schema", "schema.load", f"Optional layer file(s) not found: {missing_optional} -- those layers "
                     "are skipped.")
        rep.info("schema", "schema.load", f"Loaded schema layers: {', '.join(LAYER_NAME[s] for s in self.docs)} "
                 f"from {schema_dir}")

    def has(self, sid: str) -> bool:
        return sid in self.docs

    def errors(self, schema_id: str, defname: str, instance: Any) -> Optional[List[Any]]:
        if schema_id not in self.docs:
            return None
        key = (schema_id, defname)
        if key not in self.validators:
            self.validators[key] = Draft202012Validator({"$ref": f"{schema_id}#/$defs/{defname}"},
                                                        registry=self.registry)
        return sorted(self.validators[key].iter_errors(instance), key=lambda e: list(e.absolute_path))


# --------------------------------------------------------------------------- #
# Core checker
# --------------------------------------------------------------------------- #
class IasChecker:
    def __init__(self, args: argparse.Namespace, rep: Report):
        self.a = args
        self.R = rep
        self.now = args.at.timestamp() if args.at else time.time()
        self.tokens: Dict[str, Dict[str, Any]] = {}      # sha256 -> info
        self.token_order: List[str] = []
        self.jti_seen: Dict[str, str] = {}               # jti -> sha
        self.discovery_cache: Dict[str, Optional[dict]] = {}
        self.jwks_cache: Dict[str, Optional[dict]] = {}
        self.msg_coverage: Dict[str, List[Tuple[str, bool]]] = {"PD": [], "DQ": [], "DR": [], "FHIR": []}
        self.expected_aud = self._norm_expected_aud(args.expected_aud)
        self._last_saml_ok = False
        self.schemas: Optional[SchemaSet] = None
        self.saw_udap = False  # set when a UDAP token request / registration / metadata is processed
        self.payload_mode = False  # True while checking a decoded payload (--payload)
        # QHIN Compliance Bulletin No. 2 (v1.5.0)
        mode = getattr(args, "bulletin2", "auto")
        self.b2 = mode == "on" or (mode == "auto" and rep.as_of >= B2_ISSUED)
        notice = getattr(args, "b2_3g_notice", None)
        self.b2_3g = bool(self.b2 and notice and rep.as_of >= notice)
        if self.b2:
            why = "--bulletin2 on" if mode == "on" else f"evaluation date {rep.as_of.isoformat()} >= issue date"
            rep.profile = {"bulletin2": True, "basis": why, "issued": B2_ISSUED.isoformat(),
                           "qhin_deadline": B2_DEADLINE,
                           "b2_3g_notice": notice.isoformat() if notice else None,
                           "temporary_permissions_3b_3c": "ended" if self.b2_3g else "in effect"}
        else:
            why = ("--bulletin2 off" if mode == "off"
                   else f"evaluation date {rep.as_of.isoformat()} is before the issue date {B2_ISSUED.isoformat()}")
            rep.profile = {"bulletin2": False, "basis": why}

    def _b2_contact(self, c: dict) -> Dict[str, bool]:
        """Verification status of email / phone_number. QHIN Compliance Bulletin No. 2 §3(e)-(f): a claim with no
        *_verified flag is treated as verified; false marks it unverified. A non-boolean flag shows neither."""
        out: Dict[str, bool] = {}
        for base, flag, key in (("email", "email_verified", "em"), ("phone_number", "phone_number_verified", "ph")):
            v = c.get(base)
            has = isinstance(v, str) and v.strip() != ""
            fv = c.get(flag)
            out[f"has_{key}"] = has
            out[f"{key}_ok"] = has and (flag not in c or fv is True)
            out[f"{key}_unv"] = has and fv is False
        return out

    # ------------------------------------------------------------------ utils
    @staticmethod
    def _norm_expected_aud(v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        v = v.strip()
        return v if v.lower().startswith("urn:oid:") else f"urn:oid:{v}"

    def _load_json_file(self, path: str, what: str) -> Optional[Any]:
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as e:
            self.R.fail("input", f"{what}.read", f"Cannot read {what} file {path}: {e}")
            return None
        try:
            return json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            self.R.fail("input", f"{what}.json", f"{what} file {path} is not valid JSON: {e}",
                        evidence=short(raw[:200]))
            return None

    def ssraa_in_use(self) -> str:
        """Protocol axis: is this an SSRAA (UDAP) transaction? Explicit flag wins; otherwise inferred from inputs."""
        if self.a.ssraa_in_use != "auto":
            return self.a.ssraa_in_use
        return "yes" if self.saw_udap else "unknown"

    # =================================================================== #
    # SCHEMA cross-check
    # =================================================================== #
    def _fmt_schema_err(self, e: Any, phi: bool) -> str:
        if isinstance(e.schema, dict) and isinstance(e.schema.get("x-field"), str):  # named cross-field rule
            where = "/".join(map(str, e.absolute_path)) or "<root>"
            return f"{where}: fails {e.schema.get('x-source', 'cross-field rule')} -- " \
                   f"{short(e.schema.get('description', e.validator), 160)}"
        if e.validator in ("oneOf", "anyOf") and e.context:
            informative = [c for c in e.context if c.validator != "type"]  # skip "wrong branch" type errors
            e = best_match(informative or e.context)
        path = "/".join(map(str, e.absolute_path)) or "<root>"
        if not phi or self.R.show_phi or e.validator in ("required", "unevaluatedProperties", "const",
                                                          "additionalProperties", "dependentRequired"):
            msg = e.message
        else:  # don't echo PHI-bearing instance values
            msg = f"fails '{e.validator}' (expected {short(json.dumps(e.validator_value, ensure_ascii=False), 80)})"
        return f"{path}: {short(msg, 160)}"

    def _schema_check(self, plan: str, instance: Any, scope: List[Finding], label: str,
                      phi: bool = False, extra_hand: Tuple[str, ...] = (), name: Optional[str] = None) -> None:
        """Validate one artifact against its SCHEMA_PLAN layers and compare with the hand-written checks.
        name: the check-name stem (default: the plan), so a check keeps its name when the rule set changes."""
        if not (self.schemas and self.schemas.ok) or plan not in SCHEMA_PLAN:
            return
        S = self.schemas
        must_layers, rec_layers = SCHEMA_PLAN[plan]
        stem = name or plan
        missing = sorted({sid for sid, _, _ in must_layers if sid not in CORE_SCHEMAS and not S.has(sid)})
        if missing:
            self.R.warn("schema", f"schema.{stem}", f"{label}: schema cross-check skipped -- layer file(s) "
                        f"{[SCHEMA_FILES[s] for s in missing]} not found, and the rule set in force needs them.",
                        fix="Keep every schema file next to ias_sop_checker.py, or pass --schema-dir.")
            return

        def key(e):
            return (tuple(e.absolute_path), e.message)

        def run(layers, seen):
            out = []
            used = []
            for sid, dname, tag in layers:
                errs = S.errors(sid, dname, instance)
                if errs is None:
                    continue
                used.append(f"{LAYER_NAME[sid]}#/$defs/{dname}")
                for e in errs:
                    if key(e) not in seen:
                        seen.add(key(e))
                        out.append((tag, e))
            return out, used
        seen: set = set()
        must, used = run(must_layers, seen)
        if not used:
            return
        if self.a.allow_missing_claims_version:  # deliberate opt-out: the SOP SHOULD is judged in the rec layer
            waived = [(t, e) for t, e in must if e.validator == "required"
                      and "'tefca_ial2claims_version'" in e.message]
            for _, e in waived:
                seen.discard(key(e))
            must = [x for x in must if x not in waived]
        lines = [f"[{tag}] {self._fmt_schema_err(e, phi)}" for tag, e in must]
        hand = [f for f in scope if f.check not in NON_SCHEMA_CHECKS and
                (not f.check.startswith("claim.") or extra_hand) and
                (f.status in ("FAIL", "PENDING") or (f.status == "WARN" and f.check.startswith(extra_hand)))]
        by_tag: Dict[str, int] = {}
        for tag, _ in must:
            by_tag[tag] = by_tag.get(tag, 0) + 1
        summary = ", ".join(f"{n} {t}" for t, n in by_tag.items()) + " violation(s)"
        if must and must[0][0] == "OIDC base":
            summary += " -- OIDC-base violations mean the artifact is not even generic-OIDC conformant"
        self._compare_layer(f"schema.{stem}", label, "MUST layer", " + ".join(used), lines, hand, summary,
                            [e for _, e in must])
        if not rec_layers:
            return
        must_fields = {x for _, e in must for x in schema_fields(e)}
        rec, rused = run(rec_layers, set(seen))
        if not rused:
            return
        rec = [(t, e) for t, e in rec if not set(schema_fields(e)) & must_fields]
        rlines = [f"[{tag} recommended] {self._fmt_schema_err(e, phi)}" for tag, e in rec]
        rhand = [f for f in scope if f.status == "WARN" and is_rec_check(f.check)
                 and not set(hand_fields(f)) & must_fields]
        rby: Dict[str, int] = {}
        for tag, _ in rec:
            rby[tag] = rby.get(tag, 0) + 1
        self._compare_layer(f"schema.{stem}.recommended", label, "SHOULD/RECOMMENDED layer", " + ".join(rused),
                            rlines, rhand, ", ".join(f"{n} {t}-recommended" for t, n in rby.items()) + " item(s) not met",
                            [e for _, e in rec])

    def _compare_layer(self, chk: str, label: str, layer: str, target: str, lines: List[str],
                       hand: List[Finding], summary: str, errs: List[Any]) -> None:
        """Field-level comparison: which top-level members does each side flag?"""
        R = self.R
        sf = {x for e in errs for x in schema_fields(e)}
        hf = {x for f in hand for x in hand_fields(f)}
        only_schema, only_hand = sorted(sf - hf), sorted(hf - sf)
        if not sf and not hf:
            R.ok("schema", chk, f"{label}: {layer} valid; agrees with the checker", level="INFO")
            return
        if not only_schema and not only_hand:
            R.info("schema", chk, f"{label}: {layer} confirms the checker field-by-field ({', '.join(sorted(sf))}) "
                   f"-- {summary}.", evidence=" | ".join(lines))
            return
        parts = []
        if only_schema:
            parts.append(f"schema flags {only_schema} but the checker does not")
        if only_hand:
            parts.append(f"checker flags {only_hand} but the schema accepts them")
        msg = f"{label}: {layer} ({target}) DRIFT -- " + "; ".join(parts) + "."
        fix = ("Add the missing check to ias_sop_checker.py, or tighten/relax the schema; if a rule is not "
               "schema-expressible, add its check to NON_SCHEMA_CHECKS.")
        if self.a.allow_http:
            R.info("schema", f"{chk}.drift", msg + " (--allow-http in effect: https-only schema rules are "
                   "expected to disagree.)", evidence=" | ".join(lines))
        else:
            R.warn("schema", f"{chk}.drift", msg, evidence=" | ".join(lines), fix=fix)

    # =================================================================== #
    # TOKEN
    # =================================================================== #
    def process_token(self, raw: Any, origin: str) -> Optional[Dict[str, Any]]:
        """Run all §4.9 token checks once per distinct token; return claims."""
        R = self.R
        tok = self._normalize_token(raw, origin)
        if tok is None:
            return None
        sha = hashlib.sha256(tok.encode()).hexdigest()
        if sha in self.tokens:
            info = self.tokens[sha]
            info["seen_in"].append(origin)
            R.info("4.9", "token.dedupe", f"Same token as {info['label']} -- full checks reported there.")
            return info["claims"]
        label = f"IAL2 token #{len(self.tokens) + 1}"
        art = f"{label} (first seen in {origin})"
        prev_art = R.artifact
        R.set_artifact(art)
        info: Dict[str, Any] = {"label": label, "seen_in": [origin], "claims": None, "header": None}
        self.tokens[sha] = info
        self.token_order.append(sha)
        try:
            p0, p1, p2 = tok.split(".")
            hdr = self._decode_segment(p0, "header")
            claims = self._decode_segment(p1, "payload")
            if hdr is None or claims is None:
                return None
            info["header"], info["claims"] = hdr, claims
            log.debug("Decoded JOSE header: %s", json.dumps(hdr))
            log.debug("Decoded claims (keys): %s", sorted(claims.keys()))
            if self.a.dump_token:
                masked = {k: (v if k in ("iss", "aud", "iat", "exp", "nbf", "jti", "tefca_ial2claims_version",
                                         "email_verified", "phone_number_verified") else R.phi(v))
                          for k, v in claims.items()}
                R.info("4.9", "token.dump", "Decoded token",
                       evidence=f"header={json.dumps(hdr)} claims={json.dumps(masked, default=str)}")
            n0 = len(R.findings)
            self._check_header(hdr, p2)
            self._schema_check("idTokenHeader", hdr, R.findings[n0:], "ID token JOSE header")
            n0 = len(R.findings)
            self._check_claims(claims)
            self._claims_schema_check(claims, R.findings[n0:])
            iss = claims.get("iss") if isinstance(claims.get("iss"), str) else None
            if iss:
                self._check_issuer_env(iss)
                self.get_discovery(iss)  # always validate discovery (also when --jwks-file is given)
                self._verify_signature(tok, hdr, iss)
            else:
                R.skip("4.9(a)(ii)", "sig.verify", "Signature not verified -- no usable 'iss' to locate JWKS.")
            return claims
        finally:
            R.artifact = prev_art

    def _claims_schema_check(self, claims: dict, scope: List[Finding]) -> None:
        """Cross-check the claims with the rule set in force: the SOP-text layer, or (from 2026-10-13, or with
        --bulletin2 on) the QHIN Compliance Bulletin No. 2 layer. Check names stay schema.idTokenClaims[Strict]."""
        strict = bool(self.a.schema_strict)
        stem = "idTokenClaimsStrict" if strict else "idTokenClaims"
        label = "ID token claims" + (" (strict)" if strict else "") + (" [IAS SOP v3.0 + QHIN Bulletin 2]" if self.b2
                                                                       else " [IAS SOP v3.0 text]")
        self._schema_check(stem + ("B2" if self.b2 else ""), claims, scope, label, phi=True,
                           extra_hand=("claim.",) if strict else (), name=stem)

    def process_payload(self, path: str) -> None:
        """Decoded-claims mode (--payload): payload schema/profile checks only, as a JSON payload schema would do.
        Accepts a bare claims object or {"header": {...}, "payload": {...}}."""
        R = self.R
        R.set_artifact(f"Decoded payload {path}")
        obj = self._load_json_file(path, "payload")
        if obj is None:
            return
        hdr = None
        if isinstance(obj, dict) and isinstance(obj.get("payload"), dict):
            hdr = obj.get("header") if isinstance(obj.get("header"), dict) else None
            obj = obj["payload"]
        if not isinstance(obj, dict):
            R.fail("input", "payload.object", "Payload file is not a JSON object of claims.")
            return
        R.info("4.9", "payload.mode", "Payload-only mode: claim structure and IAS profile rules are checked. Not "
               "evaluated: signature, kid-to-JWKS resolution, discovery and issuer equality, jwks_uri, and expiry "
               "against the current time. Use --token-file for those.")
        self.payload_mode = True
        try:
            if hdr is not None:
                n0 = len(R.findings)
                self._check_header(hdr, "")
                self._schema_check("idTokenHeader", hdr, R.findings[n0:], "ID token JOSE header")
            n0 = len(R.findings)
            self._check_claims(obj)
            self._claims_schema_check(obj, R.findings[n0:])
        finally:
            self.payload_mode = False

    def _normalize_token(self, raw: Any, origin: str) -> Optional[str]:
        R = self.R
        art = f"token input ({origin})"
        if raw is None or not str(raw).strip():
            R.fail("4.9(d)", "token.empty", "Token value is empty.", artifact=art,
                   fix="The CSP-issued ID token must be relayed verbatim in every IAS request.")
            return None
        t = str(raw).strip()
        if t.lower().startswith("bearer "):
            R.warn("4.9(e)", "token.bearer", "Token value carries an HTTP 'Bearer ' prefix.", artifact=art,
                   fix="Relay only the compact JWS; 'Bearer' belongs in an Authorization header, not in "
                       "the SAML AttributeValue or tefca_ias.id_token.")
            t = t[7:].strip()
        if re.search(r"\s", t):
            R.warn("4.9(e)", "token.whitespace", "Token contains embedded whitespace / line breaks.",
                   artifact=art, why="A compact JWS contains no whitespace. Pretty-printers and XML "
                   "line-wrapping corrupt it; many validators then fail parsing or signature checks.",
                   fix="Write the token as one unbroken string in the AttributeValue / JSON field "
                       "(disable XML pretty-printing for that element).")
            t = re.sub(r"\s+", "", t)
        parts = t.split(".")
        if len(parts) == 5:
            R.fail("4.9(a)(ii)", "token.jwe", "Token is a JWE (5 segments) -- encrypted, not a signed JWS.",
                   artifact=art, fix="The SOP requires an RS256-signed ID token. Ask the CSP to disable "
                   "id_token_encrypted_response_alg for this client, or relay the decrypted inner JWS.")
            return None
        if len(parts) != 3:
            try:
                dec = base64.b64decode(t + "=" * (-len(t) % 4), validate=False)
            except (binascii.Error, ValueError):
                dec = b""
            if dec.startswith(b"eyJ") and dec.count(b".") == 2:
                R.fail("4.9(e)", "token.double-b64", "Token was base64-encoded a second time "
                       "(decoding the value yields a JWT).", artifact=art,
                       fix="Insert the JWT text as-is. Do not base64-encode it (xs:base64Binary typing "
                           "or a generic 'encode attribute' helper is the usual cause).")
                t = dec.decode("ascii", "replace").strip()
                parts = t.split(".")
            else:
                R.fail("4.9(a)", "token.format", f"Not a compact JWS: expected 3 dot-separated "
                       f"segments, found {len(parts)}.", artifact=art,
                       evidence=f"value starts with {short(t, 40)!r}",
                       fix="Confirm you are relaying the OIDC id_token (not the access_token, a "
                           "refresh token, or an opaque reference token).")
                return None
        for i, seg in enumerate(parts):
            if not B64URL_RE.match(seg):
                bad = sorted(set(re.sub(r"[A-Za-z0-9_-]", "", seg)))
                R.fail("4.9(a)", "token.b64url", f"Segment {i} is not base64url (found {''.join(bad)!r}).",
                       artifact=art, why="RFC 7515 requires unpadded base64url ('-' and '_', no '=').",
                       fix="Something converted the token to standard base64 or added padding. "
                           "Relay the CSP's original string.")
                return None
        if parts[2] == "":
            R.fail("4.9(a)(ii)", "token.unsigned", "Token has an empty signature segment (unsigned).",
                   artifact=art, fix="Only RS256-signed tokens are acceptable.")
            return None
        return t

    def _decode_segment(self, seg: str, which: str) -> Optional[dict]:
        try:
            raw = b64url_decode(seg)
        except (binascii.Error, ValueError) as e:
            self.R.fail("4.9(a)", f"token.{which}.b64", f"JWT {which} is not decodable base64url: {e}")
            return None
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            self.R.fail("4.9(a)", f"token.{which}.json", f"JWT {which} is not UTF-8 JSON: {e}",
                        evidence=short(raw[:80]))
            return None
        if not isinstance(obj, dict):
            self.R.fail("4.9(a)", f"token.{which}.object", f"JWT {which} is JSON but not an object.")
            return None
        return obj

    # ---------------------------------------------------------- Table 1
    def _check_header(self, hdr: dict, sig_seg: str) -> None:
        R, ref = self.R, "4.9 Table 1"
        alg = hdr.get("alg")
        if alg == "RS256":
            R.ok(ref, "hdr.alg", "alg = RS256", when="4.9")
        elif alg is None:
            R.fail(ref, "hdr.alg", "JOSE header has no 'alg'.", when="4.9")
        elif str(alg).lower() == "none":
            R.fail(ref, "hdr.alg", "alg = none (unsigned token).", when="4.9",
                   fix="Reject. Only RS256 signed tokens are permitted (§4.9(a)(ii)).")
        elif str(alg).upper() == "RS256":
            R.fail(ref, "hdr.alg", f"alg = {alg!r}: JOSE values are case-sensitive; must be exactly 'RS256'.",
                   when="4.9")
        else:
            R.fail(ref, "hdr.alg", f"alg = {alg!r}; SOP hardcodes 'RS256' (§4.9(a)(ii)).", when="4.9",
                   fix="Set the CSP client's id_token_signed_response_alg to RS256. Note PS256 is also "
                       "RSA but uses PSS padding and is NOT acceptable; ES256 requires an EC key.")
        kid = hdr.get("kid")
        if isinstance(kid, str) and kid.strip():
            R.ok(ref, "hdr.kid", f"kid present ({kid!r})", when="4.9")
        else:
            R.fail(ref, "hdr.kid", "kid missing or empty.", when="4.9",
                   fix="CSP must set 'kid' so validators can select the key from the JWKS.")
        typ = hdr.get("typ")
        if typ == "JWT":
            R.ok(ref, "hdr.typ", "typ = JWT", when="4.9")
        elif typ is None:
            R.fail(ref, "hdr.typ", "typ missing; SOP hardcodes 'JWT'.", when="4.9",
                   fix="Many OIDC providers omit typ by default. Ask the CSP to emit typ=JWT for "
                       "TEFCA clients.")
        else:
            R.fail(ref, "hdr.typ", f"typ = {typ!r}; SOP hardcodes exactly 'JWT'.", when="4.9",
                   fix="Values such as 'jwt', 'id_token+jwt', or 'at+jwt' do not satisfy Table 1.")
        for k in ("jku", "x5u"):
            if k in hdr:
                R.info(ref, f"hdr.{k}", f"Header carries '{k}' ({short(hdr[k], 80)}); validators must use "
                       "jwks_uri from discovery (Table 2 'iss'), never a header-supplied URL.")
        if "x5c" in hdr:
            R.info(ref, "hdr.x5c", "Header carries x5c; key selection should still use kid + JWKS.")
        if "crit" in hdr:
            R.warn(ref, "hdr.crit", f"Header declares crit={hdr['crit']}; validators that don't understand "
                   "these extensions MUST reject the token (RFC 7515 §4.1.11).")
        extra = set(hdr) - {"alg", "kid", "typ", "jku", "x5u", "x5c", "x5t", "x5t#S256", "cty", "crit"}
        if extra:
            R.info(ref, "hdr.extra", f"Additional header parameters: {sorted(extra)}")

    # ---------------------------------------------------------- Table 2/3
    def _numeric_date(self, claims: dict, name: str, ref: str) -> Optional[float]:
        R = self.R
        v = claims.get(name)
        if v is None:
            return None
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            if isinstance(v, str) and v.strip().isdigit():
                R.fail(ref, f"{name}.type", f"{name} is a JSON string ({v!r}); NumericDate must be a "
                       "JSON number.", when="4.9", fix="Emit seconds-since-epoch as a number.")
                return float(v)
            R.fail(ref, f"{name}.type", f"{name} is not a NumericDate (got {type(v).__name__}).", when="4.9")
            return None
        if v > 1e11:
            R.fail(ref, f"{name}.units", f"{name}={v} looks like MILLISECONDS ({utc(v / 1000)} if /1000).",
                   when="4.9", fix="NumericDate is whole seconds since the epoch (RFC 7519 §2).")
            return float(v) / 1000
        return float(v)

    def _check_claims(self, c: dict) -> None:
        R = self.R
        t2, w = "4.9 Table 2", "4.9"
        skew, now = self.a.clock_skew, self.now

        # -- iss
        iss = c.get("iss")
        if not isinstance(iss, str) or not iss:
            R.fail(t2, "iss", "iss missing or not a string.", when=w)
        else:
            p = urllib.parse.urlsplit(iss)
            if p.scheme == "https" and p.netloc and not p.query and not p.fragment:
                R.ok(t2, "iss", f"iss is an HTTPS URL without query/fragment ({iss})", when=w)
            elif p.scheme == "http" and self.a.allow_http:
                R.warn(t2, "iss", f"iss uses http:// ({iss}) -- tolerated by --allow-http (lab only).")
            else:
                R.fail(t2, "iss", f"iss {iss!r} is not an HTTPS URL without query/fragment.", when=w,
                       fix="Issuer must be the https base URL used for OIDC Discovery "
                           "(OIDC Core §2, Discovery §2).")
        # -- sub (required by OIDC Core even though Table 2 omits it)
        sub = c.get("sub")
        if isinstance(sub, str) and sub and len(sub) <= 255:
            R.ok("4.9(a)(iii)", "sub", "sub present (OIDC Core required claim)", when=w)
        else:
            R.fail("4.9(a)(iii)", "sub", "sub missing/empty/>255 chars -- required by OIDC Core §2 "
                   "('in addition to all other required OIDC Core claims').", when=w)
        # -- aud
        self._check_aud(c.get("aud"))
        # -- times
        iat = self._numeric_date(c, "iat", t2)
        exp = self._numeric_date(c, "exp", t2)
        nbf = self._numeric_date(c, "nbf", t2)
        if iat is None and "iat" not in c:
            R.fail(t2, "iat", "iat missing.", when=w)
        elif iat is not None:
            if iat > now + skew:
                R.fail(t2, "iat.future", f"iat {utc(iat)} is in the future (now {utc(now)}, skew {skew}s).",
                       when=w, fix="CSP clock is ahead, or --at is earlier than the capture time.")
            else:
                R.ok(t2, "iat", f"iat {utc(iat)}", when=w)
        if exp is None and "exp" not in c:
            R.fail(t2, "exp", "exp missing.", when=w)
        elif exp is not None:
            if iat is not None:
                life = exp - iat
                if life <= 0:
                    R.fail(t2, "exp.order", f"exp ({utc(exp)}) is not after iat ({utc(iat)}).", when=w)
                elif life > self.a.max_lifetime:
                    R.warn(t2, "exp.lifetime", f"Token lifetime {int(life)}s exceeds the configured "
                           f"short-lived threshold ({self.a.max_lifetime}s).",
                           why="Table 2: exp 'appropriately set based on the system requirements for a short-lived "
                               "token'. Neither the SOP nor OIDC / OAuth 2.0 sets a number for the ID Token (RFC 6749 "
                               "§4.1.2 recommends a 10-minute maximum for authorization codes, a different artifact). "
                               f"Recommended lifetimes were on the agenda of the {WG_2026_10_22}, with no number set. "
                               "Threshold is --max-lifetime (default 3600 s).")
                else:
                    R.ok(t2, "exp.lifetime", f"lifetime {int(life)}s (<= {self.a.max_lifetime}s)", when=w)
            if now > exp + skew:
                msg = f"Token expired at {utc(exp)} (evaluation time {utc(now)})."
                if self.payload_mode:
                    R.info(t2, "exp.expired", msg + " Not evaluated in payload-only mode.")
                elif self.a.ignore_expiry:
                    R.info(t2, "exp.expired", msg + " Ignored (--ignore-expiry).")
                else:
                    R.fail(t2, "exp.expired", msg, when=w,
                           fix="For a captured artifact use --at <capture time> or --ignore-expiry. In live "
                               "traffic: the IAS Provider is reusing a stale token -- re-authenticate with "
                               "the CSP and obtain a fresh token before querying.")
            else:
                R.ok(t2, "exp.valid", f"not expired (exp {utc(exp)})", when=w)
        if nbf is not None and nbf > now + skew:
            R.fail(t2, "nbf", f"nbf {utc(nbf)} is in the future.", when=w)
        # -- jti
        jti = c.get("jti")
        if isinstance(jti, str) and jti.strip():
            R.ok(t2, "jti", "jti present", when=w)
        else:
            R.fail(t2, "jti", "jti missing or empty.", when=w,
                   fix="CSP must emit a unique identifier (e.g., UUIDv4) per token.")

        # -- names
        for claim, label in (("given_name", "First Name"), ("family_name", "Last Name")):
            self._check_name(c, claim, label, required=True)
        for claim in ("middle_name", "suffix"):
            if claim in c:
                self._check_name(c, claim, claim, required=False)
        # -- birthdate
        self._check_birthdate(c.get("birthdate"))
        # -- address
        if "address" not in c:
            R.fail(t2, "address", "address missing (current verified address is required).", when=w)
        else:
            self._check_address(c["address"], "address")
        if "historical_address" in c:
            ha = c["historical_address"]
            if isinstance(ha, list) and self.b2:
                b4 = "B2 §4(a)"
                if not ha:
                    R.fail(b4, "historical_address.type", "historical_address is an empty array; QHIN Compliance "
                           "Bulletin No. 2 §4(a) allows an Address object or an array containing ONE OR MORE Address "
                           "objects.", when=w, fix="Omit historical_address when the CSP verified no historical "
                           "address.")
                else:
                    R.info(b4, "historical_address.form", f"historical_address is an array of {len(ha)} Address "
                           "object(s) (QHIN Compliance Bulletin No. 2 §4(a)); each element is checked against IAS "
                           "Table 3 (§4(b)).")
                    for i, h in enumerate(ha):
                        self._check_address(h, f"historical_address[{i}]")
            elif isinstance(ha, list):
                R.fail(t2, "historical_address.type", f"historical_address, when present, MUST use the IAS address-object "
                       f"format; it is an array of {len(ha)}. Arrays are not valid under the SOP-text reading.", when=w,
                       why="Table 2: historical_address uses 'the same format as for address', and Table 2/3 define "
                           "address as a single JSON object. QHIN Compliance Bulletin No. 2 §4(a) accepts arrays from "
                           f"{B2_ISSUED.isoformat()}; this run does not apply the Bulletin ({self.R.profile.get('basis')}).",
                       fix="Emit one historical address as a JSON object with street_address, locality, region, "
                           "postal_code and country, or evaluate under the Bulletin (--bulletin2 on / auto).")
                R.info(t2, "historical_address.elements", "Array elements not validated: the structure itself is invalid.")
            else:
                self._check_address(ha, "historical_address")
        # -- email / phone
        self._check_contact(c)
        # -- gender
        if "gender" in c:
            g = c["gender"]
            if isinstance(g, str) and g:
                lvl = "standard" if g in ("female", "male") else "non-standard OIDC value"
                R.ok(t2, "gender", f"gender present ({lvl})", when=w)
            else:
                R.fail(t2, "gender", "gender present but not a non-empty string.", when=w)
        # -- version / identifier
        v = c.get("tefca_ial2claims_version")
        if "tefca_ial2claims_version" not in c:
            R.warn("4.9(a)(iv)", "tefca_ial2claims_version", "tefca_ial2claims_version absent -- "
                   "receivers will treat the token as issued under policy '1.0'.",
                   fix="CSP SHOULD emit tefca_ial2claims_version as the string \"3.0\".")
            if not self.a.allow_missing_claims_version:
                if self.b2:
                    R.fail("B2 §2(a)", "tefca_ial2claims_version.required",
                           "tefca_ial2claims_version absent; QHIN Compliance Bulletin No. 2 §2(a): every IAL2 Claims "
                           "Token issued based on the IAS SOP v3.0 SHALL include it with the string value \"3.0\".",
                           when=w,
                           why="Bulletin §2(a) (and the implementation-group production decision keyed to the §4.8 "
                               "date, 2026-10-01). Under the SOP text alone the claim is a SHOULD and an omitted "
                               "claim means '1.0' (§4.9(a)(iv)); Bulletin §1(b) gives the Bulletin precedence.",
                           fix='CSP emits "tefca_ial2claims_version": "3.0" in every IAL2 Claims Token.')
                else:
                    R.fail("4.9(a)(iv) + prod decision", "tefca_ial2claims_version.required",
                           "tefca_ial2claims_version absent; production tokens MUST carry \"3.0\" (in force from "
                           "2026-10-01, the IAS SOP §4.8 date for IAL2 Claims Tokens).", when=w,
                           why="Implementation-group production decision. The SOP text makes the claim a SHOULD, but "
                               "an omitted claim defaults to '1.0' (§4.9(a)(iv)), which a v3.0 production profile "
                               "cannot accept.",
                           fix='CSP emits "tefca_ial2claims_version": "3.0" in every IAL2 Claims Token.')
        elif not isinstance(v, str):
            R.fail("B2 §2(a)" if self.b2 else "4.9(a)(iv)", "tefca_ial2claims_version", f"tefca_ial2claims_version is "
                   f"{type(v).__name__} ({v!r}); it MUST be a string" + (" (Bulletin 2 §2(a): the string value "
                                                                         "\"3.0\")." if self.b2 else "."), when=w,
                   fix='Emit "3.0" (quoted), not 3.0 or 3.')
        else:
            R.ok("B2 §2(a)" if self.b2 else "4.9(a)(iv)", "tefca_ial2claims_version",
                 f"tefca_ial2claims_version = {v!r}", when=w)
            if v != "3.0":
                if self.b2:
                    R.fail("B2 §2(a)", "tefca_ial2claims_version.value",
                           f"tefca_ial2claims_version {v!r} != '3.0'; QHIN Compliance Bulletin No. 2 §2(a) requires "
                           "the string value \"3.0\" (the three characters 3.0; the Bulletin prints it in typographic "
                           "quotes).", when=w,
                           why="Bulletin §1(a): IAS SOP v3.0 replaces all previous versions, and requirements from "
                               "earlier versions are no longer in effect unless restated in v3.0.",
                           fix='CSP emits "tefca_ial2claims_version": "3.0" for tokens issued under IAS SOP v3.0.')
                else:
                    R.fail("4.9(a)(iv) + prod decision", "tefca_ial2claims_version.value",
                           f"tefca_ial2claims_version {v!r} != '3.0'.", when=w,
                           why="Implementation-group production decision (IAS SOP v3.0; §4.8 date 2026-10-01). The "
                               "SOP text itself requires only a string naming the version used (§4.9(a)(iv)).",
                           fix='CSP emits "tefca_ial2claims_version": "3.0" for tokens issued under IAS SOP v3.0.')
        if "csp_issued_identifier" in c:
            cid = c["csp_issued_identifier"]
            if isinstance(cid, str) and cid:
                R.ok("4.9(a)(v)", "csp_issued_identifier", "csp_issued_identifier present (MAY)", level="MAY")
            else:
                R.fail("4.9(a)(v)", "csp_issued_identifier", "csp_issued_identifier present but not a "
                       "non-empty string.", when=w)
        else:
            R.info("4.9(a)(v)", "csp_issued_identifier", "csp_issued_identifier not present (MAY).")
        # -- unverified claims (Bulletin 2: handled with the contact rules in _check_contact_b2)
        for flag, base in (("email_verified", "email"), ("phone_number_verified", "phone_number")):
            if flag in c and not self.b2:
                fv = c[flag]
                if fv is False and base in c:
                    R.fail("4.9(a)(iii)", f"{flag}", f"{flag}=false while '{base}' is present: the token "
                           "contains an UNVERIFIED demographic.", when=w,
                           why="SOP-text reading. QHIN Compliance Bulletin No. 2 §3(b)/(c) temporarily allows an "
                               f"unverified email or phone_number alongside a verified other one, from "
                               f"{B2_ISSUED.isoformat()}; this run does not apply the Bulletin "
                               f"({self.R.profile.get('basis')}).",
                           fix=f"CSP MUST NOT include unverified demographic claims -- omit '{base}' "
                               "unless verified.")
                elif fv is False:
                    R.fail("4.9(a)(iii)", f"{flag}", f"{flag}=false with no '{base}' claim; under the SOP-text "
                           "reading a *_verified flag may only be true.", when=w,
                           fix=f"Omit {flag} when the token has no '{base}'.")
                elif not isinstance(fv, bool):
                    R.fail("4.9(a)(iii)", f"{flag}.type", f"{flag} is {type(fv).__name__} ({fv!r}); "
                           "OIDC Core §5.1 defines a JSON boolean.")
                if base not in c:
                    self._warn_orphan_flag(flag, base, fv)
        # -- unknown / namespacing (§4.9(c))
        self._check_claim_names(c)
        # -- rollups
        self._rollup_min_demographics(c)
        self._rollup_csp_capability(c)
        R.manual("4.9(a)(iii)", "unverified.attest", "Confirm with the CSP that every demographic claim "
                 "emitted was verified (the token itself cannot prove this beyond *_verified flags)"
                 + (", apart from an email or phone_number flagged false under the temporary QHIN Compliance "
                    "Bulletin No. 2 §3(b)/(c) permission; a verified email/phone means verified per IAS §4.3 "
                    "(Bulletin §3(a))." if self.b2 and not self.b2_3g else "."))

    def _check_aud(self, aud: Any) -> None:
        R, ref, w = self.R, "4.9 Table 2", "4.9"
        if aud is None:
            R.fail("B2 §5(a)" if self.b2 else ref, "aud", "aud missing.", when=w)
            return
        if self.b2 and not isinstance(aud, str):
            b5 = "B2 §5(a)"
            if not isinstance(aud, list):
                R.fail(b5, "aud.type", f"aud is {type(aud).__name__}; QHIN Compliance Bulletin No. 2 §5(a) allows a "
                       "string or an array containing exactly one string.", when=w,
                       fix="Emit aud as urn:oid:<IAS Provider HCID>.")
                return
            if len(aud) != 1:
                R.fail(b5, "aud.type", f"aud is an array of {len(aud)}; QHIN Compliance Bulletin No. 2 §5(a) allows a "
                       "string or an array containing EXACTLY ONE string (the intended recipient's HCID, §5(b)).",
                       when=w, why="An IAL2 Claims Token is issued for one IAS Provider. OIDC Core §2 allows several "
                                   "audiences; Bulletin §1(b) and §5(a) narrow that for IAS.",
                       fix="Emit aud as urn:oid:<IAS Provider HCID>, or as a one-element array holding it.")
                if self.expected_aud:
                    R.info(ref, "aud.expected", "Audience binding not evaluated: aud is not one string or a "
                           "one-element array.")
                return
            if not isinstance(aud[0], str):
                R.fail(b5, "aud.type", f"the single aud array element is {type(aud[0]).__name__}, not a string "
                       "(Bulletin 2 §5(a)).", when=w, fix="Emit aud as [\"urn:oid:<IAS Provider HCID>\"] or as the "
                       "plain string.")
                return
            R.info("B2 §5(c)", "aud.form", "aud uses the one-element array form. QHIN Compliance Bulletin No. 2 "
                   "§5(c): the recipient SHALL treat it as equivalent to the plain string; the value below is "
                   f"checked as that string (QHINs process tokens under the Bulletin; compliance by {B2_DEADLINE}).")
            aud = aud[0]
        elif not isinstance(aud, str):
            shape = f"an array of {len(aud)}" if isinstance(aud, list) else type(aud).__name__
            R.fail(ref, "aud.type", f"IAL2 Claims Token aud MUST be a single string containing the IAS Provider HCID as an "
                   f"OID URI; aud is {shape}. Array-valued aud is not valid under the SOP-text reading.", when=w,
                   why="Generic OIDC (Core §2) allows aud to be a string or an array. IAS Table 2 narrows it: aud MUST be "
                       "the unique HCID of the IAS Provider's Directory Entry, and footnote 13 has the CSP populate aud "
                       "with that HCID as urn:oid:<oid> (profile-tightened). QHIN Compliance Bulletin No. 2 §5(a) "
                       f"accepts a one-element array from {B2_ISSUED.isoformat()}; this run does not apply the "
                       f"Bulletin ({self.R.profile.get('basis')}).",
                   fix=(f"Emit aud as the plain string {aud[0]!r}." if isinstance(aud, list) and len(aud) == 1
                        and isinstance(aud[0], str) else "Emit aud as one string: urn:oid:<IAS Provider HCID>."))
            if self.expected_aud:
                R.info(ref, "aud.expected", "Audience binding not evaluated: aud is not a single string.")
            return
        for v in [aud]:
            if not isinstance(v, str):
                R.fail(ref, "aud.type", f"aud value {v!r} is not a string.", when=w)
                continue
            if v != v.strip():
                R.fail(ref, "aud.whitespace", f"aud {v!r} has leading/trailing whitespace.", when=w)
                v = v.strip()
            if OID_URN_RE.match(v):
                R.ok(ref, "aud.format", f"aud is an RFC 3061 OID URN ({v})", when=w)
            elif v.lower().startswith("urn:oid:urn:oid:"):
                R.fail(ref, "aud.format", f"aud {v!r} has a doubled 'urn:oid:' prefix.", when=w,
                       fix="The HCID in the RCE Directory may already include 'urn:oid:'; don't prefix twice.")
            elif OID_URN_ANYCASE_RE.match(v):
                R.ok(ref, "aud.format", f"aud is an RFC 3061 OID URN ({v}); the prefix case differs from the FHIR "
                     "form (see aud.case)", when=w)
                R.warn(ref, "aud.case", f"aud {v!r} writes the 'urn:oid:' prefix in upper or mixed case. It is a valid "
                       "OID URN with the same meaning (RFC 3061; RFC 8141 §3.1), but not the lower-case form the FHIR "
                       "oid data type requires.",
                       why="RFC 8141 §3.1: URN-equivalence lower-cases the 'urn' scheme and the NID before comparing, "
                           "and RFC 3061's own example is 'URN:OID:0.9.2342.19200300.100.4'. The FHIR oid data type "
                           "(regex urn:oid:[0-2](\\.(0|[1-9][0-9]*))+) requires lower case, and this value links the "
                           f"identity to the FHIR-based RCE Directory entry. {WG_2026_10_22}: recommendation that the "
                           "value comply with FHIR. Recipients that compare strings exactly will not match it.",
                       fix=f"Emit {'urn:oid:' + v[8:]!r}.")
            elif BARE_OID_RE.match(v):
                R.fail(ref, "aud.format", f"aud is a bare OID ({v}); Table 2 requires 'urn:oid:<oid>' "
                       "(RFC 3061).", when=w, fix=f"Set aud to 'urn:oid:{v}'.")
            elif re.match(r"^(urn:oid:)?[0-2](\.\d+)+$", v, re.I):
                R.fail(ref, "aud.format", f"aud {v!r} contains an OID arc with a leading zero (invalid OID).",
                       when=w)
            elif v.startswith(("http://", "https://")):
                R.fail(ref, "aud.format", f"aud {v!r} is a URL -- looks like an OAuth client_id or redirect "
                       "URI.", when=w, fix="Footnote 13: in TEFCA the IAS Provider's HCID (urn:oid:<oid>) "
                       "replaces client_id as the audience. Reconfigure the CSP client.")
            else:
                R.fail(ref, "aud.format", f"aud {v!r} is not 'urn:oid:<oid>'.", when=w,
                       fix="Likely the CSP's native client_id. Footnote 13 requires the IAS Provider HCID.")
        if self.expected_aud:
            if aud.strip() == self.expected_aud:
                R.ok(ref, "aud.expected", f"aud matches expected IAS Provider HCID {self.expected_aud}"
                     + (" (Bulletin 2 §5(b)-(c): string and one-element array compared as equivalent)" if self.b2
                        else ""), when=w)
            elif urn_equivalent(aud, self.expected_aud):
                R.ok(ref, "aud.expected", f"aud {aud.strip()!r} is URN-equivalent to the expected IAS Provider HCID "
                     f"{self.expected_aud} (RFC 8141 §3.1: 'urn' and the NID compared case-insensitively; the OID "
                     "exactly, per RFC 3061). The strings differ only in the case of the prefix (see aud.case).", when=w)
            elif f"urn:oid:{aud.strip()}" == self.expected_aud:
                R.fail(ref, "aud.expected", f"aud {aud!r} is the right OID but lacks the 'urn:oid:' prefix, "
                       f"so it does not equal {self.expected_aud}.", when=w)
            else:
                R.fail(ref, "aud.expected", f"aud {aud!r} != expected IAS Provider HCID "
                       f"{self.expected_aud}.", when=w,
                       fix="Footnote 13: CSP MUST use the IAS Provider's HCID from the RCE Directory. "
                           "Typical causes: the QHIN's HCID was used instead of the Participant/"
                           "Subparticipant IAS Provider's; a test-directory HCID in production (or vice "
                           "versa); a stale HCID after a directory change.")
        else:
            R.info(ref, "aud.expected", "No --expected-aud given; aud only format-checked. IAS Providers "
                   "MUST validate aud equals their own HCID (footnote 13)"
                   + ("; Bulletin 2 §5(b): the HCID of the IAS Provider that is the intended recipient." if self.b2
                      else "."))

    def _check_name(self, c: dict, claim: str, label: str, required: bool) -> None:
        R, ref, w = self.R, "4.9 Table 2", "4.9"
        v = c.get(claim)
        if v is None:
            if required:
                R.fail(ref, claim, f"{claim} ({label}) missing -- required demographic.", when=w)
            return
        if isinstance(v, list):
            R.fail(ref, f"{claim}.type", f"{claim} is a JSON array; must be a string with multiple parts "
                   "space-delimited (OIDC Core §5.1).", when=w, fix=f"Emit e.g. \"{' '.join(map(str, v))}\".")
            return
        if not isinstance(v, str) or not v.strip():
            R.fail(ref, f"{claim}.type", f"{claim} must be a non-empty string.", when=w)
            return
        issue = False
        if v != v.strip():
            R.fail(ref, f"{claim}.trim", f"{claim} has leading/trailing whitespace.", when=w)
            issue = True
        if re.search(r"[,;|]", v):
            R.warn(ref, f"{claim}.delim", f"{claim} {R.phi(v)} contains ',', ';' or '|'. Table 2: multiple "
                   "parts SHALL be delimited per OIDC (spaces) -- can't prove these are delimiters, hence WARN.")
            issue = True
        if re.search(r"\s{2,}", v.strip()):
            R.warn(ref, f"{claim}.space", f"{claim} has doubled internal whitespace.")
            issue = True
        if not issue:
            R.ok(ref, claim, f"{claim} present {R.phi(v)}", when=w)

    def _check_birthdate(self, v: Any) -> None:
        R, ref, w = self.R, "4.9 Table 2", "4.9"
        if v is None:
            R.fail(ref, "birthdate", "birthdate missing.", when=w)
            return
        if not isinstance(v, str):
            R.fail(ref, "birthdate.type", f"birthdate is {type(v).__name__}; must be 'YYYY-MM-DD'.", when=w)
            return
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
            if v.startswith("0000"):
                R.fail(ref, "birthdate.partial", "birthdate year is '0000' (OIDC's 'year omitted' form); "
                       "partial dates SHALL NOT be used.", when=w)
                return
            try:
                d = dt.date.fromisoformat(v)
            except ValueError:
                R.fail(ref, "birthdate.value", f"birthdate {R.phi(v)} is not a real calendar date.", when=w)
                return
            today = dt.datetime.fromtimestamp(self.now, dt.timezone.utc).date()
            if d > today:
                R.fail(ref, "birthdate.future", "birthdate is in the future.", when=w)
            elif (today.year - d.year) > 130:
                R.warn(ref, "birthdate.age", "birthdate implies age > 130 -- probable placeholder value.")
            else:
                R.ok(ref, "birthdate", "birthdate is full ISO 8601 YYYY-MM-DD", when=w)
            return
        hint = "Use YYYY-MM-DD."
        if re.fullmatch(r"\d{8}", v):
            hint = "Value is HL7v3 'YYYYMMDD'; OIDC/ISO 8601 extended form 'YYYY-MM-DD' is required."
        elif re.fullmatch(r"\d{4}(-\d{2})?", v):
            hint = "Partial date (year or year-month) -- SOP: all three elements MUST be present."
        elif re.fullmatch(r"\d{1,2}/\d{1,2}/\d{4}", v):
            hint = "US 'MM/DD/YYYY' format; convert to 'YYYY-MM-DD'."
        elif re.match(r"\d{4}-\d{2}-\d{2}T", v):
            hint = "Contains a time component; birthdate is a date only."
        R.fail(ref, "birthdate.format", f"birthdate {R.phi(v)} is not 'YYYY-MM-DD'.", when=w, fix=hint)

    def _check_address(self, a: Any, label: str) -> None:
        R, t3, w = self.R, "4.9 Table 3", "4.9"
        if isinstance(a, str):
            try:
                inner = json.loads(a)
                if isinstance(inner, dict):
                    R.fail(t3, f"{label}.encoding", f"{label} is a JSON *string* containing an object "
                           "(double-encoded).", when=w, fix="Emit the address as a JSON object, not a "
                           "stringified object.")
                    a = inner
            except json.JSONDecodeError:
                R.fail(t3, f"{label}.type", f"{label} is a plain string; must be a JSON object "
                       "(OIDC Core §5.1.1).", when=w, fix="Put the single-line form in 'formatted' and "
                       "populate street_address/locality/region/postal_code/country.")
                return
        if isinstance(a, list):
            R.fail(t3, f"{label}.type", f"{label} is an array; Table 2 requires a SINGLE JSON object"
                   + (" here (QHIN Compliance Bulletin No. 2 §4 allows an array only as the value of "
                      "historical_address, not nested inside it)." if label.startswith("historical_address[")
                      else "."), when=w,
                   fix=("Emit the current address as one object; prior addresses go in historical_address ("
                        + ("one object, or an array of objects under QHIN Compliance Bulletin No. 2 §4)."
                           if self.b2 else "one object).")) if label == "address"
                   else "Each historical_address element is one Address object.")
            return
        if not isinstance(a, dict):
            R.fail(t3, f"{label}.type", f"{label} must be a JSON object.", when=w)
            return
        aliases = {
            "street_address": ("street", "address1", "line1", "streetAddress", "address_line1", "line"),
            "locality": ("city", "town"),
            "region": ("state", "province"),
            "postal_code": ("zip", "zipcode", "zip_code", "postalCode", "postcode"),
            "country": ("country_code", "countryCode"),
        }
        for member, alts in aliases.items():
            v = a.get(member)
            if isinstance(v, str) and v.strip():
                continue
            found = [x for x in alts if x in a]
            R.fail(t3, f"{label}.{member}", f"{label}.{member} missing/empty (REQUIRED).", when=w,
                   fix=(f"Found non-OIDC key(s) {found}; rename to '{member}' (OIDC Core §5.1.1)."
                        if found else f"CSP must populate '{member}'."))
        street = a.get("street_address")
        if isinstance(street, str) and street.strip():
            R.ok(t3, f"{label}.street_address", "street_address present", when=w)
        loc = a.get("locality")
        if isinstance(loc, str) and loc.strip():
            R.ok(t3, f"{label}.locality", "locality present", when=w)
        reg = a.get("region")
        is_us = a.get("country") == "US"
        rwhy = ("Table 3: region uses the 2-letter codes defined in ISO 3166-2 for US states and territories. The "
                + WG_2026_10_22 + " clarified: the two-letter subdivision part of the ISO 3166-2 code, without the "
                  "country prefix (CA from US-CA), in upper case; lower case and full names are not compliant.")
        if isinstance(reg, str) and reg.strip():
            r = reg.strip()
            if reg != r:
                R.fail(t3, f"{label}.region", f"region {reg!r} has surrounding whitespace.", when=w)
            elif r in US_REGIONS:
                R.ok(t3, f"{label}.region", f"region '{r}' is an ISO 3166-2:US code", when=w)
            elif r.upper() in US_REGIONS:
                R.fail(t3, f"{label}.region", f"region {r!r} not upper-case; the ISO code is {r.upper()!r}.", when=w,
                       why=rwhy)
            elif r.upper().startswith("US-") and r.upper()[3:] in US_REGIONS:
                R.fail(t3, f"{label}.region", f"region {r!r} includes the 'US-' prefix; Table 3 wants the "
                       f"2-letter code ({r.upper()[3:]!r}).", when=w, why=rwhy)
            elif r.lower() in US_REGION_BY_NAME:
                R.fail(t3, f"{label}.region", f"region {r!r} is a full name; use "
                       f"{US_REGION_BY_NAME[r.lower()]!r}.", when=w, why=rwhy)
            elif r.upper() in USPS_MILITARY:
                R.fail(t3, f"{label}.region", f"region {r!r} is a USPS military code, not ISO 3166-2.", when=w)
            elif re.fullmatch(r"[A-Z]{2}", r) and not is_us and a.get("country"):
                R.info(t3, f"{label}.region", f"region {r!r} with country {a.get('country')!r} (non-US; "
                       "Table 3 code list targets US states/territories).")
            else:
                R.fail(t3, f"{label}.region", f"region {r!r} is not a 2-letter ISO 3166-2:US code.", when=w, why=rwhy)
        pc = a.get("postal_code")
        if isinstance(pc, str) and pc.strip():
            pv = pc.strip()
            if pc != pv and is_us:
                R.fail(t3, f"{label}.postal_code", "postal_code has surrounding whitespace.", when=w)
            elif re.fullmatch(r"\d{5}(-\d{4})?", pv):
                R.ok(t3, f"{label}.postal_code", "postal_code is a ZIP / ZIP+4", when=w)
            elif re.fullmatch(r"\d{9}", pv):
                R.warn(t3, f"{label}.postal_code.zip4", "postal_code is 9 digits without hyphen; ZIP+4 is "
                       "RECOMMENDED as '12345-6789'.")
            elif not is_us:
                R.info(t3, f"{label}.postal_code", f"postal_code {R.phi(pc)} with non-US country "
                       "(US ZIP rule not applied).")
            elif re.fullmatch(r"\d{3,4}", pv):
                R.fail(t3, f"{label}.postal_code", f"postal_code has {len(pv)} digits -- leading zeros were "
                       "likely stripped (numeric typing).", when=w, fix=f"Treat ZIP as a string: {pv.zfill(5)!r}.")
            else:
                R.fail(t3, f"{label}.postal_code", f"postal_code {R.phi(pc)} is not a US ZIP / ZIP+4.", when=w)
        elif isinstance(pc, (int, float)):
            R.fail(t3, f"{label}.postal_code.type", "postal_code is a JSON number (leading zeros lost).",
                   when=w, fix="Emit as a string.")
        ctry = a.get("country")
        cwhy = ("Table 3: 'Country code based on the 2-letter codes defined in ISO 3166-2'. The " + WG_2026_10_22
                + " clarified: the ISO 3166-1 alpha-2 country code, in upper case (e.g. US); lower case and full names "
                  "are not compliant.")
        if isinstance(ctry, str) and ctry.strip():
            cv = ctry.strip()
            if ctry != cv:
                R.fail(t3, f"{label}.country", f"country {ctry!r} has surrounding whitespace.", when=w)
            elif cv in ISO3166_1_ALPHA2:
                R.ok(t3, f"{label}.country", f"country '{cv}' is an ISO 3166-1 alpha-2 code", when=w)
            elif cv.upper() in ("USA", "UNITED STATES", "UNITED STATES OF AMERICA", "U.S.", "U.S.A."):
                R.fail(t3, f"{label}.country", f"country {cv!r}; Table 3 requires the 2-letter code 'US'.",
                       when=w, why=cwhy)
            elif re.fullmatch(r"[a-z]{2}", cv):
                R.fail(t3, f"{label}.country", f"country {cv!r} lower-case; the code is {cv.upper()!r}"
                       + ("." if cv.upper() in ISO3166_1_ALPHA2 else " (and that is not an assigned code either)."),
                       when=w, why=cwhy)
            elif cv in ISO3166_NOT_ASSIGNED:
                to = ISO3166_NOT_ASSIGNED[cv]
                R.fail(t3, f"{label}.country", f"country {cv!r} is reserved in ISO 3166-1 but is not an assigned "
                       "country code" + (f"; the ISO 3166-1 alpha-2 code is {to!r}." if to else "."), when=w,
                       why=cwhy, fix=f"Emit {to!r}." if to else "Emit the ISO 3166-1 alpha-2 code of the country.")
            elif re.fullmatch(r"[A-Z]{2}", cv):
                R.fail(t3, f"{label}.country", f"country {cv!r} has the right form but is not an assigned ISO "
                       "3166-1 alpha-2 code.", when=w, why=cwhy)
            else:
                R.fail(t3, f"{label}.country", f"country {cv!r} is not a 2-letter code"
                       + (" (full names are not compliant)." if len(cv) > 3 else "."), when=w, why=cwhy)
        fm = a.get("formatted")
        if fm is not None:
            if not isinstance(fm, str):
                R.fail(t3, f"{label}.formatted", "formatted present but not a string.", when=w)
            elif "\\n" in fm or "\\r" in fm:
                R.warn(t3, f"{label}.formatted", "formatted contains literal backslash-n sequences "
                       "(escaped twice); Table 3 expects real \\r\\n or \\n separators.")
            elif re.search(r"\r(?!\n)", fm):
                R.warn(t3, f"{label}.formatted", "formatted contains bare CR separators; use \\r\\n or \\n.")
            else:
                R.ok(t3, f"{label}.formatted", "formatted present (OPTIONAL) and well-formed", level="MAY")
        extra = set(a) - OIDC_ADDRESS_MEMBERS
        if extra:
            R.warn(t3, f"{label}.extra", f"{label} carries non-OIDC members {sorted(extra)}; validators "
                   "will ignore them.")

    def _warn_orphan_flag(self, flag: str, base: str, fv: Any) -> None:
        self.R.warn("B2 §3(e)-(f)" if self.b2 else "4.9(a)(iii)", f"{flag}.orphan",
                    f"{flag}={json.dumps(fv)} but the token has no '{base}' claim. Neither OIDC Core §5.1 nor QHIN "
                    f"Compliance Bulletin No. 2 §3 defines a flag with no claim to qualify; recipients should ignore it.",
                    fix=f"CSP omits {flag} when it sends no '{base}'.")

    def _check_contact_b2(self, c: dict) -> None:
        """QHIN Compliance Bulletin No. 2 §3: email / phone_number verification rules."""
        R, w = self.R, "4.9"
        s = self._b2_contact(c)
        if not (s["em_ok"] or s["ph_ok"]):
            ref = "B2 §3(a)"
            if not (s["has_em"] or s["has_ph"]):
                msg = ("Neither email nor phone_number present; QHIN Compliance Bulletin No. 2 §3(a) requires at least "
                       "one with a verified value (also IAS Table 2, §4.4(d)(viii)).")
            elif s["em_unv"] and s["ph_unv"]:
                ref = "B2 §3(d)"
                msg = ("Both email and phone_number are unverified (email_verified=false, phone_number_verified=false). "
                       "Bulletin 2 §3(d): a token SHALL NOT include both an unverified email and an unverified "
                       "phone_number; §3(a) needs at least one verified value.")
            elif s["em_unv"]:
                ref = "B2 §3(b)"
                msg = ("email is unverified (email_verified=false) and there is no verified phone_number. Bulletin 2 "
                       "§3(b) allows an unverified email only together with a verified phone_number; §3(a) needs at "
                       "least one verified value.")
            elif s["ph_unv"]:
                ref = "B2 §3(c)"
                msg = ("phone_number is unverified (phone_number_verified=false) and there is no verified email. "
                       "Bulletin 2 §3(c) allows an unverified phone_number only together with a verified email; §3(a) "
                       "needs at least one verified value.")
            else:
                msg = ("No email or phone_number is shown as verified: a *_verified flag that is not a JSON boolean "
                       "says neither true nor false (Bulletin 2 §3(a), §3(e)-(f)).")
            R.fail(ref, "email|phone_number", msg, when=w,
                   fix="CSP sends at least one of email / phone_number that it verified per IAS SOP §4.3, with its "
                       "*_verified flag true or absent.")
        else:
            state = {True: "verified", False: "unverified"}
            R.ok("B2 §3(a)", "email|phone_number",
                 "at least one verified contact (email=" + (state[s["em_ok"]] if s["has_em"] else "absent")
                 + ", phone_number=" + (state[s["ph_ok"]] if s["has_ph"] else "absent") + ")", when=w)
        for unv, flag, base, other, sec in ((s["em_unv"] and s["ph_ok"], "email_verified", "email", "phone_number",
                                             "3(b)"),
                                            (s["ph_unv"] and s["em_ok"], "phone_number_verified", "phone_number", "email",
                                             "3(c)")):
            if not unv:
                continue
            if self.b2_3g:
                R.fail("B2 §3(g)", "b2.3g", f"'{base}' is unverified ({flag}=false). The RCE notice under QHIN "
                       f"Compliance Bulletin No. 2 §3(g) ({self.a.b2_3g_notice.isoformat()}) ended the temporary §{sec} "
                       "permission; IAS SOP §4.9(a)(iii): the CSP MUST NOT include unverified demographic claims.",
                       when=w, fix=f"Omit '{base}' unless the CSP verified it.")
            else:
                R.info(f"B2 §{sec}", f"b2.{sec.replace('(', '').replace(')', '')}",
                       f"'{base}' is unverified ({flag}=false): allowed for now by QHIN Compliance Bulletin No. 2 "
                       f"§{sec}, because a verified {other} is present. It is not an IAL2-verified demographic, so it "
                       "does not count for §4.4(d)(viii) and is not expected in the XCPD body (§4.4(e)). The "
                       "permission ends when the RCE gives notice (§3(g)); model that with --b2-3g-notice DATE.")
        for flag, base, sec in (("email_verified", "email", "3(f)"), ("phone_number_verified", "phone_number", "3(e)")):
            if flag not in c:
                continue
            fv = c[flag]
            if not isinstance(fv, bool):
                R.fail(f"B2 §{sec}", f"{flag}.type", f"{flag} is {type(fv).__name__} ({fv!r}); OIDC Core §5.1 "
                       "defines a JSON boolean, and Bulletin 2 §3 uses the boolean values true and false.", when=w,
                       fix=f"Emit {flag} as true or false (no quotes), or omit it (an absent flag means verified).")
            elif fv is True and base in c:
                R.ok(f"B2 §{sec}", flag, f"{flag}=true", when=w)
            if base not in c:
                self._warn_orphan_flag(flag, base, fv)

    def _check_contact(self, c: dict) -> None:
        R, ref, w = self.R, "4.9 Table 2", "4.9"
        em, ph = c.get("email"), c.get("phone_number")
        has_em = isinstance(em, str) and em.strip() != ""
        has_ph = isinstance(ph, str) and ph.strip() != ""
        if self.b2:
            self._check_contact_b2(c)
        elif not (has_em or has_ph):
            R.fail(ref, "email|phone_number", "Neither email nor phone_number present; at least one "
                   "verified value MUST be present (also §4.4(d)(viii)).", when=w)
        else:
            R.ok(ref, "email|phone_number", f"contact present (email={has_em}, phone_number={has_ph})", when=w)
        if em is not None and not has_em:
            R.fail(ref, "email.type", "email present but empty / non-string.", when=w)
        if has_em and not re.fullmatch(r"[^@\s]+@[^@\s]+", em):
            R.fail(ref, "email.addrspec", f"email {R.phi(em)} is not an RFC 5322 addr-spec (OIDC Core §5.1 MUST).",
                   when=w)
        elif has_em and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", em):
            R.warn(ref, "email.format", f"email {R.phi(em)} has no dot in the domain part (probable typo).")
        if ph is not None and not has_ph:
            R.fail(ref, "phone_number.type", "phone_number present but empty / non-string "
                   "(a JSON number would lose '+' and leading zeros).", when=w)
        if has_ph:
            d = digits(ph)
            if not re.fullmatch(r"\+[1-9][0-9 ().-]{5,}", ph):
                R.warn(ref, "phone_number.e164", "phone_number is not in E.164 form ('+<country> <number>', "
                       "formatting spaces/dashes allowed); OIDC Core §5.1 RECOMMENDS E.164 (e.g., +1 865 555 0100).")
            if not (7 <= len(d) <= 15):
                R.warn(ref, "phone_number.digits", f"phone_number has {len(d)} digits; E.164 allows 7-15.")
            if "ext" in ph.lower() or ";ext=" in ph:
                R.info(ref, "phone_number.ext", "phone_number carries an extension; SOP asks for a "
                       "MOBILE number.")

    def _check_claim_names(self, c: dict) -> None:
        R = self.R
        for k in c:
            if k in OIDC_REGISTERED_CLAIMS or k in SOP_BARE_CLAIMS:
                continue
            m = LANG_TAGGED_RE.match(k)
            if m and m.group(1) in OIDC_REGISTERED_CLAIMS | SOP_BARE_CLAIMS:
                R.info("4.9(c)", "claim.lang", f"'{k}' is a language/script-tagged claim (OIDC Core §5.2); "
                       "receivers that ignore tags will use the untagged value.")
                continue
            if k.startswith(RCE_CLAIM_PREFIX):
                R.ok("4.9(c)", "claim.ns", f"additional claim '{k}' uses the RCE namespace", when="4.9")
            elif k.startswith("https://rce.sequoiaproject.org/OIDC/claim/"):
                R.warn("4.9(c)", "claim.ns", f"claim '{k}' uses https://; §4.9(c) specifies "
                       f"'{RCE_CLAIM_PREFIX}[claim]' exactly (http).")
            elif k.lower().startswith("http://rce.sequoiaproject.org"):
                R.warn("4.9(c)", "claim.ns", f"claim '{k}' is under rce.sequoiaproject.org but not the "
                       f"exact '{RCE_CLAIM_PREFIX}' path (check case/path).")
            elif k == "middle_initial":
                R.warn("4.9(c)", "claim.ns", "bare 'middle_initial' claim: Table 2 lists 'middle initial' but "
                       "OIDC defines no such claim. Carry it in middle_name, or namespace it as "
                       f"'{RCE_CLAIM_PREFIX}middle_initial'.")
            elif k in ("historical_name", "historical_names", "drivers_license",
                       "state_id", "dl_number", "ssn_last4", "previous_address"):
                R.fail("4.9(c)", "claim.ns", f"additional verified claim '{k}' is not namespaced.", when="4.9",
                       fix=f"Label it '{RCE_CLAIM_PREFIX}{k}'.")
            else:
                R.warn("4.9(c)", "claim.unknown", f"non-standard claim '{k}'. If it is an additional "
                       f"verified demographic it MUST be '{RCE_CLAIM_PREFIX}{k}'.")

    def _rollup_min_demographics(self, c: dict) -> None:
        R = self.R
        a = c.get("address") if isinstance(c.get("address"), dict) else {}
        need = {
            "First Name (given_name)": c.get("given_name"),
            "Last Name (family_name)": c.get("family_name"),
            "Date of Birth (birthdate)": c.get("birthdate"),
            "Street Address": a.get("street_address"),
            "City (locality)": a.get("locality"),
            "State (region)": a.get("region"),
            "Zip Code (postal_code)": a.get("postal_code"),
            # IAL2-verified only: an email/phone flagged false (Bulletin 2 §3(b)/(c)) does not count
            "Email or Mobile (verified)": ((c.get("email") if self._b2_contact(c)["em_ok"] else None)
                                           or (c.get("phone_number") if self._b2_contact(c)["ph_ok"] else None)),
        }
        missing = [k for k, v in need.items() if not (isinstance(v, str) and v.strip())]
        if missing:
            R.fail("4.4(d)", "token.min-demographics", f"Token lacks §4.4(d) minimum demographics: "
                   f"{', '.join(missing)} -- the IAS Query is not valid/usable for TEFCA Exchange.")
        else:
            R.ok("4.4(d)", "token.min-demographics", "Token carries all §4.4(d) minimum demographics")

    def _rollup_csp_capability(self, c: dict) -> None:
        R = self.R
        present, absent = [], []
        cs = self._b2_contact(c)
        for label, path in CSP_VERIFIABLE:
            if path is None:
                absent.append(label + " (no standard claim)")
                continue
            if (path == "email" and cs["em_unv"]) or (path == "phone_number" and cs["ph_unv"]):
                absent.append(label + " (present but flagged unverified)")
                continue
            node: Any = c
            for p in path.split("."):
                node = node.get(p) if isinstance(node, dict) else None
            (present if isinstance(node, str) and node.strip() else absent).append(label)
        R.info("4.3(b)", "csp.demographics", f"Verified demographics observed in token: {len(present)}/12 "
               f"[{', '.join(present)}]. Not observed: [{', '.join(absent)}]. Absence in one token does not "
               "prove the CSP lacks the capability -- confirm §4.3(b) via CSP attestation.")

    # =================================================================== #
    # ISSUER: §4.3(e) env separation, §4.3(f) discovery, §4.3(d)/§4.9(a)(i) JWKS
    # =================================================================== #
    def _check_issuer_env(self, iss: str) -> None:
        R, ref = self.R, "4.3(e)"
        prod, nonprod, env = self.a.prod_issuer, self.a.nonprod_issuer, self.a.environment
        if prod and nonprod:
            if norm_url(prod) == norm_url(nonprod):
                R.fail(ref, "issuer.distinct", f"Production and non-production issuers are the same "
                       f"({prod}).", when="4.3e", fix="CSP must expose distinct issuer URLs per environment.")
            else:
                R.ok(ref, "issuer.distinct", "Production and non-production issuer URLs are distinct",
                     when="4.3e")
            if norm_url(prod) == norm_url(nonprod):
                pass
            elif env == "production" and norm_url(iss) == norm_url(nonprod):
                R.fail(ref, "issuer.env", "Token issued by the NON-production issuer is being used in "
                       "production.", when="4.3e",
                       fix="IAS Provider is pointed at the CSP sandbox; switch the OIDC client config.")
            elif env == "nonproduction" and norm_url(iss) == norm_url(prod):
                R.fail(ref, "issuer.env", "Token issued by the PRODUCTION issuer is being used in a "
                       "non-production exchange.", when="4.3e",
                       fix="Production identities (real PHI) must not flow into test exchange.")
            elif env and norm_url(iss) not in (norm_url(prod), norm_url(nonprod)):
                R.warn(ref, "issuer.env", f"Token iss {iss} matches neither --prod-issuer nor --nonprod-issuer.")
        elif env:
            looks_test = re.search(r"(sandbox|staging|stage|test|qa|uat|dev|nonprod|preprod|demo)", iss, re.I)
            if env == "production" and looks_test:
                R.warn(ref, "issuer.heuristic", f"Production run, but iss {iss} looks like a test issuer "
                       f"('{looks_test.group(1)}').")
            elif env == "nonproduction" and not looks_test:
                R.info(ref, "issuer.heuristic", f"Non-production run with iss {iss} -- confirm this is not "
                       "the production issuer (provide --prod-issuer/--nonprod-issuer for a hard check).")
            else:
                R.info(ref, "issuer.heuristic", "Issuer naming consistent with declared environment "
                       "(heuristic only).")
        else:
            R.manual(ref, "issuer.distinct", "Distinct prod/non-prod issuers not verified -- supply "
                     "--prod-issuer and --nonprod-issuer (and --environment).", level="MUST")

    def get_discovery(self, iss: str) -> Optional[dict]:
        if iss in self.discovery_cache:
            return self.discovery_cache[iss]
        R, ref = self.R, "4.3(f)"
        doc: Optional[dict] = None
        if self.a.discovery_file:
            d = self._load_json_file(self.a.discovery_file, "discovery")
            if isinstance(d, dict):
                doc = d
                R.info(ref, "discovery.offline", f"Using offline discovery file {self.a.discovery_file}; "
                       "public reachability (§4.3(d)/(f)) NOT verified.")
        elif self.a.no_network:
            R.skip(ref, "discovery.fetch", "--no-network: discovery not fetched.")
        else:
            url = iss.rstrip("/") + "/.well-known/openid-configuration"
            if iss.endswith("/"):
                R.info(ref, "discovery.slash", "iss ends with '/'; per OIDC Discovery §4 the trailing slash "
                       f"is removed before appending the well-known path -> {url}")
            res = http_get(url, self.a.timeout, self.a.insecure)
            doc = self._parse_metadata_response(res, ref, "discovery", "OIDC Discovery document",
                                                auth_ref="4.3(f)")
        self.discovery_cache[iss] = doc
        if doc is not None:
            n0 = len(R.findings)
            self._validate_discovery(doc, iss)
            self._schema_check("discovery", doc, R.findings[n0:], "Discovery document")
        return doc

    def _parse_metadata_response(self, res: HttpResult, ref: str, chk: str, what: str,
                                 auth_ref: str, when: str = "sop") -> Optional[Any]:
        R = self.R
        ev = f"GET {res.url} -> {res.status or res.error} in {res.elapsed_ms}ms"
        if res.status is None:
            R.fail(ref, f"{chk}.fetch", f"{what} unreachable: {res.error}", evidence=ev, fix=res.hint, when=when)
            return None
        if res.status in (401, 403):
            www = res.headers.get("www-authenticate", "")
            R.fail(auth_ref, f"{chk}.public", f"{what} requires authentication (HTTP {res.status}).",
                   evidence=ev + (f"; WWW-Authenticate: {www}" if www else ""),
                   fix="The SOP requires a publicly accessible endpoint without authentication. Check WAF "
                       "/ API gateway rules, IP allow-lists, or mTLS enforced on this path.", when=when)
            return None
        if res.status == 404:
            fixes = {
                "discovery": "Verify iss exactly (tenant/realm path, e.g. Keycloak '/realms/<name>'; Azure "
                             "'/<tenant>/v2.0'). Discovery = iss + '/.well-known/openid-configuration'.",
                "jwks": "jwks_uri in the discovery document points to a missing resource -- stale URL after "
                        "a CSP migration, or wrong environment.",
                "udap": "SSRAA discovery lives at <FHIR base>/.well-known/udap. Confirm the base URL "
                        "(the RCE Directory endpoint address) and that UDAP/SSRAA is deployed on it.",
            }
            R.fail(ref, f"{chk}.fetch", f"{what} not found (404).", evidence=ev,
                   fix=fixes.get(chk, "Check the URL."), when=when)
            return None
        if res.status != 200:
            R.fail(ref, f"{chk}.fetch", f"{what} returned HTTP {res.status}.", evidence=ev,
                   fix="Expect 200 OK with a JSON body.", when=when)
            return None
        if res.final_url and res.final_url != res.url:
            R.warn(ref, f"{chk}.redirect", f"{what} was redirected to {res.final_url}. Some validators "
                   "do not follow redirects for metadata.")
        ctype = res.headers.get("content-type", "")
        if "json" not in ctype.lower():
            R.warn(ref, f"{chk}.ctype", f"{what} Content-Type is {ctype!r} (expected application/json"
                   f"{' or application/jwk-set+json' if chk == 'jwks' else ''}).")
        body = res.body
        if body.lstrip().startswith(b"-----BEGIN"):
            R.fail("4.9(a)(i)", f"{chk}.pem", f"{what} is PEM text, not JSON.",
                   fix="Publish a bare JWKS: {\"keys\":[{...JWK...}]}. x5c MAY accompany each JWK.")
            return None
        if body.lstrip()[:1] == b"<":
            R.fail(ref, f"{chk}.html", f"{what} returned HTML/XML (login page, WAF block, or error page).",
                   evidence=short(body[:160]), fix="A gateway is intercepting the request.", when=when)
            return None
        try:
            doc = json.loads(body.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            R.fail(ref, f"{chk}.json", f"{what} is not valid JSON: {e}", evidence=short(body[:160]), when=when)
            return None
        R.ok(ref, f"{chk}.fetch", f"{what} retrieved publicly (no credentials sent)", evidence=ev)
        return doc

    def _validate_discovery(self, d: dict, iss: str) -> None:
        R, ref = self.R, "4.3(f)"
        if not isinstance(d, dict):
            R.fail(ref, "discovery.object", "Discovery document is not a JSON object.")
            return
        di = d.get("issuer")
        if di == iss:
            R.ok(ref, "discovery.issuer", "metadata 'issuer' exactly equals token 'iss'")
        else:
            why = []
            if isinstance(di, str):
                if di.rstrip("/") == iss.rstrip("/"):
                    why.append("trailing-slash difference")
                if di.lower() == iss.lower():
                    why.append("case difference")
                if di.replace("http://", "https://") == iss.replace("http://", "https://"):
                    why.append("scheme difference")
            R.fail(ref, "discovery.issuer", f"metadata issuer {di!r} != token iss {iss!r}"
                   f"{' (' + ', '.join(why) + ')' if why else ''}.",
                   why="OIDC Discovery §4.3 / Core §3.1.3.7: issuer MUST exactly match iss.",
                   fix="CSP must mint iss with exactly the issuer string it publishes.")
        req = ["issuer", "authorization_endpoint", "jwks_uri", "response_types_supported",
               "subject_types_supported", "id_token_signing_alg_values_supported"]
        missing = [k for k in req if k not in d]
        if missing:
            R.fail(ref, "discovery.required", f"Discovery lacks REQUIRED metadata: {missing}",
                   why="OIDC Discovery §3 Provider Metadata.")
        else:
            R.ok(ref, "discovery.required", "All OIDC Discovery REQUIRED metadata present")
        if "token_endpoint" not in d:
            R.warn(ref, "discovery.token_endpoint", "token_endpoint absent (REQUIRED unless only the "
                   "Implicit Flow is used).")
        for k in ("response_types_supported", "subject_types_supported"):
            if k in d and not (isinstance(d[k], list) and d[k]):
                R.fail(ref, "discovery.types", f"{k} must be a non-empty JSON array.")
        st = d.get("subject_types_supported")
        if isinstance(st, list) and any(x not in ("public", "pairwise") for x in st):
            R.fail(ref, "discovery.subject_types", f"subject_types_supported {st} has values other than "
                   "'public' / 'pairwise'.")
        sc = d.get("scopes_supported")
        if sc is not None and not (isinstance(sc, list) and "openid" in sc):
            R.fail(ref, "discovery.scopes", f"scopes_supported {sc!r} must include 'openid' (Discovery §3).")
        recm = [k for k in ("userinfo_endpoint", "registration_endpoint", "scopes_supported", "claims_supported")
                if k not in d]
        if recm:
            R.warn(ref, "discovery.recommended", f"RECOMMENDED Discovery metadata absent: {recm}.")
        ju = d.get("jwks_uri")
        if isinstance(ju, str):
            if ju.startswith("https://") or (self.a.allow_http and ju.startswith("http://")):
                R.ok("4.3(d)", "jwks_uri", f"jwks_uri {ju}")
            else:
                R.fail("4.3(d)", "jwks_uri", f"jwks_uri {ju!r} is not HTTPS.")
        algs = d.get("id_token_signing_alg_values_supported")
        if isinstance(algs, list) and "RS256" in algs:
            R.ok("4.9(a)(ii)", "discovery.rs256", f"RS256 advertised (id_token algs {algs})", when="4.9")
        else:
            R.fail("4.9(a)(ii)", "discovery.rs256", f"id_token_signing_alg_values_supported {algs!r} lacks "
                   "RS256.", when="4.9")
        cs = d.get("claims_supported")
        if isinstance(cs, list):
            want = ["given_name", "family_name", "birthdate", "address", "email", "phone_number",
                    "tefca_ial2claims_version"]
            miss = [x for x in want if x not in cs]
            R.info(ref, "discovery.claims", "claims_supported " + ("covers the SOP claims" if not miss else
                   f"does not list {miss} (advisory; providers often under-advertise)."))
        st = d.get("subject_types_supported")
        if isinstance(st, list) and "pairwise" in st:
            R.info("4.9(a)(v)", "discovery.pairwise", "CSP supports pairwise 'sub'; csp_issued_identifier "
                   "SHOULD then be stable across all of the CSP's clients.")

    def get_jwks(self, iss: str) -> Optional[dict]:
        if iss in self.jwks_cache:
            return self.jwks_cache[iss]
        R = self.R
        doc: Any = None
        if self.a.jwks_file:
            doc = self._load_json_file(self.a.jwks_file, "jwks")
            R.info("4.3(d)", "jwks.offline", f"Using offline JWKS file {self.a.jwks_file}; public "
                   "reachability NOT verified.")
        else:
            disc = self.get_discovery(iss)
            ju = disc.get("jwks_uri") if isinstance(disc, dict) else None
            if self.a.no_network:
                R.skip("4.3(d)", "jwks.fetch", "--no-network: JWKS not fetched (use --jwks-file to verify "
                       "the signature offline).")
            elif not isinstance(ju, str):
                R.skip("4.3(d)", "jwks.fetch", "No jwks_uri available (discovery missing/invalid).")
            else:
                res = http_get(ju, self.a.timeout, self.a.insecure)
                doc = self._parse_metadata_response(res, "4.3(d)", "jwks", "JWKS", auth_ref="4.3(d)")
        n0 = len(R.findings)
        jwks = self._validate_jwks(doc) if doc is not None else None
        if doc is not None:
            self._schema_check("jwks", doc, R.findings[n0:], "JWKS")
        self.jwks_cache[iss] = jwks
        return jwks

    def _validate_jwks(self, doc: Any) -> Optional[dict]:
        R, ref, w = self.R, "4.9(a)(i)", "4.9"
        if isinstance(doc, dict) and "kty" in doc and "keys" not in doc:
            R.fail(ref, "jwks.bare", "Document is a single JWK, not a JWK Set.", when=w,
                   fix='Wrap it: {"keys": [ <jwk> ]}.')
            doc = {"keys": [doc]}
        elif isinstance(doc, list):
            R.fail(ref, "jwks.bare", "Document is a bare JSON array; a JWK Set is an object with 'keys'.",
                   when=w)
            doc = {"keys": doc}
        elif isinstance(doc, dict) and "keys" not in doc:
            inner = next((v for v in doc.values() if isinstance(v, dict) and "keys" in v), None)
            if inner:
                R.fail(ref, "jwks.bare", "JWK Set is wrapped inside another object.", when=w,
                       fix="Serve the JWK Set itself at jwks_uri.")
                doc = inner
            else:
                R.fail(ref, "jwks.bare", "Document has no 'keys' member.", when=w)
                return None
        keys = doc.get("keys") if isinstance(doc, dict) else None
        if not isinstance(keys, list) or not keys:
            R.fail(ref, "jwks.keys", "JWKS 'keys' is empty or not an array.", when=w)
            return None
        R.ok(ref, "jwks.bare", f"Bare JWKS with {len(keys)} key(s)", when=w)
        kids = [k.get("kid") for k in keys if isinstance(k, dict)]
        dups = {k for k in kids if k and kids.count(k) > 1}
        if dups:
            R.warn(ref, "jwks.kid.dup", f"Duplicate kid values in JWKS: {sorted(dups)} -- key selection is "
                   "ambiguous.")
        multi = len(keys) > 1
        for i, k in enumerate(keys):
            if isinstance(k, dict) and not k.get("kid") and (k.get("kty") == "RSA" or multi):
                R.warn(ref, "jwks.kid", f"key[{i}] (kty={k.get('kty')!r}) has no kid; "
                       + ("RSA signing keys need one so the token 'kid' can select them." if k.get("kty") == "RSA"
                          else "with multiple keys every key should carry kid (OIDC Core §10.1)."))
            if not isinstance(k, dict):
                R.fail(ref, f"jwks.key[{i}]", "JWKS entry is not an object.", when=w)
                continue
            tag = f"key[{i}] kid={k.get('kid')!r}"
            priv = [p for p in ("d", "p", "q", "dp", "dq", "qi") if p in k]
            if priv:
                R.fail(ref, "jwks.private", f"{tag} exposes PRIVATE key parameters {priv}!", when="sop",
                       fix="CRITICAL: the CSP signing key is compromised. Rotate immediately and publish "
                           "public parameters only.")
            if k.get("kty") != "RSA":
                R.info(ref, "jwks.kty", f"{tag} kty={k.get('kty')!r} (not usable for RS256).")
                continue
            if k.get("use") not in (None, "sig"):
                R.info(ref, "jwks.use", f"{tag} use={k.get('use')!r} -- not usable for ID token signatures.")
            if k.get("alg") not in (None, "RS256"):
                R.info(ref, "jwks.alg", f"{tag} alg={k.get('alg')!r} -- not usable for RS256 verification.")
            try:
                n = int.from_bytes(b64url_decode(k["n"]), "big")
                e = int.from_bytes(b64url_decode(k["e"]), "big")
                bits = n.bit_length()
                if bits < 2048:
                    R.fail(ref, "jwks.size", f"{tag} modulus is {bits} bits (< 2048).", when="sop",
                           why="RFC 7518 §3.3 requires >= 2048-bit keys for RS256.")
                else:
                    R.ok(ref, "jwks.key", f"{tag} RSA {bits}-bit, e={e}", when=w)
            except (KeyError, binascii.Error, ValueError, TypeError) as ex:
                R.fail(ref, "jwks.rsa", f"{tag} has invalid/missing n/e: {ex}", when=w)
                continue
            if "x5c" in k:
                self._check_x5c(k, tag, n, e)
        return doc

    def _check_x5c(self, k: dict, tag: str, n: int, e: int) -> None:
        R, ref = self.R, "4.9(a)(i)"
        x5c = k.get("x5c")
        if not HAVE_CRYPTO:
            R.skip(ref, "jwks.x5c", f"{tag} x5c present; install 'cryptography' to verify it.")
            return
        if not isinstance(x5c, list) or not x5c:
            R.fail(ref, "jwks.x5c", f"{tag} x5c is not a non-empty array.")
            return
        try:
            der = base64.b64decode(x5c[0], validate=True)
            cert = x509.load_der_x509_certificate(der)
        except Exception as ex:  # noqa: BLE001
            R.fail(ref, "jwks.x5c", f"{tag} x5c[0] is not standard-base64 DER: {ex}",
                   fix="x5c uses standard base64 (NOT base64url), DER, no PEM armor (RFC 7517 §4.7).")
            return
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey) and pub.public_numbers().n == n and pub.public_numbers().e == e:
            R.ok(ref, "jwks.x5c", f"{tag} x5c[0] certificate matches n/e (MAY accompany bare JWKS)",
                 level="MAY")
        else:
            R.fail(ref, "jwks.x5c", f"{tag} x5c[0] certificate public key does NOT match n/e.",
                   fix="The JWK and its certificate are out of sync (rotation half-done).")
        try:
            nb, na = cert.not_valid_before_utc.timestamp(), cert.not_valid_after_utc.timestamp()
        except AttributeError:  # cryptography < 42
            nb = cert.not_valid_before.replace(tzinfo=dt.timezone.utc).timestamp()
            na = cert.not_valid_after.replace(tzinfo=dt.timezone.utc).timestamp()
        if not (nb <= self.now <= na):
            R.warn(ref, "jwks.x5c.validity", f"{tag} certificate validity {utc(nb)}..{utc(na)} excludes "
                   f"evaluation time {utc(self.now)}.")

    # ------------------------------------------------------------ signature
    def _verify_signature(self, tok: str, hdr: dict, iss: str) -> None:
        R, ref, w = self.R, "4.9(a)(ii)", "4.9"
        if not HAVE_CRYPTO:
            R.skip(ref, "sig.verify", "Signature not verified: pip install cryptography")
            return
        jwks = self.get_jwks(iss)
        if not jwks:
            R.skip(ref, "sig.verify", "Signature not verified: no JWKS (see discovery/JWKS findings).")
            return
        p0, p1, p2 = tok.split(".")
        data = f"{p0}.{p1}".encode("ascii")
        try:
            sig = b64url_decode(p2)
        except (binascii.Error, ValueError) as ex:
            R.fail(ref, "sig.decode", f"Signature segment not decodable: {ex}", when=w)
            return
        rsa_keys = []
        for k in jwks.get("keys", []):
            if isinstance(k, dict) and k.get("kty") == "RSA":
                try:
                    pub = rsa.RSAPublicNumbers(int.from_bytes(b64url_decode(k["e"]), "big"),
                                               int.from_bytes(b64url_decode(k["n"]), "big")).public_key()
                    rsa_keys.append((k.get("kid"), pub))
                except Exception:  # noqa: BLE001
                    continue

        def try_verify(pub, pss=False) -> bool:
            try:
                pad = (padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO)
                       if pss else padding.PKCS1v15())
                pub.verify(sig, data, pad, hashes.SHA256())
                return True
            except (InvalidSignature, ValueError):
                return False

        kid = hdr.get("kid")
        cands = [(kd, pk) for kd, pk in rsa_keys if kd == kid]
        if not cands:
            avail = [kd for kd, _ in rsa_keys]
            R.fail(ref, "sig.kid", f"Token kid {kid!r} not found in JWKS (available: {avail}).", when=w,
                   fix="Causes: CSP rotated keys and the JWKS isn't updated yet (or you cached an old one); "
                       "token from the other environment's issuer (§4.3(e)); wrong iss.")
        for kd, pk in cands:
            if try_verify(pk):
                R.ok(ref, "sig.verify", f"RS256 signature VALID with kid={kd!r}", when=w)
                return
        for kd, pk in rsa_keys:
            if kd != kid and try_verify(pk):
                R.fail(ref, "sig.kid-mismatch", f"Signature verifies with kid={kd!r}, but header says "
                       f"kid={kid!r}.", when=w, fix="CSP is stamping the wrong kid (rotation bug).")
                return
        for kd, pk in rsa_keys:
            if try_verify(pk, pss=True):
                R.fail(ref, "sig.pss", f"Signature is RSASSA-PSS (PS256-style) with kid={kd!r}, but the "
                       "header claims RS256.", when=w, fix="CSP must sign with PKCS#1 v1.5 (RS256).")
                return
        if cands:
            mod_len = (cands[0][1].key_size + 7) // 8
            extra = (f" Signature is {len(sig)} bytes but modulus is {mod_len} bytes -- truncated/corrupted "
                     "or signed by a different-size key." if len(sig) != mod_len else "")
            R.fail(ref, "sig.verify", f"RS256 signature INVALID for kid={kid!r}.{extra}", when=w,
                   fix="Causes: token modified after signing (claims edited, re-serialized, whitespace "
                       "inserted, base64 vs base64url conversion); token forged/test-signed; JWKS key "
                       "material for that kid changed.")

    # =================================================================== #
    # SOAP / SAML  (§4.1, §4.4(d)(e)(f), §4.9(d)(e))
    # =================================================================== #
    def load_xml(self, path: str) -> Optional[ET.Element]:
        R = self.R
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as e:
            R.fail("input", "xml.read", f"Cannot read {path}: {e}")
            return None
        data = raw
        st = raw.lstrip()
        if st.startswith(b"\xef\xbb\xbf"):
            st = st[3:]
        if not st.startswith(b"<"):
            m = re.search(rb"<(?:[A-Za-z0-9_.-]+:)?Envelope\b.*?</(?:[A-Za-z0-9_.-]+:)?Envelope\s*>", raw, re.S)
            if not m:
                R.fail("input", "xml.extract", "File is not XML and no SOAP Envelope could be located.",
                       evidence=short(raw[:120]))
                return None
            data = m.group(0)
            R.info("input", "xml.extract", "Extracted SOAP Envelope from a non-XML wrapper "
                   "(MTOM/multipart or HTTP capture).")
        try:
            return ET.fromstring(data)
        except ET.ParseError as e:
            line, col = getattr(e, "position", (0, 0))
            lines = data.decode("utf-8", "replace").splitlines()
            ctx = lines[line - 1][max(0, col - 60): col + 60] if 0 < line <= len(lines) else ""
            R.fail("input", "xml.parse", f"XML not well-formed: {e}", evidence=f"line {line} col {col}: "
                   f"{ctx!r}", fix="Truncated capture, unescaped '&'/'<', or a namespace prefix declared "
                   "outside the extracted Envelope.")
            return None

    def process_soap(self, path: str) -> None:
        R = self.R
        R.set_artifact(f"SOAP {path}")
        root = self.load_xml(path)
        if root is None:
            return
        env = root if lname(root.tag) == "Envelope" else None
        body_child = None
        action = ""
        if env is not None:
            body = first_local(env, "Body")
            kids = list(body) if body is not None else []
            body_child = kids[0] if kids else None
            hdr = first_local(env, "Header")
            act = next(iter_local(hdr if hdr is not None else env, "Action"), None)
            action = text_of(act)
        else:
            body_child = root
        kind = lname(body_child.tag) if body_child is not None else ""
        mtype = {"PRPA_IN201305UV02": "PD", "AdhocQueryRequest": "DQ",
                 "RetrieveDocumentSetRequest": "DR", "PRPA_IN201306UV02": "PD-RESP"}.get(kind)
        label = {"PD": "XCPD Patient Discovery request", "DQ": "XCA Document Query request",
                 "DR": "XCA Retrieve Document Set request", "PD-RESP": "XCPD response"}.get(mtype or "", "unrecognized")
        R.info("input", "msg.type", f"{kind or '?'} -> {label}; wsa:Action={action or '-'}")
        if mtype == "PD-RESP":
            self._pd_response(root)
            return
        if mtype is None:
            R.warn("input", "msg.type", f"Body element <{kind}> is not an IAS request type (PD/DQ/DR); "
                   "SAML checks still run.")
        claims = None
        self._last_saml_ok = False
        if env is None:
            R.skip("4.9(e)", "saml", "No SOAP Envelope in file -- SAML checks skipped (body checks only).")
        else:
            claims = self._check_saml(env)
        if mtype == "PD":
            self._check_pd_body(body_child, claims)
        if mtype in ("PD", "DQ", "DR") and env is not None:
            self.msg_coverage[mtype].append((path, self._last_saml_ok))

    def _jwt_near_miss(self, root: ET.Element) -> List[str]:
        hits = []
        for e in root.iter():
            for where, val in [("text", e.text or "")] + [(f"@{lname(k)}", v) for k, v in e.attrib.items()]:
                if JWT_RE.search(val or ""):
                    hits.append(f"<{lname(e.tag)}> {where}")
        if hits:
            self.R.info("4.9(e)", "jwt.located", f"JWT-shaped value(s) found at {hits[:5]}. The ID token "
                        f"must be in SAML Attribute Name='{ID_TOKEN_ATTR_NAME}'.")
        return hits

    def _check_saml(self, env: ET.Element) -> Optional[dict]:
        R, ref, w = self.R, "4.9(e)", "4.9"
        assertions = [e for e in env.iter() if lname(e.tag) == "Assertion" and nsname(e.tag) == SAML_NS]
        if not assertions:
            if any(lname(e.tag) == "EncryptedAssertion" for e in env.iter()):
                R.skip(ref, "saml.encrypted", "Only an EncryptedAssertion is present -- capture before "
                       "encryption (or decrypt) to check the id_token attribute.")
            else:
                saml1 = any(lname(e.tag) == "Assertion" for e in env.iter())
                R.fail(ref, "saml.assertion", "No SAML 2.0 Assertion found in the message." +
                       (" (An Assertion in a non-SAML2 namespace exists -- SAML 1.1?)" if saml1 else ""),
                       when=w, fix="QHIN Query carries a SAML 2.0 assertion in the WS-Security header (QTF).")
            self._jwt_near_miss(env)
            return None
        if len(assertions) > 1:
            R.warn(ref, "saml.multiple", f"{len(assertions)} SAML assertions present; checking the first.")
        a = assertions[0]
        attrs = [e for e in a.iter() if lname(e.tag) == "Attribute" and nsname(e.tag) == SAML_NS]
        log.debug("SAML attributes: %s", [(x.get("Name"), x.get("NameFormat")) for x in attrs])
        claims: Optional[dict] = None
        self._last_saml_ok = False
        idt = [x for x in attrs if x.get("Name") == ID_TOKEN_ATTR_NAME]
        if not idt:
            near = [x for x in attrs if "id_token" in ((x.get("Name") or "") + (x.get("FriendlyName") or "")).lower()
                    or "idtoken" in (x.get("Name") or "").lower().replace("_", "")]
            if near:
                R.fail(ref, "saml.id_token.name", f"id_token attribute uses the wrong Name: "
                       f"{[x.get('Name') for x in near]}.", when=w,
                       fix=f"Name MUST be exactly '{ID_TOKEN_ATTR_NAME}' (case-sensitive). FriendlyName "
                           "does not count.")
                txt = "".join(children_local(near[0], "AttributeValue")[0].itertext()) \
                    if children_local(near[0], "AttributeValue") else ""
                if txt.strip():
                    R.info(ref, "saml.id_token.diag", "Analyzing the token found in the mis-named attribute "
                           "for further diagnostics.")
                    claims = self.process_token(txt, f"{R.artifact} (mis-named attribute)")
            else:
                R.fail(ref, "saml.id_token", f"No SAML Attribute Name='{ID_TOKEN_ATTR_NAME}' -- the IAL2 "
                       "Claims Token is not relayed.", when=w,
                       fix="IAS Provider MUST add the CSP id_token as this SAML attribute on every PD, DQ, "
                           "and DR (§4.4(f), §4.9(d)).")
                self._jwt_near_miss(env)
        else:
            if len(idt) > 1:
                R.warn(ref, "saml.id_token.multi", f"{len(idt)} id_token attributes; exactly one expected.")
            x = idt[0]
            nf = x.get("NameFormat")
            if nf == ID_TOKEN_ATTR_NAMEFORMAT:
                R.ok(ref, "saml.id_token.nameformat", "Attribute Name and NameFormat exact", when=w)
            elif nf is None:
                R.fail(ref, "saml.id_token.nameformat", "NameFormat attribute missing (defaults to "
                       "'unspecified').", when=w, fix=f"Add NameFormat='{ID_TOKEN_ATTR_NAMEFORMAT}'.")
            else:
                R.fail(ref, "saml.id_token.nameformat", f"NameFormat {nf!r} != '{ID_TOKEN_ATTR_NAMEFORMAT}'.",
                       when=w)
            vals = children_local(x, "AttributeValue")
            if len(vals) != 1:
                R.fail(ref, "saml.id_token.values", f"id_token attribute has {len(vals)} AttributeValue "
                       "elements; exactly one expected.", when=w)
            if vals:
                v = vals[0]
                xt = v.get("{http://www.w3.org/2001/XMLSchema-instance}type", "")
                if xt.endswith("base64Binary"):
                    R.warn(ref, "saml.id_token.xsitype", f"AttributeValue xsi:type={xt!r}; the JWT is text "
                           "(xs:string). base64Binary typing invites double encoding.")
                if len(list(v)):
                    R.warn(ref, "saml.id_token.children", "AttributeValue has child elements; expected the "
                           "JWT as text content only.")
                claims = self.process_token("".join(v.itertext()), R.artifact)
                self._last_saml_ok = claims is not None
        self._check_pou_saml(attrs)
        self._check_saml_signature(a)
        hc = [x for x in attrs if x.get("Name") == HCID_ATTR_NAME]
        if hc and isinstance(claims, dict):
            hv = text_of(children_local(hc[0], "AttributeValue")[0]) if children_local(hc[0], "AttributeValue") else ""
            aud = claims.get("aud")
            if self.b2 and isinstance(aud, list) and len(aud) == 1:  # Bulletin 2 §5(c) equivalence
                aud = aud[0]
            same = isinstance(aud, str) and hv.strip() == aud.strip()
            R.info("4.9 Table 2", "aud.vs.saml-hcid", f"SAML homeCommunityId={hv!r}; token aud={aud!r} "
                   f"({'equal' if same else 'different'}). The SOP binds aud to the IAS Provider's HCID; it "
                   "does not require equality with the SAML homeCommunityId.")
        return claims

    def _check_pou_saml(self, attrs: List[ET.Element]) -> None:
        R = self.R
        pa = [x for x in attrs if x.get("Name") == POU_ATTR_NAME]
        if not pa:
            near = [x.get("Name") for x in attrs if "purpose" in (x.get("Name") or "").lower()]
            R.fail("4.1", "xp.saml", "No purposeofuse SAML attribute" + (f"; near-misses {near}" if near else "") + ".",
                   fix=f"QTF-602/605 (via IAS §4.2(a)): XUA PurposeOfUse attribute Name='{POU_ATTR_NAME}' carrying "
                       f"the Exchange Purpose code {XP_CODE} (IAS §4.1).")
            return
        codes: List[Tuple[str, Optional[str], str]] = []
        for x in pa:
            for v in children_local(x, "AttributeValue"):
                proper = [e for e in v.iter() if e is not v and lname(e.tag) == "PurposeOfUse"
                          and nsname(e.tag) == HL7_V3_NS]
                if proper:
                    for e in proper:
                        if not e.get("code"):
                            R.fail("QTF-605", "xp.saml.coded", "PurposeOfUse element has no code attribute.")
                            continue
                        xt = e.get(f"{{{XSI_NS}}}type", "")
                        if xt.rsplit(":", 1)[-1] != "CE":
                            R.warn("QTF-605", "xp.saml.cetype", f"PurposeOfUse xsi:type is {xt or 'absent'!r}; the XUA "
                                   "PurposeOfUse Option uses the HL7 v3 CE data type (xsi:type=\"CE\").")
                        codes.append((e.get("code"), e.get("codeSystem"), "PurposeOfUse"))
                    continue
                wrong = [e for e in v.iter() if e is not v and e.get("code") is not None]
                if wrong:
                    desc = ", ".join(f"<{lname(e.tag)}> in namespace {nsname(e.tag) or '(none)'!r}" for e in wrong)
                    R.fail("QTF-605", "xp.saml.coded", f"No XUA PurposeOfUse element. Found {desc} carrying "
                           f"code {wrong[0].get('code')!r} instead.",
                           why="IHE XUA PurposeOfUse Option (required by QTF-605): the AttributeValue contains an "
                               "element named PurposeOfUse in namespace urn:hl7-org:v3 with HL7 v3 CE content.",
                           fix=f'<PurposeOfUse xmlns="{HL7_V3_NS}" xsi:type="CE" code="T-IAS" '
                               f'codeSystem="{DEFAULT_XP_CODE_SYSTEM}"/>')
                    R.info("4.1", "xp.saml.value", f"Code value {wrong[0].get('code')!r} seen on a non-conformant element; "
                           "not evaluated as the Exchange Purpose.")
                elif text_of(v):
                    codes.append((text_of(v), None, "#text"))
        if not codes:
            if not any(f.check == "xp.saml.coded" and f.status == "FAIL" and f.artifact == R.artifact
                       for f in R.findings):
                R.fail("4.1", "xp.saml", "purposeofuse attribute carries no code.")
            return
        if len(codes) > 1:
            R.warn("4.1", "xp.saml.multi", f"{len(codes)} purpose-of-use codes present: {[c[0] for c in codes]}.")
        for code, cs, el in codes:
            if code == XP_CODE:
                R.ok("4.1", "xp.saml", f"Purpose of use = {XP_CODE}")
            elif code.upper().replace("_", "-") == XP_CODE:
                R.fail("4.1", "xp.saml", f"Purpose of use {code!r}; must be exactly '{XP_CODE}' (case/hyphen).")
            else:
                R.fail("4.1", "xp.saml", f"Purpose of use {code!r}; all IAS exchange MUST use '{XP_CODE}'.",
                       fix="Check the IAS Provider's per-request XP selection; T-TRTMNT or legacy codes are "
                           "not valid for IAS.")
            if el == "#text":
                R.fail("QTF-605", "xp.saml.coded", "Purpose of use is plain text. QTF-605 (via IAS §4.2(a)) requires the "
                       "XUA PurposeOfUse Option: a coded PurposeOfUse element with code and codeSystem.",
                       fix='<saml:AttributeValue><PurposeOfUse xmlns="urn:hl7-org:v3" xsi:type="CE" code="T-IAS" '
                           f'codeSystem="{DEFAULT_XP_CODE_SYSTEM}"/></saml:AttributeValue>')
            elif not cs:
                R.fail("QTF-604", "xp.saml.codesystem", "PurposeOfUse has no codeSystem; QTF-604 requires the Exchange "
                       f"Purpose code system {self.a.xp_code_system}.")
            elif cs != self.a.xp_code_system:
                R.fail("QTF-604", "xp.saml.codesystem", f"codeSystem {cs!r} != {self.a.xp_code_system!r}. QTF-604 (via IAS "
                       "§4.2(a)) requires a code from the Exchange Purpose code system OID.",
                       fix="Legacy values such as the HL7 PurposeOfUse system 2.16.840.1.113883.3.18.7.1 are not "
                           "TEFCA Exchange Purpose codes.")
            else:
                R.ok("QTF-604", "xp.saml.codesystem", f"codeSystem {cs} (Exchange Purpose code system)", level="INFO")

    def _check_saml_signature(self, assertion: ET.Element) -> None:
        """QTF-501 (QHIN-to-QHIN SOAP header signing): RSA-SHA256 and SHA-256; SHA-1 SHALL NOT be used.
        Hard FAIL only when the caller asserts --hop qhin-qhin."""
        R, ref, hop = self.R, "QTF-501", self.a.hop
        ok_sm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        ok_dm = "http://www.w3.org/2001/04/xmlenc#sha256"
        sigs = [c for c in list(assertion) if lname(c.tag) == "Signature"]
        if not sigs:
            R.warn(ref, "saml.signature", f"SAML assertion has no enveloped ds:Signature (hop: {hop}). QHIN-to-QHIN "
                   "assertions are assembled and signed by the QHIN; an unsigned assertion is only plausible on an "
                   "internal Participant hop.")
            return

        def report(check: str, msg: str, fix: str) -> None:
            if hop == "qhin-qhin":
                R.fail(ref, check, msg, fix=fix)
            elif hop == "participant-qhin":
                R.info(ref, check, msg + " QTF-501 governs QHIN-to-QHIN signing only, so this is not a QTF-501 "
                       "violation on a Participant-to-QHIN hop; check the QHIN's own onboarding rules.")
            else:
                R.warn(ref, check, msg + " This is a QTF-501 FAIL if the capture is QHIN-to-QHIN; pass "
                       "--hop qhin-qhin or --hop participant-qhin to decide.", fix=fix)
        sm = next(iter_local(sigs[0], "SignatureMethod"), None)
        alg = sm.get("Algorithm") if sm is not None else None
        if alg == ok_sm:
            R.ok(ref, "saml.signature.method", "SignatureMethod rsa-sha256", level="INFO")
        elif alg and "sha1" in alg.lower():
            report("saml.signature.method", f"SignatureMethod {alg}: SHA-1 SHALL NOT be used for QHIN-to-QHIN signing.",
                   f"Sign with {ok_sm}.")
        else:
            report("saml.signature.method", f"SignatureMethod {alg!r}; QTF-501 requires {ok_sm}.", f"Sign with {ok_sm}.")
        for d in [x.get("Algorithm") for x in iter_local(sigs[0], "DigestMethod")]:
            if d == ok_dm:
                R.ok(ref, "saml.signature.digest", "DigestMethod sha256", level="INFO")
            elif d and "sha1" in d.lower():
                report("saml.signature.digest", f"DigestMethod {d}: SHA-1 SHALL NOT be used for QHIN-to-QHIN signing.",
                       f"Use {ok_dm}.")
            else:
                report("saml.signature.digest", f"DigestMethod {d!r}; QTF-501 requires {ok_dm}.", f"Use {ok_dm}.")
        R.info(ref, "saml.signature.scope", f"Capture hop: {hop}. Algorithms are checked; the XML signature itself "
               "is not cryptographically verified here.")

    # ---------------------------------------------------------------- XCPD
    @staticmethod
    def _parse_pn(v: ET.Element) -> Dict[str, List[str]]:
        return {k: [text_of(e) for e in children_local(v, k) if text_of(e)] for k in ("given", "family", "suffix")}

    @staticmethod
    def _parse_ad(v: ET.Element) -> Dict[str, Any]:
        def one(n):
            e = children_local(v, n)
            return text_of(e[0]) if e else ""
        return {"street": [text_of(e) for e in children_local(v, "streetAddressLine") if text_of(e)],
                "city": one("city"), "state": one("state"), "postal": one("postalCode"),
                "country": one("country"), "use": v.get("use", "")}

    def _demo_from_pd_request(self, body_child: ET.Element) -> Dict[str, Any]:
        out: Dict[str, Any] = {"given": [], "family": [], "suffix": [], "birth": [], "gender": [],
                               "addresses": [], "telecom": [], "found": False}
        qbp = next(iter_local(body_child, "queryByParameter"), None)
        pl = first_local(qbp, "parameterList") if qbp is not None else None
        if pl is None:
            return out
        out["found"] = True
        for p in children_local(pl, "livingSubjectName"):
            for v in children_local(p, "value"):
                for k, vals in self._parse_pn(v).items():
                    out[k] += vals
        for p in children_local(pl, "livingSubjectBirthTime"):
            out["birth"] += [v.get("value") for v in children_local(p, "value") if v.get("value")]
        for p in children_local(pl, "livingSubjectAdministrativeGender"):
            out["gender"] += [v.get("code") for v in children_local(p, "value") if v.get("code")]
        for p in children_local(pl, "patientAddress"):
            out["addresses"] += [self._parse_ad(v) for v in children_local(p, "value")]
        for p in children_local(pl, "patientTelecom"):
            out["telecom"] += [v.get("value") for v in children_local(p, "value") if v.get("value")]
        return out

    def _demo_from_person(self, person: ET.Element) -> Dict[str, Any]:
        out: Dict[str, Any] = {"given": [], "family": [], "suffix": [], "birth": [], "gender": [],
                               "addresses": [], "telecom": [], "found": True}
        for n in children_local(person, "name"):
            for k, vals in self._parse_pn(n).items():
                out[k] += vals
        bt = first_local(person, "birthTime")
        if bt is not None and bt.get("value"):
            out["birth"].append(bt.get("value"))
        g = first_local(person, "administrativeGenderCode")
        if g is not None and g.get("code"):
            out["gender"].append(g.get("code"))
        out["addresses"] = [self._parse_ad(a) for a in children_local(person, "addr")]
        out["telecom"] = [t.get("value") for t in children_local(person, "telecom") if t.get("value")]
        return out

    STREET_ABBR = {"street": "st", "avenue": "ave", "road": "rd", "drive": "dr", "lane": "ln",
                   "boulevard": "blvd", "court": "ct", "circle": "cir", "place": "pl", "parkway": "pkwy",
                   "highway": "hwy", "apartment": "apt", "suite": "ste", "north": "n", "south": "s",
                   "east": "e", "west": "w", "unit": "unit", "#": "apt"}

    def _norm_street(self, s: str) -> str:
        return " ".join(self.STREET_ABBR.get(t, t) for t in norm_tokens(s.replace("#", " # ")))

    def _addr_rows(self, ta: dict, body_addrs: List[dict], label: str) -> List[Tuple[str, Any, Any, str]]:
        def score(b):
            sc = 0
            sc += self._norm_street(" ".join(b["street"])) == self._norm_street(str(ta.get("street_address", "")))
            sc += norm_text(b["city"]) == norm_text(ta.get("locality"))
            sc += b["state"].strip().upper() == str(ta.get("region", "")).strip().upper()
            sc += digits(b["postal"])[:5] == digits(ta.get("postal_code"))[:5]
            return sc
        if not body_addrs:
            return [(f"{label}.{k}", ta.get(k), None, "ABSENT")
                    for k in ("street_address", "locality", "region", "postal_code", "country") if ta.get(k)]
        b = max(body_addrs, key=score)
        rows = []
        pairs = [("street_address", " ".join(b["street"]),
                  lambda t, v: self._norm_street(t) == self._norm_street(v)),
                 ("locality", b["city"], lambda t, v: norm_text(t) == norm_text(v)),
                 ("region", b["state"], lambda t, v: t.strip().upper() == v.strip().upper()),
                 ("postal_code", b["postal"], lambda t, v: digits(t)[:5] == digits(v)[:5]
                  and (len(digits(t)) < 9 or len(digits(v)) < 9 or digits(t) == digits(v))),
                 ("country", b["country"], lambda t, v: t.strip().upper() == v.strip().upper())]
        for k, bv, eq in pairs:
            tv = ta.get(k)
            if not isinstance(tv, str) or not tv.strip():
                continue
            if not bv:
                rows.append((f"{label}.{k}", tv, None, "ABSENT"))
            else:
                rows.append((f"{label}.{k}", tv, bv, "MATCH" if eq(tv, bv) else "MISMATCH"))
        return rows

    def _compare(self, c: dict, p: dict) -> List[Tuple[str, Any, Any, str]]:
        rows: List[Tuple[str, Any, Any, str]] = []
        bg = {t for g in p["given"] for t in norm_tokens(g)}
        for claim, key in (("given_name", "given"), ("family_name", "family"), ("suffix", "suffix")):
            tv = c.get(claim)
            if not isinstance(tv, str) or not tv.strip():
                continue
            pool = bg if key == "given" else {t for g in p[key] for t in norm_tokens(g)}
            if not p[key]:
                rows.append((claim, tv, None, "ABSENT"))
            else:
                tt = set(norm_tokens(tv))
                res = "MATCH" if tt <= pool else ("PARTIAL" if tt & pool else "MISMATCH")
                rows.append((claim, tv, " ".join(p[key]), res))
        mn = c.get("middle_name")
        if isinstance(mn, str) and mn.strip():
            ok = all(t in bg or (len(t) == 1 and any(b.startswith(t) for b in bg)) for t in norm_tokens(mn))
            rows.append(("middle_name", mn, " ".join(p["given"]) or None,
                         "MATCH" if ok else ("ABSENT" if len(p["given"]) <= 1 else "MISMATCH")))
        bd = c.get("birthdate")
        if isinstance(bd, str) and bd:
            if not p["birth"]:
                rows.append(("birthdate", bd, None, "ABSENT"))
            else:
                rows.append(("birthdate", bd, p["birth"][0],
                             "MATCH" if bd.replace("-", "") in [b[:8] for b in p["birth"]] else "MISMATCH"))
        g = c.get("gender")
        if isinstance(g, str) and g:
            want = {"female": "F", "male": "M"}.get(g.lower(), "UN")
            if not p["gender"]:
                rows.append(("gender", g, None, "ABSENT"))
            else:
                rows.append(("gender", g, p["gender"][0], "MATCH" if want in p["gender"] else "MISMATCH"))
        if isinstance(c.get("address"), dict):
            rows += self._addr_rows(c["address"], p["addresses"], "address")
        ha = c.get("historical_address")
        for i, h in enumerate(ha if isinstance(ha, list) else ([ha] if isinstance(ha, dict) else [])):
            if isinstance(h, dict):
                sub = self._addr_rows(h, p["addresses"], f"historical_address[{i}]")
                bad = [r for r in sub if r[3] != "MATCH" and not r[0].endswith(".country")]
                rows.append((f"historical_address[{i}]", "(address)", None if bad else "(address)",
                             "MATCH" if not bad else "ABSENT"))
        tel = p["telecom"]
        cs = self._b2_contact(c)  # an email/phone flagged false (Bulletin 2 §3(b)/(c)) is not a verified demographic
        em = c.get("email") if not cs["em_unv"] else None
        if isinstance(em, str) and em.strip():
            mails = [t[7:] for t in tel if t.lower().startswith("mailto:")]
            rows.append(("email", em, mails[0] if mails else None,
                         ("MATCH" if em.strip().casefold() in [m.strip().casefold() for m in mails] else "MISMATCH")
                         if mails else "ABSENT"))
        ph = c.get("phone_number") if not cs["ph_unv"] else None
        if isinstance(ph, str) and ph.strip():
            phones = [t for t in tel if t.lower().startswith("tel:")]
            rows.append(("phone_number", ph, phones[0] if phones else None,
                         ("MATCH" if digits(ph)[-10:] in [digits(x)[-10:] for x in phones] else "MISMATCH")
                         if phones else "ABSENT"))
        return rows

    def _check_pd_body(self, body_child: ET.Element, claims: Optional[dict]) -> None:
        R = self.R
        p = self._demo_from_pd_request(body_child)
        if not p["found"]:
            R.fail("4.4(d)", "pd.parameterList", "No queryByParameter/parameterList in the XCPD request.")
            return
        mins = {
            "First Name (livingSubjectName/given)": bool(p["given"]),
            "Last Name (livingSubjectName/family)": bool(p["family"]),
            "Date of Birth (livingSubjectBirthTime)": bool(p["birth"]),
            "Street (patientAddress/streetAddressLine)": any(a["street"] for a in p["addresses"]),
            "City (patientAddress/city)": any(a["city"] for a in p["addresses"]),
            "State (patientAddress/state)": any(a["state"] for a in p["addresses"]),
            "Zip (patientAddress/postalCode)": any(a["postal"] for a in p["addresses"]),
            "Email or Mobile (patientTelecom)": bool(p["telecom"]),
        }
        missing = [k for k, ok in mins.items() if not ok]
        if missing:
            R.fail("4.4(d)", "pd.min-demographics", f"XCPD body lacks §4.4(d) minimum demographics: "
                   f"{', '.join(missing)} -- query is not valid/usable for TEFCA Exchange.")
        else:
            R.ok("4.4(d)", "pd.min-demographics", "XCPD body carries all §4.4(d) minimum demographics")
        for b in p["birth"]:
            if not re.fullmatch(r"\d{8}(\d{2,6})?([+-]\d{4})?", b):
                R.warn("4.4(d)", "pd.birthTime", f"livingSubjectBirthTime {R.phi(b)} is not an HL7 TS "
                       "(YYYYMMDD...).")
        for t in p["telecom"]:
            if not re.match(r"^(mailto|tel):", t, re.I):
                R.warn("4.4(d)", "pd.telecom", f"patientTelecom value {R.phi(t)} lacks a 'mailto:' / 'tel:' "
                       "URL scheme (HL7 v3 TEL).")
        if claims is None:
            R.skip("4.4(e)", "pd.token-vs-body", "No decodable token in this message -- §4.4(e) "
                   "completeness not evaluated.")
            return
        rows = self._compare(claims, p)
        cs = self._b2_contact(claims)
        for key, base, flag in (("em_unv", "email", "email_verified"), ("ph_unv", "phone_number", "phone_number_verified")):
            if cs[key]:
                R.info("4.4(e)", f"pd.vs.token.{base}", f"token {base} is flagged unverified ({flag}=false; QHIN "
                       "Compliance Bulletin No. 2 §3(b)/(c)), so it is not an IAL2-verified demographic and §4.4(e) "
                       "does not require it in the XCPD body. Not compared.")
        bad = 0
        for fld, tv, bv, res in rows:
            if res == "MATCH":
                continue
            bad += 1
            soft = fld.endswith(".country")
            msg = (f"Verified '{fld}' {R.phi(tv)} is in the token but NOT carried in the XCPD body."
                   if res == "ABSENT" else
                   f"XCPD body '{fld}' {R.phi(bv)} carries only part of the verified value {R.phi(tv)}."
                   if res == "PARTIAL" else
                   f"XCPD body '{fld}' {R.phi(bv)} differs from the IAL2-verified token value {R.phi(tv)}.")
            fix = ("Populate the PD request from the CSP-verified token claims, not the user's self-asserted "
                   "profile; the SOP requires ALL verified demographics in the body (per QTF mapping).")
            if fld.startswith("historical_address"):
                fix += " Historical addresses typically map to additional patientAddress parameters -- " \
                       "confirm the QTF mapping."
            if soft:
                R.warn("4.4(e)", f"pd.vs.token.{fld}", msg, fix=fix)
            else:
                R.fail("4.4(e)", f"pd.vs.token.{fld}", msg, fix=fix)
        if not bad:
            R.ok("4.4(e)", "pd.vs.token", f"All {len(rows)} verified token demographics are carried in "
                 "the XCPD body and agree")

    def process_pd_response(self, path: str) -> None:
        self.R.set_artifact(f"XCPD response {path}")
        root = self.load_xml(path)
        if root is not None:
            self._pd_response(root)

    def _first_token_claims(self) -> Optional[dict]:
        for sha in self.token_order:
            c = self.tokens[sha].get("claims")
            if isinstance(c, dict):
                return c
        return None

    def _pd_response(self, root: ET.Element) -> None:
        R = self.R
        msg = root if lname(root.tag) == "PRPA_IN201306UV02" else next(iter_local(root, "PRPA_IN201306UV02"), None)
        if msg is None:
            R.fail("input", "resp.type", "No PRPA_IN201306UV02 element found.")
            return
        ack = first_local(msg, "acknowledgement", "typeCode")
        ackc = ack.get("code") if ack is not None else None
        details = [text_of(t) for d in iter_local(msg, "acknowledgementDetail") for t in children_local(d, "text")]
        cap = first_local(msg, "controlActProcess")
        qrc_el = first_local(cap, "queryAck", "queryResponseCode")
        qrc = qrc_el.get("code") if qrc_el is not None else None
        subjects = children_local(cap, "subject")
        issues = [cc.get("code") for d in iter_local(msg, "detectedIssueEvent") for cc in children_local(d, "code")]
        R.info("4.6", "resp.summary", f"acknowledgement={ackc} queryResponseCode={qrc} subjects={len(subjects)}"
               + (f" detectedIssues={issues}" if issues else ""))
        if ackc in ("AE", "AR"):
            R.warn("4.6", "resp.error", f"Responder returned acknowledgement {ackc}: {details or 'no detail'}",
                   fix="If the error cites missing/invalid token or demographics, re-check §4.4(d)/(e) and "
                       "the §4.9 findings for the request.")
        if qrc == "OK" and not subjects:
            R.warn("4.6", "resp.inconsistent", "queryResponseCode OK but no subject returned.")
        if qrc == "NF":
            R.info("4.6", "resp.nf", "No match (NF). For Mode 1 responders, footnote 8 favours possible "
                   "matches on limited demographics (first, last, DOB).")
        if len(subjects) > 1:
            R.warn("4.6(b) 2.1", "resp.multi", f"{len(subjects)} candidates returned. Mode 2 requires a "
                   "uniquely attributable match; acceptable for Mode 1 possible matches.")
        claims = self._first_token_claims()
        for i, s in enumerate(subjects):
            reg = first_local(s, "registrationEvent")
            patient = first_local(reg, "subject1", "patient")
            ids = [(e.get("root"), e.get("extension")) for e in children_local(patient, "id")]
            cust = first_local(reg, "custodian", "assignedEntity")
            cust_ids = [e.get("root") for e in children_local(cust, "id")]
            if any(ext for _, ext in ids):
                R.ok("4.6(b) 2.1.1", f"resp.subject[{i}].id", f"subject[{i}] returns patient identifier(s) "
                     f"{[(r, R.phi(x)) for r, x in ids]} usable for XCA Document Query (Mode 2 evidence).",
                     level="INFO")
            else:
                R.warn("4.6", f"resp.subject[{i}].id", f"subject[{i}] has no patient identifier. A Mode 1 / "
                       "2.1.2 responder returns a TEFCA IAS FHIR Endpoint directory identifier instead; this "
                       "SOP does not define the XCPD element -- confirm against QTF.")
            if cust_ids:
                R.info("4.7(a)(ii)", f"resp.subject[{i}].custodian", f"Custodian/responder id(s) {cust_ids} -- "
                       "notification target if the Demographics Double-Check fails.")
            person = first_local(patient, "patientPerson")
            if person is None:
                continue
            if claims is None:
                R.skip("4.7(a)", "doublecheck", "No token available -- provide --token or a PD request to run "
                       "the Demographics Double-Check aid.")
                continue
            rows = self._compare(claims, self._demo_from_person(person))
            table = "; ".join(f"{f}={r}" for f, _, _, r in rows)
            key_bad = [f for f, _, _, r in rows
                       if f in ("given_name", "family_name", "birthdate") and r not in ("MATCH", "PARTIAL")]
            other_bad = [f for f, _, _, r in rows if r == "MISMATCH" and f not in key_bad]
            if key_bad:
                R.add("4.7(a)", f"doublecheck.subject[{i}]", "WARN", f"Double-Check aid: LIKELY NO-MATCH "
                      f"(core fields {key_bad} differ/absent).", level="ADVISORY", evidence=table,
                      why="The IAS Provider's own algorithm (IAL2 + self-asserted data) is authoritative; "
                          "this is a field-level aid.",
                      fix="If the IAS Provider's algorithm also fails: §4.7(a)(i) reject the response, do NOT "
                          "retain the patient identifier, no further IAS Query to this node except via Mode 1 "
                          "(MAY offer FHIR Authorization Code flow); §4.7(a)(ii) notify the responder's "
                          "organization (directly or via its QHIN).")
            else:
                R.add("4.7(a)", f"doublecheck.subject[{i}]", "INFO", "Double-Check aid: core fields agree"
                      + (f"; other differences {other_bad}" if other_bad else "") + ".",
                      level="ADVISORY", evidence=table)

    # =================================================================== #
    # FHIR / OAuth / UDAP artifacts. Precedence: IAS SOP governs IAS content; the Facilitated FHIR SOP (FF) and
    # SSRAA apply via IAS §4.2(b); FF deadlines are superseded for IAS endpoints (July 1, 2027).
    # Format rules for an artifact that is present apply now (when="sop"); "must support / must publish" rules
    # for IAS FHIR endpoints use when="ssraa".
    # =================================================================== #
    def _read_text(self, path: str) -> Optional[str]:
        try:
            with open(path, "r", encoding="utf-8-sig") as fh:
                return fh.read().strip()
        except OSError as e:
            self.R.fail("input", "input.read", f"Cannot read {path}: {e}")
            return None

    def _check_udap_jwt(self, tok: str, what: str) -> Optional[Tuple[dict, dict, Any]]:
        """Decode a UDAP JWT, check its JOSE header (SSRAA §1.2, FF §6.1(3)(c), §6.10(4)) and verify its
        signature with the x5c leaf. Returns (header, claims, leaf certificate or None)."""
        R = self.R
        try:
            hdr, claims, si, sig = decode_jws(tok)
        except Exception as e:  # noqa: BLE001
            R.fail("SSRAA §1.2.1", "udapjwt.format", f"{what} is not a JWS compact serialization: {e}",
                   fix="UDAP JWTs SHALL be JWS compact serialized (SSRAA §1.2.1; RFC 7515 §7.1).")
            return None
        n0 = len(R.findings)
        alg = hdr.get("alg")
        if not alg or str(alg).lower() == "none":
            R.fail("SSRAA §1.2.3", "udapjwt.alg", f"{what}: alg missing or 'none'; UDAP JWTs SHALL be signed.")
        elif alg not in FF_ALGS:
            R.warn("FF §6.10(4)", "udapjwt.alg", f"{what}: alg {alg!r} is outside RS256/ES256/ES384/RS384. RS256 is "
                   "the only algorithm every implementation MUST support (FF §6.10(4), SSRAA §1.2.2).")
        else:
            R.ok("FF §6.10(4)", "udapjwt.alg", f"{what}: alg {alg}")
        leaf = None
        x5c = hdr.get("x5c")
        if not isinstance(x5c, list) or not x5c:
            R.fail("SSRAA §1.2.3", "udapjwt.x5c", f"{what}: x5c header missing; SSRAA requires the certificate chain "
                   "in x5c (UDAP keys come from certificates, not from a jwks_uri).")
        else:
            if len(x5c) < 2:
                R.fail("FF §6.1(3)(c)(i)", "udapjwt.x5c", f"{what}: x5c has {len(x5c)} certificate; FF requires the "
                       "leaf followed by the intermediate certificate that issued it.")
            certs = []
            for i, entry in enumerate(x5c):
                try:
                    certs.append(cert_from_x5c(entry))
                except Exception as e:  # noqa: BLE001
                    R.fail("SSRAA §1.2.3", "udapjwt.x5c.der", f"{what}: x5c[{i}] is not standard-base64 DER: {short(e, 80)}",
                           fix="x5c entries are standard base64 (not base64url), DER, no PEM armor (RFC 7515 §4.1.6).")
                    certs.append(None)
            leaf = certs[0] if certs else None
            if len(certs) >= 2 and certs[0] is not None and certs[1] is not None:
                ev = (f"leaf issuer={certs[0].issuer.rfc4514_string()} | x5c[1] "
                      f"subject={certs[1].subject.rfc4514_string()}")
                if certs[0].issuer != certs[1].subject:
                    R.fail("FF §6.1(3)(c)(i)", "udapjwt.chain", f"{what}: x5c[1] subject DN does not match the leaf "
                           "issuer DN.", evidence=ev)
                else:
                    try:
                        certs[0].verify_directly_issued_by(certs[1])
                        R.ok("FF §6.1(3)(c)(i)", "udapjwt.chain", f"{what}: x5c[1] issued the leaf (issuer DN matches and "
                             "the leaf's signature verifies with x5c[1]'s key). Path to a TEFCA trust anchor not validated.")
                    except AttributeError:  # cryptography < 40
                        R.ok("FF §6.1(3)(c)(i)", "udapjwt.chain", f"{what}: x5c[1] subject DN matches the leaf issuer DN; "
                             "certificate signature linkage not verified (cryptography < 40).")
                    except Exception as e:  # noqa: BLE001  InvalidSignature, ValueError, TypeError
                        R.fail("FF §6.1(3)(c)(i)", "udapjwt.chain", f"{what}: x5c[1] has the right subject DN but did NOT "
                               f"sign the leaf certificate ({type(e).__name__}).", evidence=ev,
                               fix="x5c[1] must be the actual issuing intermediate, not another certificate with the "
                                   "same name (re-issued or impostor intermediate).")
            if leaf is not None:
                try:
                    nb, na = leaf.not_valid_before_utc.timestamp(), leaf.not_valid_after_utc.timestamp()
                except AttributeError:  # cryptography < 42
                    nb = leaf.not_valid_before.replace(tzinfo=dt.timezone.utc).timestamp()
                    na = leaf.not_valid_after.replace(tzinfo=dt.timezone.utc).timestamp()
                if not (nb <= self.now <= na):
                    R.fail("SSRAA §1.2.3", "udapjwt.validity", f"{what}: leaf certificate validity {utc(nb)}..{utc(na)} "
                           f"excludes evaluation time {utc(self.now)}.")
                if alg and str(alg).lower() != "none":
                    ok, why = verify_jws(str(alg), leaf.public_key(), si, sig)
                    if ok:
                        R.ok("SSRAA §1.2.1", "udapjwt.sig", f"{what}: signature verifies with the x5c leaf key")
                    elif ok is None:
                        R.skip("SSRAA §1.2.1", "udapjwt.sig", f"{what}: signature not verified ({why}).")
                    else:
                        R.fail("SSRAA §1.2.1", "udapjwt.sig", f"{what}: {why}.",
                               fix="Sign with the private key matching x5c[0]; re-serialize nothing after signing.")
                R.info("FF §6.1(3)", "udapjwt.trust", f"{what}: leaf SAN URIs {cert_san_uris(leaf)}. Chain validation "
                       "to an RCE-approved TEFCA CA is not performed (needs the TEFCA trust bundle).")
        self._schema_check("udapJwtHeader", hdr, R.findings[n0:], f"{what} JOSE header")
        return hdr, claims, leaf

    def _check_token_request(self, form: Dict[str, str]) -> Optional[str]:
        R = self.R
        n0 = len(R.findings)
        gt = form.get("grant_type")
        if gt not in ("client_credentials", "authorization_code"):
            R.fail("SSRAA §5.2.2", "tokreq.grant_type", f"grant_type {gt!r}; UDAP token requests use "
                   "client_credentials or authorization_code.")
        else:
            R.ok("SSRAA §5.2.2", "tokreq.grant_type", f"grant_type {gt}")
        if form.get("client_assertion_type") != JWT_BEARER:
            R.fail("SSRAA §5.2.2", "tokreq.client_assertion_type", f"client_assertion_type "
                   f"{form.get('client_assertion_type')!r}; fixed value {JWT_BEARER} (RFC 7523 §2.2).")
        if not form.get("client_assertion"):
            R.fail("SSRAA §5.2.2", "tokreq.client_assertion", "client_assertion missing.")
        if form.get("udap") == "1":
            self.saw_udap = True
        if form.get("udap") != "1":
            R.fail("SSRAA §5.2.2", "tokreq.udap", f"udap parameter {form.get('udap')!r}; fixed value '1' is required.",
                   fix="Without udap=1 many UDAP servers treat the request as plain OAuth and reject the assertion.")
        if gt == "authorization_code":
            if not form.get("code"):
                R.fail("SSRAA §5.2.2", "tokreq.code", "code missing for authorization_code.")
            if not form.get("code_verifier"):
                R.info("RFC 7636", "tokreq.code_verifier", "No PKCE code_verifier. Not required by SSRAA STU1.1 (the version "
                       "FF pins); required by SSRAA STU2 and recommended by RFC 9700.")
        self._schema_check("tokenRequestCC" if gt == "client_credentials" else "tokenRequestAC", form,
                           R.findings[n0:], "Token request parameters")
        return gt

    def _check_auth_claims(self, c: dict, grant: Optional[str]) -> None:
        R = self.R
        n0 = len(R.findings)
        for k in ("iss", "sub", "aud", "exp", "iat", "jti"):
            if k not in c:
                R.fail("SSRAA §5.2.1", f"authjwt.{k}", f"Authentication JWT lacks required claim '{k}'.")
        if c.get("iss") and c.get("iss") != c.get("sub"):
            R.fail("SSRAA §5.2.1", "authjwt.issub", "iss and sub differ; both SHALL be the client_id assigned at "
                   "registration.", fix="A common bug is putting the certificate SAN URI (used in the software "
                   "statement) into iss here. After registration, iss = sub = client_id.")
        if self.a.token_endpoint and c.get("aud") not in (self.a.token_endpoint, [self.a.token_endpoint]):
            R.fail("SSRAA §5.2.1", "authjwt.aud.match", f"aud {c.get('aud')!r} != token endpoint "
                   f"{self.a.token_endpoint!r}.")
        exp, iat = c.get("exp"), c.get("iat")
        if isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
            if exp - iat > 300:
                R.fail("SSRAA §5.2.1", "authjwt.exp.lifetime", f"Authentication JWT lifetime {int(exp - iat)} s exceeds "
                       "the 300 s maximum.")
            if self.now > exp + self.a.clock_skew:
                (R.info if self.a.ignore_expiry else R.fail)(
                    "SSRAA §5.2.1", "authjwt.exp.expired", f"Authentication JWT expired at {utc(exp)}.")
        self._schema_check("authJwtClaims", c, R.findings[n0:], "Authentication JWT claims")

    def _check_b2b(self, b: dict) -> None:
        R = self.R
        n0 = len(R.findings)
        if b.get("version") != "1":
            R.fail("SSRAA §5.2.1.1", "b2b.version", f"hl7-b2b version {b.get('version')!r}; fixed string '1'.")
        oid = b.get("organization_id")
        if not oid:
            R.fail("FF Table 2", "b2b.organization_id", "organization_id missing (required).")
        elif re.fullmatch(r"Organization/[^/\s]+", str(oid)):
            R.ok("FF Table 2", "b2b.organization_id", f"organization_id {oid}")
            R.info("FF Table 2 / SSRAA §5.2.1.1", "b2b.organization_id.conflict", "UNRESOLVED CONFLICT: this relative form "
                   "is what FF Table 2 requires, but SSRAA STU1.1 says organization_id SHALL be a URI and a relative "
                   "reference has no scheme. Strict SSRAA validators may reject it. Open RCE/HL7 clarification.")
        elif re.search(r"/Organization/[^/\s]+$", str(oid)):
            R.fail("FF Table 2", "b2b.organization_id", f"organization_id {oid!r} is absolute; FF Table 2 explicitly "
                   "specifies a relative reference to the RCE Directory base, e.g. 'Organization/1.2.3'.",
                   why="This satisfies SSRAA's URI wording but not the explicit TEFCA profile form. FF Table 2 and "
                       "SSRAA §5.2.1.1 are in unresolved conflict (open RCE/HL7 question); the checker applies the "
                       "explicit profile rule, not a 'stricter wins' rule.")
        else:
            R.fail("FF Table 2", "b2b.organization_id", f"organization_id {oid!r} is not 'Organization/<directory id>'.",
                   fix="Use the most granular RCE Directory Organization resource id (lowest Subparticipant/child), "
                       "the same value QTF-504(c) puts in the SAML Subject Organization ID.")
        if not b.get("organization_name"):
            R.fail("FF Table 2", "b2b.organization_name", "organization_name missing; FF Table 2 makes it required. "
                   "SSRAA leaves it optional, and FF compatibly tightens that (profile-tightened).")
        if b.get("subject_name") and not b.get("subject_id"):
            R.info("SSRAA §5.2.1.1", "b2b.subject_id", "subject_name present without subject_id. SSRAA (US Realm) uses "
                   "the individual NPI; for an Individual using IAS there is normally none, so omission is expected.")
        pou = b.get("purpose_of_use")
        if pou is None:
            R.fail("FF Table 2", "b2b.purpose_of_use", "purpose_of_use missing (required).")
        elif not isinstance(pou, list):
            R.fail("FF Table 2", "b2b.purpose_of_use", f"purpose_of_use is {type(pou).__name__}; must be an array of one string.")
        else:
            if len(pou) != 1:
                R.fail("FF Table 2", "b2b.purpose_of_use", f"purpose_of_use has {len(pou)} entries; FF Table 2 requires "
                       "a length-1 array (one Exchange Purpose per request).")
            for v in pou:
                sysuri, _, code = str(v).rpartition("#")
                if sysuri and sysuri != XP_CODE_SYSTEM_URN:
                    R.fail("FF §6.4", "b2b.purpose_of_use", f"purpose_of_use {v!r} uses code system {sysuri!r}; FF §6.4 "
                           f"requires the Exchange Purpose code system {XP_CODE_SYSTEM_URN}.")
                elif code != XP_CODE:
                    R.fail("4.1", "b2b.purpose_of_use", f"purpose_of_use {v!r}; IAS exchange MUST use {XP_CODE} (IAS §4.1).")
                else:
                    R.ok("4.1", "b2b.purpose_of_use", f"purpose_of_use {v!r}")
        if b.get("consent_reference") and not b.get("consent_policy"):
            R.fail("SSRAA §5.2.1.1", "b2b.consent_reference", "consent_reference present without consent_policy.")
        extra = set(b) - {"version", "subject_name", "subject_id", "subject_role", "organization_name",
                          "organization_id", "purpose_of_use", "consent_policy", "consent_reference"}
        if extra:
            R.info("SSRAA §5.2.1.1", "b2b.extra", f"Unrecognized hl7-b2b members {sorted(extra)} (servers MAY ignore).")
        self._schema_check("hl7-b2b", b, R.findings[n0:], "hl7-b2b extension")

    @staticmethod
    def _demo_from_fhir_patient(pt: dict) -> Dict[str, Any]:
        out: Dict[str, Any] = {"given": [], "family": [], "suffix": [], "birth": [], "gender": [],
                               "addresses": [], "telecom": [], "found": True}
        for n in pt.get("name", []) or []:
            out["given"] += [g for g in n.get("given", []) or [] if g]
            if n.get("family"):
                out["family"].append(n["family"])
            out["suffix"] += [x for x in n.get("suffix", []) or [] if x]
        if pt.get("birthDate"):
            out["birth"].append(str(pt["birthDate"]).replace("-", ""))
        if pt.get("gender"):
            out["gender"].append({"female": "F", "male": "M"}.get(pt["gender"], "UN"))
        for a in pt.get("address", []) or []:
            out["addresses"].append({"street": a.get("line", []) or [], "city": a.get("city", "") or "",
                                     "state": a.get("state", "") or "", "postal": a.get("postalCode", "") or "",
                                     "country": a.get("country", "") or "", "use": a.get("use", "")})
        for t in pt.get("telecom", []) or []:
            if t.get("system") == "email" and t.get("value"):
                out["telecom"].append("mailto:" + t["value"])
            elif t.get("system") in ("phone", "sms") and t.get("value"):
                out["telecom"].append("tel:" + t["value"])
        return out

    def _check_tefca_ias(self, t: dict) -> Optional[dict]:
        R = self.R
        n0 = len(R.findings)
        if t.get("version") != "1":
            R.fail("FF Table 4", "tefca_ias.version", f"tefca_ias version {t.get('version')!r}; fixed string '1'.")
        ui = t.get("user_information")
        is_self = False
        if not isinstance(ui, dict):
            R.fail("FF Table 4", "tefca_ias.user_information", "user_information missing or not a FHIR resource object.")
        else:
            if ui.get("resourceType") != "RelatedPerson":
                R.fail("FF Table 4", "tefca_ias.user_information", f"user_information.resourceType "
                       f"{ui.get('resourceType')!r}; must be a FHIR RelatedPerson.")
            codes = [c.get("code") for rel in ui.get("relationship", []) or [] for c in rel.get("coding", []) or []]
            is_self = "ONESELF" in codes
            R.info("FF Table 4", "tefca_ias.relationship", "User is the patient (relationship ONESELF)." if is_self else
                   f"User is NOT the patient (relationship codes {codes or 'none'}); consent_policy becomes required.")
        if not is_self and not t.get("consent_policy"):
            R.fail("FF Table 4", "tefca_ias.consent_policy", "consent_policy missing and the user is not shown to be the patient (no ONESELF relationship).",
                   fix="Assert the Access Consent Policy OID(s) for the identity-proofing assurance of the user, as "
                       "URIs, e.g. ['urn:oid:...'].")
        for v in t.get("consent_policy", []) or []:
            if not str(v).startswith("urn:oid:"):
                R.fail("FF Table 4", "tefca_ias.consent_policy", f"consent_policy value {v!r} is not a urn:oid URI.")
        pi = t.get("patient_information")
        if not isinstance(pi, dict):
            R.fail("FF Table 4", "tefca_ias.patient_information", "patient_information missing or not a FHIR resource object.")
        elif pi.get("resourceType") != "Patient":
            R.fail("FF Table 4", "tefca_ias.patient_information", f"patient_information.resourceType "
                   f"{pi.get('resourceType')!r}; must be a FHIR (US Core) Patient.")
        if "purpose_of_use" in t:
            R.warn("FF Table 4", "tefca_ias.purpose_of_use", "purpose_of_use inside tefca_ias is not a Table 4 element; "
                   "the Exchange Purpose belongs in hl7-b2b.purpose_of_use (FF Table 2).")
        extra = set(t) - {"version", "user_information", "patient_information", "id_token", "consent_policy",
                          "consent_reference", "purpose_of_use"}
        if extra:
            R.info("FF Table 4", "tefca_ias.extra", f"Unrecognized tefca_ias members {sorted(extra)}.")
        idt = t.get("id_token")
        if not idt:
            R.fail("4.4(f)", "tefca_ias.id_token", "tefca_ias.id_token missing. IAS §4.4(f)/§4.9(d)-(e) make it a client "
                   "MUST (FF Table 4 also lists it as required; servers SHOULD answer invalid_grant).",
                   why="Precedence: profile-tightened. The IAS client MUST is compatible with FF's server-side SHOULD.")
        self._schema_check("tefcaIasExtension", t, R.findings[n0:], "tefca_ias extension", phi=True)
        claims = None
        if idt:
            R.ok("4.9(e)", "tefca_ias.id_token", "tefca_ias.id_token present")
            claims = self.process_token(idt, f"{R.artifact} tefca_ias.id_token")
        if isinstance(pi, dict) and pi.get("resourceType") == "Patient" and isinstance(claims, dict):
            self._check_patient_info_vs_token(pi, claims)
        return claims

    def _check_patient_info_vs_token(self, pi: dict, claims: dict) -> None:
        """FF §6.11 IAS(4): patient_information MUST correspond to the verified identity attributes."""
        R, ref = self.R, "FF §6.11 IAS(4)"
        p = self._demo_from_fhir_patient(pi)
        rows = self._compare(claims, p)
        bad = 0
        for fld, tv, bv, res in rows:
            if res == "MATCH":
                continue
            bad += 1
            msg = {"ABSENT": f"verified '{fld}' {R.phi(tv)} is in the IAL2 token but missing from patient_information.",
                   "PARTIAL": f"patient_information '{fld}' {R.phi(bv)} carries only part of the verified value {R.phi(tv)}.",
                   }.get(res, f"patient_information '{fld}' {R.phi(bv)} differs from the verified token value {R.phi(tv)}.")
            (R.warn if fld.endswith(".country") else R.fail)(
                ref, f"piv.{fld}", msg, fix="Build patient_information from the CSP-verified claims (IAS §4.9 Table 2) "
                "so the responder's match and the IAS SOP demographics agree; mismatches lead to invalid_grant "
                "(FF §6.11 IAS(5)).")
        if not bad:
            R.ok(ref, "piv", f"patient_information agrees with all {len(rows)} verified token demographics")
        cs = self._b2_contact(claims)
        if any(t.startswith("tel:") for t in p["telecom"]) and not cs["ph_ok"]:
            R.info(ref, "piv.extra", "patient_information has a phone number the IAL2 token does not verify "
                   "(self-asserted?). FF requires correspondence to VERIFIED attributes -- confirm with the responder.")
        if any(t.startswith("mailto:") for t in p["telecom"]) and not cs["em_ok"]:
            R.info(ref, "piv.extra", "patient_information has an email the IAL2 token does not verify (self-asserted?).")

    def process_fhir(self, path: str) -> None:
        R = self.R
        fart = f"FHIR auth {path}"
        R.set_artifact(fart)
        s = self._read_text(path)
        if s is None:
            return
        form: Optional[Dict[str, str]] = None
        jwt: Optional[str] = None
        payload: Any = None
        if s.startswith("{"):
            try:
                obj = json.loads(s)
            except json.JSONDecodeError as e:
                R.fail("input", "fhir.json", f"Not valid JSON: {e}")
                return
            if isinstance(obj, dict) and isinstance(obj.get("client_assertion"), str):
                form = {k: str(v) for k, v in obj.items()}
                jwt = obj["client_assertion"]
            else:
                payload = obj
        elif "client_assertion=" in s or "grant_type=" in s:
            form = {k: v[0] for k, v in urllib.parse.parse_qs(s, keep_blank_values=True).items()}
            jwt = form.get("client_assertion")
        elif s.count(".") == 2:
            jwt = s
        grant = self.a.grant_type
        if form is not None:
            grant = self._check_token_request(form) or grant
        if jwt:
            res = self._check_udap_jwt(jwt, "Authentication JWT")
            if res is None:
                self.msg_coverage["FHIR"].append((path, False))
                return
            payload = res[1]
        if not isinstance(payload, dict):
            R.fail("input", "fhir.parse", "No token request, Authentication JWT, or JSON payload found.")
            return
        ext = payload.get("extensions") if "extensions" in payload else (
            payload if any(k in payload for k in ("tefca_ias", "hl7-b2b")) else None)
        if grant is None and isinstance(ext, dict) and "hl7-b2b" in ext:
            grant = "client_credentials"
            R.info("SSRAA §5.2.1", "authjwt.extensions.grant", "grant type inferred as client_credentials (hl7-b2b present); "
                   "pass --grant-type or the token request form body to be explicit.")
        if jwt:
            self._check_auth_claims(payload, grant)
        b2b = ext.get("hl7-b2b") if isinstance(ext, dict) else None
        tia = None
        if isinstance(ext, dict):
            tia = ext.get("tefca_ias")
            if tia is None:
                var = [k for k in ext if k.lower().replace("-", "_") == "tefca_ias" and k != "tefca_ias"]
                if var:
                    R.fail("FF Table 4", "authjwt.extensions", f"Extension key {var[0]!r}; the key name is exactly 'tefca_ias'.")
                    tia = ext[var[0]]
        if grant == "client_credentials":
            if not isinstance(b2b, dict):
                R.fail("FF §6.11 B2B(1)", "authjwt.extensions", "client_credentials request without an hl7-b2b extension.",
                       why="SSRAA §5.2.1 and FF §6.11 B2B(1) require hl7-b2b for client credentials.")
            if not isinstance(tia, dict):
                R.fail("FF §6.11 IAS(3)", "authjwt.extensions", "IAS client_credentials request without tefca_ias.",
                       why="FF §6.11 IAS(3): tefca_ias is required in addition to hl7-b2b; IAS §4.4(f) requires the "
                           "IAL2 token in FHIR authentication requests.")
        elif grant == "authorization_code":
            if isinstance(b2b, dict):
                R.warn("SSRAA §5.2.1", "authjwt.extensions", "hl7-b2b present in an authorization_code request; SSRAA "
                       "says to omit it for authorization_code.")
            if not isinstance(tia, dict):
                R.info("4.4(f)", "authjwt.extensions", "authorization_code request without tefca_ias. OPEN QUESTION: IAS "
                       "§4.4(f) requires the token in 'applicable' FHIR authentication requests, while SSRAA omits "
                       "extensions for authorization_code; whether Mode 1 auth-code requests are 'applicable' is not "
                       "defined. Confirm with the RCE.")
        if not isinstance(ext, dict):
            R.fail("4.9(e)", "authjwt.extensions", "No 'extensions' object: the tefca_ias extension carrying id_token is absent.")
        if isinstance(b2b, dict):
            self._check_b2b(b2b)
        claims = self._check_tefca_ias(tia) if isinstance(tia, dict) else None
        self.msg_coverage["FHIR"].append((path, claims is not None))

    # =================================================================== #
    # OAuth token response / error (FF §6.10, §6.11 B2B(3), §6.12; SSRAA §5.2.2; RFC 6749 §5)
    # =================================================================== #
    TOKEN_ERRORS = {
        "invalid_grant": "Grant or authorization context rejected. TEFCA uses it for: insufficient/unacceptable "
                         "consent policy (FF §6.11 B2B(3), may carry extensions.hl7-b2b.consent_required); a missing "
                         "tefca_ias.id_token (FF Table 4); user information that does not match a person known to the "
                         "responder, or IAS workflow not supported (FF §6.11 IAS(5)).",
        "invalid_scope": "Requested scope invalid/unsupported. FF §6.11(10): user scope requested without a user; "
                         "FF §6.12(5),(8),(13): wildcard not supported or none of the scopes available.",
        "invalid_client": "Client authentication failed: bad/expired Authentication JWT, wrong iss/sub (must be "
                          "client_id), wrong aud (token endpoint), untrusted x5c chain, or a retired client_id "
                          "(FF §6.11(7)-(8)).",
        "unauthorized_client": "Client not allowed to use this grant type (registration grant_types).",
        "unsupported_grant_type": "Server does not support this grant type (check udap metadata grant_types_supported).",
        "invalid_request": "Malformed request: missing udap=1, client_assertion_type, or other required parameter.",
        "invalid_client_metadata": "Registration-time error (RFC 7591); FF §6.12 also allows it for scope problems.",
    }

    def process_oauth_response(self, path: str) -> None:
        R = self.R
        R.set_artifact(f"OAuth response {path}")
        obj = self._load_json_file(path, "oauth-response")
        if not isinstance(obj, dict):
            return
        n0 = len(R.findings)
        if "error" in obj:
            err = obj.get("error")
            R.info("RFC 6749 §5.2", "tokerr.meaning", f"error={err!r}: " + self.TOKEN_ERRORS.get(
                str(err), "non-standard error code (RFC 6749 §8.5 extension)."),
                evidence=f"error_description={obj.get('error_description')!r}")
            ext = (obj.get("extensions") or {}).get("hl7-b2b") if isinstance(obj.get("extensions"), dict) else None
            if ext is not None:
                if err != "invalid_grant":
                    R.warn("FF §6.11 B2B(3)", "tokerr.extensions", "TEFCA consent error extension on a non-invalid_grant error.")
                cr = ext.get("consent_required") if isinstance(ext, dict) else None
                if not (isinstance(cr, list) and cr and all(isinstance(x, str) and ":" in x for x in cr)):
                    R.fail("FF §6.11 B2B(3)", "tokerr.extensions", "extensions.hl7-b2b.consent_required must be a non-empty "
                           "array of policy URIs.")
                else:
                    R.ok("FF §6.11 B2B(3)", "tokerr.extensions", f"consent_required {cr}"
                         + (f"; consent_form {ext.get('consent_form')}" if ext.get("consent_form") else ""))
            elif err == "invalid_grant":
                R.info("FF §6.11 B2B(3)", "tokerr.extensions", "invalid_grant without the TEFCA consent error extension "
                       "(SHOULD be included when the cause is an omitted or unacceptable consent policy).")
            self._schema_check("tokenError", obj, R.findings[n0:], "Token error response")
            return
        for k in ("access_token", "token_type"):
            if not obj.get(k):
                R.fail("RFC 6749 §5.1", f"tokresp.{k}", f"{k} missing.")
        ei = obj.get("expires_in")
        if ei is None:
            R.warn("RFC 6749 §5.1", "tokresp.expires_in", "expires_in absent (RECOMMENDED); the client cannot tell the "
                   "access-token lifetime, and the 60-minute limit cannot be checked.")
        elif isinstance(ei, (int, float)) and ei > 3600:
            use = self.ssraa_in_use()
            msg = f"Access token lifetime {int(ei)} s > 3600 s."
            if use == "yes":
                R.fail("SSRAA §5.2.2", "tokresp.expires_in.ssraa", msg + " [Protocol axis] This is an SSRAA "
                       "transaction, and SSRAA STU1.1 §5.2.2 requires access tokens of 60 minutes or less.")
            elif use == "unknown":
                R.warn("SSRAA §5.2.2", "tokresp.expires_in.ssraa", msg + " [Protocol axis] FAIL if this is an SSRAA "
                       "transaction (SSRAA §5.2.2 SHALL); pass --ssraa-in-use yes|no.")
            else:
                R.info("SSRAA §5.2.2", "tokresp.expires_in.ssraa", msg + " [Protocol axis] Not an SSRAA transaction "
                       "(--ssraa-in-use no), so SSRAA §5.2.2 does not apply.")
            R.fail("4.6 SSRAA", "tokresp.expires_in.max", msg + " [TEFCA adoption axis] IAS FHIR endpoints must support "
                   "SSRAA, including this limit, from July 1, 2027 (IAS §4.6(a)(1.2)/(b)(2.3)). Until then FF §6.10(2) "
                   "makes 60 minutes a SHOULD.", when="ssraa")
        elif isinstance(ei, (int, float)):
            R.ok("FF §6.10(2)", "tokresp.expires_in", f"expires_in {int(ei)} s (<= 60 min)")
        if "refresh_token" in obj:
            if self.a.grant_type == "client_credentials":
                R.fail("SSRAA §5.3", "tokresp.refresh_token.grant", "Refresh token issued for client_credentials; refresh "
                       "tokens are not used with that grant (SSRAA §5.3; FF §6.10(3)).")
            else:
                R.info("FF §6.10(3)", "tokresp.refresh_token.grant", "refresh_token issued: allowed only for authorization "
                       "code clients authorized for offline_access.")
        if self.a.requested_scope is not None:
            req = set(self.a.requested_scope.split())
            if "scope" not in obj:
                R.info("FF §6.12(14)", "tokresp.scope.compare", "No scope in the response: per FF §6.12(14) that means the "
                       "granted set equals the requested set.")
            else:
                got = set(str(obj["scope"]).split())
                R.info("FF §6.12(14)", "tokresp.scope.compare", "Granted == requested." if got == req else
                       f"Granted differs. Not granted: {sorted(req - got)}; extra: {sorted(got - req)}.")
        self._schema_check("tokenResponse", obj, R.findings[n0:], "Token response")

    # =================================================================== #
    # UDAP dynamic registration (SSRAA §3; FF §6.11(2)-(10))
    # =================================================================== #
    def process_udap_registration(self, path: str) -> None:
        R = self.R
        R.set_artifact(f"UDAP registration {path}")
        obj = self._load_json_file(path, "udap-registration")
        if not isinstance(obj, dict):
            return
        self.saw_udap = True
        n0 = len(R.findings)
        if not obj.get("software_statement"):
            R.fail("SSRAA §3.1", "regreq.software_statement", "software_statement missing.")
        if obj.get("udap") != "1":
            R.fail("SSRAA §3.1", "regreq.udap", f"udap {obj.get('udap')!r}; fixed value '1'.")
        certs = obj.get("certifications")
        if not (isinstance(certs, list) and certs):
            R.fail("FF §6.11(3)", "regreq.certifications", "No certifications; the TEFCA basic-app certification is "
                   "required for all TEFCA registrations.")
        self._schema_check("registrationRequest", obj, R.findings[n0:], "Registration request")
        ss_iss = None
        if obj.get("software_statement"):
            res = self._check_udap_jwt(obj["software_statement"], "Software statement")
            if res:
                hdr, c, leaf = res
                ss_iss = c.get("iss")
                n1 = len(R.findings)
                sans = cert_san_uris(leaf) if leaf is not None else []
                if leaf is not None:
                    if ss_iss in sans:
                        R.ok("FF §6.11(5)", "softstmt.iss.san", f"iss {ss_iss} is a SAN URI of the certificate")
                    else:
                        R.fail("FF §6.11(5)", "softstmt.iss.san", f"iss {ss_iss!r} is not one of the certificate SAN URIs "
                               f"{sans}.", why="SSRAA §3.1 and FF §6.11(5): register with an iss equal to a client SAN URI.")
                xp = re.findall(r"T-[A-Z0-9-]+", urllib.parse.urlsplit(str(ss_iss or "")).path)
                if not xp:
                    R.fail("FF §6.11(5)(a)", "softstmt.iss.xp", f"iss/SAN URI path {ss_iss!r} does not contain an Exchange "
                           "Purpose code.", fix="FF requires the SAN URI path to contain the XP this client exchanges for, "
                           "e.g. https://ias.example.org/fhir-client/T-IAS.")
                elif XP_CODE not in xp:
                    R.warn("FF §6.11(5)(a)", "softstmt.iss.xp", f"SAN URI path carries {xp}, not {XP_CODE}: this "
                           "registration is not for IAS.")
                else:
                    R.ok("FF §6.11(5)(a)", "softstmt.iss.xp", f"SAN URI path contains {XP_CODE}")
                if c.get("sub") != ss_iss:
                    R.fail("SSRAA §3.1", "softstmt.sub.eq", "sub must equal iss in the software statement.")
                if self.a.registration_endpoint and c.get("aud") != self.a.registration_endpoint:
                    R.fail("SSRAA §3.1", "softstmt.aud.match", f"aud {c.get('aud')!r} != registration endpoint "
                           f"{self.a.registration_endpoint!r}.")
                if isinstance(c.get("exp"), (int, float)) and isinstance(c.get("iat"), (int, float)) \
                        and c["exp"] - c["iat"] > 300:
                    R.fail("SSRAA §3.1", "softstmt.exp.lifetime", f"software statement lifetime {int(c['exp'] - c['iat'])} s "
                           "> 300 s.")
                gts = c.get("grant_types") or []
                if ("authorization_code" in gts) == ("client_credentials" in gts):
                    R.fail("SSRAA §3.1", "softstmt.grant_types", f"grant_types {gts}: exactly one of authorization_code "
                           "or client_credentials.", fix="FF §6.11(4): register one client per Exchange Purpose and grant.")
                if c.get("token_endpoint_auth_method") != "private_key_jwt":
                    R.fail("SSRAA §3.1", "softstmt.token_endpoint_auth_method", "token_endpoint_auth_method must be "
                           "'private_key_jwt'.")
                if not any(str(x).startswith("mailto:") for x in c.get("contacts", []) or []):
                    R.fail("SSRAA §3.1", "softstmt.contacts", "contacts must include at least one mailto: address.")
                if "authorization_code" in gts:
                    for k in ("redirect_uris", "logo_uri", "response_types"):
                        if k not in c:
                            R.fail("SSRAA §3.1", f"softstmt.{k}", f"{k} required for authorization_code clients.")
                self._schema_check("softwareStatement", c, R.findings[n1:], "Software statement claims")
        basic = 0
        for i, cj in enumerate(certs or []):
            res = self._check_udap_jwt(cj, f"Certification[{i}]")
            if not res:
                continue
            cc, cleaf = res[1], res[2]
            nb = len(R.findings)
            self._check_cert_base(cc, cleaf, i)
            uris = cc.get("certification_uris")
            if not (isinstance(uris, list) and BASIC_APP_CERT_URI in uris):
                R.info("SSRAA §3.3", "cert.other", f"Certification[{i}] is not the TEFCA basic-app certification "
                       f"(uris {uris}).")
                continue
            basic += 1
            if cc.get("certification_name") != BASIC_APP_CERT_NAME:
                R.fail("FF §6.11(6)", "cert.certification_name", f"certification_name {cc.get('certification_name')!r}; "
                       f"fixed value {BASIC_APP_CERT_NAME!r}.")
            if uris != [BASIC_APP_CERT_URI]:
                R.fail("FF §6.11(6)", "cert.certification_uris", f"certification_uris {uris}; fixed one-element array.")
            xps = cc.get("exchange_purposes")
            if not (isinstance(xps, list) and len(xps) == 1):
                R.fail("FF §6.11(6)", "cert.exchange_purposes", f"exchange_purposes {xps!r}; an array of exactly one XP.")
            elif str(xps[0]).rpartition("#")[2] != XP_CODE:
                R.warn("FF §6.11(6)", "cert.exchange_purposes", f"exchange_purposes {xps} -- not an IAS registration.")
            else:
                R.ok("FF §6.11(6)", "cert.exchange_purposes", f"exchange_purposes {xps}")
            if not cc.get("home_community_id"):
                R.fail("FF §6.11(6)", "cert.home_community_id", "home_community_id missing (the registering Node's HCID).")
            if ss_iss and isinstance(xps, list) and xps and \
                    str(xps[0]).rpartition("#")[2] not in urllib.parse.urlsplit(str(ss_iss)).path:
                R.fail("FF §6.11(5)", "cert.xp.match", "Certification exchange_purposes does not match the XP in the "
                       "software statement SAN URI path.")
            self._schema_check("certification", cc, R.findings[nb:], "Basic-app certification claims (base + TEFCA)")
        if certs and not basic:
            R.fail("FF §6.11(3)", "regreq.certifications.basic", "No certification carries the TEFCA basic-app "
                   f"certification URI {BASIC_APP_CERT_URI}.")

    def _check_cert_base(self, cc: dict, leaf: Any, i: int) -> None:
        """UDAP Certification JWT base claims (UDAP C&E STU1; SSRAA §1.2.4), checked for EVERY certification
        before any TEFCA Basic App profile rules."""
        R, ref = self.R, "UDAP C&E STU1"
        n0 = len(R.findings)
        for k in ("iss", "sub", "exp", "iat", "jti"):
            v = cc.get(k)
            if v is None or v == "":
                R.fail(ref, f"cert.{k}", f"Certification[{i}] lacks required claim '{k}'.",
                       why="A UDAP certification is a JWT with its own iss, sub, exp, iat and jti (SSRAA §1.2.4 "
                           "requires iss, exp and jti for every SSRAA JWT).")
            elif k in ("exp", "iat") and (isinstance(v, bool) or not isinstance(v, (int, float))):
                R.fail(ref, f"cert.{k}", f"Certification[{i}] {k} is not a NumericDate.")
        exp, iat = cc.get("exp"), cc.get("iat")
        if isinstance(exp, (int, float)) and self.now > exp + self.a.clock_skew:
            (R.info if self.a.ignore_expiry else R.fail)(ref, "cert.exp.expired",
                                                         f"Certification[{i}] expired at {utc(exp)}.")
        if isinstance(iat, (int, float)) and iat > self.now + self.a.clock_skew:
            R.fail(ref, "cert.iat.future", f"Certification[{i}] iat {utc(iat)} is in the future.")
        if isinstance(exp, (int, float)) and isinstance(iat, (int, float)) and exp <= iat:
            R.fail(ref, "cert.exp.order", f"Certification[{i}] exp is not after iat.")
        sub = cc.get("sub")
        if sub and leaf is not None:
            sans = cert_san_uris(leaf)
            if sub in sans:
                R.ok(ref, "cert.sub.san", f"Certification[{i}] sub is a SAN URI of the client certificate")
            elif cc.get("iss") == sub:
                R.fail(ref, "cert.sub.san", f"Self-signed Certification[{i}] sub {sub!r} is not a SAN URI of its x5c "
                       f"certificate {sans}.", why="The certification is bound to the client by sub matching a "
                       "uniformResourceIdentifier SAN of the client certificate.")
            else:
                R.info(ref, "cert.sub.san", f"Certification[{i}] is issued by {cc.get('iss')!r} (third party); its sub "
                       f"{sub!r} should match a SAN URI of the CLIENT certificate, which is not in this JWT's x5c.")
        if cc.get("iss") and cc.get("iss") == sub:
            R.info(ref, "cert.selfsigned", f"Certification[{i}] is self-signed (iss == sub).")
        self._schema_check("certificationBase", cc, R.findings[n0:], f"Certification[{i}] base claims")

    # =================================================================== #
    # SSRAA discovery probe (IAS §4.6 Modes 1.2 / 2.3 -> SSRAA §2, FF §6.11(1)-(3), §6.12(1))
    # =================================================================== #
    UDAP_REQUIRED = ["udap_versions_supported", "udap_profiles_supported", "udap_authorization_extensions_supported",
                     "udap_certifications_supported", "grant_types_supported", "token_endpoint",
                     "token_endpoint_auth_methods_supported", "token_endpoint_auth_signing_alg_values_supported",
                     "registration_endpoint", "signed_metadata"]

    def check_ssraa(self, base: str) -> None:
        R, w, p = self.R, "ssraa", "sop"   # w = TEFCA adoption axis (date-gated); p = protocol axis (now)
        R.set_artifact(f"FHIR endpoint {base}")
        self.saw_udap = True
        R.info("4.6 SSRAA", "udap.precedence", "TEFCA IAS FHIR Endpoints must support SSRAA from July 1, 2027 "
               "(IAS §4.6(a)(1.2)/(b)(2.3)); this supersedes the FF §6.2 Q1-2027 / Jan-1-2027 milestones per IAS §4.2(b).")
        if self.a.no_network:
            R.skip("4.6 SSRAA", "udapmeta.fetch", "--no-network: /.well-known/udap not fetched.")
            return
        url = base.rstrip("/") + "/.well-known/udap?community=" + urllib.parse.quote(TEFCA_COMMUNITY_URI, safe=":")
        res = http_get(url, self.a.timeout, self.a.insecure)
        if res.status == 204:
            R.fail("FF §6.11(1)", "udapmeta.community", "204 No Content for the TEFCA community URI: the server does not "
                   f"recognize {TEFCA_COMMUNITY_URI} (SSRAA §2.4).", when=w)
            return
        doc = self._parse_metadata_response(res, "SSRAA §2.1", "udap", "UDAP metadata (/.well-known/udap)",
                                            auth_ref="SSRAA §2.1", when=w)
        if not isinstance(doc, dict):
            return
        R.info("4.6 SSRAA", "udap.axes", "Two axes: metadata that is published is checked for SSRAA/FF protocol "
               "conformance now; whether an IAS endpoint must publish it at all, and the IAS capability items "
               "(authorization_code, tefca_ias), are date-gated to July 1, 2027.")
        n0 = len(R.findings)
        for k in self.UDAP_REQUIRED:
            if k not in doc:
                R.fail("SSRAA §2.2", f"udapmeta.{k}", f"UDAP metadata lacks required '{k}'.", when=p)
        if doc.get("udap_versions_supported", ["1"]) != ["1"]:
            R.fail("SSRAA §2.2", "udapmeta.udap_versions_supported", "udap_versions_supported must be ['1'].", when=p)
        gts = doc.get("grant_types_supported") or []
        prof = doc.get("udap_profiles_supported") or []
        need = ["udap_dcr", "udap_authn"] + (["udap_authz"] if "client_credentials" in gts else [])
        miss = [x for x in need if x not in prof]
        if miss:
            R.fail("SSRAA §2.2", "udapmeta.udap_profiles_supported", f"udap_profiles_supported lacks {miss}.", when=p)
        if doc.get("token_endpoint_auth_methods_supported", ["private_key_jwt"]) != ["private_key_jwt"]:
            R.fail("SSRAA §2.2", "udapmeta.token_endpoint_auth_methods_supported", "must be ['private_key_jwt'].", when=p)
        exts = doc.get("udap_authorization_extensions_supported") or []
        if exts and "udap_authorization_extensions_required" not in doc:
            R.fail("SSRAA §2.2", "udapmeta.udap_authorization_extensions_required", "required when extensions are "
                   "supported.", when=p)
        cs = doc.get("udap_certifications_supported") or []
        if cs and "udap_certifications_required" not in doc:
            R.fail("SSRAA §2.2", "udapmeta.udap_certifications_required", "required when certifications are "
                   "supported.", when=p)
        if "refresh_token" in gts and "authorization_code" not in gts:
            R.fail("SSRAA §2.2", "udapmeta.grant_types_supported", "refresh_token listed without authorization_code.", when=p)
        if "authorization_code" in gts and "authorization_endpoint" not in doc:
            R.fail("SSRAA §2.2", "udapmeta.authorization_endpoint", "authorization_endpoint required with "
                   "authorization_code.", when=p)
        for k in ("token_endpoint", "registration_endpoint", "authorization_endpoint"):
            if k in doc and not str(doc[k]).startswith("https://"):
                R.fail("SSRAA §2.2", f"udapmeta.{k}", f"{k} {doc[k]!r} is not an absolute https URL.", when=p)
        if BASIC_APP_CERT_URI not in cs:
            R.fail("FF §6.11(2)", "udapmeta.udap_certifications_supported", "basic-app certification URI not in "
                   "udap_certifications_supported.", when=p)
        if BASIC_APP_CERT_URI not in (doc.get("udap_certifications_required") or []):
            R.fail("FF §6.11(3)", "udapmeta.udap_certifications_required", "basic-app certification URI not in "
                   "udap_certifications_required.", when=p)
        if "scopes_supported" not in doc:
            R.fail("FF §6.12(1)", "udapmeta.scopes_supported", "scopes_supported SHALL be present (FF), although "
                   "optional in SSRAA.", when=p)
        if "authorization_code" not in gts:
            R.fail("FF §6.11 IAS(1)", "udapmeta.grant_types_supported", "authorization_code not supported; FF requires "
                   "responders to support it for IAS. OPEN QUESTION: IAS §4.6 lets a responder choose its Response "
                   "Mode; supporting the grant is a technical capability, not Mode 1.", when=w)
        if "tefca_ias" not in exts:
            R.fail("FF §6.11 IAS(2)", "udapmeta.udap_authorization_extensions_supported", "tefca_ias not listed as "
                   "a supported authorization extension.", when=w)
        if "client_credentials" in gts and "hl7-b2b" not in exts:
            R.fail("SSRAA §2.2", "udapmeta.udap_authorization_extensions_supported", "client_credentials supported but "
                   "hl7-b2b not listed.", when=p)
        if "registration_endpoint_jwt_signing_alg_values_supported" not in doc:
            R.warn("SSRAA §2.2", "udapmeta.registration_endpoint_jwt_signing_alg_values_supported",
                   "RECOMMENDED metadata absent.")
        self._schema_check("udapMetadata", doc, R.findings[n0:], "UDAP metadata")
        R.info("FF §6.12(1)", "udapmeta.scopes", f"scopes_supported: {doc.get('scopes_supported')}")
        sm = doc.get("signed_metadata")
        if isinstance(sm, str):
            self._check_signed_metadata(sm, doc, base)

    def _check_signed_metadata(self, sm: str, doc: dict, base: str) -> None:
        R, w = self.R, "sop"   # protocol axis: published signed_metadata must conform now
        try:
            hdr, c, si, sig = decode_jws(sm)
        except Exception as e:  # noqa: BLE001
            R.fail("SSRAA §2.3", "sigmeta.format", f"signed_metadata is not a JWS: {e}", when=w)
            return
        if hdr.get("alg") != "RS256":
            R.fail("SSRAA §2.3", "sigmeta.alg", f"signed_metadata alg {hdr.get('alg')!r}; SHALL be RS256.", when=w)
        leaf = None
        x5c = hdr.get("x5c")
        if isinstance(x5c, list) and x5c:
            try:
                leaf = cert_from_x5c(x5c[0])
            except Exception as e:  # noqa: BLE001
                R.fail("SSRAA §2.3", "sigmeta.x5c", f"signed_metadata x5c[0] unreadable: {short(e, 80)}", when=w)
        else:
            R.fail("SSRAA §1.2.3", "sigmeta.x5c", "signed_metadata has no x5c header.", when=w)
        n0 = len(R.findings)
        iss = c.get("iss")
        if iss is not None and norm_url(str(iss)) != norm_url(base):
            R.fail("SSRAA §2.3", "sigmeta.iss.base", f"signed_metadata iss {iss!r} != FHIR base URL {base!r}.", when=w)
        if leaf is not None and iss not in cert_san_uris(leaf):
            R.fail("SSRAA §2.3", "sigmeta.iss.san", f"iss {iss!r} is not a SAN URI of the server certificate "
                   f"{cert_san_uris(leaf)}.", when=w)
        if c.get("sub") != iss:
            R.fail("SSRAA §2.3", "sigmeta.sub.eq", "signed_metadata sub must equal iss.", when=w)
        if isinstance(c.get("exp"), (int, float)) and isinstance(c.get("iat"), (int, float)) \
                and c["exp"] - c["iat"] > 366 * 86400:
            R.fail("SSRAA §2.3", "sigmeta.exp.lifetime", "signed_metadata exp is more than 1 year after iat.", when=w)
        for k in ("token_endpoint", "registration_endpoint", "authorization_endpoint"):
            if k in doc and k in c and c[k] != doc[k]:
                R.fail("SSRAA §2.3", "sigmeta.endpoint.mismatch", f"signed {k} {c[k]!r} != unsigned {doc[k]!r}.", when=w,
                       fix="Clients SHALL use the signed values; a mismatch usually means stale signed metadata.")
            elif k == "authorization_endpoint" and k in doc and k not in c:
                R.fail("SSRAA §2.3", "sigmeta.endpoint.mismatch", "authorization_endpoint in metadata but not in "
                       "signed_metadata.", when=w)
        self._schema_check("signedMetadata", c, R.findings[n0:], "signed_metadata claims")
        if leaf is not None and hdr.get("alg"):
            ok, why = verify_jws(str(hdr["alg"]), leaf.public_key(), si, sig)
            if ok:
                R.ok("SSRAA §2.3", "sigmeta.sig", "signed_metadata signature verifies with the x5c leaf key")
            elif ok is None:
                R.skip("SSRAA §2.3", "sigmeta.sig", f"signed_metadata signature not verified ({why}).")
            else:
                R.fail("SSRAA §2.3", "sigmeta.sig", f"signed_metadata: {why}.", when=w)

    # =================================================================== #
    # Coverage + manual items
    # =================================================================== #
    def coverage(self) -> None:
        R = self.R
        R.set_artifact("Cross-message coverage")
        names = {"PD": "Patient Discovery", "DQ": "Document Query", "DR": "Document Retrieval",
                 "FHIR": "FHIR authentication"}
        for k, lab in names.items():
            entries = self.msg_coverage[k]
            if not entries:
                R.info("4.4(f)", f"coverage.{k}", f"No {lab} artifact supplied -- token presence not verified.")
            elif all(ok for _, ok in entries):
                R.ok("4.4(f)", f"coverage.{k}", f"IAL2 Claims Token present in all {len(entries)} {lab} "
                     "artifact(s)")
            else:
                bad = [p for p, ok in entries if not ok]
                R.fail("4.4(f)", f"coverage.{k}", f"IAL2 Claims Token missing, mis-placed or undecodable in {lab}: {bad}",
                       fix="§4.4(f)/§4.9(d): the token MUST be in every PD, DQ, DR and FHIR auth request.")
        for sha in self.token_order:
            info = self.tokens[sha]
            jti = (info.get("claims") or {}).get("jti")
            if isinstance(jti, str):
                if jti in self.jti_seen and self.jti_seen[jti] != sha:
                    R.fail("4.9 Table 2", "jti.unique", f"jti {jti!r} reused by DIFFERENT tokens "
                           f"({self.tokens[self.jti_seen[jti]]['label']} and {info['label']}).", when="4.9")
                self.jti_seen.setdefault(jti, sha)

    MANUAL_ITEMS = [
        ("4.2(a)", "MUST", "All IAS exchange follows the QTF -- beyond this tool's specific checks; verify "
         "through QHIN conformance testing."),
        ("4.2(b)", "MUST", "Facilitated FHIR flows follow the Facilitated FHIR SOP (SSRAA dates per §4.6 "
         "1.2/2.3 supersede)."),
        ("4.3", "MUST", "CSP approved by an RCE-selected CSP approval organization (list on RCE website)."),
        ("4.3(a)", "MUST", "CSP identity proofing to at least NIST IAL2 (then-latest SP 800-63A) -- "
         "certification/attestation."),
        ("4.3(b)", "MUST", "CSP capable of verifying all 12 demographics incl. State ID/Driver's License "
         "(token observation above is partial evidence only)."),
        ("4.3(c)", "MUST", "CSP delivers a signed IAL2 Claims Token after verification -- a valid signature "
         "above is evidence."),
        ("4.4(a)", "MUST", "IAS Provider has an agreement with an approved CSP."),
        ("4.4(b)", "MUST", "IAS Provider authenticates Individuals at AAL2 (SP 800-63B)."),
        ("4.4(c)", "MUST", "IAL2 (re)verification before first TEFCA use, when verified demographics change, "
         "and when they expire/are invalidated by the CSP."),
        ("4.5", "MUST", "Required Information per the Exchange Purposes SOP."),
        ("4.6", "MUST", "Responding Node supports >=1 Response Mode; Mode indicated in the RCE Directory "
         "(60 days after directory fields are implemented)."),
        ("4.6(a) 1.1", "MUST", "Mode 1: on a possible match, respond with the TEFCA IAS FHIR Endpoint "
         "directory identifier."),
        ("4.6(b) 2.1-2.2", "MUST", "Mode 2: uniquely attributable match -> DQ identifier or directory "
         "identifier without portal login; respond with Required Information after the Double-Check."),
        ("4.7(a)", "MUST", "IAS Provider runs the Demographics Double-Check (IAL2 + self-asserted vs PD "
         "response) [from 2027-01-01]."),
        ("4.7(a)(i)", "MUST", "No-match: reject response; do not retain patient id; no further IAS Query to "
         "that node except via Mode 1; MAY offer FHIR Authorization Code flow."),
        ("4.7(a)(ii)", "MUST", "No-match: notify the organization behind the Responding Node (directly or via "
         "its QHIN)."),
        ("4.7(b)", "MUST", "Wrong-person data reported by the Individual: timely notify the responder's "
         "organization; timely purge erroneous data."),
        ("4.9(b)", "ENCOURAGED", "Nodes validate issuer, audience, validity window, signature and "
         "proofed-identity-to-patient -- this tool performs these checks."),
        ("4.9(f)", "INFO", "Compare artifacts with RCE-published examples when available."),
        ("FF §6.1(3) / TTR", "MUST", "UDAP certificates chain to an RCE-approved TEFCA CA per the Technical Trust "
         "Requirements; validate x5c chains against the TEFCA trust bundle (not available to this tool)."),
        ("FF §6.1(3)(a)", "MUST", "Directory Entry lists the supported registration and authn/authz standards and the "
         "TEFCA FHIR Endpoint."),
        ("FF §6.11(4)", "MUST", "Initiating Nodes register a separate client application per Exchange Purpose."),
        ("FF §6.11(7)-(9)", "MUST", "client_id rotation on registration modification: client uses only the new id; server "
         "disables the old id and preserves retired ids for log correlation."),
        ("FF §6.11(10)", "MUST", "Server answers invalid_scope (does not silently downgrade to system scope) when a user "
         "scope is requested without a user at registration."),
        ("FF §6.11 IAS(5)", "MUST", "Responder returns invalid_grant when the submitted user information does not match a "
         "known person or the IAS workflow is unsupported."),
        ("FF §6.12(2)-(14)", "MIXED", "Scope negotiation behaviour (wildcards, subsets/supersets, error choice, scope in "
         "token response when granted != requested)."),
        ("FF §6.10(3)", "MAY", "Refresh tokens only for Authorization Code clients authorized for offline_access."),
        ("SSRAA §1.2.4", "MUST", "jti not reused for the same iss before expiry; replay trackers allow reuse after expiry."),
        ("OPEN QUESTION", "RCE", "IAS §4.4(f) puts the IAL2 token in 'applicable' FHIR authentication requests, while "
         "SSRAA omits extensions for authorization_code. Which Mode 1 / auth-code requests are 'applicable'?"),
        ("OPEN QUESTION", "RCE", "FF §6.11 IAS(1) requires responders to support the Authorization Code grant for IAS; "
         "IAS §4.6 lets responders choose their Response Mode. Confirm the grant-support requirement applies to "
         "Mode-2-only responders."),
        ("OPEN QUESTION", "RCE", "FF Table 2 makes organization_id a relative reference ('Organization/<id>'); SSRAA "
         "§5.2.1.1 says the value SHALL be a URI. Confirm validators accept the relative form."),
        ("OPEN QUESTION", "RCE", "RCE IAS workgroup (Oct 22, 2026): should the SOP advise lifetimes for the IAL2 Claims "
         "Token and the CSP refresh token? Table 2 says only 'short-lived'; the SOP is silent on the CSP refresh token. "
         "Set --max-lifetime once a number is agreed."),
        ("OPEN QUESTION", "RCE", "RCE IAS workgroup (Oct 22, 2026): refined aud language ('whose HCID') is pending. "
         "Current text: Table 2 and footnote 13 (the HCID of the IAS Provider's Directory Entry; Bulletin 2 §5(b): of "
         "the intended recipient). Recommendation recorded: the value should comply with the FHIR oid data type."),
        ("OPEN QUESTION", "RCE", "RCE IAS workgroup (Oct 22, 2026): sunset dates for the Bulletin 2 temporary measures "
         "(§3(b)/(c)) are under discussion. When the RCE gives notice (§3(g)), re-run with --b2-3g-notice <date>."),
    ]

    def manual_items(self) -> None:
        R = self.R
        R.set_artifact("Attestation / process items (not machine-testable)")
        for ref, lvl, text in self.MANUAL_ITEMS:
            R.manual(ref, "attest", text, level=lvl)
        if self.b2:
            R.manual("B2 intro", "attest", "QHINs process IAS Claims Tokens under QHIN Compliance Bulletin No. 2 from "
                     f"{B2_ISSUED.isoformat()}; a QHIN that cannot must tell the RCE its expected compliance date and "
                     f"report progress daily; non-compliance as of {B2_DEADLINE} may bring consequences under the "
                     "Consequences for QHIN Non-Compliance SOP. Recipient behaviour to confirm by testing: accept aud as "
                     "a string or one-element array and treat them as equivalent (§5(c)); accept historical_address as "
                     "an object or an array (§4); accept an unverified email/phone only under §3(b)/(c); treat an "
                     "absent *_verified flag as verified (§3(e)-(f)).", level="MUST")
            R.manual("B2 §3(g)", "attest", "Watch for the RCE notice ending the temporary §3(b)/(c) permissions; from "
                     "then on, no unverified claims (IAS §4.9(a)(iii)). Re-run with --b2-3g-notice <notice date>.",
                     level="MUST")
            R.manual("B2 Next Steps", "INFO", "The Bulletin says technical examples will be shared separately; compare "
                     "tokens with them when published (cf. IAS §4.9(f)).", level="INFO")


# --------------------------------------------------------------------------- #
# Obligation table (from x-obligation / x-source annotations)
# --------------------------------------------------------------------------- #
def obligation_rows(S: SchemaSet) -> List[Tuple[str, str, str, str, str]]:
    rows: List[Tuple[str, str, str, str, str]] = []

    def walk(node: Any, path: str, layer: str) -> None:
        if isinstance(node, list):
            for n in node:
                walk(n, path, layer)
            return
        if not isinstance(node, dict):
            return
        if "x-obligation" in node or "x-precedence" in node:
            note = node.get("description", "")
            if node.get("x-precedence"):
                note = f"[precedence: {node['x-precedence']}] " + note
            rows.append((layer, path, node.get("x-obligation", "-"), node.get("x-source", ""), note))
        for rule in node.get("x-not-expressible", []):
            rows.append((layer, path, "NOT-EXPRESSIBLE", "", rule))
        for k, v in node.get("properties", {}).items():
            walk(v, f"{path}.{k}", layer)
        for k, v in node.get("patternProperties", {}).items():
            walk(v, f"{path}[/{k}/]", layer)
        if "propertyNames" in node:
            walk(node["propertyNames"], f"{path}{{names}}", layer)
        for k in ("items", "then", "allOf"):
            if k in node:
                walk(node[k], f"{path}[]" if k == "items" else path, layer)

    for sid, doc in S.docs.items():
        for dname, d in doc.get("$defs", {}).items():
            walk(d, dname, LAYER_NAME[sid])
    return rows


def print_obligations(S: SchemaSet, fmt: str, out=sys.stdout) -> None:
    rows = obligation_rows(S)
    if fmt == "csv":
        import csv
        w = csv.writer(out)
        w.writerow(["layer", "path", "obligation", "source", "note"])
        w.writerows(rows)
        return
    print(f"{'LAYER':<13} {'PATH':<52} {'OBLIGATION':<17} SOURCE / NOTE", file=out)
    for layer, path, obl, src, note in rows:
        print(f"{layer:<13} {short(path, 52):<52} {obl:<17} {src}{' -- ' + note if note else ''}", file=out)


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
COLORS = {"FAIL": "\033[1;31m", "PENDING": "\033[35m", "WARN": "\033[33m", "PASS": "\033[32m",
          "INFO": "\033[36m", "SKIP": "\033[90m", "MANUAL": "\033[34m"}
RESET = "\033[0m"


def render(rep: Report, args: argparse.Namespace, out=sys.stdout) -> None:
    use_color = out.isatty() and not args.no_color

    def tag(st: str) -> str:
        t = f"[{st:<7}]"
        return f"{COLORS.get(st, '')}{t}{RESET}" if use_color else t

    hide = set()
    if args.problems_only:
        hide = {"PASS", "INFO", "SKIP", "MANUAL"}
    print("=" * 100, file=out)
    print(f"IAS SOP checker v{VERSION} -- {SOP_NAME}", file=out)
    print(f"Evaluated as of {rep.as_of.isoformat()}  |  token clock {utc(args.at.timestamp()) if args.at else 'now'}"
          f"  |  PHI {'SHOWN' if rep.show_phi else 'masked'}", file=out)
    pr = rep.profile
    if pr.get("bulletin2"):
        print(f"Rule set: IAS SOP v3.0 + QHIN Compliance Bulletin No. 2 v1.0 ({pr['basis']}; issued {pr['issued']}, "
              f"QHIN compliance by {pr['qhin_deadline']})  |  §3(b)/(c) temporary permissions: "
              f"{pr['temporary_permissions_3b_3c']}"
              + (f" (RCE notice {pr['b2_3g_notice']})" if pr.get("b2_3g_notice") else ""), file=out)
    elif pr:
        print(f"Rule set: IAS SOP v3.0 text only -- QHIN Compliance Bulletin No. 2 not applied ({pr['basis']})", file=out)
    print("=" * 100, file=out)
    for art in rep.artifact_order:
        fs = [f for f in rep.findings if f.artifact == art and f.status not in hide]
        if not fs:
            continue
        print(f"\n## {art}", file=out)
        for f in fs:
            ref = ("§" if f.ref[:1].isdigit() else "") + f.ref
            print(f"  {tag(f.status)} {ref:<16} {f.check:<34} {f.message}", file=out)
            if f.status in ("FAIL", "PENDING", "WARN") or args.verbose:
                if f.evidence:
                    print(f"{'':14}evidence: {f.evidence}", file=out)
                if f.why:
                    print(f"{'':14}why:      {f.why}", file=out)
                if f.fix:
                    print(f"{'':14}fix:      {f.fix}", file=out)
            elif f.evidence and args.verbose:
                print(f"{'':14}evidence: {f.evidence}", file=out)

    # rollup by SOP reference
    print("\n" + "-" * 100, file=out)
    print("REQUIREMENT ROLLUP (worst status per SOP reference)", file=out)
    worst: Dict[str, str] = {}
    for f in rep.findings:
        if f.ref in ("input",):
            continue
        cur = worst.get(f.ref)
        if cur is None or STATUS_RANK[f.status] < STATUS_RANK[cur]:
            worst[f.ref] = f.status

    def refkey(r: str):
        return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", r)]
    for ref in sorted(worst, key=refkey):
        print(f"  {tag(worst[ref])} {'§' if ref[:1].isdigit() else ''}{ref}", file=out)
    counts = {s: sum(1 for f in rep.findings if f.status == s) for s in STATUS_RANK}
    print("-" * 100, file=out)
    print("TOTALS  " + "  ".join(f"{k}={v}" for k, v in counts.items()), file=out)
    verdict = "NON-CONFORMANT" if counts["FAIL"] else ("CONFORMANT WITH WARNINGS / PENDING" if
                                                         counts["WARN"] or counts["PENDING"] else "CONFORMANT")
    print(f"VERDICT (machine-testable items only): {verdict}", file=out)
    if counts["PENDING"]:
        print("  PENDING = would fail, but the §4.8 compliance date is after the evaluation date.", file=out)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=f"Check TEFCA IAS artifacts against the {SOP_NAME}.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  # Live CSP token: discovery + JWKS + signature + all claim checks
  %(prog)s --token-file id_token.jwt --expected-aud urn:oid:2.16.840.1.113883.3.XXXX

  # Captured QHIN traffic (PD/DQ/DR) + responder answer, replayed at capture time
  %(prog)s --soap pd.xml dq.xml dr.mtom --xcpd-response pd_resp.xml \\
           --at 2026-10-05T14:03:00Z --expected-aud urn:oid:2.16.840.1.113883.3.XXXX

  # Facilitated FHIR / UDAP artifacts for an IAS client-credentials flow
  %(prog)s --fhir-auth token_request.txt --udap-registration reg.json --oauth-response token_resp.json \
           --token-endpoint https://as.example/token --registration-endpoint https://as.example/register \
           --requested-scope "system/Patient.rs" --fhir-base https://fhir.example/r4

  # QHIN Compliance Bulletin No. 2 is applied automatically from 2026-10-13; compare with the SOP-text reading,
  # or model the RCE notice that ends the temporary unverified email/phone permissions (§3(g))
  %(prog)s --payload claims.json --bulletin2 off
  %(prog)s --token-file t.jwt --b2-3g-notice 2026-12-01 --as-of 2026-12-02

  # Print the obligation / precedence table built from the schema annotations
  %(prog)s --obligations csv > obligations.csv

  # Offline (no network), with environment separation check
  %(prog)s --token-file t.jwt --discovery-file disc.json --jwks-file jwks.json \\
           --prod-issuer https://id.csp.example --nonprod-issuer https://sandbox.id.csp.example \\
           --environment production
""")
    g = ap.add_argument_group("inputs")
    g.add_argument("--token", help="Compact JWT ID token")
    g.add_argument("--token-file", help="File with the JWT, or a JSON CSP token response with 'id_token'")
    g.add_argument("--soap", nargs="+", default=[], metavar="FILE",
                   help="Captured XCPD / XCA DQ / XCA DR request(s) (XML, MTOM or HTTP capture)")
    g.add_argument("--xcpd-response", nargs="+", default=[], metavar="FILE",
                   help="Captured XCPD response(s) (PRPA_IN201306UV02)")
    g.add_argument("--payload", nargs="+", default=[], metavar="FILE",
                   help="Decoded IAL2 token payload(s) (claims JSON, or {header, payload}); payload/profile checks only")
    g.add_argument("--fhir-auth", nargs="+", default=[], metavar="FILE",
                   help="UDAP client assertion JWT, token-request form body, or JSON with 'extensions'")
    g.add_argument("--fhir-base", nargs="+", default=[], metavar="URL",
                   help="TEFCA IAS FHIR base URL(s) to probe for SSRAA /.well-known/udap?community=<TEFCA URI>")
    g.add_argument("--oauth-response", nargs="+", default=[], metavar="FILE",
                   help="Captured OAuth token response or token error response (JSON)")
    g.add_argument("--udap-registration", nargs="+", default=[], metavar="FILE",
                   help="Captured UDAP registration request JSON (software_statement, certifications, udap)")
    g.add_argument("--discovery-file", help="Offline OIDC discovery JSON (skips network fetch)")
    g.add_argument("--jwks-file", help="Offline JWKS JSON (skips network fetch)")
    sg = ap.add_argument_group("json schema")
    sg.add_argument("--schema-dir", help="Directory holding oidc-core-1.0.schema.json and "
                    "tefca-ias-sop-v3.schema.json (default: this script's directory)")
    sg.add_argument("--schema-strict", action="store_true",
                    help="Validate claims with idTokenClaimsStrict (reject un-namespaced unknown claims)")
    sg.add_argument("--no-schema", action="store_true", help="Disable the JSON Schema cross-check")
    sg.add_argument("--obligations", nargs="?", const="text", choices=["text", "csv"],
                    help="Print the obligation table from the schema annotations and exit")
    c = ap.add_argument_group("expectations")
    c.add_argument("--expected-aud", help="IAS Provider HCID (urn:oid:... or bare OID)")
    c.add_argument("--prod-issuer", help="CSP production issuer URL (§4.3(e))")
    c.add_argument("--nonprod-issuer", help="CSP non-production issuer URL (§4.3(e))")
    c.add_argument("--environment", choices=["production", "nonproduction"],
                   help="Environment the artifacts came from")
    c.add_argument("--xp-code-system", default=DEFAULT_XP_CODE_SYSTEM,
                   help=f"Expected PurposeOfUse codeSystem OID (default {DEFAULT_XP_CODE_SYSTEM})")
    c.add_argument("--token-endpoint", help="Expected token endpoint (Authentication JWT aud)")
    c.add_argument("--registration-endpoint", help="Expected registration endpoint (software statement aud)")
    c.add_argument("--allow-missing-claims-version", action="store_true",
                   help="Analysis only: do not FAIL an absent tefca_ial2claims_version (SOP-text reading, SHOULD). "
                        "Production policy since 2026-10-01, and QHIN Compliance Bulletin No. 2 §2(a), require the "
                        "claim with value \"3.0\"")
    c.add_argument("--bulletin2", choices=["auto", "on", "off"], default="auto",
                   help="Apply TEFCA QHIN Compliance Bulletin No. 2 v1.0 (aud one-element array, historical_address "
                        "array, temporary unverified email/phone, version \"3.0\"). auto (default) = on when --as-of "
                        f"is on or after {B2_ISSUED.isoformat()} (Issue Date); off = IAS SOP v3.0 text reading only")
    c.add_argument("--b2-3g-notice", type=dt.date.fromisoformat, default=None, metavar="DATE",
                   help="Date of the RCE notice that ends the temporary Bulletin 2 §3(b)/(c) permissions (§3(g)). "
                        "From that date (vs --as-of) an unverified email or phone_number FAILs (IAS §4.9(a)(iii)). "
                        "A date on or before --as-of also reproduces the production 'no unverified data' decision")
    c.add_argument("--require-claims-version", action="store_true",
                   help="Deprecated no-op: requiring the claim is now the default")
    c.add_argument("--hop", choices=["qhin-qhin", "participant-qhin", "unknown"], default="unknown",
                   help="Transport hop of SOAP captures. QTF-501 algorithm violations are a hard FAIL only for "
                        "qhin-qhin; unknown (default) reports WARN; participant-qhin reports INFO")
    c.add_argument("--ssraa-in-use", choices=["auto", "yes", "no", "unknown"], default="auto",
                   help="Protocol axis: are the OAuth artifacts part of an SSRAA (UDAP) transaction? auto = yes if a "
                        "UDAP token request, registration or metadata is in the same run, else unknown")
    c.add_argument("--grant-type", choices=["client_credentials", "authorization_code"],
                   help="Grant type of the FHIR artifacts when not evident from a token request body")
    c.add_argument("--requested-scope", help="Space-delimited scopes the client requested (token-response comparison)")
    c.add_argument("--max-lifetime", type=int, default=3600,
                   help="WARN if exp-iat exceeds this many seconds (default 3600)")
    t = ap.add_argument_group("time")
    t.add_argument("--as-of", type=dt.date.fromisoformat, default=None,
                   help="Date for §4.8 compliance-date evaluation (default: today, UTC)")
    t.add_argument("--at", type=lambda s: dt.datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
                   if dt.datetime.fromisoformat(s.replace("Z", "+00:00")).tzinfo
                   else dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc),
                   help="Evaluate exp/iat as of this instant (e.g. capture time 2026-10-05T14:03:00Z)")
    t.add_argument("--ignore-expiry", action="store_true", help="Report expiry as INFO instead of FAIL")
    t.add_argument("--clock-skew", type=int, default=300, help="Allowed clock skew seconds (default 300)")
    n = ap.add_argument_group("network")
    n.add_argument("--no-network", action="store_true", help="Never fetch discovery/JWKS/UDAP")
    n.add_argument("--insecure", action="store_true", help="Skip TLS verification (diagnosis only)")
    n.add_argument("--allow-http", action="store_true", help="Tolerate http:// issuer/jwks_uri (lab only)")
    n.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout seconds (default 15)")
    o = ap.add_argument_group("output")
    o.add_argument("--show-phi", action="store_true", help="Print demographic values unmasked")
    o.add_argument("--dump-token", action="store_true", help="Print decoded header/claims (masked unless --show-phi)")
    o.add_argument("--problems-only", action="store_true", help="Show only FAIL/PENDING/WARN findings")
    o.add_argument("--no-manual", action="store_true", help="Omit the attestation/process checklist")
    o.add_argument("--json-report", metavar="PATH", help="Also write findings as JSON")
    o.add_argument("-v", "--verbose", action="store_true", help="Show evidence/why/fix for every finding")
    o.add_argument("--debug", action="store_true", help="Debug logging to stderr (HTTP, parsing, decisions)")
    o.add_argument("--no-color", action="store_true")
    a = ap.parse_args(argv)
    if not a.obligations and not any([a.token, a.token_file, a.payload, a.soap, a.xcpd_response, a.fhir_auth, a.fhir_base,
                                      a.oauth_response, a.udap_registration]):
        ap.error("supply at least one input (--token/--token-file/--payload/--soap/--xcpd-response/--fhir-auth/--fhir-base/"
                 "--oauth-response/--udap-registration)")
    return a


def load_token_arg(a: argparse.Namespace, rep: Report) -> Optional[str]:
    if a.token:
        return a.token
    if not a.token_file:
        return None
    try:
        with open(a.token_file, "r", encoding="utf-8-sig") as fh:
            s = fh.read().strip()
    except OSError as e:
        rep.fail("input", "token.read", f"Cannot read {a.token_file}: {e}")
        return None
    if s.startswith("{"):
        try:
            obj = json.loads(s)
        except json.JSONDecodeError as e:
            rep.fail("input", "token.json", f"{a.token_file} looks like JSON but is invalid: {e}")
            return None
        if isinstance(obj, dict) and "id_token" in obj:
            rep.info("input", "token.response", "Extracted 'id_token' from a CSP token response JSON.")
            if "access_token" in obj:
                rep.info("input", "token.response", "Note: access_token is NOT the IAL2 Claims Token -- "
                         "only id_token is relayed.")
            if "refresh_token" in obj:
                life = [f"{k}={obj[k]!r}" for k in ("refresh_expires_in", "refresh_token_expires_in") if k in obj]
                rep.info("input", "token.response.refresh",
                         "The CSP token response includes a refresh_token (kept by the IAS Provider; not relayed, and "
                         "not the IAL2 Claims Token). IAS SOP v3.0 is silent on the use and lifetime of the CSP refresh "
                         f"token; recommended lifetimes for the IAL2 Claims Token and the refresh token were on the "
                         f"agenda of the {WG_2026_10_22}, with no number set. "
                         + (f"Refresh lifetime given (non-standard field): {', '.join(life)}." if life else
                            "OAuth 2.0 defines no refresh-token lifetime field, and none is present.")
                         + (f" expires_in={obj['expires_in']!r} is the access token's lifetime (RFC 6749 §5.1)."
                            if "expires_in" in obj else ""))
            return obj["id_token"]
        rep.fail("input", "token.json", "JSON file has no 'id_token' member.")
        return None
    return s


def main(argv: Optional[List[str]] = None) -> int:
    a = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.debug else logging.WARNING, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    as_of = a.as_of or dt.datetime.now(dt.timezone.utc).date()
    if a.b2_3g_notice and a.bulletin2 == "off":
        print("ias_sop_checker: --b2-3g-notice has no effect with --bulletin2 off", file=sys.stderr)
    rep = Report(as_of, a.show_phi)
    chk = IasChecker(a, rep)
    if not a.no_schema or a.obligations:
        import os
        sdir = a.schema_dir or os.path.dirname(os.path.abspath(__file__))
        chk.schemas = SchemaSet(sdir, explicit=bool(a.schema_dir), rep=rep)
    if a.obligations:
        if not chk.schemas.ok:
            for f in rep.findings:
                print(f"{f.status}: {f.message}", file=sys.stderr)
            return 2
        print_obligations(chk.schemas, a.obligations)
        return 0
    if not HAVE_CRYPTO:
        rep.set_artifact("environment")
        rep.warn("env", "cryptography", "Python package 'cryptography' not installed: signature and x5c "
                 "checks will be SKIPPED.", fix="pip install cryptography")
    log.debug("args=%s as_of=%s", vars(a), as_of)

    tok = load_token_arg(a, rep)
    if tok is not None:
        rep.set_artifact("--token input")
        chk.process_token(tok, "--token input")
    for p in a.soap:
        chk.process_soap(p)
    for p in a.fhir_auth:
        chk.process_fhir(p)
    for p in a.payload:
        chk.process_payload(p)
    for p in a.xcpd_response:
        chk.process_pd_response(p)
    for p in a.udap_registration:
        chk.process_udap_registration(p)
    for p in a.oauth_response:
        chk.process_oauth_response(p)
    for u in a.fhir_base:
        chk.check_ssraa(u)
    if a.soap or a.fhir_auth:
        chk.coverage()
    elif chk.tokens:
        rep.set_artifact("Cross-message coverage")
        rep.info("4.4(f)", "coverage", "Token checked standalone; supply --soap PD/DQ/DR captures and "
                 "--fhir-auth to verify it is relayed in every IAS request.")
    if not a.no_manual:
        chk.manual_items()
    render(rep, a)
    if a.json_report:
        with open(a.json_report, "w", encoding="utf-8") as fh:
            json.dump({"tool": f"ias_sop_checker {VERSION}", "sop": SOP_NAME, "as_of": as_of.isoformat(),
                       "rule_set": dict(rep.profile, bulletin=B2_NAME if rep.profile.get("bulletin2") else None),
                       "findings": [asdict(f) for f in rep.findings]}, fh, indent=2)
        print(f"\nJSON report written to {a.json_report}")
    return 1 if any(f.status == "FAIL" for f in rep.findings) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
