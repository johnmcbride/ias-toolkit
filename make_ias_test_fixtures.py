#!/usr/bin/env python3
"""Generate synthetic test fixtures for ias_sop_checker.py (all demographics are fictitious).

Usage:
  python3 make_ias_test_fixtures.py [--output-dir DIR] [--issuer URL] [--fhir-base URL] [--force]
  python3 make_ias_test_fixtures.py --help

Writes into --output-dir (default ./ias_fixtures) and refuses to overwrite a non-empty directory unless
--force is given. Fresh keys are generated on every run, so tokens verify only against that run's jwks.json,
and time-based claims are set at generation time (ID tokens expire after 10 minutes; use --at or
--ignore-expiry with the checker later). manifest.json lists every fixture and its intended outcome.
The regression suite (test_ias_toolkit.py) drives this generator and asserts the checker's findings.
"""
import base64
import datetime as dt
import json
import os
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

import argparse

ap = argparse.ArgumentParser(description="Generate synthetic IAS / UDAP / OAuth test fixtures.")
ap.add_argument("--output-dir", default="ias_fixtures", help="Directory to write fixtures into (default ./ias_fixtures)")
ap.add_argument("--issuer", default="https://id.csp.example", help="CSP issuer URL placed in the ID tokens")
ap.add_argument("--fhir-base", default="http://127.0.0.1:8765/fhir",
                help="FHIR base URL used for the server certificate SAN and signed_metadata iss")
ap.add_argument("--force", action="store_true", help="Overwrite an existing non-empty output directory")
args = ap.parse_args()
if os.path.isdir(args.output_dir) and os.listdir(args.output_dir) and not args.force:
    ap.error(f"output directory {args.output_dir!r} is not empty; pass --force to overwrite it")
os.makedirs(args.output_dir, exist_ok=True)
os.chdir(args.output_dir)
ISS = args.issuer
FHIR_BASE = args.fhir_base
MANIFEST = {}
XP_SYS = "urn:oid:2.16.840.1.113883.3.7204.1.5.2.1"
BASIC = "https://rce.sequoiaproject.org/udap/profiles/basic-app-certification"
CLIENT_SAN = "https://ias.example.org/fhir-client/T-IAS"
TOKEN_EP = "https://as.responder.example/token"
REG_EP = "https://as.responder.example/register"
now = int(time.time())


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64(b):
    return base64.b64encode(b).decode()


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def mk_cert(subject_cn, subject_key, issuer_cert, issuer_key, ca=False, san=None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    b = (x509.CertificateBuilder().subject_name(name)
         .issuer_name(issuer_cert.subject if issuer_cert else name)
         .public_key(subject_key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(dt.datetime(2026, 1, 1)).not_valid_after(dt.datetime(2028, 12, 31))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san)]), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def der(c):
    return b64(c.public_bytes(serialization.Encoding.DER))


def sign(hdr, claims, key, pss=False):
    si = b64u(json.dumps(hdr).encode()) + "." + b64u(json.dumps(claims).encode())
    pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32) if pss else padding.PKCS1v15()
    return si + "." + b64u(key.sign(si.encode(), pad, hashes.SHA256()))


def dump(name, obj, note=None):
    os.makedirs(os.path.dirname(name) or ".", exist_ok=True)
    with open(name, "w") as fh:
        fh.write(obj if isinstance(obj, str) else json.dumps(obj, indent=2))
    if note:
        MANIFEST[name] = note


# ---------------------------------------------------------------- CSP keys / OIDC metadata
csp_key = new_key()
csp_cert = mk_cert("csp", csp_key, None, csp_key)
pn = csp_key.public_key().public_numbers()
jwk = {"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256", "n": b64u(pn.n.to_bytes(256, "big")),
       "e": b64u(pn.e.to_bytes(3, "big")), "x5c": [der(csp_cert)]}
dump("jwks.json", {"keys": [jwk]})
dump("disc.json", {"issuer": ISS, "authorization_endpoint": ISS + "/auth", "token_endpoint": ISS + "/token",
                   "jwks_uri": ISS + "/jwks", "response_types_supported": ["code"],
                   "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"]})

# ---------------------------------------------------------------- IAL2 tokens
good = {"iss": ISS, "sub": "abc123", "aud": "urn:oid:2.16.840.1.113883.3.9999.1", "iat": now, "exp": now + 600,
        "jti": str(uuid.uuid4()), "given_name": "Mary Ann", "family_name": "Smith", "middle_name": "Q",
        "birthdate": "1980-02-29",
        "address": {"street_address": "123 Main Street", "locality": "Farragut", "region": "TN",
                    "postal_code": "37934", "country": "US"},
        "email": "mary@example.com", "phone_number": "+1 865 555 0100", "tefca_ial2claims_version": "3.0"}
G = sign({"alg": "RS256", "kid": "k1", "typ": "JWT"}, good, csp_key)
dump("good.jwt", G, "GOOD: IAL2 Claims Token (expires 10 minutes after generation)")
bad = dict(good)
bad.update({"aud": "2.16.840.1.113883.3.9999.1", "birthdate": "19800229", "tefca_ial2claims_version": 3.0,
            "address": {"street": "123 Main St", "locality": "Farragut", "region": "US-TN", "postal_code": "7934",
                        "country": "USA"},
            "email_verified": False, "middle_initial": "Q", "exp": now + 86400})
del bad["jti"]
dump("bad.jwt", sign({"alg": "RS256", "kid": "k2"}, bad, csp_key, pss=True),
     "BAD: PSS signature, unknown kid, no typ, bare-OID aud, HL7 birthdate, US-TN, USA, numeric version, "
     "email_verified false, no jti")

# ---------------------------------------------------------------- Decoded payloads (memo / Mohammed review cases)
# Reconstructions of the cases named in the revision memo; Mohammed's original files were not supplied.
HIST = {"street_address": "9 Old Mill Road", "locality": "Knoxville", "region": "TN", "postal_code": "37902",
        "country": "US"}


def variant(**changes):
    c = json.loads(json.dumps(good))
    for k, v in changes.items():
        if v is None:
            c.pop(k, None)
        else:
            c[k] = v
    return c


PAYLOADS = {
    "valid-baseline-v3.json": (variant(), "GOOD: claims with tefca_ial2claims_version '3.0'"),
    "valid-historical-address-object.json": (variant(historical_address=HIST),
                                             "GOOD: historical_address as one address object"),
    # Names kept from the memo. Under QHIN Compliance Bulletin No. 2 (checker default from 2026-10-13) the first
    # three are VALID; they FAIL only under the SOP-text reading (--bulletin2 off).
    "invalid-aud-is-an-array.json": (variant(aud=[good["aud"]]),
                                     "SOP-text: aud.type FAIL. Bulletin 2 §5(a): VALID one-element array (aud.form INFO)"),
    "invalid-historical-address-is-array.json": (
        variant(historical_address=[HIST]),
        "SOP-text: historical_address.type FAIL. Bulletin 2 §4(a): VALID array of one Address object"),
    "temp-valid-unverified-email-but-verified-phone.json": (
        variant(email_verified=False, phone_number_verified=True),
        "SOP-text: email_verified FAIL. Bulletin 2 §3(b): VALID while the temporary permission lasts (b2.3b INFO); "
        "b2.3g FAIL with --b2-3g-notice on or before --as-of"),
    "invalid-claims-version-1.0.json": (variant(tefca_ial2claims_version="1.0"),
                                        "BAD (v3.0 baseline): version '1.0' -> tefca_ial2claims_version.value FAIL"),
    "missing-claims-version.json": (variant(tefca_ial2claims_version=None),
                                    "BAD (production decision, from 2026-10-01): absent version -> tefca_ial2claims_version.required FAIL; the SOP-text SHOULD is also reported as WARN"),
    # ---- QHIN Compliance Bulletin No. 2 (toolkit 1.5.0)
    "b2-invalid-aud-two-element-array.json": (variant(aud=[good["aud"], "urn:oid:2.16.840.1.113883.3.9999.2"]),
                                              "BAD (Bulletin 2 §5(a)): aud array of two -> aud.type FAIL"),
    "b2-invalid-aud-empty-array.json": (variant(aud=[]), "BAD (Bulletin 2 §5(a)): aud = [] -> aud.type FAIL"),
    "b2-valid-historical-address-array.json": (
        variant(historical_address=[HIST, dict(HIST, street_address="44 Elm Street", postal_code="37919")]),
        "GOOD (Bulletin 2 §4): historical_address array of two Address objects"),
    "b2-invalid-historical-address-array-bad-element.json": (
        variant(historical_address=[HIST, dict(HIST, region="Tennessee")]),
        "BAD (Bulletin 2 §4(b), IAS Table 3): second element region 'Tennessee' -> historical_address[1].region FAIL"),
    "b2-invalid-historical-address-empty-array.json": (
        variant(historical_address=[]), "BAD (Bulletin 2 §4(a)): empty array -> historical_address.type FAIL"),
    "b2-temp-valid-unverified-phone-but-verified-email.json": (
        variant(phone_number_verified=False, email_verified=True),
        "TEMPORARILY VALID (Bulletin 2 §3(c)): unverified phone with a verified email -> b2.3c INFO"),
    "b2-invalid-unverified-email-no-phone.json": (
        variant(email_verified=False, phone_number=None),
        "BAD (Bulletin 2 §3(a)-(b)): unverified email and no phone -> email|phone_number FAIL"),
    "b2-invalid-both-unverified.json": (
        variant(email_verified=False, phone_number_verified=False),
        "BAD (Bulletin 2 §3(d)): email and phone both unverified -> email|phone_number FAIL"),
    # ---- RCE IAS workgroup, October 22, 2026 (toolkit 1.6.0)
    "wg-aud-uppercase-prefix.json": (variant(aud="URN:OID:2.16.840.1.113883.3.9999.1"),
                                     "WARN only: upper-case URN:OID: prefix is a valid OID URN (RFC 3061, RFC 8141) but "
                                     "not the FHIR oid form -> aud.case WARN; aud.expected PASS by URN-equivalence"),
    "wg-invalid-country-UK.json": (variant(address=dict(good["address"], country="UK")),
                                   "BAD: country 'UK' is reserved, not an assigned ISO 3166-1 alpha-2 code (use GB) "
                                   "-> address.country FAIL"),
    "wg-invalid-region-lowercase.json": (variant(address=dict(good["address"], region="tn")),
                                         "BAD: region 'tn' is not upper case -> address.region FAIL"),
    "b2-invalid-verified-flag-string.json": (
        variant(email_verified="true"),
        "BAD (Bulletin 2 §3(f), OIDC Core §5.1): email_verified is the string 'true' -> email_verified.type FAIL"),
}
for name, (claims, note) in PAYLOADS.items():
    dump(f"payloads/{name}", claims, note)
dump("tok_history_object.jwt", sign({"alg": "RS256", "kid": "k1", "typ": "JWT"}, variant(historical_address=HIST), csp_key),
     "GOOD: signed token with historical_address as one object")
dump("tok_aud_array.jwt", sign({"alg": "RS256", "kid": "k1", "typ": "JWT"}, variant(aud=[good["aud"]]), csp_key),
     "Signed token with aud as a one-element array: VALID under Bulletin 2 §5; aud.type FAIL with --bulletin2 off")
dump("tok_history_array.jwt", sign({"alg": "RS256", "kid": "k1", "typ": "JWT"}, variant(historical_address=[HIST]),
                                   csp_key),
     "Signed token with historical_address as an array: VALID under Bulletin 2 §4; FAIL with --bulletin2 off")
TOK_B2_UNV = sign({"alg": "RS256", "kid": "k1", "typ": "JWT"}, variant(email_verified=False, phone_number_verified=True),
                  csp_key)
dump("csp_token_response_refresh.json",
     {"id_token": G, "access_token": "at-" + uuid.uuid4().hex, "token_type": "Bearer", "expires_in": 300,
      "refresh_token": "rt-" + uuid.uuid4().hex, "refresh_token_expires_in": 2592000},
     "CSP token response with a refresh_token -> token.response.refresh INFO (the SOP is silent on refresh tokens)")
dump("tok_b2_unverified_email.jwt", TOK_B2_UNV,
     "Signed token with an unverified email and a verified phone: temporarily valid under Bulletin 2 §3(b)")

# ---------------------------------------------------------------- SOAP
SIG_OK = ('<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>'
          '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
          '<ds:Reference><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></ds:Reference>'
          '</ds:SignedInfo></ds:Signature>')
SIG_SHA1 = SIG_OK.replace("xmldsig-more#rsa-sha256", "xmldsig#rsa-sha1").replace("xmlenc#sha256", "xmldsig#sha1")


def pou_xml(code="T-IAS", cs="2.16.840.1.113883.3.7204.1.5.2.1", elem="PurposeOfUse", ns="urn:hl7-org:v3"):
    csattr = f' codeSystem="{cs}"' if cs else ""
    return (f'<{elem} xmlns="{ns}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CE" '
            f'code="{code}"{csattr}/>')


def soap(body, tok=G, name="urn:ietf:params:oauth:token-type:id_token",
         fmt=' NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"', pou="T-IAS",
         cs="2.16.840.1.113883.3.7204.1.5.2.1", sig=SIG_OK, pou_elem=None):
    pe = pou_elem if pou_elem is not None else pou_xml(pou, cs)
    attr = (f'<saml2:Attribute Name="{name}"{fmt}><saml2:AttributeValue>{tok}</saml2:AttributeValue>'
            '</saml2:Attribute>') if tok else ""
    return f'''<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
<s:Header><a:Action>urn:x</a:Action><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">{sig}<saml2:AttributeStatement>
<saml2:Attribute Name="urn:oasis:names:tc:xspa:1.0:subject:purposeofuse"><saml2:AttributeValue>{pe}</saml2:AttributeValue></saml2:Attribute>
<saml2:Attribute Name="urn:nhin:names:saml:homeCommunityId"><saml2:AttributeValue>urn:oid:2.16.840.1.113883.3.1111</saml2:AttributeValue></saml2:Attribute>
{attr}</saml2:AttributeStatement></saml2:Assertion></wsse:Security></s:Header><s:Body>{body}</s:Body></s:Envelope>'''


pd = '''<PRPA_IN201305UV02 xmlns="urn:hl7-org:v3"><controlActProcess><queryByParameter><parameterList>
<livingSubjectAdministrativeGender><value code="F"/></livingSubjectAdministrativeGender>
<livingSubjectBirthTime><value value="19800229"/></livingSubjectBirthTime>
<livingSubjectName><value><given>Mary</given><given>Ann</given><given>Q</given><family>Smith</family></value></livingSubjectName>
<patientAddress><value><streetAddressLine>123 Main St</streetAddressLine><city>Farragut</city><state>TN</state><postalCode>37934</postalCode><country>US</country></value></patientAddress>
<patientTelecom><value value="mailto:mary@example.com"/></patientTelecom>
<patientTelecom><value value="tel:+18655550100"/></patientTelecom>
</parameterList></queryByParameter></controlActProcess></PRPA_IN201305UV02>'''
dump("pd.xml", soap(pd), "GOOD: XCPD request, token in SAML, coded T-IAS, rsa-sha256")
dump("pd_notpou.xml", soap(pd, pou_elem=pou_xml(elem="NotPurposeOfUse")),
     "BAD: right code/codeSystem on an element that is not PurposeOfUse -> xp.saml.coded FAIL")
dump("pd_wrongns.xml", soap(pd, pou_elem=pou_xml(ns="urn:example:not-hl7")),
     "BAD: PurposeOfUse in the wrong namespace -> xp.saml.coded FAIL")
dump("pd_nocodesystem.xml", soap(pd, pou_elem=pou_xml(cs=None)),
     "BAD: PurposeOfUse without codeSystem -> xp.saml.codesystem FAIL")
dump("pd_sha1.xml", soap(pd, sig=SIG_SHA1),
     "HOP-DEPENDENT: SHA-1 assertion signature -> FAIL with --hop qhin-qhin, INFO participant-qhin, WARN unknown")
dump("pd_bad.xml", soap(pd.replace("<given>Ann</given>", "").replace("19800229", "19800228")
                        .replace('<patientTelecom><value value="mailto:mary@example.com"/></patientTelecom>', ""),
                        name="id_token", fmt="", pou="T-TRTMNT", cs="2.16.840.1.113883.3.18.7.1", sig=SIG_SHA1),
     "BAD: mis-named token attribute, T-TRTMNT, HL7 code system, SHA-1, demographics mismatch")
dump("pd_b2_unverified_email.xml",
     soap(pd.replace('<patientTelecom><value value="mailto:mary@example.com"/></patientTelecom>', ""), tok=TOK_B2_UNV),
     "GOOD (Bulletin 2 §3(b)): token email is unverified, so the XCPD body need not carry it (§4.4(e))")
dump("dq.xml", soap('<query:AdhocQueryRequest xmlns:query="urn:oasis:names:tc:ebxml-regrep:xsd:query:3.0"/>'),
     "GOOD: XCA Document Query with token")
dump("dr.mtom", "--uuid:1\r\nContent-Type: application/xop+xml\r\n\r\n"
     + soap('<RetrieveDocumentSetRequest xmlns="urn:ihe:iti:xds-b:2007"/>', tok=None) + "\r\n--uuid:1--",
     "BAD: MTOM Document Retrieve WITHOUT the token -> coverage.DR FAIL")
dump("resp.xml", '''<PRPA_IN201306UV02 xmlns="urn:hl7-org:v3"><acknowledgement><typeCode code="AA"/></acknowledgement><controlActProcess>
<subject><registrationEvent><subject1><patient><id root="1.2.3.4" extension="PAT77"/><patientPerson>
<name><given>Mary</given><family>Smyth</family></name><administrativeGenderCode code="F"/><birthTime value="19800229"/>
<addr><streetAddressLine>123 Main St.</streetAddressLine><city>Farragut</city><state>TN</state><postalCode>37934-1234</postalCode></addr>
</patientPerson></patient></subject1><custodian><assignedEntity><id root="2.16.840.1.113883.3.5555"/></assignedEntity></custodian></registrationEvent></subject>
<queryAck><queryResponseCode code="OK"/></queryAck></controlActProcess></PRPA_IN201306UV02>''')

# ---------------------------------------------------------------- Test PKI for UDAP
root_key, int_key, cli_key, srv_key = new_key(), new_key(), new_key(), new_key()
root = mk_cert("Test TEFCA Root", root_key, None, root_key, ca=True)
inter = mk_cert("Test TEFCA Intermediate", int_key, root, root_key, ca=True)
cli = mk_cert("ias-client", cli_key, inter, int_key, san=CLIENT_SAN)
srv = mk_cert("fhir-server", srv_key, inter, int_key, san=FHIR_BASE)
CHAIN = [der(cli), der(inter)]

patient = {"resourceType": "Patient", "name": [{"given": ["Mary", "Ann", "Q"], "family": "Smith"}],
           "birthDate": "1980-02-29", "gender": "female",
           "address": [{"line": ["123 Main St"], "city": "Farragut", "state": "TN", "postalCode": "37934",
                        "country": "US"}],
           "telecom": [{"system": "email", "value": "mary@example.com"}, {"system": "phone", "value": "+18655550100"}]}
related = {"resourceType": "RelatedPerson", "patient": {"reference": "Patient/self"},
           "relationship": [{"coding": [{"system": "http://terminology.hl7.org/CodeSystem/v3-RoleCode",
                                         "code": "ONESELF"}]}]}
b2b = {"version": "1", "organization_id": "Organization/2.16.840.1.113883.3.9999.1",
       "organization_name": "Example IAS App", "purpose_of_use": [XP_SYS + "#T-IAS"]}
tia = {"version": "1", "user_information": related, "patient_information": patient, "id_token": G}
auth = {"iss": "client-123", "sub": "client-123", "aud": TOKEN_EP, "iat": now, "exp": now + 300,
        "jti": str(uuid.uuid4()), "extensions": {"hl7-b2b": b2b, "tefca_ias": tia}}
assertion = sign({"alg": "RS256", "x5c": CHAIN}, auth, cli_key)
FORM = ("grant_type=client_credentials&client_assertion_type="
        "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion={}&udap=1")
dump("fhir_cc.txt", FORM.format(assertion), "GOOD: IAS client-credentials token request (hl7-b2b + tefca_ias)")
abs_auth = json.loads(json.dumps(auth))
abs_auth["extensions"]["hl7-b2b"]["organization_id"] = "https://directory.example/fhir/Organization/2.16.840.1.113883.3.9999.1"
dump("fhir_cc_absorg.txt", FORM.format(sign({"alg": "RS256", "x5c": CHAIN}, abs_auth, cli_key)),
     "BAD (FF Table 2): absolute organization_id -> b2b.organization_id FAIL; relative form is an unresolved conflict")
imp_key = new_key()
impostor = mk_cert("Test TEFCA Intermediate", imp_key, root, root_key, ca=True)
dump("fhir_badchain.txt", FORM.format(sign({"alg": "RS256", "x5c": [der(cli), der(impostor)]}, auth, cli_key)),
     "BAD: x5c[1] has the intermediate's subject DN but did not sign the leaf -> udapjwt.chain FAIL")
bad_pt = json.loads(json.dumps(patient))
bad_pt["birthDate"] = "1980-03-01"
bad_auth = {"iss": CLIENT_SAN, "sub": "client-123", "aud": TOKEN_EP, "iat": now, "exp": now + 600,
            "jti": str(uuid.uuid4()),
            "extensions": {"hl7-b2b": {"version": "1", "purpose_of_use": ["T-IAS", "T-TRTMNT"],
                                       "organization_id": "https://directory.example/fhir/Organization/2.16.1"},
                           "tefca_ias": {"version": "2", "purpose_of_use": "T-IAS", "patient_information": bad_pt,
                                         "id_token": G}}}
dump("fhir_bad.jwt", sign({"alg": "RS256", "x5c": [der(cli)]}, bad_auth, cli_key),
     "BAD: Authentication JWT with leaf-only x5c, iss != sub, 600 s life, bad hl7-b2b and tefca_ias")

# ---------------------------------------------------------------- OAuth responses
dump("token_resp.json", {"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600,
                         "scope": "system/Patient.rs system/Observation.rs"}, "GOOD: token response")
dump("token_resp_7200.json", {"access_token": "at-3", "token_type": "Bearer", "expires_in": 7200},
     "TWO-AXIS: 7200 s token -> SSRAA protocol FAIL (when SSRAA in use) + TEFCA adoption PENDING until 2027-07-01")
dump("token_resp_bad.json", {"access_token": "at-2", "token_type": "Bearer", "expires_in": 7200,
                             "refresh_token": "rt-1"}, "BAD: 7200 s token plus a refresh token")
dump("token_err.json", {"error": "invalid_grant", "error_description": "consent policy required",
                        "extensions": {"hl7-b2b": {"consent_required": ["urn:oid:2.16.840.1.113883.3.7204.1.1.1.1.2.1"],
                                                   "consent_form": "https://responder.example/consent.pdf"}}},
     "GOOD: invalid_grant with the TEFCA consent error extension")

# ---------------------------------------------------------------- UDAP registration
ss = {"iss": CLIENT_SAN, "sub": CLIENT_SAN, "aud": REG_EP, "iat": now, "exp": now + 300, "jti": str(uuid.uuid4()),
      "client_name": "Example IAS App", "contacts": ["mailto:ops@ias.example.org"], "grant_types": ["client_credentials"],
      "token_endpoint_auth_method": "private_key_jwt", "scope": "system/Patient.rs"}
cert_claims = {"iss": CLIENT_SAN, "sub": CLIENT_SAN, "iat": now, "exp": now + 300, "jti": str(uuid.uuid4()),
               "certification_name": "TEFCA Basic App Certification", "certification_uris": [BASIC],
               "exchange_purposes": ["T-IAS"], "home_community_id": "urn:oid:2.16.840.1.113883.3.9999.1"}
SS_JWT = sign({"alg": "RS256", "x5c": CHAIN}, ss, cli_key)


def reg_with(cert):
    return {"software_statement": SS_JWT, "certifications": [sign({"alg": "RS256", "x5c": CHAIN}, cert, cli_key)],
            "udap": "1"}


dump("reg.json", reg_with(cert_claims), "GOOD: registration with software statement and basic-app certification")
dump("reg_cert_missing_base.json",
     reg_with({k: v for k, v in cert_claims.items() if k not in ("iss", "sub", "exp", "iat", "jti")}),
     "BAD: signed basic-app certification without iss/sub/exp/iat/jti -> cert.iss/sub/exp/iat/jti FAIL")
dump("reg_cert_missing_exp.json", reg_with({k: v for k, v in cert_claims.items() if k != "exp"}),
     "BAD: certification without exp -> cert.exp FAIL")
dump("reg_cert_sub_mismatch.json", reg_with(dict(cert_claims, iss="https://other.example/app",
                                                  sub="https://other.example/app")),
     "BAD: self-signed certification whose sub is not a SAN URI of its certificate -> cert.sub.san FAIL")
ss_bad = dict(ss, iss="https://ias.example.org/fhir-client", sub="https://ias.example.org/fhir-client",
              exp=now + 900, grant_types=["client_credentials", "authorization_code"], contacts=["ops@ias.example.org"])
cert_bad = dict(cert_claims, certification_name="TEFCA Basic App Cert", exchange_purposes=["T-IAS", "T-TRTMNT"])
del cert_bad["home_community_id"]
dump("reg_bad.json", {"software_statement": sign({"alg": "RS256", "x5c": CHAIN}, ss_bad, cli_key),
                      "certifications": [sign({"alg": "RS256", "x5c": CHAIN}, cert_bad, cli_key)]},
     "BAD: no udap, iss not a SAN, no XP in SAN path, 900 s statement, both grants, bad certification fields")

# ---------------------------------------------------------------- UDAP metadata (served from srv/)
meta = {"udap_versions_supported": ["1"], "udap_profiles_supported": ["udap_dcr", "udap_authn", "udap_authz"],
        "udap_authorization_extensions_supported": ["hl7-b2b", "tefca_ias"],
        "udap_authorization_extensions_required": ["hl7-b2b"],
        "udap_certifications_supported": [BASIC], "udap_certifications_required": [BASIC],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "scopes_supported": ["openid", "offline_access", "system/*.rs", "patient/*.rs"],
        "authorization_endpoint": "https://as.responder.example/authorize", "token_endpoint": TOKEN_EP,
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
        "registration_endpoint": REG_EP, "registration_endpoint_jwt_signing_alg_values_supported": ["RS256"]}
meta["signed_metadata"] = sign({"alg": "RS256", "x5c": [der(srv), der(inter)]},
                               {"iss": FHIR_BASE, "sub": FHIR_BASE, "iat": now, "exp": now + 86400 * 30,
                                "jti": str(uuid.uuid4()), "token_endpoint": TOKEN_EP, "registration_endpoint": REG_EP,
                                "authorization_endpoint": meta["authorization_endpoint"]}, srv_key)
dump("srv/fhir/.well-known/udap", meta, "GOOD: UDAP metadata served at <fhir-base>/.well-known/udap")
bad_meta = json.loads(json.dumps(meta))
for k in ("scopes_supported", "udap_certifications_required"):
    bad_meta.pop(k)
bad_meta.update({"udap_certifications_supported": [], "udap_authorization_extensions_supported": ["hl7-b2b"],
                 "token_endpoint": TOKEN_EP + "2", "udap_profiles_supported": ["udap_dcr", "udap_authn"]})
dump("srv/bad/.well-known/udap", bad_meta, "BAD: UDAP metadata for <server>/bad: TEFCA items missing, stale signed_metadata")
dump("manifest.json", MANIFEST)
print(f"{len(MANIFEST)} fixtures written to {os.getcwd()}")
