#!/usr/bin/env python3
"""Assertion-based regression suite for the IAS toolkit (v1.6.0) (ias_sop_checker.py, the seven schema layers and
make_ias_test_fixtures.py). QHIN Compliance Bulletin No. 2 applies by default (evaluation date on or after
2026-10-13); tests of the SOP-text reading pass --bulletin2 off. Keep all toolkit files in one directory, then run:

    python3 test_ias_toolkit.py -v

Every checker run asserts specific named findings and, unless a test deliberately loosens a schema, that no
schema-vs-checker DRIFT warning appears. A local HTTP server serves the generated UDAP metadata.
Requires: cryptography, jsonschema>=4.18.
"""
import base64
import functools
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER = os.path.join(HERE, "ias_sop_checker.py")
GEN = os.path.join(HERE, "make_ias_test_fixtures.py")
SCHEMAS = ["oidc-core-1.0.schema.json", "oauth2-core.schema.json", "hl7-udap-security-1.1.0.schema.json",
           "tefca-facilitated-fhir-v2.schema.json", "tefca-ias-sop-v3.schema.json",
           "tefca-ias-sop-v3.recommended.schema.json", "tefca-qhin-bulletin-2.schema.json"]
OFFLINE = ["--discovery-file", "disc.json", "--jwks-file", "jwks.json"]
AUD = ["--expected-aud", "urn:oid:2.16.840.1.113883.3.9999.1"]


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):  # noqa: D401
        pass


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _mutate_jwt(tok, fn):
    """Return the token with its payload changed by fn (signature becomes invalid; used for schema tests)."""
    h, p, s = tok.split(".")
    claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    fn(claims)
    return ".".join([h, _b64u(json.dumps(claims).encode()), s])


class IasToolkit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="ias_regress_")
        cls.fx = os.path.join(cls.tmp, "fx")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = sock.getsockname()[1]
        cls.base = f"http://127.0.0.1:{cls.port}/fhir"
        r = subprocess.run([sys.executable, GEN, "--output-dir", cls.fx, "--fhir-base", cls.base],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        handler = functools.partial(_Quiet, directory=os.path.join(cls.fx, "srv"))
        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", cls.port), handler)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ------------------------------------------------------------ helpers
    def run_checker(self, *args, schema_dir=None, allow_drift=False):
        type(self).n += 1
        rep = os.path.join(self.tmp, f"report_{self.n}.json")
        cmd = [sys.executable, CHECKER, *args, "--no-manual", "--no-color", "--json-report", rep]
        if schema_dir:
            cmd += ["--schema-dir", schema_dir]
        r = subprocess.run(cmd, cwd=self.fx, capture_output=True, text=True)
        self.assertTrue(os.path.exists(rep), f"checker produced no report: {r.stderr[-2000:]}")
        with open(rep) as fh:
            self.last_report = json.load(fh)
        findings = self.last_report["findings"]
        if not allow_drift:
            drift = [f["check"] + ": " + f["message"] for f in findings if f["check"].endswith(".drift")]
            self.assertEqual(drift, [], "unexpected schema/checker drift")
        return findings

    def st(self, findings, check):
        return {f["status"] for f in findings if f["check"] == check}

    def assertStatus(self, findings, check, status):
        got = self.st(findings, check)
        self.assertIn(status, got, f"expected {check}={status}, got {got or 'nothing'}")

    def assertNotStatus(self, findings, check, status):
        self.assertNotIn(status, self.st(findings, check), f"{check} unexpectedly {status}")

    def assertNoFail(self, findings):
        fails = [f"{f['check']}: {f['message']}" for f in findings if f["status"] == "FAIL"]
        self.assertEqual(fails, [], "unexpected FAIL findings")

    def loosened_schemas(self, edit):
        d = tempfile.mkdtemp(dir=self.tmp)
        for f in SCHEMAS:
            shutil.copy(os.path.join(HERE, f), d)
        edit(d)
        return d

    @staticmethod
    def edit_json(path, fn):
        with open(path) as fh:
            doc = json.load(fh)
        fn(doc)
        with open(path, "w") as fh:
            json.dump(doc, fh)

    # ------------------------------------------------------------ generator / schemas
    def test_00_generator_help_does_not_write(self):
        d = tempfile.mkdtemp(dir=self.tmp)
        r = subprocess.run([sys.executable, GEN, "--help"], cwd=d, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("usage", r.stdout)
        self.assertEqual(os.listdir(d), [], "--help must not write fixtures")

    def test_01_generator_rejects_unknown_flag_and_refuses_overwrite(self):
        r = subprocess.run([sys.executable, GEN, "--bogus"], cwd=self.tmp, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        r = subprocess.run([sys.executable, GEN, "--output-dir", self.fx], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("--force", r.stderr)

    def test_02_schemas_meta_valid_and_refs_resolve(self):
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
        docs = []
        for f in SCHEMAS:
            with open(os.path.join(HERE, f)) as fh:
                docs.append(json.load(fh))
        for d in docs:
            Draft202012Validator.check_schema(d)
        reg = Registry().with_resources([(d["$id"], Resource.from_contents(d)) for d in docs])
        for d in docs:
            for name in d["$defs"]:
                list(Draft202012Validator({"$ref": f"{d['$id']}#/$defs/{name}"}, registry=reg).iter_errors({}))

    def test_03_obligations_use_new_precedence_vocabulary(self):
        r = subprocess.run([sys.executable, CHECKER, "--obligations", "csv"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("unresolved-conflict", r.stdout)
        self.assertNotIn("stricter-of", r.stdout)

    # ------------------------------------------------------------ good artifacts
    def test_10_good_suite_has_no_fail_and_no_drift(self):
        f = self.run_checker("--soap", "pd.xml", "dq.xml", "--xcpd-response", "resp.xml", "--fhir-auth", "fhir_cc.txt",
                             "--udap-registration", "reg.json", "--oauth-response", "token_resp.json", "token_err.json",
                             "--fhir-base", self.base, "--token-endpoint", "https://as.responder.example/token",
                             "--registration-endpoint", "https://as.responder.example/register", "--hop", "qhin-qhin",
                             *OFFLINE, *AUD)
        self.assertNoFail(f)
        for c in ("xp.saml", "xp.saml.codesystem", "udapjwt.chain", "udapjwt.sig", "cert.sub.san", "piv",
                  "sigmeta.sig", "coverage.PD", "coverage.DQ", "coverage.FHIR"):
            self.assertStatus(f, c, "PASS")

    # ------------------------------------------------------------ HIGH #1: certification base claims
    def test_20_certification_missing_base_claims_fail(self):
        f = self.run_checker("--udap-registration", "reg_cert_missing_base.json")
        for k in ("iss", "sub", "exp", "iat", "jti"):
            self.assertStatus(f, f"cert.{k}", "FAIL")

    def test_21_certification_missing_exp_fails(self):
        f = self.run_checker("--udap-registration", "reg_cert_missing_exp.json")
        self.assertStatus(f, "cert.exp", "FAIL")
        for k in ("iss", "sub", "iat", "jti"):
            self.assertNotStatus(f, f"cert.{k}", "FAIL")

    def test_22_certification_sub_not_bound_to_certificate_fails(self):
        f = self.run_checker("--udap-registration", "reg_cert_sub_mismatch.json")
        self.assertStatus(f, "cert.sub.san", "FAIL")

    # ------------------------------------------------------------ HIGH #2: XUA PurposeOfUse structure
    def test_30_wrong_purposeofuse_element_fails(self):
        f = self.run_checker("--soap", "pd_notpou.xml", *OFFLINE)
        self.assertStatus(f, "xp.saml.coded", "FAIL")
        self.assertNotStatus(f, "xp.saml", "PASS")

    def test_31_wrong_purposeofuse_namespace_fails(self):
        f = self.run_checker("--soap", "pd_wrongns.xml", *OFFLINE)
        self.assertStatus(f, "xp.saml.coded", "FAIL")
        self.assertNotStatus(f, "xp.saml", "PASS")

    def test_32_missing_codesystem_fails(self):
        f = self.run_checker("--soap", "pd_nocodesystem.xml", *OFFLINE)
        self.assertStatus(f, "xp.saml.codesystem", "FAIL")

    def test_33_wrong_code_and_codesystem_fail(self):
        f = self.run_checker("--soap", "pd_bad.xml", *OFFLINE)
        self.assertStatus(f, "xp.saml", "FAIL")
        self.assertStatus(f, "xp.saml.codesystem", "FAIL")

    # ------------------------------------------------------------ MEDIUM: QTF-501 hop context
    def test_40_sha1_qhin_qhin_fails(self):
        f = self.run_checker("--soap", "pd_sha1.xml", "--hop", "qhin-qhin", *OFFLINE)
        self.assertStatus(f, "saml.signature.method", "FAIL")
        self.assertStatus(f, "saml.signature.digest", "FAIL")

    def test_41_sha1_participant_qhin_is_not_qtf501_fail(self):
        f = self.run_checker("--soap", "pd_sha1.xml", "--hop", "participant-qhin", *OFFLINE)
        self.assertNotStatus(f, "saml.signature.method", "FAIL")
        self.assertStatus(f, "saml.signature.method", "INFO")

    def test_42_sha1_unknown_hop_warns(self):
        f = self.run_checker("--soap", "pd_sha1.xml", *OFFLINE)
        self.assertStatus(f, "saml.signature.method", "WARN")

    # ------------------------------------------------------------ MEDIUM: organization_id conflict
    def test_50_relative_organization_id_passes_with_conflict_note(self):
        f = self.run_checker("--fhir-auth", "fhir_cc.txt", *OFFLINE)
        self.assertStatus(f, "b2b.organization_id", "PASS")
        self.assertStatus(f, "b2b.organization_id.conflict", "INFO")

    def test_51_absolute_organization_id_fails_ff_table2(self):
        f = self.run_checker("--fhir-auth", "fhir_cc_absorg.txt", *OFFLINE)
        self.assertStatus(f, "b2b.organization_id", "FAIL")

    # ------------------------------------------------------------ MEDIUM: token lifetime two axes
    def test_60_long_token_before_adoption_date(self):
        f = self.run_checker("--oauth-response", "token_resp_7200.json", "--ssraa-in-use", "yes", "--as-of", "2027-01-01")
        self.assertStatus(f, "tokresp.expires_in.ssraa", "FAIL")
        self.assertStatus(f, "tokresp.expires_in.max", "PENDING")

    def test_61_long_token_after_adoption_date(self):
        f = self.run_checker("--oauth-response", "token_resp_7200.json", "--ssraa-in-use", "yes", "--as-of", "2027-08-01")
        self.assertStatus(f, "tokresp.expires_in.ssraa", "FAIL")
        self.assertStatus(f, "tokresp.expires_in.max", "FAIL")

    def test_62_long_token_protocol_axis_depends_on_ssraa_use(self):
        self.assertStatus(self.run_checker("--oauth-response", "token_resp_7200.json", "--ssraa-in-use", "no"),
                          "tokresp.expires_in.ssraa", "INFO")
        self.assertStatus(self.run_checker("--oauth-response", "token_resp_7200.json"),
                          "tokresp.expires_in.ssraa", "WARN")
        f = self.run_checker("--oauth-response", "token_resp_7200.json", "--fhir-auth", "fhir_cc.txt", *OFFLINE)
        self.assertStatus(f, "tokresp.expires_in.ssraa", "FAIL")  # auto: a UDAP request is in the same run

    # ------------------------------------------------------------ LOW/MEDIUM: x5c linkage
    def test_70_impostor_intermediate_fails_chain(self):
        f = self.run_checker("--fhir-auth", "fhir_badchain.txt", *OFFLINE)
        self.assertStatus(f, "udapjwt.chain", "FAIL")
        self.assertStatus(f, "udapjwt.sig", "PASS")   # the JWT itself is validly signed by the leaf

    # ------------------------------------------------------------ prior bad fixtures fail for intended reasons
    def test_80_bad_id_token(self):
        f = self.run_checker("--token-file", "bad.jwt", *OFFLINE)
        for c in ("hdr.typ", "aud.format", "birthdate.format", "address.region", "address.country",
                  "tefca_ial2claims_version", "jti", "sig.kid", "sig.pss"):
            self.assertStatus(f, c, "FAIL")
        self.assertStatus(f, "b2.3b", "INFO")          # email_verified=false + verified phone: Bulletin 2 §3(b)
        f = self.run_checker("--token-file", "bad.jwt", "--bulletin2", "off", *OFFLINE)
        self.assertStatus(f, "email_verified", "FAIL")  # SOP-text reading

    def test_81_bad_fhir_assertion(self):
        f = self.run_checker("--fhir-auth", "fhir_bad.jwt", *OFFLINE)
        for c in ("udapjwt.x5c", "authjwt.issub", "authjwt.exp.lifetime", "b2b.organization_id",
                  "b2b.organization_name", "b2b.purpose_of_use", "tefca_ias.version", "tefca_ias.user_information",
                  "piv.birthdate"):
            self.assertStatus(f, c, "FAIL")
        self.assertStatus(f, "tefca_ias.purpose_of_use", "WARN")

    def test_82_bad_registration(self):
        f = self.run_checker("--udap-registration", "reg_bad.json")
        for c in ("regreq.udap", "softstmt.iss.san", "softstmt.iss.xp", "softstmt.exp.lifetime",
                  "softstmt.grant_types", "cert.certification_name", "cert.exchange_purposes",
                  "cert.home_community_id"):
            self.assertStatus(f, c, "FAIL")

    def test_83_bad_token_response(self):
        f = self.run_checker("--oauth-response", "token_resp_bad.json", "--grant-type", "client_credentials")
        self.assertStatus(f, "tokresp.refresh_token.grant", "FAIL")

    def test_84_bad_soap_and_coverage(self):
        f = self.run_checker("--soap", "pd.xml", "dq.xml", "dr.mtom", "pd_bad.xml", *OFFLINE)
        self.assertStatus(f, "coverage.DR", "FAIL")
        self.assertStatus(f, "saml.id_token.name", "FAIL")

    def test_85_bad_udap_metadata_protocol_now_capability_pending(self):
        f = self.run_checker("--fhir-base", self.base.replace("/fhir", "/bad"), "--as-of", "2026-12-01")
        for c in ("udapmeta.udap_certifications_supported", "udapmeta.scopes_supported", "sigmeta.iss.base",
                  "sigmeta.endpoint.mismatch"):
            self.assertStatus(f, c, "FAIL")                       # protocol axis: published metadata, checked now
        self.assertStatus(f, "udapmeta.udap_authorization_extensions_supported", "PENDING")  # IAS capability, 2027

    # ------------------------------------------------------------ drift detection still works in every layer
    def test_90_drift_recommended_layer(self):
        # the version claim moved to the MUST layer (v1.4.0), so prove recommended-layer drift with email.format
        with open(os.path.join(self.fx, "payloads", "valid-baseline-v3.json")) as fh:
            claims = json.load(fh)
        claims.update(email="a@nodot", email_verified=True)
        with open(os.path.join(self.fx, "payloads", "_nodot.json"), "w") as fh:
            json.dump(claims, fh)
        d = self.loosened_schemas(lambda d: self.edit_json(
            os.path.join(d, "tefca-ias-sop-v3.recommended.schema.json"),
            lambda s: s["$defs"]["idTokenClaimsDelta"]["properties"].pop("email")))
        f = self.run_checker("--payload", os.path.join("payloads", "_nodot.json"), schema_dir=d, allow_drift=True)
        self.assertStatus(f, "email.format", "WARN")
        self.assertStatus(f, "schema.idTokenClaims.recommended.drift", "WARN")

    def test_91_drift_must_layer_nested_address(self):
        def edit(d):
            def fn(s):
                s["$defs"]["address"]["properties"]["region"] = {}
                s["$defs"]["address"]["then"]["properties"].pop("region")
            self.edit_json(os.path.join(d, "tefca-ias-sop-v3.schema.json"), fn)
        f = self.run_checker("--token-file", "bad.jwt", *OFFLINE, schema_dir=self.loosened_schemas(edit),
                             allow_drift=True)
        self.assertStatus(f, "schema.idTokenClaims.drift", "WARN")

    def test_92_drift_certification_base_layer(self):
        d = self.loosened_schemas(lambda d: self.edit_json(
            os.path.join(d, "hl7-udap-security-1.1.0.schema.json"),
            lambda s: s["$defs"]["certificationJwtClaims"].update({"required": []})))
        f = self.run_checker("--udap-registration", "reg_cert_missing_base.json", schema_dir=d, allow_drift=True)
        self.assertStatus(f, "schema.certificationBase.drift", "WARN")


    # ------------------------------------------------------------ v1.3.2: revision memo (Mohammed schema review)
    def payload(self, name, *extra, mutate=None):
        """Run --payload on a generated payload fixture, optionally mutated first."""
        path = os.path.join("payloads", name)
        if mutate:
            with open(os.path.join(self.fx, path)) as fh:
                claims = json.load(fh)
            mutate(claims)
            type(self).n += 1
            path = os.path.join("payloads", f"_mut_{self.n}.json")
            with open(os.path.join(self.fx, path), "w") as fh:
                json.dump(claims, fh)
        return self.run_checker("--payload", path, *extra)

    def test_100_memo_A_aud_array_fails(self):
        f = self.payload("invalid-aud-is-an-array.json", "--bulletin2", "off")
        self.assertStatus(f, "aud.type", "FAIL")
        f = self.run_checker("--token-file", "tok_aud_array.jwt", "--bulletin2", "off", *OFFLINE)  # validly signed
        self.assertStatus(f, "aud.type", "FAIL")
        self.assertStatus(f, "sig.verify", "PASS")

    def test_101_memo_A_string_oid_aud_passes(self):
        f = self.payload("valid-baseline-v3.json", *AUD)
        self.assertStatus(f, "aud.format", "PASS")
        self.assertStatus(f, "aud.expected", "PASS")
        self.assertNoFail(f)

    def test_102_memo_B_historical_address_array_fails(self):
        f = self.payload("invalid-historical-address-is-array.json", "--bulletin2", "off")
        self.assertStatus(f, "historical_address.type", "FAIL")
        f = self.run_checker("--token-file", "tok_history_array.jwt", "--bulletin2", "off", *OFFLINE)
        self.assertStatus(f, "historical_address.type", "FAIL")

    def test_103_memo_B_historical_address_object_passes_with_component_checks(self):
        f = self.payload("valid-historical-address-object.json")
        self.assertNoFail(f)
        for m in ("street_address", "locality", "region", "postal_code", "country"):
            self.assertStatus(f, f"historical_address.{m}", "PASS")
        self.assertNoFail(self.run_checker("--token-file", "tok_history_object.jwt", *OFFLINE))
        bad = self.payload("valid-historical-address-object.json",
                           mutate=lambda c: c["historical_address"].update(region="Tennessee"))
        self.assertStatus(bad, "historical_address.region", "FAIL")

    def test_104_memo_C_unverified_email_with_verified_phone_fails(self):
        f = self.payload("temp-valid-unverified-email-but-verified-phone.json", "--bulletin2", "off")
        self.assertStatus(f, "email_verified", "FAIL")
        f = self.payload("valid-baseline-v3.json", "--bulletin2", "off",
                         mutate=lambda c: c.update(phone_number_verified=False))
        self.assertStatus(f, "phone_number_verified", "FAIL")

    def test_105_memo_7_2_verified_flags_not_required(self):
        f = self.payload("valid-baseline-v3.json",
                         mutate=lambda c: [c.pop(k, None) for k in ("email_verified", "phone_number_verified")])
        self.assertNoFail(f)

    def test_106_memo_D_v3_required_production_decision(self):
        self.assertStatus(self.payload("valid-baseline-v3.json"), "tefca_ial2claims_version", "PASS")
        self.assertStatus(self.payload("invalid-claims-version-1.0.json"), "tefca_ial2claims_version.value", "FAIL")
        f = self.payload("missing-claims-version.json")
        self.assertStatus(f, "tefca_ial2claims_version.required", "FAIL")     # production decision (default)
        self.assertStatus(f, "tefca_ial2claims_version", "WARN")              # SOP-text SHOULD, still reported
        f = self.payload("missing-claims-version.json", "--as-of", "2026-09-30")
        self.assertStatus(f, "tefca_ial2claims_version.required", "PENDING")  # keyed to the §4.8 date
        f = self.payload("missing-claims-version.json", "--allow-missing-claims-version")
        self.assertNotStatus(f, "tefca_ial2claims_version.required", "FAIL")  # analysis opt-out, no false drift
        self.assertNoFail(f)
        f = self.payload("valid-baseline-v3.json", mutate=lambda c: c.update(tefca_ial2claims_version=3.0))
        self.assertStatus(f, "tefca_ial2claims_version", "FAIL")              # must be a string

    def test_107_memo_6_priority2_unchanged(self):
        cases = [("birthdate", "1980", "birthdate.format"), ("birthdate", "1980-02", "birthdate.format"),
                 ("birthdate", "19800229", "birthdate.format"), ("birthdate", "1981-02-29", "birthdate.value"),
                 ("aud", "2.16.840.1.113883.3.9999.100", "aud.format"), ("aud", "https://ias.example.org", "aud.format"),
                 ("aud", "urn:uuid:0d8f0f1e-1111-2222-3333-444455556666", "aud.format"), ("aud", "urn:oid:", "aud.format"),
                 ("iss", "http://id.csp.example", "iss")]
        for claim, value, check in cases:
            with self.subTest(claim=claim, value=value):
                f = self.payload("valid-baseline-v3.json", mutate=lambda c, k=claim, v=value: c.update({k: v}))
                self.assertStatus(f, check, "FAIL")
        for member, value in (("region", "Tennessee"), ("region", "Alabama"), ("country", "USA"),
                              ("country", "United States")):
            with self.subTest(member=member, value=value):
                f = self.payload("valid-baseline-v3.json",
                                 mutate=lambda c, m=member, v=value: c["address"].update({m: v}))
                self.assertStatus(f, f"address.{member}", "FAIL")
        f = self.payload("valid-baseline-v3.json", mutate=lambda c: c.update(historical_name="Previous Name"))
        self.assertStatus(f, "claim.ns", "FAIL")

    def test_108_memo_7_not_over_corrected(self):
        f = self.payload("valid-baseline-v3.json", mutate=lambda c: c["address"].update(county="Knox"))
        self.assertStatus(f, "address.extra", "WARN")
        self.assertNoFail(f)
        f = self.payload("valid-baseline-v3.json", mutate=lambda c: c.update(middle_initial="Q"))
        self.assertStatus(f, "claim.ns", "WARN")
        self.assertNoFail(f)
        f = self.payload("valid-baseline-v3.json", mutate=lambda c: c.update(vendor_score=7))
        self.assertStatus(f, "claim.unknown", "WARN")
        self.assertNoFail(f)

    def test_109_payload_mode_skips_crypto_and_clock(self):
        f = self.payload("valid-baseline-v3.json", mutate=lambda c: c.update(iat=1000000000, exp=1000000600))
        self.assertStatus(f, "payload.mode", "INFO")
        self.assertStatus(f, "exp.expired", "INFO")
        self.assertEqual(self.st(f, "sig.verify"), set())
        self.assertNoFail(f)


    # ------------------------------------------------------------ v1.3.3: found by Mohammed's fixture set
    def test_110_no_contact_fails_without_false_drift(self):
        # invalid-no-email-no-phoneno.json: checker and schema both reject it; the drift reporter must
        # map the schema's anyOf-of-required error to the root, as it does the checker's email|phone_number.
        f = self.payload("valid-baseline-v3.json",
                         mutate=lambda c: [c.pop(k, None) for k in ("email", "email_verified",
                                                                     "phone_number", "phone_number_verified")])
        self.assertStatus(f, "email|phone_number", "FAIL")
        self.assertEqual(self.st(f, "schema.idTokenClaims.drift"), set())


    # ------------------------------------------------------------ v1.5.0: QHIN Compliance Bulletin No. 2
    def ref_of(self, findings, check, status):
        return {f["ref"] for f in findings if f["check"] == check and f["status"] == status}

    def test_120_b2_rule_set_follows_the_evaluation_date(self):
        f = self.payload("invalid-aud-is-an-array.json")                       # default: today >= 2026-10-13
        self.assertTrue(self.last_report["rule_set"]["bulletin2"])
        self.assertStatus(f, "aud.form", "INFO")
        self.assertNoFail(f)
        f = self.payload("invalid-aud-is-an-array.json", "--as-of", "2026-10-12")   # day before the issue date
        self.assertFalse(self.last_report["rule_set"]["bulletin2"])
        self.assertStatus(f, "aud.type", "FAIL")
        f = self.payload("invalid-aud-is-an-array.json", "--as-of", "2026-10-12", "--bulletin2", "on")
        self.assertNoFail(f)
        f = self.payload("invalid-aud-is-an-array.json", "--as-of", "2026-10-13")
        self.assertNoFail(f)

    def test_121_b2_aud_one_element_array_is_equivalent(self):
        f = self.run_checker("--token-file", "tok_aud_array.jwt", *OFFLINE, *AUD)
        self.assertNoFail(f)
        self.assertStatus(f, "sig.verify", "PASS")
        self.assertStatus(f, "aud.form", "INFO")
        self.assertStatus(f, "aud.format", "PASS")
        self.assertStatus(f, "aud.expected", "PASS")                          # §5(c): compared as the string
        for name in ("b2-invalid-aud-two-element-array.json", "b2-invalid-aud-empty-array.json"):
            with self.subTest(name=name):
                f = self.payload(name)
                self.assertStatus(f, "aud.type", "FAIL")
                self.assertEqual(self.ref_of(f, "aud.type", "FAIL"), {"B2 §5(a)"})
        f = self.payload("invalid-aud-is-an-array.json", mutate=lambda c: c.update(aud=["2.16.840.1.113883.3.9999.1"]))
        self.assertStatus(f, "aud.format", "FAIL")                            # §5(b): RFC 3061 URI inside the array
        f = self.payload("invalid-aud-is-an-array.json", mutate=lambda c: c.update(aud=[7]))
        self.assertStatus(f, "aud.type", "FAIL")

    def test_122_b2_historical_address_array(self):
        f = self.payload("b2-valid-historical-address-array.json")
        self.assertNoFail(f)
        self.assertStatus(f, "historical_address.form", "INFO")
        for i in (0, 1):
            for m in ("street_address", "locality", "region", "postal_code", "country"):
                self.assertStatus(f, f"historical_address[{i}].{m}", "PASS")
        self.assertNoFail(self.run_checker("--token-file", "tok_history_array.jwt", *OFFLINE))
        f = self.payload("b2-invalid-historical-address-array-bad-element.json")
        self.assertStatus(f, "historical_address[1].region", "FAIL")
        self.assertNotStatus(f, "historical_address[0].region", "FAIL")
        f = self.payload("b2-invalid-historical-address-empty-array.json")
        self.assertEqual(self.ref_of(f, "historical_address.type", "FAIL"), {"B2 §4(a)"})
        f = self.payload("valid-historical-address-object.json")             # one object is still valid
        self.assertNoFail(f)
        f = self.payload("b2-valid-historical-address-array.json",
                         mutate=lambda c: c.update(historical_address=[c["historical_address"]]))
        self.assertStatus(f, "historical_address[0].type", "FAIL")            # no nested arrays

    def test_123_b2_unverified_email_or_phone(self):
        f = self.payload("temp-valid-unverified-email-but-verified-phone.json")
        self.assertNoFail(f)
        self.assertStatus(f, "b2.3b", "INFO")
        self.assertStatus(f, "token.min-demographics", "PASS")                # the verified phone satisfies §4.4(d)
        self.assertTrue(self.last_report["rule_set"]["temporary_permissions_3b_3c"] == "in effect")
        f = self.payload("b2-temp-valid-unverified-phone-but-verified-email.json")
        self.assertNoFail(f)
        self.assertStatus(f, "b2.3c", "INFO")
        cases = {"b2-invalid-unverified-email-no-phone.json": "B2 §3(b)", "b2-invalid-both-unverified.json": "B2 §3(d)"}
        for name, ref in cases.items():
            with self.subTest(name=name):
                f = self.payload(name)
                self.assertEqual(self.ref_of(f, "email|phone_number", "FAIL"), {ref})
                self.assertStatus(f, "token.min-demographics", "FAIL")
        f = self.payload("b2-invalid-verified-flag-string.json")
        self.assertStatus(f, "email_verified.type", "FAIL")
        f = self.payload("valid-baseline-v3.json", mutate=lambda c: [c.pop("email"), c.update(email_verified=True)])
        self.assertStatus(f, "email_verified.orphan", "WARN")
        self.assertNoFail(f)
        f = self.payload("valid-baseline-v3.json", mutate=lambda c: [c.pop(k) for k in ("email", "phone_number")])
        self.assertEqual(self.ref_of(f, "email|phone_number", "FAIL"), {"B2 §3(a)"})

    def test_124_b2_3g_notice_ends_the_temporary_permission(self):
        args = ("--as-of", "2026-12-02")
        f = self.payload("temp-valid-unverified-email-but-verified-phone.json", *args, "--b2-3g-notice", "2026-12-01")
        self.assertStatus(f, "b2.3g", "FAIL")
        self.assertEqual(self.last_report["rule_set"]["temporary_permissions_3b_3c"], "ended")
        f = self.payload("temp-valid-unverified-email-but-verified-phone.json", *args, "--b2-3g-notice", "2026-12-03")
        self.assertNoFail(f)                                                   # notice date still in the future
        f = self.payload("valid-baseline-v3.json", *args, "--b2-3g-notice", "2026-12-01")
        self.assertNoFail(f)                                                   # verified tokens unaffected

    def test_125_b2_version_claim(self):
        f = self.payload("missing-claims-version.json")
        self.assertEqual(self.ref_of(f, "tefca_ial2claims_version.required", "FAIL"), {"B2 §2(a)"})
        f = self.payload("invalid-claims-version-1.0.json")
        self.assertEqual(self.ref_of(f, "tefca_ial2claims_version.value", "FAIL"), {"B2 §2(a)"})
        f = self.payload("missing-claims-version.json", "--allow-missing-claims-version")
        self.assertNoFail(f)

    def test_126_b2_unverified_email_not_required_in_xcpd_body(self):
        f = self.run_checker("--soap", "pd_b2_unverified_email.xml", *OFFLINE, *AUD)
        self.assertStatus(f, "pd.vs.token.email", "INFO")
        self.assertNotStatus(f, "pd.vs.token.email", "FAIL")
        self.assertStatus(f, "pd.vs.token", "PASS")
        f = self.run_checker("--soap", "pd_b2_unverified_email.xml", "--bulletin2", "off", *OFFLINE, *AUD)
        self.assertStatus(f, "email_verified", "FAIL")                         # SOP-text reading

    def test_127_b2_strict_schema_and_missing_layer(self):
        f = self.payload("b2-valid-historical-address-array.json", "--schema-strict",
                         mutate=lambda c: c.update(aud=[c["aud"]], email_verified=False))
        self.assertNoFail(f)                                                   # and no drift (run_checker asserts it)
        d = self.loosened_schemas(lambda d: os.remove(os.path.join(d, "tefca-qhin-bulletin-2.schema.json")))
        f = self.run_checker("--payload", os.path.join("payloads", "valid-baseline-v3.json"), schema_dir=d)
        self.assertStatus(f, "schema.idTokenClaims", "WARN")                  # cross-check skipped, said so
        f = self.run_checker("--payload", os.path.join("payloads", "valid-baseline-v3.json"), "--bulletin2", "off",
                             schema_dir=d)
        self.assertNotStatus(f, "schema.idTokenClaims", "WARN")               # SOP-text layer does not need it

    def test_128_b2_drift_detection_in_the_bulletin_layer(self):
        d = self.loosened_schemas(lambda d: self.edit_json(
            os.path.join(d, "tefca-qhin-bulletin-2.schema.json"),
            lambda s: s["$defs"]["aud"]["then"].pop("maxItems")))
        f = self.run_checker("--payload", os.path.join("payloads", "b2-invalid-aud-two-element-array.json"),
                             schema_dir=d, allow_drift=True)
        self.assertStatus(f, "aud.type", "FAIL")
        self.assertStatus(f, "schema.idTokenClaims.drift", "WARN")


    # ------------------------------------------------------------ v1.6.0: RCE IAS workgroup, October 22, 2026
    def test_130_wg_aud_prefix_case_is_a_warning(self):
        f = self.payload("wg-aud-uppercase-prefix.json", *AUD)
        self.assertNoFail(f)
        self.assertStatus(f, "aud.case", "WARN")
        self.assertStatus(f, "aud.format", "PASS")
        self.assertStatus(f, "aud.expected", "PASS")                          # RFC 8141 URN-equivalence
        for value in ("Urn:Oid:2.16.840.1.113883.3.9999.1", ["URN:OID:2.16.840.1.113883.3.9999.1"]):
            with self.subTest(value=value):
                f = self.payload("valid-baseline-v3.json", *AUD, mutate=lambda c, v=value: c.update(aud=v))
                self.assertNoFail(f)
                self.assertStatus(f, "aud.case", "WARN")
        f = self.payload("wg-aud-uppercase-prefix.json", "--bulletin2", "off", *AUD)
        self.assertStatus(f, "aud.case", "WARN")
        self.assertNoFail(f)
        f = self.payload("valid-baseline-v3.json", mutate=lambda c: c.update(aud="URN:OID:2.16.840.1.113883.3.09"))
        self.assertStatus(f, "aud.format", "FAIL")                            # leading zero is still invalid

    def test_131_wg_country_is_iso3166_1_alpha2(self):
        f = self.payload("wg-invalid-country-UK.json")
        self.assertStatus(f, "address.country", "FAIL")
        for value in ("XX", "us", "Canada", "U.S."):
            with self.subTest(value=value):
                f = self.payload("valid-baseline-v3.json",
                                 mutate=lambda c, v=value: c["address"].update(country=v))
                self.assertStatus(f, "address.country", "FAIL")
        f = self.payload("valid-baseline-v3.json", mutate=lambda c: c["address"].update(country="GB", region="ENG"))
        self.assertStatus(f, "address.country", "PASS")
        f = self.payload("b2-valid-historical-address-array.json",
                         mutate=lambda c: c["historical_address"][1].update(country="UK"))
        self.assertStatus(f, "historical_address[1].country", "FAIL")

    def test_132_wg_region_forms(self):
        self.assertStatus(self.payload("wg-invalid-region-lowercase.json"), "address.region", "FAIL")
        for value in ("ca", "California", "US-CA", "CAL"):
            with self.subTest(value=value):
                f = self.payload("valid-baseline-v3.json", mutate=lambda c, v=value: c["address"].update(region=v))
                self.assertStatus(f, "address.region", "FAIL")
        f = self.payload("valid-baseline-v3.json", mutate=lambda c: c["address"].update(region="CA"))
        self.assertStatus(f, "address.region", "PASS")

    def test_133_wg_refresh_token_reported_not_judged(self):
        f = self.run_checker("--token-file", "csp_token_response_refresh.json", *OFFLINE, "--ignore-expiry")
        self.assertStatus(f, "token.response.refresh", "INFO")
        msg = [x["message"] for x in f if x["check"] == "token.response.refresh"][0]
        self.assertIn("refresh_token_expires_in=2592000", msg)
        self.assertNoFail(f)


if __name__ == "__main__":
    unittest.main()
