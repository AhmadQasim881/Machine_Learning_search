"""End-to-end-ish tests for the scaffold. Stdlib unittest only:  python -m unittest"""
import os
import tempfile
import unittest

from harness.schema import Finding, Status, CweAssignment, ConfidenceSource
from harness.store import Store, dedup_key
from harness.ingest import get_adapter, available_adapters
from harness.classify import KeywordCweClassifier, apply_gate

HERE = os.path.dirname(__file__)
SAMPLE = os.path.join(HERE, "..", "samples", "nuclei_sample.jsonl")


class TestSchema(unittest.TestCase):
    def test_roundtrip(self):
        f = Finding(title="Reflected XSS", vuln_type="xss", host="t.example")
        f.cwes.append(CweAssignment("CWE-79", 0.9, ConfidenceSource.MODEL, "r"))
        f2 = Finding.from_json(f.to_json())
        self.assertEqual(f2.title, "Reflected XSS")
        self.assertEqual(f2.top_cwe().cwe_id, "CWE-79")
        self.assertEqual(f2.status, Status.NEW)

    def test_authorization_gate_property(self):
        f = Finding()
        self.assertFalse(f.authorization.actionable)
        f.authorization.in_scope = True
        f.authorization.roe_ok = True
        self.assertTrue(f.authorization.actionable)


class TestIngest(unittest.TestCase):
    def test_adapters_registered(self):
        self.assertIn("nuclei", available_adapters())
        self.assertIn("generic", available_adapters())

    def test_nuclei_parse(self):
        findings = get_adapter("nuclei").parse_file(SAMPLE)
        self.assertEqual(len(findings), 5)
        log4j = findings[0]
        self.assertEqual(log4j.source_tool, "nuclei")
        self.assertEqual(log4j.host, "shop.example.com")
        self.assertEqual(log4j.severity, "Critical")
        # tool-asserted CWE + CVSS pre-seeded
        self.assertTrue(any(c.cwe_id == "CWE-94" for c in log4j.cwes))
        self.assertIsNotNone(log4j.cvss)
        self.assertAlmostEqual(log4j.cvss.base_score, 10.0)


class TestClassifyAndGate(unittest.TestCase):
    def setUp(self):
        self.clf = KeywordCweClassifier()

    def test_predicts_web_cwes(self):
        self.assertTrue(any(c.cwe_id == "CWE-79"
                            for c in self.clf.predict("reflected cross-site scripting")))
        self.assertTrue(any(c.cwe_id == "CWE-918"
                            for c in self.clf.predict("server-side request forgery ssrf")))

    def test_gate_routes_low_confidence_to_review(self):
        f = Finding(title="weird thing", description="something odd happened")
        self.clf.classify(f)
        apply_gate(f, threshold=0.80)
        self.assertEqual(f.status, Status.NEEDS_REVIEW)

    def test_gate_auto_triages_high_confidence(self):
        f = Finding(description="confirmed sql injection via union select")
        self.clf.classify(f)
        apply_gate(f, threshold=0.80)
        self.assertEqual(f.top_cwe().cwe_id, "CWE-89")
        self.assertEqual(f.status, Status.TRIAGED)


class TestStoreDedup(unittest.TestCase):
    def test_exact_duplicate_collapsed(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "t.db")
            with Store(db) as store:
                a = Finding(source_tool="nuclei", vuln_type="xss",
                            host="t.example", param="q")
                b = Finding(source_tool="nuclei", vuln_type="xss",
                            host="t.example", param="q")
                _, a_new = store.add_deduped(a)
                _, b_new = store.add_deduped(b)
                self.assertTrue(a_new)
                self.assertFalse(b_new)
                self.assertEqual(dedup_key(a), dedup_key(b))
                stored_b = store.get(b.id)
                self.assertEqual(stored_b.status, Status.DUPLICATE)


if __name__ == "__main__":
    unittest.main()
