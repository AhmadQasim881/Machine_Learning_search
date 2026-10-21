"""Regression tests for the review-hardening fixes (parsers, dedup, gate, export,
priors, authorization). Stdlib unittest; sklearn-dependent paths are avoided."""
import os
import tempfile
import unittest

from harness.schema import (Authorization, CvssScore, CweAssignment,
                            ConfidenceSource, Finding, Status)
from harness.store import Store, dedup_key
from harness.ingest import get_adapter
from harness.ingest.nuclei import NucleiAdapter
from harness.enrich.nvd import NvdClient
from harness.classify import apply_gate
from harness.export import to_defectdojo_generic


class TestNucleiEdgeCases(unittest.TestCase):
    def setUp(self):
        self.a = NucleiAdapter()

    def test_null_cvss_metrics_with_score_does_not_crash(self):
        line = ('{"template-id":"t","info":{"name":"x","severity":"high",'
                '"classification":{"cvss-metrics":null,"cvss-score":7.5}},'
                '"host":"h","matched-at":"https://h/a"}')
        out = self.a.parse(line)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].cvss.base_score, 7.5)
        self.assertEqual(out[0].cvss.vector, "")

    def test_v2_vector_labeled_v2(self):
        line = ('{"template-id":"t","info":{"name":"x","classification":'
                '{"cvss-metrics":"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"}},"host":"h"}')
        out = self.a.parse(line)
        self.assertEqual(out[0].cvss.version, "2.0")
        self.assertFalse(out[0].cvss.vector.startswith("CVSS:"))

    def test_bad_port_does_not_abort_batch(self):
        good = '{"template-id":"a","info":{"name":"ok"},"matched-at":"https://h/x"}'
        bad = '{"template-id":"b","info":{"name":"bad"},"matched-at":"http://h:notaport/y"}'
        out = self.a.parse(good + "\n" + bad)
        self.assertEqual(len(out), 2)              # neither record lost

    def test_bare_int_cwe_id(self):
        line = ('{"template-id":"t","info":{"name":"x","classification":'
                '{"cwe-id":79}},"host":"h"}')
        out = self.a.parse(line)
        self.assertTrue(any(c.cwe_id == "CWE-79" for c in out[0].cwes))


class TestGenericAdapter(unittest.TestCase):
    def setUp(self):
        self.a = get_adapter("generic")

    def test_pretty_printed_single_object(self):
        out = self.a.parse('{\n  "title": "X",\n  "host": "h"\n}')
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].title, "X")

    def test_json_array_and_jsonl(self):
        self.assertEqual(len(self.a.parse('[{"title":"a"},{"title":"b"}]')), 2)
        self.assertEqual(len(self.a.parse('{"title":"a"}\n{"title":"b"}')), 2)

    def test_non_dict_records_skipped(self):
        self.assertEqual(len(self.a.parse('[{"title":"a"}, 5, "junk"]')), 1)


class TestNvdParse(unittest.TestCase):
    def test_parse_v31_and_filters_noninfo(self):
        payload = {"vulnerabilities": [{"cve": {
            "descriptions": [{"lang": "en", "value": "desc"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
            "weaknesses": [{"description": [
                {"value": "CWE-79"}, {"value": "NVD-CWE-noinfo"}, {"value": "CWE-1000"}]}],
        }}]}
        info = NvdClient._parse(payload)
        self.assertEqual(info["cvss_score"], 9.8)
        self.assertEqual(info["cwes"], ["CWE-79"])   # noinfo + pillar dropped


class TestDedupPath(unittest.TestCase):
    def test_distinct_paths_not_collapsed(self):
        a = Finding(source_tool="nuclei", vuln_type="xss", host="h", url="https://h/a")
        b = Finding(source_tool="nuclei", vuln_type="xss", host="h", url="https://h/b")
        self.assertNotEqual(dedup_key(a), dedup_key(b))
        same = Finding(source_tool="nuclei", vuln_type="xss", host="h", url="https://h/a")
        self.assertEqual(dedup_key(a), dedup_key(same))


class TestGatePreservesHumanStates(unittest.TestCase):
    def test_validated_not_regated(self):
        f = Finding(status=Status.VALIDATED)
        f.cwes.append(CweAssignment("CWE-79", 0.99, ConfidenceSource.MODEL, "r"))
        apply_gate(f)
        self.assertEqual(f.status, Status.VALIDATED)   # human decision preserved

    def test_needs_review_can_be_regated_up(self):
        f = Finding(status=Status.NEEDS_REVIEW)
        f.cwes.append(CweAssignment("CWE-89", 0.95, ConfidenceSource.MODEL, "r"))
        apply_gate(f, threshold=0.8)
        self.assertEqual(f.status, Status.TRIAGED)


class TestExportHardening(unittest.TestCase):
    def test_unauthorized_marked_inactive(self):
        f = Finding(title="x", severity="High", status=Status.TRIAGED)
        f.authorization = Authorization(in_scope=False, roe_ok=False)
        item = to_defectdojo_generic([f])["findings"][0]
        self.assertFalse(item["active"])
        self.assertIn("UNAUTHORIZED", item["tags"])
        self.assertIn("DO NOT ACTION", item["description"])

    def test_v2_vector_not_emitted_as_cvssv3(self):
        f = Finding(title="x", cvss=CvssScore(version="2.0", vector="AV:N/AC:L",
                                              base_score=5.0))
        f.authorization = Authorization(in_scope=True, roe_ok=True)
        item = to_defectdojo_generic([f])["findings"][0]
        self.assertNotIn("cvssv3", item)
        self.assertEqual(item["cvssv3_score"], 5.0)

    def test_multi_cwe_in_tags(self):
        f = Finding(title="x")
        f.authorization = Authorization(in_scope=True, roe_ok=True)
        f.cwes = [CweAssignment("CWE-79", 0.9), CweAssignment("CWE-80", 0.4)]
        item = to_defectdojo_generic([f])["findings"][0]
        self.assertIn("cwe-79", item["tags"])
        self.assertIn("cwe-80", item["tags"])


class TestCvssPriors(unittest.TestCase):
    def test_prior_seeds_and_scores(self):
        from harness.score import prior_vector, score_vector
        v = prior_vector("CWE-89")
        self.assertTrue(v)
        base, sev = score_vector(v)
        self.assertGreater(base, 0.0)


class TestModelIntegritySidecar(unittest.TestCase):
    def test_tampered_model_rejected(self):
        try:
            from harness.classify.sklearn_model import SklearnCweClassifier
        except ImportError:
            self.skipTest("scikit-learn not installed")
        rows_t = ["sql injection union select", "reflected xss script"]
        rows_l = ["CWE-89", "CWE-79"]
        clf = SklearnCweClassifier.train(rows_t * 5, rows_l * 5)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.pkl")
            clf.save(p)
            self.assertTrue(os.path.exists(p + ".sha256"))
            with open(p, "ab") as fh:        # tamper
                fh.write(b"evil")
            with self.assertRaises(ValueError):
                SklearnCweClassifier.load(p)


if __name__ == "__main__":
    unittest.main()
