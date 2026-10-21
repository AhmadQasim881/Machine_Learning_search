"""Tests for the brain stages: CVSS scoring, prioritization, export, enrichment
(mocked), and the sklearn classifier round-trip. Stdlib unittest.

The sklearn-dependent tests skip automatically if scikit-learn is not installed,
so the suite still passes on a bare stdlib environment."""
import os
import tempfile
import unittest

from harness.schema import (CvssScore, Exploit, Finding, Status, CweAssignment,
                            ConfidenceSource)
from harness.score import score_vector, parse_vector, base_score
from harness import prioritize as prio
from harness.export import to_defectdojo_generic

try:
    import sklearn  # noqa: F401
    HAVE_SKLEARN = True
except ImportError:
    HAVE_SKLEARN = False


class TestCvss(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
                         (10.0, "Critical"))
        self.assertEqual(score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
                         (9.8, "Critical"))
        self.assertEqual(score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
                         (6.1, "Medium"))

    def test_bare_vector_and_validation(self):
        self.assertAlmostEqual(base_score(parse_vector("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")), 7.8)
        with self.assertRaises(ValueError):
            parse_vector("AV:N/AC:L")          # missing required metrics
        with self.assertRaises(ValueError):
            parse_vector("AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")  # illegal value


class TestPrioritize(unittest.TestCase):
    def test_kev_floor_dominates(self):
        f = Finding(severity="Low", cvss=CvssScore(vector="x", base_score=2.0))
        res = prio.score(f, epss=0.01, in_kev=True)
        self.assertGreaterEqual(res.score, prio.KEV_FLOOR)
        self.assertTrue(any("KEV" in r for r in res.reasons))

    def test_fusion_orders_sensibly(self):
        crit = Finding(cvss=CvssScore(vector="x", base_score=9.8, severity="Critical"))
        low = Finding(cvss=CvssScore(vector="x", base_score=3.1, severity="Low"))
        self.assertGreater(prio.score(crit, epss=0.5).score, prio.score(low, epss=0.5).score)

    def test_poc_bonus(self):
        f = Finding(cvss=CvssScore(vector="x", base_score=5.0))
        without = prio.score(f, epss=0.1).score
        f.exploit = Exploit(poc_verified=True)
        with_poc = prio.score(f, epss=0.1).score
        self.assertGreater(with_poc, without)


class TestExport(unittest.TestCase):
    def test_defectdojo_mapping(self):
        f = Finding(title="SSRF", vuln_type="ssrf", host="api.example.com",
                    url="https://api.example.com/x", severity="High",
                    cvss=CvssScore(vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                   base_score=7.5))
        f.cwes.append(CweAssignment("CWE-918", 0.9, ConfidenceSource.MODEL, "r"))
        f.priority_score = 72.5
        payload = to_defectdojo_generic([f])
        self.assertEqual(len(payload["findings"]), 1)
        item = payload["findings"][0]
        self.assertEqual(item["severity"], "High")
        self.assertEqual(item["cwe"], 918)
        self.assertTrue(item["cvssv3"].startswith("CVSS:3.1/"))
        self.assertIn("Harness priority: 72.5", item["description"])


@unittest.skipUnless(HAVE_SKLEARN, "scikit-learn not installed")
class TestSklearnClassifier(unittest.TestCase):
    def _data(self):
        rows = []
        base = {
            "CWE-89": "sql injection via union select in {p}",
            "CWE-79": "reflected cross-site scripting xss in {p}",
            "CWE-918": "server side request forgery ssrf in {p} webhook",
        }
        for i in range(12):
            for cwe, t in base.items():
                rows.append({"text": t.format(p=f"app{i}"), "cwe": cwe,
                             "date": f"20{10+i:02d}-01-01"})
        return rows

    def test_train_predict_save_load(self):
        from harness.classify.sklearn_model import SklearnCweClassifier
        rows = self._data()
        clf = SklearnCweClassifier.train([r["text"] for r in rows],
                                         [r["cwe"] for r in rows])
        preds = clf.predict("sql injection union select dump users")
        self.assertEqual(preds[0].cwe_id, "CWE-89")
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.pkl")
            clf.save(p)
            clf2 = SklearnCweClassifier.load(p)
            self.assertEqual(clf2.predict("ssrf webhook fetches internal")[0].cwe_id, "CWE-918")

    def test_temporal_evaluate(self):
        from harness.evaluate import evaluate
        res = evaluate(self._data(), train_frac=0.7)
        self.assertIn("macro_f1", res)
        self.assertGreaterEqual(res["macro_f1"], 0.0)
        self.assertEqual(res["n_train"] + res["n_test"], len(self._data()))


class TestEnrichMocked(unittest.TestCase):
    def test_epss_parses_and_caches(self):
        import harness.enrich.epss as epss_mod

        class _Resp:
            def raise_for_status(self): pass
            def json(self):
                return {"data": [{"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.99"}]}

        class _Req:
            @staticmethod
            def get(*a, **k): return _Resp()

        with tempfile.TemporaryDirectory() as d:
            orig = epss_mod.requests
            epss_mod.requests = _Req()
            try:
                c = epss_mod.EpssClient(cache_path=os.path.join(d, "epss.json"))
                out = c.scores(["CVE-2021-44228"], now=1000.0)
                self.assertAlmostEqual(out["CVE-2021-44228"]["epss"], 0.97)
            finally:
                epss_mod.requests = orig

    def test_kev_seed_contains(self):
        from harness.enrich import KevCatalog
        with tempfile.TemporaryDirectory() as d:
            k = KevCatalog(cache_path=os.path.join(d, "kev.json"))
            k.seed(["CVE-2021-44228", "CVE-2017-0144"], now=1000.0)
            self.assertTrue(k.contains("cve-2021-44228"))
            self.assertFalse(k.contains("CVE-2099-0001"))


if __name__ == "__main__":
    unittest.main()
