"""Repository imports must never send newer findings to an older AI source tree."""
import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
import ai_review
import kit


class ProvenanceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.repo = self.repo.resolve()
        self.patch = mock.patch.object(kit, "DATA", self.root / "data")
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.client = kit.client_dir("TEST")
        self.sha = "a" * 40
        self.finding = {"id": 1, "test": 7, "component_name": "lodash", "component_version": "4.17.20",
                        "file_path": "package-lock.json", "vulnerability_ids": [{"vulnerability_id": "CVE-TEST"}]}
        self.raw = self.root / "trivy.json"
        self.raw.write_text(json.dumps({"Results": [{"Target": "package-lock.json", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-TEST", "PkgName": "lodash", "InstalledVersion": "4.17.20"}]}]}))
        self.entry = {"product": "app", "scan_type": "Trivy Scan", "raw": str(self.raw),
                      "source": {"repo": str(self.repo), "commit": self.sha, "literal": True}}
        (self.client / "tests.json").write_text(json.dumps({"7": self.entry}))
        (self.client / "scan-log.jsonl").write_text("".join(json.dumps(entry) + "\n" for entry in [
            {"tool": "Trivy git", "product": "app", "target": f"{self.repo}@main {'b' * 40}"},
            {"tool": "Trivy repository", "product": "app", "target": f"{self.repo}@main {self.sha}"}]))

    def run_ai(self, findings):
        units = [ai_review.Unit("app", "lodash", findings)]
        with mock.patch.object(ai_review, "units", return_value=units), \
             mock.patch.object(ai_review, "find_claude", return_value="unused"), \
             mock.patch.object(ai_review.signal, "signal"), \
             mock.patch.object(ai_review, "prepare_tree") as prepare, \
             mock.patch.object(ai_review, "ask_claude", return_value=[]) as ask, \
             mock.patch.object(kit, "triage_client", return_value=Counter()), mock.patch.object(kit, "say"):
            try:
                ai_review.run(mock.Mock(), "TEST", "all")
            except kit.KitError as error:
                return prepare, ask, error
            return prepare, ask, None

    def test_new_import_uses_its_commit_and_literal_snapshot_despite_old_scan_log(self):
        prepare, ask, error = self.run_ai([self.finding])
        self.assertIsNone(error)
        self.assertEqual(prepare.call_args.args[:2], (self.repo, self.sha))
        self.assertTrue(prepare.call_args.kwargs["literal"])
        self.assertIn(self.sha[:12], ask.call_args.args[2])

    def test_retained_finding_missing_from_current_report_is_not_ai_dismissed(self):
        self.raw.write_text('{"Results": []}')
        prepare, ask, error = self.run_ai([self.finding])
        self.assertIsInstance(error, kit.KitError)
        prepare.assert_not_called()
        ask.assert_not_called()

    def test_mixed_commits_and_unbound_legacy_findings_are_not_guessed(self):
        for source in ({**self.entry, "source": {**self.entry["source"], "commit": "c" * 40}},
                       {k: v for k, v in self.entry.items() if k != "source"}):
            with self.subTest(source=source.get("source")):
                (self.client / "tests.json").write_text(json.dumps({"7": self.entry, "8": source}))
                prepare, ask, error = self.run_ai([self.finding, {**self.finding, "id": 2, "test": 8}])
                self.assertIsInstance(error, kit.KitError)
                prepare.assert_not_called()
                ask.assert_not_called()

    def test_removed_url_clone_does_not_fall_back_to_old_repository(self):
        self.entry["source"]["repo"] = str(self.root / "removed-clone")
        (self.client / "tests.json").write_text(json.dumps({"7": self.entry}))
        prepare, ask, error = self.run_ai([self.finding])
        self.assertIsInstance(error, kit.KitError)
        prepare.assert_not_called()
        ask.assert_not_called()

    def test_missing_test_metadata_cannot_reactivate_the_old_git_scan_cursor(self):
        (self.client / "tests.json").write_text("{}")
        prepare, ask, error = self.run_ai([self.finding])
        self.assertIsInstance(error, kit.KitError)
        prepare.assert_not_called()
        ask.assert_not_called()

    def test_import_stores_source_locally_without_sending_local_paths_to_dojo(self):
        d = mock.Mock()
        d.reimport.return_value = {"test": 9}
        with mock.patch.object(kit, "connect", return_value=d), mock.patch.object(kit, "note_skipped"), \
             mock.patch.object(kit, "note_system"), mock.patch.object(kit, "say"), \
             mock.patch.object(kit, "dedupe_test", return_value=(0, 0, "")), \
             mock.patch.object(kit, "classify_test", return_value=Counter()), \
             mock.patch.object(kit, "triage_test", return_value=Counter()), mock.patch.object(kit, "load_intel"):
            kit.import_result("Trivy Scan", self.raw, kit.Target("TEST", "app", "e"), "repository",
                              source_repo=self.repo, source_literal=True, commit_hash=self.sha)
        saved = kit.load_json(self.client / "tests.json", {})["9"]
        self.assertEqual(saved["source"], {"repo": str(self.repo), "commit": self.sha, "literal": True})
        self.assertEqual(d.reimport.call_args.kwargs["extra"], {"commit_hash": self.sha})


if __name__ == "__main__":
    unittest.main()
