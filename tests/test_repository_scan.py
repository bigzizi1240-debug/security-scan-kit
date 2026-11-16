"""Repository scanning: one immutable source, partial results, and private artifacts."""
import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
import classify
import kit
import repository_scan
import targets


def git(path, *args):
    return subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True,
                          text=True, env={**os.environ, "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.test",
                                          "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.test"}).stdout.strip()


def trivy_data():
    return {"SchemaVersion": 2, "ArtifactName": "/private/snapshot", "ArtifactType": "filesystem", "Results": [
        {"Target": "app/package-lock.json", "Class": "lang-pkgs", "Type": "npm",
         "Packages": [{"Name": "lodash", "Version": "4.17.20"}, {"Name": "safe-package", "Version": "1.0.0"}],
         "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-1234", "PkgName": "lodash", "InstalledVersion": "4.17.20",
                              "FixedVersion": "4.17.21", "Severity": "HIGH", "Title": "Example vulnerability"}]},
        {"Target": "config.js", "Secrets": [{"RuleID": "example-token", "Title": "Token", "Severity": "HIGH",
                                              "StartLine": 2, "Match": "TOP-SECRET", "Code": {"Lines": [{"Content": "TOP-SECRET"}]}}]},
        {"Target": "Dockerfile", "Misconfigurations": [{"ID": "DS001", "Title": "Root user", "Severity": "MEDIUM",
            "Message": "Run as non-root", "Resolution": "Use USER", "CauseMetadata": {"StartLine": 3,
            "Code": {"Lines": [{"Content": "ANOTHER-SECRET"}]}}}]}]}


class NormalizationTest(unittest.TestCase):
    def test_valid_empty_trivy_report_is_distinct_from_missing_or_invalid_report(self):
        raw = {"SchemaVersion": 2, "ArtifactType": "filesystem", "ArtifactName": "/private/snapshot"}
        data = repository_scan.sanitize_trivy(raw, "app")
        self.assertEqual(repository_scan.trivy_findings(data), [])
        self.assertEqual(data["Results"], [])
        with self.assertRaises(ValueError):
            repository_scan.sanitize_trivy({"SchemaVersion": 2}, "app")

    def test_dojo_import_uses_utc_date_before_the_japan_day_rollover(self):
        utc = dt.datetime(2026, 11, 11, 20, 0, tzinfo=dt.timezone.utc)
        local = dt.date(2026, 11, 12)
        d = mock.Mock()
        d.reimport.return_value = {}
        with tempfile.TemporaryDirectory() as tmp:
            result = Path(tmp) / "report.json"
            result.write_text("{}")
            with mock.patch.object(kit, "connect", return_value=d), mock.patch.object(kit, "note_skipped"), \
                 mock.patch.object(kit.dt, "datetime") as clock, mock.patch.object(kit.dt, "date") as date:
                clock.now.return_value = utc
                date.today.return_value = local
                kit.import_result("Trivy Scan", result, kit.Target("TEST", "app", "test"), "fixture")
        self.assertEqual(d.reimport.call_args.kwargs["scan_date"], "2026-11-11")

    def test_dependencies_secrets_and_config_have_shared_fields_without_values(self):
        data = repository_scan.sanitize_trivy(trivy_data(), "app")
        findings = repository_scan.trivy_findings(data)
        self.assertEqual({f["category"] for f in findings}, {"dependency", "secret", "config"})
        dependency = next(f for f in findings if f["category"] == "dependency")
        self.assertEqual((dependency["component"], dependency["fixed_version"], dependency["severity"]),
                         ("lodash", "4.17.21", "High"))
        self.assertNotIn("TOP-SECRET", json.dumps(data) + json.dumps(findings))
        self.assertNotIn("ANOTHER-SECRET", json.dumps(data) + json.dumps(findings))
        self.assertEqual(len(data["Results"][0]["Packages"]), 2)
        self.assertEqual(data["ArtifactName"], "app")
        self.assertIn("伏せ", data["Results"][1]["Secrets"][0]["Match"])

    def test_sast_is_marked_for_review_instead_of_automatically_low_risk(self):
        result = classify.classify({"file_path": "src/api.js", "severity": "High"}, "Semgrep JSON Report",
                                   {"exposure": "external"})
        self.assertEqual(result[0], 1)
        self.assertTrue(result[2])

    def test_sbom_keeps_components_but_drops_credential_urls(self):
        raw = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
               "components": [{"type": "library", "name": "safe-package", "version": "1.0.0",
                               "bom-ref": "pkg:npm/safe-package@1.0.0", "purl": "pkg:npm/safe-package@1.0.0",
                               "externalReferences": [{"type": "vcs", "url": "https://user:TOP-SECRET@github.com/a/b"}]}]}
        data = repository_scan.sanitize_sbom(raw, "app", "a" * 40, "main")
        self.assertEqual(data["components"][0]["name"], "safe-package")
        self.assertEqual(data["metadata"]["component"]["version"], "a" * 40)
        self.assertNotIn("TOP-SECRET", json.dumps(data))

    def test_sbom_preserves_root_and_dependency_references(self):
        raw = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
               "metadata": {"component": {"type": "application", "name": "old", "bom-ref": "root"}},
               "components": [{"type": "library", "name": "library", "bom-ref": "dep"}],
               "dependencies": [{"ref": "root", "dependsOn": ["dep"]}, {"ref": "dep"}]}
        data = repository_scan.sanitize_sbom(raw, "app", "a" * 40, "main")
        refs = {data["metadata"]["component"].get("bom-ref"), *[c.get("bom-ref") for c in data["components"]]}
        self.assertTrue(all(d["ref"] in refs for d in data["dependencies"]))


class InputTest(unittest.TestCase):
    def test_github_url_is_restricted_to_repository_without_credentials(self):
        self.assertEqual(repository_scan.github_url("https://github.com/example-org/gas"),
                         "https://github.com/example-org/gas.git")
        for url in ("https://token@github.com/a/b", "https://example.test/a/b", "file:///tmp/repo",
                    "https://github.com/a/b?token=x", "https://github.com/a/b/tree/main"):
            with self.subTest(url=url), self.assertRaises(kit.KitError):
                repository_scan.github_url(url)

    def test_repository_job_validates_target_and_branch(self):
        with tempfile.TemporaryDirectory() as tmp:
            title, client, argv = targets.build_job({"tool": "repository", "target": tmp, "client": "TEST_B", "branch": "main"})
            self.assertEqual(client, "TEST_B")
            self.assertEqual(argv[:2], ["repository-scan", str(Path(tmp).resolve())])
            self.assertIn("main", argv)
            with self.assertRaises(targets.BadRequest):
                targets.build_job({"tool": "repository", "target": tmp, "client": "TEST_B", "branch": "--upload-pack=evil"})

    def test_cli_exposes_repository_scan(self):
        args = kit.build_parser().parse_args(["repository-scan", "/tmp/app", "--client", "TEST_B", "--no-import"])
        self.assertTrue(args.no_import)
        self.assertEqual(args.target, "/tmp/app")


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo, self.data = self.root / "repo", self.root / "data"
        self.repo.mkdir()
        git(self.repo, "init", "-b", "main")
        (self.repo / "code.js").write_text("const committed = true;\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-m", "fixture")
        self.sha = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "code.js").write_text("const uncommitted = true;\n")
        self.sources = []

    def command(self, argv, **kwargs):
        if "fs" in argv:
            source = Path(argv[-1])
            self.sources.append(source)
            self.assertEqual((source / "code.js").read_text(), "const committed = true;\n")
            self.assertIn("--list-all-pkgs", argv)
            Path(argv[argv.index("--output") + 1]).write_text(json.dumps(trivy_data()))
        elif "convert" in argv:
            packages = json.loads(Path(argv[-1]).read_text())["Results"][0]["Packages"]
            self.assertEqual(len(packages), 2)
            Path(argv[argv.index("--output") + 1]).write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "components": [{"type": "library", "name": p["Name"], "version": p["Version"]} for p in packages]}))
        return subprocess.CompletedProcess(argv, 0, "", "")

    def sast(self, source, directory):
        self.assertEqual(source, self.sources[0])
        return {"status": "completed", "tool": "Semgrep CE", "version": "1.179.0", "message": "", "scanned_files": 1,
                "report": None, "findings": [{"category": "code", "tool": "Semgrep", "id": "test.eval", "title": "eval",
                    "severity": "High", "file": "code.js", "line": 1, "component": "", "installed_version": "", "fixed_version": "",
                    "description": "Manual verification needed", "mitigation": "Review input"}]}

    def execute(self, command=None, sast=None, import_results=False):
        with mock.patch.object(kit, "DATA", self.data), \
             mock.patch.object(kit, "remote_tip", return_value=("main", self.sha, True)), \
             mock.patch.object(kit, "check_trivy", return_value="trivy"), \
             mock.patch.object(kit, "tool_version", return_value="0.76.1"), \
             mock.patch.object(repository_scan, "run_command", side_effect=command or self.command), \
             mock.patch.object(repository_scan.sast, "scan", side_effect=sast or self.sast):
            return repository_scan.scan_repository(self.repo, kit.Target("TEST_B", "app", "test"), import_results=import_results)

    def test_one_commit_is_shared_and_all_packages_are_saved(self):
        scan = self.execute()
        self.assertEqual(scan["status"], "completed")
        self.assertEqual(scan["commit"], self.sha)
        self.assertEqual(scan["counts"]["total"], 4)
        directory = self.data / "TEST_B" / "repository-scans" / scan["id"]
        result = json.loads((directory / "result.json").read_text())
        sbom = json.loads((directory / "sbom.cdx.json").read_text())
        self.assertEqual(len(sbom["components"]), 2)
        self.assertEqual(result["counts"]["category"]["code"], 1)
        self.assertNotIn("TOP-SECRET", "".join(p.read_text() for p in directory.glob("*.json")))
        self.assertEqual((directory.stat().st_mode & 0o777), 0o700)
        self.assertEqual((directory / "result.json").stat().st_mode & 0o777, 0o600)
        self.assertFalse(self.sources[0].exists())
        self.assertIn("uncommitted", (self.repo / "code.js").read_text())

    def test_sast_failure_preserves_other_results_as_partial(self):
        scan = self.execute(sast=lambda *_: {"status": "failed", "tool": "Semgrep CE", "version": "", "message": "unavailable",
                                            "findings": [], "report": None, "scanned_files": 0})
        self.assertEqual(scan["status"], "partial")
        self.assertEqual(scan["counts"]["category"]["dependency"], 1)
        self.assertTrue((self.data / "TEST_B" / "repository-scans" / scan["id"] / "sbom.cdx.json").is_file())

    def test_empty_trivy_findings_still_allow_completed_scan_and_sbom(self):
        def empty(argv, **kwargs):
            destination = Path(argv[argv.index("--output") + 1])
            if "fs" in argv:
                self.sources.append(Path(argv[-1]))
                destination.write_text(json.dumps({"SchemaVersion": 2, "ArtifactType": "filesystem", "ArtifactName": argv[-1]}))
            elif "convert" in argv:
                destination.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}')
            return subprocess.CompletedProcess(argv, 0, "", "")

        scan = self.execute(command=empty)
        self.assertEqual(scan["status"], "completed")
        self.assertEqual(scan["counts"]["category"]["dependency"], 0)
        self.assertTrue((self.data / "TEST_B" / "repository-scans" / scan["id"] / "sbom.cdx.json").is_file())

    def test_trivy_parse_diagnostics_make_scan_and_sbom_partial_without_storing_diagnostics(self):
        sentinel = "FIXTURE_DIAGNOSTIC_SECRET"
        diagnostics = ['\tDEBUG\tWalk error\tfile_path="broken/package-lock.json" ',
                       '\tDEBUG\t[analyzer] Analysis error\t',
                       '\tWARN\t[helm scanner] Skipping chart\tfile_path="chart" ']
        for diagnostic in diagnostics:
            with self.subTest(diagnostic=diagnostic):
                self.sources = []

                def partly_parsed(argv, **kwargs):
                    result = self.command(argv, **kwargs)
                    return subprocess.CompletedProcess(argv, 0, "", diagnostic + f'err="parse error: {sentinel}"\n') \
                        if "fs" in argv else result

                scan = self.execute(command=partly_parsed)
                self.assertEqual(scan["status"], "partial")
                stages = {stage["id"]: stage["status"] for stage in scan["stages"]}
                self.assertEqual(stages["trivy"], "partial")
                self.assertEqual(stages["sbom"], "partial")
                self.assertEqual(stages["sast"], "completed")
                self.assertEqual(scan["counts"]["total"], 4)
                directory = self.data / "TEST_B" / "repository-scans" / scan["id"]
                self.assertTrue((directory / "sbom.cdx.json").is_file())
                self.assertNotIn(sentinel, "".join(path.read_text() for path in directory.glob("*.json")))

    def test_trivy_advice_and_error_text_in_paths_do_not_mark_successful_analysis_partial(self):
        diagnostics = ['2026-11-12\tWARN\t[secret] The size of the scanned file is too large. It is recommended '
                       'to use `--skip-files` for this file to avoid high memory consumption.\tfile_path="large.txt"\n',
                       '2026-11-12\tDEBUG\t[secret] Using streaming scanner\tfile_path="error=handling.js"\n',
                       '2026-11-12\tDEBUG\t[secret] Skipped secret scanning as non-compliant to the rule\t'
                       'file_path="safe.js" rule_id="maven-settings-password"\n',
                       '2026-11-12\tWARN\tAdvisory information\tfile_path="error=handling.js"\n']
        for diagnostic in diagnostics:
            with self.subTest(diagnostic=diagnostic):
                self.sources = []
                def successful(argv, **kwargs):
                    result = self.command(argv, **kwargs)
                    return subprocess.CompletedProcess(argv, 0, "", diagnostic) if "fs" in argv else result
                scan = self.execute(command=successful)
                self.assertEqual(scan["status"], "completed")
                self.assertTrue(all(stage["status"] == "completed" for stage in scan["stages"]))

    def test_bad_trivy_output_does_not_stop_sast_or_claim_dependency_success(self):
        def broken(argv, **kw):
            if "fs" in argv:
                self.sources.append(Path(argv[-1]))
                Path(argv[argv.index("--output") + 1]).write_text('{"unexpected": true}')
                return subprocess.CompletedProcess(argv, 0, "", "")
            return self.command(argv, **kw)
        scan = self.execute(command=broken)
        self.assertEqual(scan["status"], "partial")
        self.assertEqual(scan["counts"]["category"]["code"], 1)
        self.assertEqual(next(s for s in scan["stages"] if s["id"] == "trivy")["status"], "failed")

    def test_malformed_nested_trivy_entries_do_not_stop_sast(self):
        def broken(argv, **kw):
            if "fs" in argv:
                self.sources.append(Path(argv[-1]))
                Path(argv[argv.index("--output") + 1]).write_text('{"SchemaVersion":2,"Results":[null]}')
                return subprocess.CompletedProcess(argv, 0, "", "")
            return self.command(argv, **kw)
        scan = self.execute(command=broken)
        self.assertEqual(scan["status"], "partial")
        self.assertEqual(scan["counts"]["category"]["code"], 1)
        self.assertEqual(next(s for s in scan["stages"] if s["id"] == "trivy")["status"], "failed")

    def test_literal_snapshot_ignores_export_ignore_and_export_subst(self):
        (self.repo / ".gitattributes").write_text("code.js export-ignore\nformat.txt export-subst\n")
        (self.repo / "format.txt").write_text("$Format:%H$\n")
        git(self.repo, "add", ".gitattributes", "format.txt")
        git(self.repo, "commit", "-m", "attributes")
        commit = git(self.repo, "rev-parse", "HEAD")
        destination = self.root / "literal"
        kit.export_tree(self.repo, commit, destination, literal=True)
        self.assertEqual((destination / "code.js").read_text(), "const committed = true;\n")
        self.assertEqual((destination / "format.txt").read_text(), "$Format:%H$\n")

    def test_cancellation_keeps_existing_findings_and_records_unfinished_stages(self):
        with self.assertRaises(KeyboardInterrupt):
            self.execute(sast=mock.Mock(side_effect=KeyboardInterrupt))
        path = next(self.data.glob("*/repository-scans/*/result.json"))
        result = json.loads(path.read_text())
        self.assertEqual(result["status"], "interrupted")
        self.assertEqual(result["counts"]["category"]["dependency"], 1)
        self.assertEqual(next(s for s in result["stages"] if s["id"] == "sast")["status"], "interrupted")

    def test_imports_cannot_close_previous_findings_and_failure_keeps_artifacts(self):
        with mock.patch.object(kit, "import_result", side_effect=kit.KitError("offline")) as imported:
            scan = self.execute(import_results=True)
        self.assertEqual(scan["status"], "partial")
        self.assertTrue(imported.called)
        self.assertTrue(all(c.kwargs["close_old_findings"] == "false" for c in imported.call_args_list))
        self.assertTrue((self.data / "TEST_B" / "repository-scans" / scan["id"] / "result.json").is_file())

    def test_import_records_visibility_and_exact_source_before_classification(self):
        def imported(*args, **kwargs):
            self.assertEqual(kit.load_systems("TEST_B")["app"]["visibility"], "public")
            self.assertEqual(kwargs["source_repo"], self.repo)
            self.assertEqual(kwargs["commit_hash"], self.sha)
            self.assertTrue(kwargs["source_literal"])

        with mock.patch.object(kit, "repo_visibility", return_value="public"), \
             mock.patch.object(kit, "import_result", side_effect=imported) as importer:
            scan = self.execute(import_results=True)
        self.assertTrue(importer.called)
        self.assertEqual(scan["status"], "completed")

    def test_scan_versions_are_available_to_existing_reports_without_moving_legacy_ai_cursor(self):
        self.execute()
        with mock.patch.object(kit, "DATA", self.data):
            versions = kit.used_tool_versions("TEST_B", "app", "test")
        self.assertEqual(versions["Trivy"], "0.76.1")
        self.assertEqual(versions["Semgrep"], "1.179.0")
        entries = [json.loads(line) for line in (self.data / "TEST_B" / "scan-log.jsonl").read_text().splitlines()]
        self.assertNotIn("Trivy git", [entry["tool"] for entry in entries])


if __name__ == "__main__":
    unittest.main()
