"""SASTの固定設定・結果の消毒・未完了表示。外部サービスには接続しない。"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

try:
    import sast
except ModuleNotFoundError:
    sast = None


CATALOG = {"test.eval": {"message": "動的コード評価です。入力元を確認してください。", "severity": "WARNING"}}


def example_report(**changes):
    data = {
        "version": "1.179.0",
        "results": [{"check_id": "test.eval", "path": "/src/app.js", "start": {"line": 3, "col": 1},
                     "end": {"line": 3, "col": 28},
                     "extra": {"severity": "WARNING", "message": "dynamic value: SECRET_SOURCE_VALUE",
                               "lines": "eval('SECRET_SOURCE_VALUE')", "metavars": {"$X": "SECRET_SOURCE_VALUE"},
                               "dataflow_trace": {"content": "SECRET_SOURCE_VALUE"}}}],
        "errors": [], "paths": {"scanned": ["/src/app.js"]},
    }
    data.update(changes)
    return data


class SastTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(sast, "SAST module is not implemented")

    def test_preserves_locations_and_uses_trusted_descriptions_only(self):
        report, findings, scanned, invalid = sast.sanitize_report(example_report(), CATALOG)
        self.assertEqual((scanned, invalid), (1, 0))
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual((f["category"], f["id"], f["severity"], f["file"], f["line"]),
                         ("code", "test.eval", "Medium", "app.js", 3))
        for field in ("component", "installed_version", "fixed_version", "mitigation", "description"):
            self.assertIn(field, f)
        self.assertIn("動的コード評価", f["description"])
        persisted = json.dumps({"report": report, "findings": findings}, ensure_ascii=False)
        self.assertNotIn("SECRET_SOURCE_VALUE", persisted)
        self.assertNotIn("metavars", persisted)
        self.assertNotIn("dataflow_trace", persisted)
        self.assertEqual(report["results"][0]["path"], "app.js")

    def test_unknown_rules_and_outside_paths_are_not_trusted(self):
        data = example_report()
        data["results"] += [dict(data["results"][0], check_id="SECRET_SOURCE_VALUE"),
                            dict(data["results"][0], path="/etc/passwd"),
                            dict(data["results"][0], path="/src/../out/secret"),
                            dict(data["results"][0], path="../../secret")]
        report, findings, _, invalid = sast.sanitize_report(data, CATALOG)
        self.assertEqual((len(findings), invalid), (1, 4))
        self.assertNotIn("SECRET_SOURCE_VALUE", json.dumps(report))

    def test_info_severity_matches_defectdojo_low_mapping(self):
        catalog = {"test.eval": {"message": "確認候補です。", "severity": "INFO"}}
        _, findings, _, _ = sast.sanitize_report(example_report(), catalog)
        self.assertEqual(findings[0]["severity"], "Low")

    def test_command_is_offline_pinned_and_mounts_are_read_only(self):
        image = "semgrep/semgrep@sha256:" + "a" * 64
        argv = sast.command(image, Path("/tmp/source, spaced"), Path("/tmp/rules"), Path("/tmp/output"), "kit-sast-owned")
        self.assertIn("--network=none", argv)
        self.assertIn("--read-only", argv)
        self.assertIn("--cap-drop=ALL", argv)
        self.assertIn("--security-opt=no-new-privileges", argv)
        self.assertIn("--pull=never", argv)
        self.assertIn("--oss-only", argv)
        self.assertIn("--metrics=off", argv)
        self.assertIn("--no-rewrite-rule-ids", argv)
        self.assertIn("--x-ignore-semgrepignore-files", argv)
        self.assertIn(image, argv)
        self.assertIn("--config=/rules", argv)
        self.assertFalse(any(".semgrep" in value for value in argv))
        import csv
        mounts = [next(csv.reader([argv[i + 1]])) for i, value in enumerate(argv) if value == "--mount"]
        self.assertIn(["type=bind", "src=/tmp/source, spaced", "dst=/src", "readonly"], mounts)
        self.assertIn(["type=bind", "src=/tmp/rules", "dst=/rules", "readonly"], mounts)

    def test_modified_or_unlisted_rules_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "rules"
            shutil.copytree(sast.RULES, root)
            (root / "extra.yaml").write_text("rules: []")
            config = json.loads(sast.CONFIG.read_bytes())["semgrep"]
            with self.assertRaises(ValueError):
                sast.validate_rules(root, config)

    def test_changed_pinned_rule_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "rules"
            shutil.copytree(sast.RULES, root)
            (root / "local-web-baseline.yaml").write_text("rules: []")
            config = json.loads(sast.CONFIG.read_bytes())["semgrep"]
            with self.assertRaises(ValueError):
                sast.validate_rules(root, config)

    def simulate_scan(self, raw, returncode=0):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source, directory = root / "source", root / "result"
        source.mkdir()
        (source / "app.js").write_text("eval(value)")
        calls = []

        def run(argv, **kw):
            calls.append((argv, kw))
            if argv[1] == "run":
                import csv
                mounts = [dict(item.split("=", 1) for item in next(csv.reader([argv[i + 1]])) if "=" in item)
                          for i, value in enumerate(argv) if value == "--mount"]
                out = next(mount["src"] for mount in mounts if mount["dst"] == "/out")
                if raw is not None:
                    (Path(out) / "semgrep.json").write_text(json.dumps(raw))
                return subprocess.CompletedProcess(argv, returncode)
            return subprocess.CompletedProcess(argv, 0)

        config = {"image": "semgrep/semgrep@sha256:" + "a" * 64, "version": "1.179.0"}
        with mock.patch.object(sast, "configuration", return_value=(config, CATALOG)), \
             mock.patch.object(sast.kit, "which", return_value="/usr/bin/docker"), \
             mock.patch.object(sast.subprocess, "run", side_effect=run):
            result = sast.scan(source, directory)
        return result, directory, calls

    def test_scan_persists_only_sanitized_report_with_private_permissions(self):
        result, directory, calls = self.simulate_scan(example_report())
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["scanned_files"], 1)
        self.assertEqual(result["version"], "1.179.0")
        self.assertEqual(result["report"], directory.resolve() / "semgrep.json")
        self.assertNotIn("SECRET_SOURCE_VALUE", result["report"].read_text())
        self.assertEqual(result["report"].stat().st_mode & 0o777, 0o600)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertTrue(any(argv[1:3] == ["container", "rm"] for argv, _ in calls))
        self.assertFalse(any(p.name.startswith("raw") for p in directory.iterdir()))

    def test_parser_errors_keep_findings_but_mark_partial(self):
        raw = example_report(errors=[{"type": "ParseError", "message": "SECRET_SOURCE_VALUE"}])
        result, _, _ = self.simulate_scan(raw)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["findings"]), 1)
        self.assertNotIn("SECRET_SOURCE_VALUE", result["report"].read_text())

    def test_no_scanned_files_is_not_applicable_not_clean(self):
        result, _, _ = self.simulate_scan(example_report(results=[], paths={"scanned": []}))
        self.assertEqual(result["status"], "not_applicable")

    def test_missing_image_is_unavailable_and_does_not_create_report(self):
        result, directory, _ = self.simulate_scan(None, returncode=125)
        self.assertEqual(result["status"], "unavailable")
        self.assertIsNone(result["report"])
        self.assertFalse((directory / "semgrep.json").exists())

    def test_nonzero_exit_is_not_completed_even_with_valid_json(self):
        result, _, _ = self.simulate_scan(example_report(), returncode=2)
        self.assertEqual(result["status"], "partial")

    def test_malformed_result_is_not_accepted_as_clean(self):
        raw = example_report(results=["invalid", {"start": []}])
        result, _, _ = self.simulate_scan(raw)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["findings"], [])

    def test_incomplete_report_shape_fails_without_persisting_source(self):
        raw = example_report(paths=["SECRET_SOURCE_VALUE"])
        result, directory, _ = self.simulate_scan(raw)
        self.assertEqual(result["status"], "failed")
        self.assertIsNone(result["report"])
        self.assertFalse((directory / "semgrep.json").exists())

    def test_symlink_source_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            linked = root / "linked"
            linked.symlink_to(source, target_is_directory=True)
            result = sast.scan(linked, root / "result")
            self.assertEqual(result["status"], "failed")
            self.assertIsNone(result["report"])

    def test_non_directory_output_is_a_failed_stage_not_an_exception(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / "source", root / "output"
            source.mkdir()
            output.write_text("existing file")
            with mock.patch.object(sast, "configuration", return_value=({}, CATALOG)), \
                 mock.patch.object(sast.kit, "which", return_value="/usr/bin/docker"):
                result = sast.scan(source, output)
            self.assertEqual(result["status"], "failed")

    def test_desktop_path_uses_same_resolved_docker_and_environment_for_run_and_cleanup(self):
        import csv
        import kit

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, tools = root / "source", root / "tools"
            source.mkdir()
            tools.mkdir()
            (source / "app.js").write_text("eval(value)")
            docker = tools / "docker"
            docker.write_text("#!/bin/sh\nexit 1\n")
            docker.chmod(0o755)
            calls = []

            def run(argv, **kw):
                calls.append((argv, kw))
                if argv[1] == "run":
                    mounts = [dict(item.split("=", 1) for item in next(csv.reader([argv[i + 1]])) if "=" in item)
                              for i, value in enumerate(argv) if value == "--mount"]
                    out = next(mount["src"] for mount in mounts if mount["dst"] == "/out")
                    (Path(out) / "semgrep.json").write_text(json.dumps(example_report()))
                return subprocess.CompletedProcess(argv, 0)

            config = {"image": "semgrep/semgrep@sha256:" + "a" * 64, "version": "1.179.0"}
            with mock.patch.dict(os.environ, {"PATH": str(root / "empty-path")}), \
                 mock.patch.object(kit, "TOOLS_BIN", tools), \
                 mock.patch.object(sast, "configuration", return_value=(config, CATALOG)), \
                 mock.patch.object(sast.subprocess, "run", side_effect=run):
                self.assertIsNone(shutil.which("docker"))
                self.assertEqual(kit.which("docker"), str(docker))
                result = sast.scan(source, root / "result")
            self.assertEqual(result["status"], "completed")
            self.assertEqual([argv[1] for argv, _ in calls], ["run", "container"])
            for argv, kw in calls:
                self.assertEqual(argv[0], str(docker))
                self.assertEqual(kw["env"]["PATH"].split(os.pathsep)[0], str(tools))


if __name__ == "__main__":
    unittest.main()
