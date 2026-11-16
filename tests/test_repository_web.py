"""Local HTTP integration: auth, scoped artifact lookup, and the repository API."""
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
import dojo
import kit
import repository_scan
import web

RUN = "20261112-120000-abcdef012345"


class QuietHandler(web.Handler):
    def log_message(self, *args):
        pass


class RepositoryWebTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data = Path(self.tmp.name) / "data"
        patcher = mock.patch.object(kit, "DATA", self.data)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.directory = self.data / "TEST_B" / "repository-scans" / RUN
        self.directory.mkdir(parents=True)
        self.record = {"id": RUN, "client": "TEST_B", "product": "app", "created": "2026-11-12T12:00:00",
                       "status": "partial", "branch": "main", "commit": "a" * 40, "fresh": True,
                       "counts": {"total": 1, "category": {"code": 1}, "severity": {"High": 1}},
                       "stages": [{"id": "sast", "name": "コードの検査", "status": "partial", "message": "未完了",
                                   "count": 1, "version": "1.179.0"}],
                       "sbom": "sbom.cdx.json", "results": "result.json",
                       "findings": [{"category": "code", "title": "<script>fixture</script>", "file": "src/a.js", "line": 1}]}
        (self.directory / "result.json").write_text(json.dumps(self.record))
        (self.directory / "sbom.cdx.json").write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}')
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        self.server.token, self.server.version = "unit-token", "unit-test"
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (self.server.shutdown(), self.server.server_close(), thread.join(timeout=2)))
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def fetch(self, route, token=True):
        req = urllib.request.Request(self.base + route, headers={"X-Kit-Gateway": "unit-token"} if token else {})
        try:
            response = dojo.OPENER.open(req, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.loads(response.read()), response.headers

    def test_repository_list_and_detail_share_the_existing_gateway_authentication(self):
        self.assertEqual(self.fetch("/kit/api/repository-scans", token=False)[0], 403)
        status, data, _ = self.fetch("/kit/api/repository-scans")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["scans"]), 1)
        self.assertNotIn("findings", data["scans"][0])
        self.assertEqual(data["scans"][0]["status"], "partial")
        status, data, _ = self.fetch(f"/kit/api/repository-scans/{RUN}")
        self.assertEqual(status, 200)
        self.assertEqual(data["scan"]["findings"][0]["title"], "<script>fixture</script>")
        self.assertEqual(data["scan"]["commit"], "a" * 40)

    def test_client_filter_and_unknown_ids_do_not_become_paths(self):
        status, data, _ = self.fetch("/kit/api/repository-scans?client=OTHER")
        self.assertEqual((status, data), (200, {"scans": []}))
        for value in ("missing", "../result.json", "%2e%2e%2fresult.json", RUN + "x"):
            self.assertEqual(self.fetch(f"/kit/api/repository-scans/{value}")[0], 404)

    def test_sbom_download_has_a_distinct_useful_filename(self):
        status, data, _ = self.fetch(f"/kit/api/repository-scans/{RUN}")
        self.assertEqual(status, 200)
        url = data["scan"]["sbom"]
        status, data, headers = self.fetch(url + "?download=1")
        self.assertEqual(status, 200)
        self.assertEqual(data["bomFormat"], "CycloneDX")
        filename = urllib.parse.unquote(headers["Content-Disposition"])
        self.assertIn("SBOM", filename)
        self.assertIn(RUN, filename)
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_symlinked_results_are_not_listed_or_downloadable(self):
        outside = Path(self.tmp.name) / "outside.json"
        outside.write_text('{"secret":"fixture"}')
        link_dir = self.data / "OTHER" / "repository-scans" / "20261112-120001-abcdef012346"
        link_dir.mkdir(parents=True)
        (link_dir / "result.json").symlink_to(outside)
        self.assertEqual(len(repository_scan.list_scans()), 1)
        self.assertIsNone(repository_scan.get_scan(link_dir.name))
        self.assertEqual(self.fetch("/kit/files/OTHER/repository-scans/" + link_dir.name + "/result.json")[0], 404)

    def test_result_artifact_link_does_not_follow_a_symlink(self):
        (self.directory / "sbom.cdx.json").write_text("{}")
        other = self.data / "OTHER" / "private.json"
        other.parent.mkdir()
        other.write_text('{"secret":"fixture"}')
        # A fake record cannot redirect its SBOM link to a different artifact.
        self.record["sbom"] = "../../OTHER/private.json"
        (self.directory / "result.json").write_text(json.dumps(self.record))
        scan = repository_scan.get_scan(RUN)
        self.assertTrue(scan["sbom"].endswith("/sbom.cdx.json"))

    def test_a_dead_or_reused_worker_is_reconciled_as_interrupted(self):
        self.record.update(status="running", worker={"pid": 1, "started": "old process"})
        self.record["stages"][0]["status"] = "running"
        (self.directory / "result.json").write_text(json.dumps(self.record))
        with mock.patch.object(repository_scan, "process_started", return_value="different process"):
            scan = repository_scan.get_scan(RUN)
        self.assertEqual(scan["status"], "interrupted")
        self.assertEqual(scan["stages"][0]["status"], "interrupted")
        self.assertEqual(len(scan["findings"]), 1)
        self.assertNotIn("worker", scan)

    def test_worker_completion_during_liveness_check_does_not_lose_final_findings(self):
        self.record.update(status="running", worker={"pid": 1, "started": "old process"})
        (self.directory / "result.json").write_text(json.dumps(self.record))
        def worker_exits(_pid):
            completed = {**self.record, "status": "completed",
                         "findings": [*self.record["findings"], {"title": "last finding", "category": "code"}]}
            (self.directory / "result.json").write_text(json.dumps(completed))
            return "different process"
        with mock.patch.object(repository_scan, "process_started", side_effect=worker_exits):
            scan = repository_scan.get_scan(RUN)
        self.assertEqual(scan["status"], "completed")
        self.assertEqual(scan["findings"][-1]["title"], "last finding")
        self.assertEqual(json.loads((self.directory / "result.json").read_text())["status"], "completed")

    def test_temporary_ps_failure_does_not_overwrite_a_live_run(self):
        self.record.update(status="running", worker={"pid": 1, "started": "original process"})
        (self.directory / "result.json").write_text(json.dumps(self.record))
        with mock.patch.object(repository_scan, "process_started", return_value=None), \
             mock.patch.object(kit.jobs, "_alive", return_value=True):
            scan = repository_scan.get_scan(RUN)
        self.assertEqual(scan["status"], "running")


if __name__ == "__main__":
    unittest.main()
