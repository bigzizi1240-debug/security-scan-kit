"""ダッシュボード(大項目のページ)と、大項目・小項目ごとの報告書・CSV の単体テスト。

DefectDojo と外部のサービスには触れない。
実行: uv run --no-project --python '>=3.11' -m unittest discover -s tests -v
"""
import csv
import datetime as dt
import io
import re
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

import ai_review  # noqa: E402
import classify  # noqa: E402
import jobs  # noqa: E402
import kit  # noqa: E402
import report  # noqa: E402
import targets  # noqa: E402
import triage  # noqa: E402
import web  # noqa: E402

T1, T2, T3 = classify.TIER_TAGS[1], classify.TIER_TAGS[2], classify.TIER_TAGS[3]
FIX, DECIDE, ACCEPT = triage.TAGS["fix"], triage.TAGS["decide"], triage.TAGS["accept"]
PRODUCTS = {"TEST_B": [{"id": 10, "name": "web", "prod_type": 3}, {"id": 11, "name": "api", "prod_type": 3}],
            "TEST_A": [{"id": 20, "name": "demo-app", "prod_type": 4}]}
# DefectDojo の有効な指摘の偽物(製品・重大度・タグ)。① は web 4 件・api 3 件
FINDINGS = [(10, "Critical", [T1, FIX]), (10, "Critical", [T1, FIX]), (10, "High", [T1, FIX]),
            (10, "High", [T1, FIX, ACCEPT]),  # 仕分けのタグが 2 つ(人が足したなど)。急ぐ方の「直す」だけに数える
            (11, "High", [T1, DECIDE]), (11, "High", [T1, DECIDE, classify.REVIEW_TAG]),
            (11, "High", [T1]),  # 仕分けがまだない
            (20, "High", [T2, ACCEPT])]


def fake_counts(params: dict) -> dict:
    """DefectDojo の件数の API の偽物(tags・tags__and・not_tags・重大度・製品で絞る)。"""
    def match(product: int, severity: str, tags: list[str]) -> bool:
        return (params.get("tags", tags[0]) in tags
                and set(filter(None, params.get("tags__and", "").split(","))) <= set(tags)
                and not set(filter(None, params.get("not_tags", "").split(","))) & set(tags)
                and params.get("severity", severity) == severity
                and params.get("test__engagement__product", product) == product)
    return {"count": sum(match(*f) for f in FINDINGS)}


class DashboardTest(unittest.TestCase):
    def load(self, tier="1", client="3", products=PRODUCTS):
        d = mock.Mock()
        d.call.side_effect = lambda method, path, params=None, **kw: fake_counts(params)
        with mock.patch.object(kit, "connect", return_value=d), \
             mock.patch.object(web, "client_products", return_value=products), \
             mock.patch.object(kit, "scope_summary", return_value=([("GCP", "権限がない")], [{"title": "x"}])):
            return web.dashboard(tier, client), d

    def test_counts_by_severity_system_and_triage(self):
        data, d = self.load()
        self.assertEqual((data["tier"], data["name"], data["total"], data["review"]), (1, "① 外部攻撃系統", 7, 1))
        self.assertEqual(data["meaning"], classify.TIER_MEANINGS[1])
        self.assertEqual(data["severities"], {"Critical": 2, "High": 5, "Medium": 0, "Low": 0, "Info": 0})
        self.assertEqual([(s["name"], s["count"]) for s in data["systems"]], [("web", 4), ("api", 3)])  # 顧客で絞る
        fix = next(t for t in data["triage"] if t["key"] == "fix")
        self.assertEqual((fix["label"], fix["severities"]["Critical"], fix["severities"]["High"]), ("直す", 2, 2))
        self.assertEqual([t["key"] for t in data["triage"]], list(triage.CATEGORIES))
        # 1 件は 1 つの小項目にだけ数える(タグが 2 つなら急ぐ方。報告書・リスク受容と同じ)。残りは仕分けなし
        self.assertEqual({t["key"]: t["total"] for t in data["triage"]}, {"fix": 4, "decide": 2, "accept": 0})
        self.assertEqual(data["untriaged"], 1)
        self.assertEqual(data["scope"], [{"client": "TEST_B", "skipped": [{"name": "GCP", "reason": "権限がない"}],
                                          "unjudged": 1}])
        for call in d.call.call_args_list:  # どの件数も、有効・重複でない・選んだ顧客の指摘で数える
            params = call.kwargs["params"]
            self.assertEqual((params["active"], params["duplicate"], params[web.CLIENT_PARAM]), ("true", "false", "3"))

    def test_links_open_the_matching_lists(self):
        data, _ = self.load()
        query = lambda url: urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)  # noqa: E731
        self.assertEqual(query(data["findings_url"]), {"tags": [T1], web.CLIENT_PARAM: ["3"]})
        links = {t["key"]: query(t["findings_url"]) for t in data["triage"]}
        self.assertEqual(links["fix"], {"tags_and": [T1, FIX], web.CLIENT_PARAM: ["3"]})
        self.assertEqual(links["decide"], {"tags_and": [T1, DECIDE], "not_tags": [FIX], web.CLIENT_PARAM: ["3"]})
        # DefectDojo の一覧は not_tags を 1 つの値として読む(繰り返すと最後の 1 つしか効かない)ので、カンマでつなぐ
        self.assertEqual(links["accept"], {"tags_and": [T1, ACCEPT], "not_tags": [f"{FIX},{DECIDE}"], web.CLIENT_PARAM: ["3"]})
        self.assertEqual(data["systems"][0]["url"], "/product/10/finding/open?" + urllib.parse.urlencode({"tags": T1}))

    def test_all_clients_and_the_tail_of_systems(self):
        many = {"A": [{"id": 100 + i, "name": f"s{i:02d}", "prod_type": 7} for i in range(12)]}
        d = mock.Mock()
        d.call.side_effect = lambda method, path, params=None, **kw: (
            {"count": params["test__engagement__product"] - 99} if "test__engagement__product" in params else {"count": 0})
        with mock.patch.object(kit, "connect", return_value=d), mock.patch.object(web, "client_products", return_value=many), \
             mock.patch.object(kit, "scope_summary", return_value=([], [])):
            data = web.dashboard("2", "")
        self.assertEqual(len(data["systems"]), web.TOP_SYSTEMS)  # 多い順に 10 本、残りは「その他」
        self.assertEqual(data["systems"][0], {"name": "s11", "client": "A", "count": 12,
                                              "url": "/product/111/finding/open?" + urllib.parse.urlencode({"tags": T2})})
        self.assertEqual(data["other"], {"count": 1 + 2, "systems": 2})
        self.assertNotIn(web.CLIENT_PARAM, d.call.call_args.kwargs["params"])  # すべての顧客

    def test_bad_input_is_refused(self):
        for tier, client in (("4", ""), ("", ""), ("1", "99"), ("1", "x")):
            with self.assertRaises(web.BadRequest):
                self.load(tier, client)


def finding(fid, tags, title="t", severity="High", **kw):
    f = {"id": fid, "title": title, "severity": severity, "tags": list(tags), "description": "説明", "mitigation": "1.1",
         "references": "", "component_name": "lodash", "component_version": "1.0", "file_path": "package-lock.json",
         "line": 3, "vulnerability_ids": [{"vulnerability_id": "CVE-2026-0001"}], "cvssv3": "CVSS:3.1/AV:N",
         "cvssv3_score": 9.8, "date": "2026-10-29", "epss_score": 0.2, "epss_percentile": 0.95,
         "known_exploited": False, "kev_date": None}
    f.update(kw)
    return f


class ReportScopeTest(unittest.TestCase):
    def test_collect_findings_filters_by_tier_and_triage(self):
        d = mock.Mock()
        d.iterate.side_effect = lambda path, params=None: {"/api/v2/engagements/": [{"id": 5, "name": "e"}],
                                                           "/api/v2/tests/": [{"id": 7, "title": "t"}],
                                                           "/api/v2/findings/": []}[path]
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)), \
             mock.patch.object(kit, "client_products", return_value=[{"id": 1, "name": "app", "prod_type": 3}]):
            for tier, key, expected in ((1, "fix", {"tags__and": f"{T1},{FIX}"}),
                                        (1, "decide", {"tags__and": f"{T1},{DECIDE}", "not_tags": FIX}),
                                        (None, "accept", {"tags": ACCEPT, "not_tags": f"{FIX},{DECIDE}"}),
                                        (2, None, {"tags": T2})):
                kit.collect_findings(d, "A", None, None, tier, key)
                params = [c.args[1] for c in d.iterate.call_args_list if c.args[0] == "/api/v2/findings/"][-1]
                self.assertEqual({k: v for k, v in params.items() if "tags" in k}, expected)

    def test_csv_has_tier_and_triage_columns_and_is_safe_for_excel(self):
        rows = [report.finding_from_api("app", "e", {"title": "Trivy"}, finding(1, (T1, "仕分け-直す")), "外部に公開", "",
                                        "版上げ"),
                report.finding_from_api("app", "e", {"title": "Trivy"},
                                        finding(2, (T3, "仕分け-リスク受容"), title="=HYPERLINK(1)", severity="Low"))]
        table = list(csv.reader(io.StringIO(report.render_csv(list(reversed(rows)), "http://127.0.0.1:18080"))))
        head = table[0]
        self.assertEqual(head[:4], ["大項目", "小項目", "優先", "仕分けの理由"])
        self.assertEqual([r[:4] for r in table[1:]], [["① 外部攻撃系統", "直す", "1: 悪用の証拠", "版上げ"],
                                                      ["③ 低可能性", "リスク受容", "1: 悪用の証拠", ""]])  # EPSS 20%
        self.assertEqual(table[2][head.index("タイトル")], "'=HYPERLINK(1)")  # 数式として動かない
        self.assertEqual(table[1][head.index("DefectDojo")], "http://127.0.0.1:18080/finding/1")
        self.assertEqual((table[1][head.index("部品")], table[1][head.index("版")], table[1][head.index("場所")]),
                         ("lodash", "1.0", "package-lock.json:3"))
        self.assertEqual(table[1][head.index("EPSS")], "20.0%")

    def test_report_files_carry_tier_and_triage(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp).resolve()):
            folder = kit.client_dir("TEST_B") / "reports"
            folder.mkdir()
            for ext in (".html", ".pdf", ".csv"):
                (folder / f"report-20261030-191506-tier1-fix{ext}").write_text("x", encoding="utf-8")
            html = folder / "report-20261030-191506-tier1-fix.html"
            self.assertEqual(web.report_scope(html), (1, "fix", "① 外部攻撃系統 › 直す"))
            self.assertEqual(web.download_name(html.with_suffix(".csv")), "TEST_B_脆弱性診断_①外部攻撃系統_直す_20261030-1915.csv")
            listing = web.list_reports()
            self.assertEqual((listing[0]["scope"], listing[0]["csv"].endswith(".csv")), ("① 外部攻撃系統 › 直す", True))
            self.assertIsNotNone(web.resolve_data_file("TEST_B/reports/report-20261030-191506-tier1-fix.csv"))
        self.assertEqual(web.report_scope(Path("report-20261030-191506.html")), (None, None, "すべて"))

    def test_scoped_report_counts_only_its_subitem(self):
        rows = [report.finding_from_api("app", "e", {"title": "Trivy"}, finding(1, (T1, FIX)))]
        page = report.render_html("A", rows, {}, dt.datetime(2026, 10, 30), tier=1, triage_key="fix")
        self.assertIn("<tr><th>載せた指摘</th><td>① 外部攻撃系統 › 直す</td></tr>", page)
        self.assertIn("<td>① 外部攻撃系統 › 直す</td>", page)  # 1 章の件数の表
        self.assertNotIn("① 外部攻撃系統 › システムごとに決める", page)  # 絞って外した小項目を 0 件と書かない
        everything = report.render_html("A", rows, {}, dt.datetime(2026, 10, 30))
        self.assertIn("<td>① 外部攻撃系統 › システムごとに決める</td>", everything)  # すべてなら 0 件の行も並べる

    def test_scope_label(self):
        self.assertEqual([report.scope_label(t, k) for t, k in ((None, None), (2, None), (1, "fix"), (None, "accept"))],
                         ["すべて", "② 横展開系統", "① 外部攻撃系統 › 直す", "すべて › リスク受容"])
        self.assertEqual(report.scope_label(None, None, "すべての指摘"), "すべての指摘")

    def test_report_job_takes_tier_and_triage(self):
        title, _, argv = targets.build_job({"tool": "report", "client": "A", "tier": "1", "triage": "fix"})
        self.assertEqual(argv, ["report", "--client", "A", "--tier", "1", "--triage", "fix"])
        self.assertEqual(title, "報告書: A(① 外部攻撃系統 › 直す)")
        self.assertEqual(targets.build_job({"tool": "report", "client": "A"})[0], "報告書: A")
        with self.assertRaises(targets.BadRequest):
            targets.build_job({"tool": "report", "client": "A", "triage": "now"})
        self.assertEqual(kit.build_parser().parse_args(["report", "--client", "A", "--triage", "decide"]).triage, "decide")


class TagNameTest(unittest.TestCase):
    def test_tags_survive_defectdojo_tag_parsing(self):
        # DefectDojo(tagulous)は一覧の画面のタグの値を、カンマ・空白・" で区切って読む(not_tags はカンマでつなぐ)
        names = [*triage.TAGS.values(), *classify.TIER_TAGS.values(), classify.REVIEW_TAG, *ai_review.TAGS.values()]
        self.assertEqual([t for t in names if re.search(r'[,"\s]', t) or t != t.lower()], [])


class JobReportTest(unittest.TestCase):
    """ダッシュボードの PDF・CSV は、そのジョブが作った報告書を保存する(ジョブのログの行から探す)。"""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        real = Path(tmp.name) / "data"
        real.mkdir()
        link = Path(tmp.name) / "data-link"  # data/ がシンボリックリンクでも動く(パスを resolve した側とそろえる)
        link.symlink_to(real, target_is_directory=True)
        for name, value in (("DATA", link), ("JOBS_DIR", link / "jobs")):
            patcher = mock.patch.object(kit, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_job(self, log_text: str) -> dict:
        job = jobs.create(kit.JOBS_DIR, "報告書", "A", ["report"])
        (kit.JOBS_DIR / job["id"] / "log.txt").write_text(log_text, encoding="utf-8")
        return web.job_report(job["id"])

    def test_files_come_from_the_job_log(self):
        folder = kit.client_dir("A") / "reports"
        folder.mkdir()
        html = folder / "report-20261030-200811-tier2-accept.html"
        for ext in (".html", ".csv"):  # PDF は作れなかった(Chrome がない)
            html.with_suffix(ext).write_text("x", encoding="utf-8")
        (folder / "report-20261030-200812-tier2-accept.html").write_text("x", encoding="utf-8")  # ほかのジョブの分
        files = self.run_job(f"取り込み…\n{kit.REPORT_DONE}(3 件): {html.resolve()}\nCSV: …\n")
        self.assertEqual(files, {"html": "/kit/files/A/reports/report-20261030-200811-tier2-accept.html", "pdf": None,
                                 "csv": "/kit/files/A/reports/report-20261030-200811-tier2-accept.csv"})

    def test_client_folder_with_percent(self):
        folder = kit.client_dir("A%2e%2e") / "reports"
        folder.mkdir()
        (folder / "report-1.html").write_text("x", encoding="utf-8")
        files = self.run_job(f"{kit.REPORT_DONE}(1 件): {(folder / 'report-1.html').resolve()}\n")
        self.assertEqual(files["html"], "/kit/files/A%252e%252e/reports/report-1.html")

    def test_refuses_lines_outside_the_reports(self):
        outside = kit.client_dir("A") / "run"
        outside.mkdir()
        (outside / "result.html").write_text("x", encoding="utf-8")  # data/ の中だが、報告書の場所ではない
        hosts = Path("/etc/hosts")
        for text in ("", f"{kit.REPORT_DONE}(1 件): {(outside / 'result.html').resolve()}\n",
                     f"{kit.REPORT_DONE}(1 件): {hosts}.html\n"):
            with self.subTest(text=text), self.assertRaises(web.BadRequest):
                self.run_job(text)


class ReportNameTest(unittest.TestCase):
    def test_cmd_report_does_not_overwrite_a_report_of_the_same_second(self):
        frozen = dt.datetime(2026, 10, 30, 20, 7, 34)
        clock = mock.Mock(datetime=mock.Mock(now=mock.Mock(return_value=frozen)), timedelta=dt.timedelta)
        args = kit.build_parser().parse_args(["report", "--client", "A", "--tier", "1", "--triage", "accept"])
        rows = [report.finding_from_api("app", "e", {"title": "Trivy"}, finding(1, (T1, ACCEPT)))]
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)), \
             mock.patch.object(kit, "dt", clock), mock.patch.object(kit, "say"), mock.patch.object(kit, "connect"), \
             mock.patch.object(kit, "collect_findings", return_value=(rows, [])), \
             mock.patch.object(kit, "scope_summary", return_value=([], [])), \
             mock.patch.object(kit, "count_ai_dismissed", return_value=0), \
             mock.patch.object(kit, "count_closed", return_value=0), \
             mock.patch.object(kit, "used_tool_versions", return_value={}), \
             mock.patch.object(report, "html_to_pdf", return_value=False):
            folder = Path(tmp) / "A" / "reports"
            kit.cmd_report(args)
            kit.cmd_report(args)  # 同じ秒に、同じ範囲の報告書をもう 1 つ(ダッシュボードと報告書のタブが重なったなど)
            pages = sorted(folder.glob("*.html"))
            self.assertEqual([p.name for p in pages],
                             ["report-20261030-200734-tier1-accept.html", "report-20261030-200735-tier1-accept.html"])
            self.assertTrue(all(p.read_text(encoding="utf-8").startswith("<!doctype html>") for p in pages))
            with mock.patch.object(report, "render_html", side_effect=RuntimeError("壊れた")), self.assertRaises(RuntimeError):
                kit.cmd_report(args)
            self.assertEqual(len(list(folder.glob("*.html"))), 2)  # 作る途中で失敗しても、空の報告書を残さない

    def test_reports_made_in_the_same_second_get_their_own_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = dt.datetime(2026, 10, 30, 20, 7, 34)
            first = kit.new_report_path(Path(tmp), now, "-tier1")
            second = kit.new_report_path(Path(tmp), now, "-tier1")  # 同じ秒・同じ範囲のジョブが重なった
            self.assertEqual((first.name, second.name),
                             ("report-20261030-200734-tier1.html", "report-20261030-200735-tier1.html"))
            self.assertTrue(first.exists() and second.exists())


if __name__ == "__main__":
    unittest.main()
