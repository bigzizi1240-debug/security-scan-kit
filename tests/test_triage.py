"""仕分け(lib/triage.py)・EPSS と KEV(lib/intel.py)・リスク受容(lib/accept.py)の単体テスト。

DefectDojo と外部のサービスには触れない。
実行: uv run --no-project --python '>=3.11' -m unittest discover -s tests -v
"""
import csv
import datetime as dt
import gzip
import http.client
import io
import json
import os
import re
import sys
import tempfile
import time
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

import accept  # noqa: E402
import classify  # noqa: E402
import dojo  # noqa: E402
import intel  # noqa: E402
import kit  # noqa: E402
import report  # noqa: E402
import targets  # noqa: E402
import triage  # noqa: E402
import web  # noqa: E402

T1, T2, T3 = classify.TIER_TAGS[1], classify.TIER_TAGS[2], classify.TIER_TAGS[3]


def _intel(epss=None, kev=None):
    return intel.Intel(epss=epss or {}, kev=kev or {}, epss_version="v1(2026-10-29 の値)" if epss is not None else "",
                       kev_version="2026.10.29" if kev is not None else "")


def _dep(fid=1, cve="CVE-2026-0001", version="15.5.23", fixed="15.5.28, 16.4.1", tags=(T1, "npm"), **kw):
    f = {"id": fid, "test": 7, "title": f"{cve} Next", "tags": list(tags), "component_name": "next",
         "component_version": version, "mitigation": fixed, "vulnerability_ids": [{"vulnerability_id": cve}],
         "vuln_id_from_tool": None, "severity": "High"}
    f.update(kw)
    return f


def _epss_gz(rows, header="#model_version:v2026.06.15,score_date:2026-10-29T12:03:14Z"):
    return gzip.compress(("\n".join([header, "cve,epss,percentile", *rows]) + "\n").encode())


def _kev_json(*items, version="2026.10.29"):
    return json.dumps({"catalogVersion": version, "vulnerabilities": list(items)}).encode()


class IntelTest(unittest.TestCase):
    def test_parse(self):
        scores, version = intel.parse_epss(_epss_gz(["CVE-2026-0001,0.34,0.99", "junk,1,1", "CVE-2026-0002,0.01,0.2"]))
        self.assertEqual(scores, {"CVE-2026-0001": (0.34, 0.99), "CVE-2026-0002": (0.01, 0.2)})
        self.assertEqual(version, "v2026.06.15(2026-10-29 の値)")
        for bad in (b"not gzip", _epss_gz(["CVE-2026-0001,1.5,0.9"]), _epss_gz([], header="#x"), gzip.compress(b"a,b\n")):
            with self.assertRaises(intel.IntelError):
                intel.parse_epss(bad)
        kev, kev_version = intel.parse_kev(_kev_json(
            {"cveID": "CVE-2026-0001", "dateAdded": "2026-01-22", "knownRansomwareCampaignUse": "Known"},
            {"cveID": "bad"}, {"cveID": "CVE-2026-0002", "dateAdded": "soon"}))
        self.assertEqual(kev, {"CVE-2026-0001": intel.Kev("2026-01-22", True), "CVE-2026-0002": intel.Kev("", False)})
        self.assertEqual(kev_version, "2026.10.29")
        for bad in (b"{", b"[]", _kev_json(), json.dumps({"vulnerabilities": []}).encode()):
            with self.assertRaises(intel.IntelError):
                intel.parse_kev(bad)

    def test_cache_refresh_and_fallback(self):
        good = {intel.EPSS_URL: _epss_gz(["CVE-2026-0001,0.5,0.9"]),
                intel.KEV_URL: _kev_json({"cveID": "CVE-2026-0001", "dateAdded": "2026-01-22"})}
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "intel"
            with mock.patch.object(intel, "download", side_effect=lambda url: good[url]) as download:
                first = intel.load(folder)
                again = intel.load(folder)  # 24 時間以内は取り直さない
            self.assertEqual(download.call_count, 2)
            self.assertEqual((first.epss, again.kev_version, first.notes), ({"CVE-2026-0001": (0.5, 0.9)}, "2026.10.29", []))
            old = time.time() - intel.MAX_AGE - 60
            for name in ("epss.csv.gz", "kev.json"):
                os.utime(folder / name, (old, old))
            with mock.patch.object(intel, "download", side_effect=OSError("offline")):
                stale = intel.load(folder)  # 取れなければ前のファイルを使う
            self.assertEqual(stale.epss_version, "v2026.06.15(2026-10-29 の値)")
            self.assertTrue(any("取れませんでした" in n for n in stale.notes))
            self.assertTrue(any("に取った一覧を使いました" in n for n in stale.notes))
            with mock.patch.object(intel, "download", return_value=b"broken"):
                kept = intel.load(folder, refresh=True)  # 形の合わないもので前のファイルを置き換えない
            self.assertEqual(kept.kev_version, "2026.10.29")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(intel, "download", side_effect=OSError("offline")):
            empty = intel.load(Path(tmp))
        self.assertEqual((empty.epss_version, empty.kev_version, empty.epss), ("", "", {}))
        self.assertTrue(any("データがない" in n for n in empty.notes))

    def test_broken_inputs_and_insecure_redirects_are_refused(self):
        broken = bytearray(_epss_gz(["CVE-2026-0001,0.5,0.9"] * 50))
        broken[20:40] = b"\xff" * 20  # 頭は正しく、中身が壊れた gzip(zlib.error)
        with self.assertRaises(intel.IntelError):
            intel.parse_epss(bytes(broken))
        with self.assertRaises(intel.IntelError):
            intel.parse_kev(b"[" * 200000 + b"]" * 200000)  # 深い入れ子(RecursionError)

        class Res:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self, n):
                return b"data"

            def geturl(self):
                return "http://example.invalid/epss.csv.gz"
        with mock.patch.object(intel.urllib.request, "urlopen", return_value=Res()):
            with self.assertRaises(intel.IntelError):
                intel.download(intel.EPSS_URL)  # HTTPS 以外へ転送されたものは使わない


class VersionTest(unittest.TestCase):
    def test_fix_plan(self):
        self.assertEqual(triage.fix_plan("15.5.23", "15.5.28, 16.4.1"), ("same", "15.5.23 → 15.5.28"))
        self.assertEqual(triage.fix_plan("4.2.1", "6.2.4, 5.4.16"), ("cross", "4.2.1 → 5.4.16"))
        self.assertEqual(triage.fix_plan("0.17.1", "0.18.0"), ("cross", "0.17.1 → 0.18.0"))  # 0.x はマイナー版が系列
        self.assertEqual(triage.fix_plan("0.17.1", "0.17.3, 0.18.0"), ("same", "0.17.1 → 0.17.3"))
        self.assertEqual(triage.fix_plan("v1.2.3", "v1.4.0"), ("same", "v1.2.3 → v1.4.0"))
        self.assertEqual(triage.fix_plan("1.2.3", ""), ("none", ""))
        self.assertEqual(triage.fix_plan("1.2.3", None), ("none", ""))
        self.assertEqual(triage.fix_plan("abc", "1.0.0")[0], "unknown")
        self.assertEqual(triage.fix_plan("1:2.3.4-1", "1:2.3.5-1")[0], "unknown")  # OS のパッケージの epoch は読まない
        self.assertEqual(triage.fix_plan("2.0.0", "1.9.9")[0], "unknown")  # 今より新しい直した版がない
        # Ruby(Bundler)の直した版は条件の記号つき(>=・~>)。記号を外して読む
        self.assertEqual(triage.fix_plan("1.11.7", ">= 1.19.4"), ("same", "1.11.7 → 1.19.4"))
        self.assertEqual(triage.fix_plan("2.2.3", "~> 2.2.23, ~> 3.1.21, >= 3.2.6"), ("same", "2.2.3 → 2.2.23"))
        self.assertEqual(triage.fix_plan("6.0.4", "~> 7.2.3, >= 7.2.3.1, ~> 8.0.4"), ("cross", "6.0.4 → 7.2.3"))
        self.assertEqual(triage.fix_plan("6.0.4", "~> 6.0.4, >= 6.0.4.1, >= 6.1.4.1"), ("same", "6.0.4 → 6.0.4.1"))
        self.assertEqual(triage.fix_plan("2.2.0", ">=2.2.1"), ("same", "2.2.0 → 2.2.1"))
        # 数字が同じで後ろだけ違う(前リリース・パッケージの改訂)は、同じ系列の版上げ
        self.assertEqual(triage.fix_plan("15.0.0-canary.3", "15.0.0, 14.2.25"), ("same", "15.0.0-canary.3 → 15.0.0"))
        self.assertEqual(triage.fix_plan("2.36-9+deb12u4", "2.36-9+deb12u7"), ("same", "2.36-9+deb12u4 → 2.36-9+deb12u7"))
        self.assertEqual(triage.fix_plan("1.2.3", "1.2.3")[0], "unknown")  # 同じ版は直した版ではない


class RulesTest(unittest.TestCase):
    def decide(self, finding, scan_type="Trivy Scan", check="", info=None, ai=False):
        return triage.triage(finding, scan_type, check, info or _intel({}, {}), ai)

    def test_first_matching_rule_wins(self):
        info = _intel({"CVE-2026-0001": (0.5, 0.99)}, {"CVE-2026-0001": intel.Kev("2026-01-22", True)})
        secret = self.decide(_dep(tags=(T1, "secret")), info=info)
        self.assertEqual((secret.key, secret.group), ("fix", "秘密情報"))
        kev = self.decide(_dep(), info=info, ai=True)
        self.assertEqual((kev.key, kev.group), ("fix", "CISA KEV"))
        self.assertIn("2026-01-22 に追加。ランサムウェアでの悪用も確認", kev.reason)
        ai = self.decide(_dep(), info=_intel({"CVE-2026-0001": (0.5, 0.99)}, {}), ai=True)
        self.assertEqual(ai.group, "AI の確認で影響あり")
        epss = self.decide(_dep(), info=_intel({"CVE-2026-0001": (0.34, 0.99)}, {}))
        self.assertEqual((epss.key, epss.group), ("fix", "EPSS が高い"))
        self.assertEqual(epss.reason, "CVE-2026-0001 の EPSS 34.0%(30 日以内に悪用される見込み。上位 1%)")
        self.assertEqual(triage.epss_text(0.5, None), "EPSS 50.0%(30 日以内に悪用される見込み)")
        low = self.decide(_dep(), info=_intel({"CVE-2026-0001": (0.0999, 0.9)}, {}))
        self.assertEqual((low.key, low.group), ("fix", "同じ系列の版上げ"))

    def test_dependencies(self):
        self.assertEqual(self.decide(_dep()).reason, "同じ系列の版上げで直る(15.5.23 → 15.5.28)")
        cross = self.decide(_dep(version="4.2.1", fixed="6.2.4, 5.4.16"))
        self.assertEqual((cross.key, cross.group), ("decide", "系列をまたぐ版上げ"))
        self.assertEqual(self.decide(_dep(fixed="")).group, "直した版がない")
        self.assertIn("版を読めない", self.decide(_dep(version="latest")).reason)

    def test_github_and_config(self):
        prowler = {"tags": [T2], "title": "x", "vulnerability_ids": []}
        batch = self.decide(prowler, "Prowler Scan", "repository_default_branch_protection_enabled")
        self.assertEqual((batch.key, batch.reason), ("fix", "GitHub の設定でまとめて直せる(既定ブランチの保護)"))
        sign = self.decide(prowler, "Prowler Scan", "repository_default_branch_requires_signed_commits")
        self.assertEqual((sign.key, sign.group), ("accept", "GitHub の運用ルール"))
        self.assertEqual(self.decide(prowler, "Prowler Scan", "iam_root_mfa_enabled").group, "規則なし")
        self.assertIn("元の結果", self.decide(prowler, "Prowler Scan", "").reason)  # チェックを引けないことを理由に出す
        root = {"tags": [T2, "config"], "title": "DS-0002 - Image User Should Not Be 'Root'", "vulnerability_ids": []}
        self.assertEqual(self.decide(root).group, "コンテナを root で動かす")
        log = {"tags": [T2, "config"], "title": "GCP-0077 - Cloud Storage Bucket Logging Not Enabled",
               "vulnerability_ids": []}
        self.assertEqual(self.decide(log).group, "記録(ログ)の設定")
        exposed = {"tags": [T1, "config"], "title": "AWS-0107 - Security group allows ingress from 0.0.0.0/0",
                   "vulnerability_ids": []}
        self.assertEqual(self.decide(exposed).group, "規則なし")
        catalog = {"tags": [T2, "config"], "title": "Catalog of things", "vulnerability_ids": []}  # 単語でない log
        self.assertEqual(self.decide(catalog).group, "規則なし")

    def test_low_likelihood_is_always_risk_acceptance(self):
        info = _intel({"CVE-2026-0001": (0.9, 0.999)}, {"CVE-2026-0001": intel.Kev("2026-01-22", True)})
        for finding in (_dep(tags=(T3, "secret")), _dep(tags=(T3,))):
            decision = triage.triage(finding, "Trivy Scan", "", info, True, tier=3)
            self.assertEqual((decision.key, decision.group), ("accept", "低可能性"))

    def test_vuls_uses_only_kev_and_epss(self):
        host = _dep(tags=(T1,))
        self.assertEqual(self.decide(host, "Vuls Scan").group, "規則なし")
        self.assertEqual(self.decide(host, "Vuls Scan", info=_intel({"CVE-2026-0001": (0.2, 0.95)}, {})).group,
                         "EPSS が高い")

    def test_intel_fields(self):
        info = _intel({"CVE-2026-0001": (0.2, 0.9), "CVE-2026-0002": (0.5, 0.97)},
                      {"CVE-2026-0002": intel.Kev("2026-02-01", False)})
        both = _dep(vulnerability_ids=[{"vulnerability_id": "CVE-2026-0001"}, {"vulnerability_id": "CVE-2026-0002"}])
        self.assertEqual(triage.intel_fields(both, info), {"epss_score": 0.5, "epss_percentile": 0.97,
                                                           "known_exploited": True, "ransomware_used": False,
                                                           "kev_date": "2026-02-01"})
        ghsa = _dep(vulnerability_ids=[{"vulnerability_id": "GHSA-xxxx"}])
        self.assertEqual(triage.intel_fields(ghsa, info)["epss_score"], None)
        self.assertEqual(triage.intel_fields(both, intel.Intel()), {})  # データがなければ欄に触れない


class TierNameTest(unittest.TestCase):
    def test_tier_names_and_legacy_tags(self):
        self.assertEqual([(classify.TIER_TAGS[t], classify.TIER_NAMES[t]) for t in (1, 2, 3)],
                         [("①外部攻撃系統", "① 外部攻撃系統"), ("②横展開系統", "② 横展開系統"), ("③低可能性", "③ 低可能性")])
        self.assertFalse(hasattr(classify, "TIER_LABELS"))  # 長い名前はやめ、画面・報告書とも TIER_NAMES にそろえた
        # 前の名前(①外部から直接・②横展開・③可能性が低い)も読む
        self.assertEqual([classify.tier_of(t) for t in (["x", "②横展開"], ["①外部から直接"], ["③可能性が低い"],
                                                         ["③低可能性"], ["②横展開系統"], ["x"])], [2, 1, 3, 3, 2, None])

    def test_reclassify_renames_old_tier_tags_on_closed_findings(self):
        # 誤検知・重複・リスク受容・直ったものは分類し直さないが、前の名前のタグは今の名前に付け替える
        closed = [_dep(2, tags=("①外部から直接", "ai判定-影響なし"), active=False, false_p=True),
                  _dep(3, tags=("npm", "②横展開"), active=False, duplicate=True)]
        queries = []

        def iterate(path, params):
            queries.append(params)
            if params.get("active") == "true":
                return [_dep(1, tags=("①外部から直接", "npm"))]
            return closed if params.get("active") == "false" else []
        d = mock.Mock()
        d.iterate.side_effect = iterate
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)):
            counts = kit.classify_test(d, "A", "app", 7, "Trivy Scan")
        patches = {c.args[1]: c.kwargs["json_body"]["tags"] for c in d.call.call_args_list}
        # 有効な指摘は重複を除いて引き(有効なまま重複になったものは DefectDojo が PATCH を拒む)、
        # 有効でない指摘は前の名前のタグ(カンマでつなぐと OR)で 1 回だけ引く
        self.assertEqual(queries, [{"test": 7, "active": "true", "duplicate": "false"},
                                   {"test": 7, "active": "false", "tags": ",".join(classify.LEGACY_TIER_TAGS)}])
        self.assertEqual(counts, Counter({1: 1}))  # 数えるのは有効な指摘だけ
        self.assertEqual(patches["/api/v2/findings/2/"], ["①外部攻撃系統", "ai判定-影響なし"])
        self.assertEqual(patches["/api/v2/findings/3/"], ["npm", "②横展開系統"])
        self.assertEqual(sorted(patches["/api/v2/findings/1/"]), sorted(["npm", "①外部攻撃系統", "分類を要確認"]))

    def test_reclassify_replaces_the_old_tier_tag(self):
        d = mock.Mock()
        d.iterate.return_value = [_dep(1, tags=("③可能性が低い", "npm"), file_path="test/package-lock.json")]
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)):
            counts = kit.classify_test(d, "A", "app", 7, "Trivy Scan")
        self.assertEqual(counts, Counter({3: 1}))
        self.assertEqual(sorted(d.call.call_args.kwargs["json_body"]["tags"]), sorted(["npm", "③低可能性"]))


class ManualTest(unittest.TestCase):
    FIX = triage.Decision("fix", "理由", "EPSS が高い")
    DECIDE = triage.Decision("decide", "系列をまたぐ", "系列をまたぐ版上げ")

    def test_auto_and_manual(self):
        tags, record = triage.resolve([T1, "npm"], None, self.FIX)
        self.assertEqual((tags, record["auto"], record["manual"]), ([T1, "npm", "仕分け-直す"], "fix", False))
        tags, record = triage.resolve(tags, record, self.DECIDE)  # 規則の結果が変われば付け替える
        self.assertEqual(tags, [T1, "npm", "仕分け-システムごとに決める"])
        manual = [T1, "npm", "仕分け-リスク受容"]  # 人が変えた
        tags, record = triage.resolve(manual, record, self.FIX)
        self.assertEqual((tags, record["category"], record["manual"], record["group"]), (manual, "accept", True, "手動"))
        self.assertIn("規則では「直す」", record["reason"])
        tags, record = triage.resolve(tags, record, self.FIX)  # 手動のまま
        self.assertEqual((tags, record["manual"]), (manual, True))
        tags, record = triage.resolve([T1, "npm"], record, self.FIX)  # 人がタグを外すと自動に戻る
        self.assertEqual((tags[-1], record["manual"]), ("仕分け-直す", False))

    def test_lost_record_and_extra_tag(self):
        self.assertFalse(triage.resolve([T1, "仕分け-直す"], None, self.FIX)[1]["manual"])  # 記録がなくても規則と同じなら自動
        self.assertTrue(triage.resolve([T1, "仕分け-リスク受容"], None, self.FIX)[1]["manual"])
        tags, record = triage.resolve([T1, "仕分け-直す", "仕分け-リスク受容"], {"auto": "fix"}, self.FIX)
        self.assertEqual((tags, record["category"]), ([T1, "仕分け-リスク受容"], "accept"))  # キットの古いタグは外す

    def test_kit_tag_saved_without_its_record_stays_automatic(self):
        # PATCH は通ったが、記録を保存する前に止まった(中止・失敗・並行の実行): タグは新しい規則の結果、記録は前のまま
        tags, record = triage.resolve([T1, "仕分け-直す"], {"auto": "decide", "manual": False}, self.FIX)
        self.assertEqual((tags, record["manual"], record["auto"]), ([T1, "仕分け-直す"], False, "fix"))
        # 人が決めた記録は、タグが規則と同じになっても手動のまま
        self.assertTrue(triage.resolve([T1, "仕分け-直す"], {"auto": None, "manual": True}, self.FIX)[1]["manual"])

    def test_legacy_tags_are_renamed(self):
        # 前の 4 区分(すぐ直す・まとめて直す・受け入れ候補)のタグと記録は、次の仕分けで 3 区分に付け替える
        tags, record = triage.resolve([T1, "npm", "仕分け-まとめて直す"], {"auto": "batch", "manual": False}, self.FIX)
        self.assertEqual((tags, record["manual"], record["auto"]), ([T1, "npm", "仕分け-直す"], False, "fix"))
        self.assertEqual(triage.resolve([T1, "仕分け-すぐ直す"], {"auto": "now"}, self.FIX)[0], [T1, "仕分け-直す"])
        tags, record = triage.resolve([T1, "仕分け-受け入れ候補"], {"auto": None, "manual": True}, self.FIX)
        self.assertEqual((tags, record["category"], record["manual"]), ([T1, "仕分け-リスク受容"], "accept", True))
        self.assertEqual(triage.category_of(["仕分け-まとめて直す"]), "fix")
        self.assertEqual(triage.untriage([T3, "仕分け-すぐ直す"], {"auto": "now"}), [T3])
        self.assertEqual(triage.current_record(["仕分け-すぐ直す"], {"category": "now", "reason": "r"})["reason"], "r")

    def test_current_record(self):
        record = {"category": "fix", "reason": "版上げ", "group": "同じ系列の版上げ"}
        self.assertEqual(triage.current_record([T1, "仕分け-直す"], record), record)
        self.assertIsNone(triage.current_record([T1, "仕分け-リスク受容"], record))  # 人がタグを変えた後の古い理由は使わない
        self.assertIsNone(triage.current_record([T1, "仕分け-直す"], None))

    def test_untriage_removes_only_the_kit_tag(self):
        self.assertEqual(triage.untriage([T3, "仕分け-直す"], {"auto": "fix"}), [T3])
        self.assertEqual(triage.untriage([T3, "仕分け-リスク受容"], {"auto": None, "manual": True}),
                         [T3, "仕分け-リスク受容"])
        self.assertEqual(triage.untriage([T3, "仕分け-直す"], None), [T3, "仕分け-直す"])  # 誰が付けたか分からない

    def test_category_of(self):
        self.assertEqual(triage.category_of(["x", "仕分け-リスク受容", "仕分け-システムごとに決める"]), "decide")
        self.assertEqual(triage.category_of(["x"]), "")


class KitTriageTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(kit, "say")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_triage_test_patches_changes_and_keeps_records(self):
        findings = [
            _dep(1),                                                   # ① の依存 → 直す
            _dep(2, tags=(T3, "npm", "仕分け-直す")),                   # ③ になった → リスク受容に付け替える
            _dep(3, tags=(T2, "npm", "仕分け-リスク受容")),             # 人が変えた → 手動
            _dep(4, tags=(T1, "npm", "ai判定-影響あり"), epss_score=0.01, epss_percentile=0.5, known_exploited=False,
                 ransomware_used=False, kev_date=None),                # AI の影響あり → 直す。EPSS は同じ値
            _dep(5, tags=(T1, "npm", "仕分け-まとめて直す")),           # 前の区分のタグ → 直す に付け替える
            _dep(6, tags=("npm", "仕分け-直す")),                       # 分類のない指摘 → キットのタグを外す
        ]
        d = mock.Mock()
        d.iterate.return_value = findings
        info = _intel({"CVE-2026-0001": (0.01, 0.5)}, {})
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)):
            kit.save_json(kit.client_dir("A") / "triage.json",
                          {"findings": {"2": {"auto": "fix"}, "3": {"auto": "decide"}, "5": {"auto": "batch"},
                                        "6": {"auto": "fix"}, "9": {"auto": "fix"}}})
            counts = kit.triage_test(d, "A", 7, "Trivy Scan", info)
            saved = kit.load_json(kit.client_dir("A") / "triage.json", {})
        patches = {c.args[1]: c.kwargs["json_body"] for c in d.call.call_args_list}
        self.assertEqual(counts, Counter({"fix": 3, "accept": 2}))
        self.assertEqual(patches["/api/v2/findings/1/"]["tags"][-1], "仕分け-直す")
        self.assertEqual(patches["/api/v2/findings/1/"]["epss_score"], 0.01)  # EPSS の欄も同じ PATCH で送る
        self.assertEqual(patches["/api/v2/findings/2/"]["tags"], [T3, "npm", "仕分け-リスク受容"])
        self.assertEqual(patches["/api/v2/findings/6/"]["tags"], ["npm"])
        self.assertNotIn("tags", patches["/api/v2/findings/3/"])  # 人が変えたタグはそのまま
        self.assertEqual(patches["/api/v2/findings/4/"], {"tags": [T1, "npm", "ai判定-影響あり", "仕分け-直す"]})
        self.assertEqual(patches["/api/v2/findings/5/"]["tags"], [T1, "npm", "仕分け-直す"])  # 前の区分のタグは外す
        self.assertEqual(saved["findings"]["1"]["category"], "fix")
        self.assertEqual((saved["findings"]["2"]["category"], saved["findings"]["2"]["group"]), ("accept", "低可能性"))
        self.assertNotIn("6", saved["findings"])  # 分類のない指摘の記録は消す
        self.assertTrue(saved["findings"]["3"]["manual"])
        self.assertIn("9", saved["findings"])  # この検査にない指摘の記録は残す
        self.assertEqual(saved["intel"]["epss"], "v1(2026-10-29 の値)")

    def test_failed_patch_keeps_the_old_record(self):
        d = mock.Mock()
        d.iterate.return_value = [_dep(1), _dep(2)]

        def call(method, path, **kw):
            if path.endswith("/2/"):
                raise dojo.DojoError("落ちた")
            return {}
        d.call.side_effect = call
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)):
            with self.assertRaises(kit.KitError):
                kit.triage_test(d, "A", 7, "Trivy Scan", _intel({}, {}))
            saved = kit.load_json(kit.client_dir("A") / "triage.json", {})
        self.assertIn("1", saved["findings"])
        self.assertNotIn("2", saved["findings"])  # 付け直せなかった指摘は、前の記録のまま(ここでは記録なし)

    def test_unexpected_errors_still_save_the_finished_records(self):
        d = mock.Mock()
        d.iterate.return_value = [_dep(1), _dep(2)]

        def call(method, path, **kw):
            if path.endswith("/2/"):
                raise http.client.IncompleteRead(b"")  # dojo.request が包まずに上げる例外
            return {}
        d.call.side_effect = call
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)):
            with self.assertRaises(kit.KitError):
                kit.triage_test(d, "A", 7, "Trivy Scan", _intel({}, {}))
            saved = kit.load_json(kit.client_dir("A") / "triage.json", {})
        self.assertEqual(list(saved["findings"]), ["1"])

    def test_prowler_check_comes_from_the_raw_result(self):
        finding = {"id": 1, "title": "Repository o/r Does Not Require Signed Commits", "tags": [T2],
                   "vulnerability_ids": []}
        d = mock.Mock()
        d.iterate.return_value = [finding]
        raw = [{"status_code": "FAIL", "message": "Repository o/r does not require signed commits",
                "metadata": {"event_code": "repository_default_branch_requires_signed_commits"}}]
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)):
            raw_path = Path(tmp) / "prowler.ocsf.json"
            raw_path.write_text(json.dumps(raw), encoding="utf-8")
            kit.save_json(kit.client_dir("A") / "tests.json", {"7": {"raw": str(raw_path), "scan_type": "Prowler Scan"}})
            counts = kit.triage_test(d, "A", 7, "Prowler Scan", _intel({}, {}))
        self.assertEqual(counts, Counter({"accept": 1}))

    def test_classify_continues_when_triage_fails(self):
        d = mock.Mock()
        d.iterate.side_effect = lambda path, params=None: {
            "/api/v2/engagements/": [{"id": 5}], "/api/v2/tests/": [{"id": 7, "title": "a"}, {"id": 8, "title": "b"}]}[path]
        args = mock.Mock(client="A")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)), \
             mock.patch.object(kit, "connect", return_value=d), mock.patch.object(kit, "load_intel"), \
             mock.patch.object(kit, "client_products", return_value=[{"id": 1, "name": "app"}]), \
             mock.patch.object(kit, "classify_test", return_value=Counter({1: 1})) as classified, \
             mock.patch.object(kit, "triage_test", side_effect=[kit.KitError("落ちた"), Counter({"fix": 1})]):
            with self.assertRaises(kit.KitError):
                kit.cmd_classify(args)
        self.assertEqual(classified.call_count, 2)

    def test_parser_has_the_new_commands(self):
        args = kit.build_parser().parse_args(["accept-risk", "--client", "A", "--by", "部長"])
        self.assertEqual((args.days, args.no_reactivate, args.dry_run, args.product, args.expect),
                         (180, False, False, None, None))
        self.assertTrue(kit.build_parser().parse_args(["triage", "--client", "A", "--refresh"]).refresh)
        self.assertEqual(kit.build_parser().parse_args(["accept-risk", "--client", "A", "--by", "部長", "--tier", "3"]).tier, 3)
        with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
            kit.build_parser().parse_args(["accept-risk", "--client", "A", "--by", "部長", "--days", "30"])


class AcceptTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(kit, "say")
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake(self, enabled=True, extra=()):
        d = mock.Mock()
        pages = {"/api/v2/engagements/": [{"id": 5, "name": "診断 2026-10"}],
                 "/api/v2/tests/": [{"id": 7, "engagement": 5}, {"id": 8, "engagement": 5}],
                 "/api/v2/findings/": [{"id": n, "test": t, "tags": [T2, *extra]} for n, t, extra in (
                     (1, 7, ["仕分け-リスク受容"]), (2, 8, ["仕分け-リスク受容"]), (3, 7, ["仕分け-リスク受容"]),
                     (4, 99, ["仕分け-リスク受容"]),  # 顧客の外の検査
                     (5, 7, ["仕分け-直す", "仕分け-リスク受容"]))] + list(extra),  # 5: 人が「直す」も付けた(今の仕分けは 直す)
                 "/api/v2/users/": [{"id": 1, "username": "admin"}]}
        d.iterate.side_effect = lambda path, params=None: pages[path]
        d.call.return_value = {"id": 42}
        return d, [{"id": 10, "name": "GitHub o", "prod_type": 3, "enable_full_risk_acceptance": enabled}]

    def run_with(self, records, fn, enabled=True, extra=()):
        d, products = self.fake(enabled, extra)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)), \
             mock.patch.object(kit, "client_products", return_value=products):
            kit.save_json(kit.client_dir("A") / "triage.json", {"findings": records})
            result = fn(d)
        return d, result

    def test_plan_groups_by_engagement_and_reason(self):
        records = {"1": {"category": "accept", "group": "GitHub の運用ルール", "reason": "署名"},
                   "2": {"category": "accept", "group": "GitHub の運用ルール", "reason": "承認"},
                   "3": {"category": "fix", "group": "同じ系列の版上げ", "reason": "古い理由"}}  # 人がタグを変えた後の古い記録
        d, batches = self.run_with(records, lambda d: accept.plan(d, "A"))
        query = next(c.args[1] for c in d.iterate.call_args_list if c.args[0] == "/api/v2/findings/")
        self.assertEqual([(b.group, b.findings, b.reasons) for b in batches],
                         [("GitHub の運用ルール", [1, 2], ["署名", "承認"]), ("手動", [3], [])])  # 5 は今の仕分けが 直す
        self.assertEqual((query["tags"], query["active"], query["duplicate"]), ("仕分け-リスク受容", "true", "false"))
        self.assertEqual(accept.describe(batches), "リスク受容 3 件(1 案件、2 まとまり)")

    def test_plan_can_be_limited_to_a_tier(self):
        low = [{"id": 6, "test": 8, "tags": [T3, "仕分け-リスク受容"]}]
        records = {"6": {"category": "accept", "group": "低可能性", "reason": "低可能性"}}
        _, only_low = self.run_with(records, lambda d: accept.plan(d, "A", tier=3), extra=low)
        self.assertEqual([(b.group, b.findings) for b in only_low], [("低可能性", [6])])
        _, without_low = self.run_with(records, lambda d: accept.plan(d, "A", tier=2), extra=low)
        self.assertNotIn(6, [f for b in without_low for f in b.findings])

    def test_run_posts_one_acceptance_per_batch(self):
        d, _ = self.run_with({}, lambda d: accept.run(d, "A", "情報システム部長", days=90, expect=3))
        posts = [c for c in d.call.call_args_list if c.args[0] == "POST"]
        self.assertEqual(len(posts), 1)  # 記録のない指摘は「手動」の 1 つのまとまり(test 99 は顧客の外)
        body = posts[0].kwargs["json_body"]
        self.assertEqual((body["accepted_findings"], body["owner"], body["accepted_by"], body["decision"]),
                         ([1, 2, 3], 1, "情報システム部長", "A"))
        self.assertTrue(body["reactivate_expired"])
        self.assertEqual(body["expiration_date"][:10], f"{dt.date.today() + dt.timedelta(days=90):%Y-%m-%d}")
        self.assertEqual(body["name"], f"リスク受容: 手動({dt.date.today():%Y-%m-%d})")

    def test_dry_run_and_disabled_products_send_nothing(self):
        for enabled, dry_run in ((True, True), (False, False)):
            d, _ = self.run_with({}, lambda d: accept.run(d, "A", "部長", dry_run=dry_run), enabled)
            self.assertFalse([c for c in d.call.call_args_list if c.args[0] == "POST"])

    def test_a_failed_batch_does_not_stop_the_others(self):
        def go(d):
            d.call.side_effect = [TimeoutError("timed out"), {"id": 43}, {"id": 44}]
            with self.assertRaises(kit.KitError) as caught:
                accept.run(d, "A", "部長")
            return caught.exception
        d, error = self.run_with({"1": {"category": "accept", "group": "a"}, "2": {"category": "accept", "group": "b"}}, go)
        self.assertEqual(len([c for c in d.call.call_args_list if c.args[0] == "POST"]), 3)
        self.assertIn("GitHub o / 診断 2026-10 / a", str(error))  # 失敗の一覧に案件も出す

    def test_expected_count_must_match(self):
        def go(d):
            with self.assertRaises(kit.KitError) as caught:
                accept.run(d, "A", "部長", expect=2)  # 見込みは 2 件だったが、今は 3 件
            return caught.exception
        d, error = self.run_with({}, go)
        self.assertIn("見込み", str(error))
        self.assertFalse([c for c in d.call.call_args_list if c.args[0] == "POST"])

    def test_unknown_client_or_product_is_refused_without_a_folder(self):
        d, products = self.fake()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)):
            with mock.patch.object(kit, "client_products", side_effect=kit.KitError("ない")):
                with self.assertRaises(kit.KitError):
                    accept.plan(d, "ない顧客")
            with mock.patch.object(kit, "client_products", return_value=products):
                with self.assertRaises(kit.KitError):
                    accept.plan(d, "A", "ないシステム")
            self.assertEqual(list(Path(tmp).iterdir()), [])  # 見込みを開いただけで data/ にフォルダを作らない

    def test_disabled_products_are_not_counted(self):
        d, batches = self.run_with({}, lambda d: accept.plan(d, "A"), enabled=False)
        self.assertEqual(accept.accepted_count(batches), 0)
        self.assertIn("うち 3 件はリスク受容(full)が無効なので飛ばす", accept.describe(batches))

    def test_bad_accepted_by_is_refused(self):
        d, _ = self.fake()
        for bad in ("", "-x", "a\nb", "部長\n", "x" * 201):
            with self.assertRaises(kit.KitError):
                accept.run(d, "A", bad)


class ReportTriageTest(unittest.TestCase):
    def row(self, product="app", tags=(T1, "仕分け-直す"), reason="EPSS 34%(…)", ai_impact=False, **kw):
        f = {"title": "CVE-2026-0001 Next", "severity": "High", "description": "", "mitigation": "", "references": "",
             "component_name": "next", "component_version": "15.5.23", "file_path": "package-lock.json", "line": None,
             "vulnerability_ids": [{"vulnerability_id": "CVE-2026-0001"}], "tags": list(tags),
             "epss_score": 0.34, "epss_percentile": 0.99, "known_exploited": True, "kev_date": "2026-01-22", **kw}
        return report.finding_from_api(product, "e", {"title": "Trivy"}, f, "", "", reason, ai_impact=ai_impact)

    def test_sections_by_tier_and_triage(self):
        rows = [self.row(), self.row("api", (T1, "仕分け-システムごとに決める"), "系列をまたぐ版上げが要る(…)"),
                self.row(tags=(T3, "仕分け-リスク受容"), reason="低可能性(…)", title="Low One", severity="Low")]
        scope = report.Scope(scanned=[], skipped=[], unjudged=[], risk_accepted=5,
                             intel={"epss": "v2026.06.15(2026-10-29 の値)", "kev": "2026.10.29", "notes": []})
        page = report.render_html("A", rows, {}, dt.datetime(2026, 10, 30), scope=scope)
        self.assertIn("大項目・小項目ごとの件数", page)
        headings = re.findall(r"<h3>(\d+)\.\d+ ([^<(]+)", page)  # 一覧(2 章)と詳細(3 章)は「大項目 › 小項目」の節
        self.assertEqual([title for chapter, title in headings if chapter == "2"],
                         ["① 外部攻撃系統 › 直す", "① 外部攻撃系統 › システムごとに決める", "③ 低可能性 › リスク受容"])
        self.assertEqual([title for chapter, title in headings if chapter == "3"],
                         ["① 外部攻撃系統 › 直す", "① 外部攻撃系統 › システムごとに決める"])  # 詳細は緊急・高だけ
        self.assertIn("<pre>系列をまたぐ版上げが要る(…)</pre>", page)  # 仕分けの理由
        self.assertNotIn("<th>件数</th><th>仕分け</th>", page)  # 節が小項目なので、一覧に仕分けの列はない
        self.assertIn("EPSS 34.0%(30 日以内に悪用される見込み。上位 1%)", page)
        self.assertIn("CISA KEV に載っている(2026-01-22 に追加", page)
        self.assertIn("リスク受容した 5 件", page)
        self.assertIn("EPSS v2026.06.15(2026-10-29 の値)、CISA KEV 2026.10.29 版", page)
        self.assertIn("6. 仕分け(直すか、受け入れるか)の基準", page)

    def test_reports_without_triage_or_exploit_data(self):
        page = report.render_html("A", [self.row(tags=(T3,), reason="", epss_score=None, known_exploited=False)], {},
                                  dt.datetime(2026, 10, 30), tier=3)
        self.assertIn("③ 低可能性 › 仕分けなし", page)
        for text in ("仕分け(直すか", "<th>件数</th><th>仕分け</th>", "悪用の見込み"):
            self.assertNotIn(text, page)

    def test_reason_is_shown_only_while_it_matches_the_tag(self):
        d = mock.Mock()
        pages = {"/api/v2/engagements/": [{"id": 5, "name": "e"}], "/api/v2/tests/": [{"id": 7, "title": "Trivy"}],
                 "/api/v2/findings/": [_dep(1, tags=(T1, "仕分け-リスク受容")), _dep(2, tags=(T1, "仕分け-直す"))]}
        d.iterate.side_effect = lambda path, params=None: pages[path]
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)), \
             mock.patch.object(kit, "client_products", return_value=[{"id": 1, "name": "app", "prod_type": 3}]):
            kit.save_json(kit.client_dir("A") / "triage.json", {"findings": {
                "1": {"category": "fix", "reason": "古い理由"}, "2": {"category": "fix", "reason": "版上げ"}}})
            found, _ = kit.collect_findings(d, "A", None, None)
        self.assertEqual([(f.triage_key, f.triage_reason) for f in found], [("accept", ""), ("fix", "版上げ")])

    def test_kev_without_a_date(self):
        page = report.render_html("A", [self.row(kev_date=None)], {}, dt.datetime(2026, 10, 30))
        self.assertIn("CISA KEV に載っている(実際の悪用を確認。追加日は不明)", page)

    def plain(self, title, cve, severity="Critical", **kw):
        return self.row(**{"title": title, "severity": severity, "vulnerability_ids": [{"vulnerability_id": cve}],
                           "epss_score": 0.01, "known_exploited": False, **kw})

    def test_fix_order_puts_exploit_evidence_and_secrets_then_ai_first(self):
        rows = [self.plain("Critical plain", "CVE-3"),
                self.row("api", title="AI one", severity="Low", vulnerability_ids=[{"vulnerability_id": "CVE-2"}],
                         epss_score=0.01, known_exploited=False, ai_impact=True),
                self.plain("EPSS one", "CVE-1", severity="Medium", epss_score=0.34, ai_impact=True),
                self.plain("KEV one", "CVE-4", severity="Low", known_exploited=True),
                self.row(title="Leaked key", severity="High", tags=(T1, "仕分け-直す", "secret"), vulnerability_ids=[],
                         epss_score=None, known_exploited=False, component_name=None)]
        page = report.render_html("A", rows, {}, dt.datetime(2026, 10, 31))
        listed = re.findall(r'<tr><td class="num">\d+</td><td><span class="sev[^>]*>[^<]*</span></td><td>(.*?)</td>', page)
        self.assertEqual(listed, ['<span class="pri">秘密情報</span>Leaked key', '<span class="pri">悪用の証拠</span>EPSS one',
                                  '<span class="pri">悪用の証拠</span>KEV one', '<span class="pri">AI で影響あり</span>AI one',
                                  "Critical plain"])  # 優先 → 重大度の順
        self.assertIn("<p>先に直すもの: 悪用の証拠(CISA KEV・EPSS 10% 以上)2 件、秘密情報 1 件、"
                      "次に AI の確認で影響あり 1 件(前の 2 つに当たるものを除く)。", page)
        table = list(csv.reader(io.StringIO(report.render_csv(rows, "http://dd"))))
        self.assertEqual(table[0][:4], ["大項目", "小項目", "優先", "仕分けの理由"])
        self.assertEqual([(r[2], r[table[0].index("タイトル")]) for r in table[1:]],
                         [("1: 秘密情報", "Leaked key"), ("1: 悪用の証拠", "EPSS one"), ("1: 悪用の証拠", "KEV one"),
                          ("2: AI で影響あり", "AI one"), ("3: そのほか", "Critical plain")])
        self.assertEqual(page.count("悪用の証拠(CISA KEV・EPSS 10% 以上)があるものと秘密情報"), 1)  # 並びの説明は 2 章の 1 か所

    def test_low_likelihood_keys_and_accepted_rows_are_not_fixed_first(self):
        # ③ の「公開してよい種類の鍵」は秘密情報の優先にしない。リスク受容の行は「先に直すもの」に数えない
        key = self.row(title="Stripe publishable key", severity="High", tags=(T3, "secret", "仕分け-リスク受容"),
                       vulnerability_ids=[], epss_score=None, known_exploited=False, component_name=None)
        kev = self.plain("KEV in low", "CVE-9", severity="High", known_exploited=True, tags=(T3, "仕分け-リスク受容"))
        self.assertEqual([report.priority(key), report.priority(kev)], [3, 1])
        page = report.render_html("A", [key, kev], {}, dt.datetime(2026, 10, 31), tier=3)
        self.assertNotIn("先に直すもの", page)
        self.assertNotIn('<span class="pri">秘密情報</span>', page)
        self.assertIn('<span class="pri">悪用の証拠</span>KEV in low', page)  # 受容の中の悪用の証拠は、印で目立たせる
        # 数えないのは小項目が「リスク受容」の行(大項目ではない)。人が ③ を「直す」にしたものは数える
        accepted = self.plain("KEV accepted in 1", "CVE-8", known_exploited=True, tags=(T1, "仕分け-リスク受容"))
        fixed = self.plain("KEV fixed in 3", "CVE-7", known_exploited=True, tags=(T3, "仕分け-直す"))
        page = report.render_html("A", [accepted, fixed], {}, dt.datetime(2026, 10, 31))
        self.assertIn("先に直すもの: 悪用の証拠(CISA KEV・EPSS 10% 以上)1 件、", page)

    def test_no_priority_line_without_evidence(self):
        page = report.render_html("A", [self.plain("Critical plain", "CVE-3")], {}, dt.datetime(2026, 10, 31))
        self.assertNotIn("先に直すもの", page)
        self.assertNotIn('<span class="pri">', page)

    def test_location_lists_the_other_lockfiles_of_merged_duplicates(self):
        d = mock.Mock()
        kept = _dep(1, tags=(T1, "仕分け-直す"), file_path="app/package-lock.json")
        duplicates = [_dep(2, file_path="app/yarn.lock", active=False, duplicate=True, duplicate_finding=1),
                      _dep(3, file_path="app/pnpm-lock.yaml", active=False, duplicate=True, duplicate_finding=1,
                           is_mitigated=True)]  # 閉じた(直った)重複の場所は載せない

        def iterate(path, params=None):
            if path == "/api/v2/findings/":
                return duplicates if params.get("duplicate") == "true" else [kept]
            return {"/api/v2/engagements/": [{"id": 5, "name": "e"}], "/api/v2/tests/": [{"id": 7, "title": "Trivy"}]}[path]
        d.iterate.side_effect = iterate
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)), \
             mock.patch.object(kit, "client_products", return_value=[{"id": 1, "name": "app", "prod_type": 3}]):
            found, _ = kit.collect_findings(d, "A", None, None, 1)
        self.assertEqual([(f.location, f.target) for f in found],
                         [("app/package-lock.json、app/yarn.lock", "next 15.5.23 / app/package-lock.json、app/yarn.lock")])
        page = report.render_html("A", found, {}, dt.datetime(2026, 10, 31))
        self.assertIn("場所には同じフォルダのほかのロックファイルも載せています", page)

    def test_collect_findings_reads_the_ai_tag(self):
        d = mock.Mock()
        pages = {"/api/v2/engagements/": [{"id": 5, "name": "e"}], "/api/v2/tests/": [{"id": 7, "title": "Trivy"}],
                 "/api/v2/findings/": [_dep(1, tags=(T1, "ai判定-影響あり")), _dep(2, tags=(T1, "ai判定-要確認"))]}
        d.iterate.side_effect = lambda path, params=None: pages[path]
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)), \
             mock.patch.object(kit, "client_products", return_value=[{"id": 1, "name": "app", "prod_type": 3}]):
            found, _ = kit.collect_findings(d, "A", None, None)
        self.assertEqual([f.ai_impact for f in found], [True, False])

    def test_risk_accepted_is_counted_in_scope(self):
        d = mock.Mock()
        d.iterate.return_value = [{"id": 1, "test": 7, "tags": [T1]}, {"id": 2, "test": 9, "tags": [T1]}]
        with mock.patch.object(kit, "client_products", return_value=[{"id": 1, "name": "app", "prod_type": 3}]):
            self.assertEqual(kit.count_closed(d, "A", [("app", {"id": 7})], None, risk_accepted="true"), 1)
        self.assertEqual(d.iterate.call_args.args[1]["risk_accepted"], "true")


class WebTriageTest(unittest.TestCase):
    def test_jobs(self):
        self.assertEqual(targets.build_job({"tool": "triage", "client": "A"})[2], ["triage", "--client", "A", "--refresh"])
        title, _, argv = targets.build_job({"tool": "accept", "client": "A", "by": "部長", "days": "90",
                                            "product": "web", "reactivate": False, "expect": 12})
        self.assertEqual(argv, ["accept-risk", "--client", "A", "--by", "部長", "--days", "90", "--expect", "12",
                                "--product", "web", "--no-reactivate"])
        self.assertIn("部長", title)
        self.assertEqual(targets.build_job({"tool": "accept", "client": "A", "by": "部長", "expect": "3"})[2][-4:],
                         ["--days", "180", "--expect", "3"])
        for bad in ({"by": "", "expect": 1}, {"by": "-x", "expect": 1}, {"by": "部長", "days": "30", "expect": 1},
                    {"by": "部長"}, {"by": "部長", "expect": 0}, {"by": "部長", "expect": "x"}):
            with self.assertRaises(targets.BadRequest):
                targets.build_job({"tool": "accept", "client": "A", **bad})
        self.assertIn("プリセット", targets.blocker({"tool": "accept", "client": "A", "by": "部長", "expect": 1}))
        title, _, argv = targets.build_job({"tool": "accept", "client": "A", "by": "部長", "expect": 1, "tier": "3"})
        self.assertEqual((argv[-2:], title), (["--tier", "3"], "リスク受容: A(③ 低可能性、受け入れた人: 部長)"))
        with self.assertRaises(targets.BadRequest):
            targets.build_job({"tool": "accept", "client": "A", "by": "部長", "expect": 1, "tier": "4"})

    def test_gateway_values_fit_nginx(self):
        # nginx は 1 つの値を 4096 バイトまでしか読めない(超えると入口が起動しない)。余裕を持たせて 3/4 までにする
        text = (kit.KIT / "defectdojo" / "gateway" / "default.conf.template").read_text(encoding="utf-8")
        for value in re.findall(r"'([^']*)'", text):
            self.assertLessEqual(len(value.encode()), 3072, value[:60])

    def test_sidebar_opens_the_dashboard_for_each_tier_and_subitem(self):
        text = (kit.KIT / "defectdojo" / "gateway" / "default.conf.template").read_text(encoding="utf-8")
        # 差し込む HTML(sub_filter の置き換え。変数 $kit_menu_* はテンプレートの set の値)を組み立てる
        values = dict(re.findall(r"set \$(kit_menu_\w+) '([^']*)';", text))
        replacement = re.search(r"sub_filter '<!-- Products -->' '([^']*)';", text).group(1)
        menu = re.sub(r"\$(kit_menu_\w+)", lambda m: values[m.group(1)], replacement)
        self.assertTrue(menu.endswith("<!-- Products -->"))
        expected = [("/kit/", "検査・報告書")]
        for tier in (1, 2, 3):  # 大項目はそのページ、小項目はそのページの詳細(その小項目)を開く
            expected.append((f"/kit/#dashboard/{tier}", classify.TIER_NAMES[tier]))
            expected += [(f"/kit/#dashboard/{tier}/{key}", label) for key, label in triage.CATEGORIES.items()]
        self.assertEqual(re.findall(r'<a href="(/kit/[^"]*)"[^>]*>([^<]+)</a>', menu), expected)
        self.assertNotIn("/finding", menu)  # 分類を要確認・AI の判定の一覧は外した(要確認の件数はダッシュボードに出す)
        self.assertIn('<div id="kit-client" hidden', menu)
        self.assertIn('<script src="/kit/static/sidebar.js" defer></script>', menu)

    def test_page_uses_the_tier_names(self):
        page = (kit.KIT / "web" / "index.html").read_text(encoding="utf-8")
        for tier, name in classify.TIER_NAMES.items():
            self.assertEqual(page.count(f'<option value="{tier}">{name}</option>'), 2)  # リスク受容と報告書の大項目
            self.assertIn(f'<button type="button" data-tier="{tier}">{name}</button>', page)  # ダッシュボード
            self.assertIn(f"<li><strong>{name}</strong>:", page)  # 分類の設定の説明
        for old in classify.LEGACY_TIER_TAGS:
            self.assertNotIn(f"{old[0]} {old[1:]}<", page)

    def test_accept_preview(self):
        batch = accept.Batch("web", 5, "診断", "GitHub の運用ルール", False, [1, 2], ["署名"])
        with mock.patch.object(accept, "plan", return_value=[batch]) as plan, mock.patch.object(kit, "connect"):
            data = web.accept_preview("A", "", "")
        self.assertEqual(plan.call_args.args[1:], ("A", None, None))
        self.assertEqual((data["total"], data["batches"][0]["enabled"]), (0, False))  # 飛ばす分は数えない
        self.assertEqual(data["summary"], "リスク受容 2 件(1 案件、1 まとまり)。うち 2 件はリスク受容(full)が無効なので飛ばす")


if __name__ == "__main__":
    unittest.main()
