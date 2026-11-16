"""重複のまとめ(lib/dedupe.py と kit.dedupe_test)の単体テスト。DefectDojo には触れない。

実行: uv run --no-project --python '>=3.11' -m unittest discover -s tests -v
"""
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))

import classify  # noqa: E402
import dedupe  # noqa: E402
import kit  # noqa: E402

T1 = classify.TIER_TAGS[1]


def dep(fid, path="app/package-lock.json", pkg="axios", version="0.21.1", vid="CVE-2026-1", tags=(T1, "npm"), **kw):
    f = {"id": fid, "test": 7, "title": f"{vid} {pkg}", "file_path": path, "component_name": pkg,
         "component_version": version, "vulnerability_ids": [{"vulnerability_id": vid}] if vid else [],
         "vuln_id_from_tool": vid, "tags": list(tags), "active": True, "duplicate": False, "duplicate_finding": None,
         "is_mitigated": False, "false_p": False, "risk_accepted": False, "out_of_scope": False}
    f.update(kw)
    return f


def oldest(f):
    return -f["id"]


class PlanTest(unittest.TestCase):
    def test_same_vulnerability_in_two_lockfiles_of_one_folder_counts_once(self):
        findings = [dep(1), dep(2, path="app/yarn.lock"),                 # 同じフォルダの 2 つのロックファイル → 1 件
                    dep(3, path="web/yarn.lock"),                          # 別のフォルダ(別のアプリ)は別
                    dep(4, path="app/yarn.lock", version="1.6.0"),         # 版が違えば別
                    dep(5, path="app/yarn.lock", vid="CVE-2026-2"),        # 脆弱性が違えば別
                    # 最上位のフォルダ。部品の名前の大文字・小文字は区別しない
                    dep(6, path="package-lock.json"), dep(7, path="yarn.lock", pkg="Axios"),
                    dep(8, path="app/.env", pkg=None, tags=(T1, "secret")),
                    dep(9, path="app/.env", pkg=None, tags=(T1, "secret")),  # 秘密情報はまとめない
                    dep(10, path="app/Dockerfile", pkg="x", tags=(T1, "config")),
                    dep(11, path="app/Dockerfile", pkg="x", tags=(T1, "config")),  # 設定もまとめない
                    dep(12, vid=None), dep(13, path="app/yarn.lock", vid=None)]  # 脆弱性の ID がなければまとめない
        self.assertEqual(dedupe.plan(findings, oldest), {2: 1, 7: 6})

    def test_only_lockfiles_are_merged(self):
        findings = [dep(1, path="usr/local/bin/app", pkg="stdlib"), dep(2, path="usr/local/bin/migrate", pkg="stdlib"),
                    dep(3, path="api/requirements.txt", pkg="requests"), dep(4, path="api/Pipfile.lock", pkg="requests")]
        # 同じフォルダの別のプログラム(イメージの検査)は別のもの。Python のロックファイルは同じアプリ
        self.assertEqual(dedupe.plan(findings, oldest), {4: 3})

    def test_different_exposure_is_not_merged(self):
        profile = {"exposure": "external", "paths": [{"prefix": "app/yarn.lock", "exposure": "none"}]}
        # パスの例外で公開範囲が違えば、分類(①〜③)も違いうるのでまとめない
        self.assertEqual(dedupe.plan([dep(1), dep(2, path="app/yarn.lock")], oldest, profile), {})

    def test_keeps_the_best_ranked_and_never_hides_pinned_findings(self):
        findings = [dep(1), dep(2, path="app/yarn.lock"), dep(3, path="app/pnpm-lock.yaml")]
        self.assertEqual(dedupe.plan(findings, lambda f: f["id"] == 2), {1: 2, 3: 2})
        self.assertEqual(dedupe.plan(findings, lambda f: f["id"] == 2, pinned=lambda f: f["id"] == 3), {1: 2})


class RestoreTest(unittest.TestCase):
    def dup(self, **kw):
        return dep(2, path="app/yarn.lock", active=False, duplicate=True, duplicate_finding=1, **kw)

    def test_restores_a_duplicate_whose_original_was_fixed(self):
        self.assertEqual(dedupe.to_restore([dep(1, active=False, is_mitigated=True), self.dup()]), [2])

    def test_leaves_other_duplicates_alone(self):
        # DefectDojo は誤検知・範囲外にすると、必ず is_mitigated も立てる
        for findings in ([dep(1), self.dup()],                                                    # 元はまだ有効
                         [dep(1, active=False, false_p=True, is_mitigated=True), self.dup()],     # 元は誤検知
                         [dep(1, active=False, out_of_scope=True, is_mitigated=True), self.dup()],  # 元は範囲外
                         [dep(1, active=False, risk_accepted=True), self.dup()],                  # 元はリスク受容
                         [dep(1, active=False, is_mitigated=True), self.dup(is_mitigated=True)],  # 重複も直った
                         [dep(1, active=False, is_mitigated=True),
                          self.dup(false_p=True, is_mitigated=True)],                             # 重複を人が誤検知にした
                         [self.dup()]):                                                            # 元がこの検査にない
            self.assertEqual(dedupe.to_restore(findings), [], findings)

    def test_restores_when_the_exposure_setting_now_differs(self):
        # まとめたあとに「分類の設定」で、残した方だけ公開範囲が変わった(③ になると、① の重複が隠れたままになる)
        profile = {"exposure": "external", "paths": [{"prefix": "app/package-lock.json", "exposure": "none"}]}
        self.assertEqual(dedupe.to_restore([dep(1), self.dup()], profile), [2])
        self.assertEqual(dedupe.to_restore([dep(1), self.dup()]), [])  # 公開範囲が同じなら重複のまま
        # 版の違うものを人が重複にしたもの(キットの鍵が違う)は触らない
        self.assertEqual(dedupe.to_restore([dep(1), self.dup(component_version="1.6.0")], profile), [])
        # 元がリスク受容なら戻す(③ の一括の受容の陰に ① が隠れないように)。誤検知・範囲外はコードについての判断なので戻さない
        for original, restored in ((dep(1, active=False, risk_accepted=True), [2]),
                                   (dep(1, active=False, false_p=True, is_mitigated=True), []),
                                   (dep(1, active=False, out_of_scope=True, is_mitigated=True), [])):
            self.assertEqual(dedupe.to_restore([original, self.dup()], profile), restored, original)


class KitDedupeTest(unittest.TestCase):
    def run_dedupe(self, findings, records=None, scan_type="Trivy Scan"):
        d = mock.Mock()
        d.iterate.return_value = findings
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)):
            if records:
                kit.save_json(kit.client_dir("A") / "triage.json", {"findings": records})
            result = kit.dedupe_test(d, "A", "app", 7, scan_type)
        return result, d

    def posts(self, d):
        return sorted(c.args[:2] for c in d.call.call_args_list)

    def test_marks_duplicates_and_restores_fixed_originals(self):
        findings = [dep(1), dep(2, path="app/yarn.lock", tags=(T1, "npm", "ai判定-影響あり")),  # AI の確認がある方を残す
                    dep(3, path="web/package-lock.json", active=False, is_mitigated=True),
                    dep(4, path="web/yarn.lock", active=False, duplicate=True, duplicate_finding=3)]  # 元が直った
        (merged, restored, problem), d = self.run_dedupe(findings)
        self.assertEqual((merged, restored, problem), (1, 1, ""))
        self.assertEqual(d.iterate.call_args.args, ("/api/v2/findings/", {"test": 7}))  # 有効でないものも引く
        self.assertEqual(self.posts(d), [("POST", "/api/v2/findings/1/original/2/"),
                                         ("POST", "/api/v2/findings/4/duplicate/reset/")])

    def test_restored_duplicate_is_merged_again_when_a_twin_is_still_open(self):
        findings = [dep(1, active=False, is_mitigated=True),
                    dep(2, path="app/yarn.lock", active=False, duplicate=True, duplicate_finding=1),
                    dep(3, path="app/pnpm-lock.yaml")]
        (merged, restored, _), d = self.run_dedupe(findings)
        self.assertEqual((merged, restored), (1, 1))
        self.assertIn(("POST", "/api/v2/findings/3/original/2/"), self.posts(d))

    def test_keeps_an_existing_original_and_never_hides_it(self):
        # 4 は 5 の元(DefectDojo は、重複を持つ指摘を重複にすると有効のまま残すので、元は重複にしない)
        findings = [dep(3, path="app/pnpm-lock.yaml"), dep(4), dep(6, path="app/npm-shrinkwrap.json"),
                    dep(5, path="app/yarn.lock", active=False, duplicate=True, duplicate_finding=4)]
        _, d = self.run_dedupe(findings)
        self.assertEqual(self.posts(d), [("POST", "/api/v2/findings/3/original/4/"),
                                         ("POST", "/api/v2/findings/6/original/4/")])
        both = [dep(1), dep(2, path="app/yarn.lock"),
                dep(8, path="app/pnpm-lock.yaml", active=False, duplicate=True, duplicate_finding=1),
                dep(9, path="app/npm-shrinkwrap.json", active=False, duplicate=True, duplicate_finding=2)]
        (merged, _, _), d = self.run_dedupe(both)
        self.assertEqual((merged, self.posts(d)), (0, []))  # 元どうしはまとめない(二重の数えが残るだけ)

    def test_never_hides_the_findings_a_person_sorted(self):
        _, d = self.run_dedupe([dep(1), dep(2, path="app/yarn.lock")], {"2": {"manual": True}})
        self.assertEqual(self.posts(d), [("POST", "/api/v2/findings/1/original/2/")])
        (merged, _, _), d = self.run_dedupe([dep(1), dep(2, path="app/yarn.lock")],
                                         {"1": {"manual": True}, "2": {"manual": True}})
        self.assertEqual((merged, self.posts(d)), (0, []))  # 両方とも人が決めたなら、どちらも隠さない

    def test_restores_a_duplicate_when_the_exposure_setting_changed(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)):
            kit.save_systems("A", {"app": {"exposure": "external",
                                           "paths": [{"prefix": "app/package-lock.json", "exposure": "none"}]}})
            d = mock.Mock()
            d.iterate.return_value = [dep(1), dep(2, path="app/yarn.lock", active=False, duplicate=True, duplicate_finding=1)]
            self.assertEqual(kit.dedupe_test(d, "A", "app", 7, "Trivy Scan"), (0, 1, ""))
        self.assertEqual(self.posts(d), [("POST", "/api/v2/findings/2/duplicate/reset/")])

    def test_uses_the_system_exposure(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)):
            kit.save_systems("A", {"app": {"exposure": "external",
                                           "paths": [{"prefix": "app/yarn.lock", "exposure": "none"}]}})
            d = mock.Mock()
            d.iterate.return_value = [dep(1), dep(2, path="app/yarn.lock")]
            self.assertEqual(kit.dedupe_test(d, "A", "app", 7, "Trivy Scan"), (0, 0, ""))

    def test_one_failed_call_does_not_stop_the_others(self):
        findings = [dep(1), dep(2, path="app/yarn.lock"), dep(3, path="web/package-lock.json"),
                    dep(4, path="web/yarn.lock"), dep(5, path="api/package-lock.json", active=False, is_mitigated=True),
                    dep(6, path="api/yarn.lock", active=False, duplicate=True, duplicate_finding=5)]
        d = mock.Mock()
        d.iterate.return_value = findings

        def call(method, path, **kw):
            if path in ("/api/v2/findings/2/original/1/", "/api/v2/findings/6/duplicate/reset/"):
                raise kit.dojo.DojoError("落ちた")
            return {}
        d.call.side_effect = call
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)):
            merged, restored, problem = kit.dedupe_test(d, "A", "app", 7, "Trivy Scan")
        self.assertEqual((merged, restored), (1, 0))  # できた分は数える
        self.assertIn("2 件", problem)
        self.assertIn(("POST", "/api/v2/findings/4/original/3/"), self.posts(d))

    def test_other_scanners_are_left_alone(self):
        result, d = self.run_dedupe([dep(1), dep(2, path="app/yarn.lock")], scan_type="Prowler Scan")
        self.assertEqual(result, (0, 0, ""))
        d.iterate.assert_not_called()

    def classify_with(self, dedupe_step, triage_step=None):
        d = mock.Mock()
        d.iterate.side_effect = lambda path, params=None: {
            "/api/v2/engagements/": [{"id": 5}],
            "/api/v2/tests/": [{"id": 7, "title": "Trivy git: app@main", "scan_type": "Trivy Scan"}]}[path]
        steps = mock.Mock()
        steps.dedupe_test.side_effect = dedupe_step
        steps.classify_test.return_value = Counter({1: 2})
        steps.triage_test.return_value = Counter({"fix": 2})
        steps.triage_test.side_effect = triage_step
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)), \
             mock.patch.object(kit, "connect", return_value=d), mock.patch.object(kit, "load_intel"), \
             mock.patch.object(kit, "client_products", return_value=[{"id": 1, "name": "app"}]), \
             mock.patch.object(kit, "dedupe_test", steps.dedupe_test), \
             mock.patch.object(kit, "classify_test", steps.classify_test), \
             mock.patch.object(kit, "triage_test", steps.triage_test), mock.patch.object(kit, "say") as say:
            try:
                kit.cmd_classify(mock.Mock(client="A"))
                error = None
            except kit.KitError as e:
                error = e
        return steps, "\n".join(c.args[0] for c in say.call_args_list), error

    def test_classify_merges_duplicates_before_classifying(self):
        steps, said, error = self.classify_with(lambda *a: (3, 1, ""))
        self.assertEqual([name for name, *_ in steps.mock_calls], ["dedupe_test", "classify_test", "triage_test"])
        self.assertEqual(steps.dedupe_test.call_args.args[1:], ("A", "app", 7, "Trivy Scan"))
        self.assertIn("重複: 3 件をまとめ、1 件を戻した", said)
        self.assertIsNone(error)

    def test_classify_and_triage_continue_when_merging_fails(self):
        for failure in (kit.dojo.DojoError("つながらない"), lambda *a: (2, 0, "1 件の重複を更新できませんでした")):
            steps, said, error = self.classify_with(failure, kit.KitError("仕分けも落ちた"))
            self.assertEqual([name for name, *_ in steps.mock_calls], ["dedupe_test", "classify_test", "triage_test"])
            self.assertIn("bin/kit classify", str(error))
            self.assertEqual(str(error).count("app / Trivy git: app@main"), 1)  # まとめと仕分けの両方が落ちても 1 回
        self.assertIn("重複: 2 件をまとめた", said)  # 一部が失敗しても、できた分は出す

    def import_with(self, dedupe_step):
        d = mock.Mock()
        d.reimport.return_value = {"test": 7}
        steps = mock.Mock()
        steps.dedupe_test.side_effect = dedupe_step
        steps.classify_test.return_value = Counter({1: 1})
        steps.triage_test.return_value = Counter({"fix": 1})
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(kit, "DATA", Path(tmp)), \
             mock.patch.object(kit, "connect", return_value=d), mock.patch.object(kit, "load_intel"), \
             mock.patch.object(kit, "note_system"), mock.patch.object(kit, "dedupe_test", steps.dedupe_test), \
             mock.patch.object(kit, "classify_test", steps.classify_test), \
             mock.patch.object(kit, "triage_test", steps.triage_test), mock.patch.object(kit, "say") as say:
            result = Path(tmp) / "trivy.json"
            result.write_text("{}", encoding="utf-8")
            kit.import_result("Trivy Scan", result, kit.Target(client="A", product="app", engagement="e"), "t")
        return steps, [c.args[0] for c in say.call_args_list]

    def test_import_merges_duplicates_before_classifying(self):
        steps, said = self.import_with(lambda *a: (2, 0, ""))
        self.assertEqual([name for name, *_ in steps.mock_calls], ["dedupe_test", "classify_test", "triage_test"])
        self.assertEqual(steps.dedupe_test.call_args.args[1:], ("A", "app", 7, "Trivy Scan"))
        self.assertIn("  重複: 2 件をまとめた", said)

    def test_import_classifies_even_when_merging_fails(self):
        for failure in (kit.dojo.DojoError("つながらない"), lambda *a: (1, 0, "1 件の重複を更新できませんでした")):
            steps, said = self.import_with(failure)
            self.assertEqual([name for name, *_ in steps.mock_calls], ["dedupe_test", "classify_test", "triage_test"])
            self.assertTrue(any("重複のまとめに失敗しました" in line for line in said))
        self.assertIn("  重複: 1 件をまとめた", said)  # 一部が失敗しても、できた分は出す


if __name__ == "__main__":
    unittest.main()
