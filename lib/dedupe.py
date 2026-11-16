"""同じ指摘の二重の数えを、DefectDojo の「重複」にまとめる(機械のルール)。

同じフォルダにロックファイルが 2 つ(package-lock.json と yarn.lock など)あると、Trivy は同じ部品の同じ脆弱性を
ロックファイルごとに出す。同じアプリの同じ問題なので 1 件だけ残し、残りは重複にする(重複は有効な指摘に数えない)。
元が直ったのに重複がまだ残っているときと、公開範囲の設定が変わって元と公開範囲が違うようになったときは、
重複を有効に戻す(DefectDojo は取り込み直しで重複を有効に戻さない)。
"""
from __future__ import annotations

from collections.abc import Callable

import classify

# 同じアプリに形式の違うものが並びうるロックファイル(これだけをまとめる。イメージの中のプログラムなどは別のもの)
LOCKFILES = frozenset({"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
                       "Pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock", "requirements.txt"})
JUDGED = ("false_p", "out_of_scope", "risk_accepted")  # 人や AI の判断(DefectDojo は誤検知・範囲外でも is_mitigated を立てる)


def key(finding: dict, profile: dict) -> tuple[str, ...] | None:
    """二重の数えを見分ける鍵(脆弱性の ID, 部品, 版, フォルダ, 公開範囲)。ロックファイルの依存の脆弱性でなければ None。"""
    path = finding.get("file_path") or ""
    folder, _, name = path.rpartition("/")
    vid = classify.vuln_id(finding)
    if name not in LOCKFILES or not finding.get("component_name") or not vid \
            or set(finding.get("tags") or []) & {"secret", "config"}:
        return None
    exposure = classify.exposure_for(profile, path)[0]  # パスの例外で公開範囲が違えば、分類(①〜③)も違いうる
    return vid, finding["component_name"].lower(), finding.get("component_version") or "", folder, exposure


def plan(findings: list[dict], rank: Callable[[dict], tuple], profile: dict | None = None,
         pinned: Callable[[dict], bool] = lambda f: False) -> dict[int, int]:
    """有効な指摘のうち、重複にするもの → 残すもの(元)。同じ鍵のうち rank の最も大きいものを残し、
    pinned に当たる指摘は重複にしない。profile はシステムの公開範囲(systems.json の 1 システム分)。"""
    groups: dict[tuple, list[dict]] = {}
    for f in findings:
        if found := key(f, profile or {}):
            groups.setdefault(found, []).append(f)
    marks = {}
    for members in groups.values():
        keep = max(members, key=rank)
        marks.update({f["id"]: keep["id"] for f in members if f is not keep and not pinned(f)})
    return marks


def still_open(finding: dict) -> bool:
    """閉じていない(直っていない。誤検知・範囲外・リスク受容でもない)。"""
    return not finding.get("is_mitigated") and not any(finding.get(state) for state in JUDGED)


def to_restore(findings: list[dict], profile: dict | None = None) -> list[int]:
    """重複のうち、自分はまだ残っていて、元と同じものとは言えなくなったもの(有効に戻す)。元がこの検査にないものは触らない。

    - 元が直って閉じた。元が誤検知・範囲外・リスク受容のときは同じ判断が当てはまるので、重複のまま
    - まとめたあとに公開範囲の設定が変わり、ほかは同じなのに元と公開範囲だけが違う(分類も違いうる。元が ③ になって
      リスク受容されると ① が隠れる)。元が誤検知・範囲外のときは、コードについての判断なので重複のまま。
      公開範囲のほかにも元と違うもの(人が重複にしたもの)は、この理由では戻さない
    """
    by_id = {f["id"]: f for f in findings}

    def fixed(original: dict) -> bool:
        return bool(original.get("is_mitigated")) and not any(original.get(s) for s in JUDGED)

    def moved(dup: dict, original: dict) -> bool:
        if original.get("false_p") or original.get("out_of_scope"):
            return False
        a, b = key(dup, profile or {}), key(original, profile or {})
        return bool(a and b) and a[:-1] == b[:-1] and a[-1] != b[-1]

    return [f["id"] for f in findings
            if f.get("duplicate") and still_open(f) and (original := by_id.get(f.get("duplicate_finding")))
            and (fixed(original) or moved(f, original))]
