"""①〜③ の指摘を、直すか受け入れるかで 3 つに仕分ける(機械のルール)。③ 低可能性はすべてリスク受容。

直す: 秘密情報。悪用が確認された(CISA KEV)・悪用の見込みが高い(EPSS)脆弱性。AI の確認で影響ありのもの。
      同じ系列の版上げで直る依存。設定の変更でまとめて直せる GitHub の設定(急ぐものかは、理由とまとまりに出る)
システムごとに決める: 系列をまたぐ版上げが要る依存、直した版がない依存、規則のないもの
リスク受容: 体制に合わせて決める運用の規則。被害を抑える・検知を強める設定

判断の材料は、指摘(タグ・CVE・版)、元の結果の Prowler のチェック、EPSS・KEV(intel.py)。
規則の表と例は docs/superpowers/specs/2026-10-30-triage-design.md。
"""
from __future__ import annotations

import re
from dataclasses import dataclass

CATEGORIES = {"fix": "直す", "decide": "システムごとに決める", "accept": "リスク受容"}
ORDER = list(CATEGORIES)  # 急ぐ順
# 英字の大文字は使わない(DefectDojo はタグで絞るとき値を小文字にして比べる)
TAGS = {key: f"仕分け-{label}" for key, label in CATEGORIES.items()}
TAG_KEYS = {tag: key for key, tag in TAGS.items()}
# 前の 4 区分(2026-10-30。すぐ直す・まとめて直す・受け入れ候補)のタグと記録の鍵。次の仕分けで今の区分に付け替える
LEGACY_TAGS = {"仕分け-すぐ直す": "fix", "仕分け-まとめて直す": "fix", "仕分け-受け入れ候補": "accept"}
LEGACY_KEYS = {"now": "fix", "batch": "fix"}
EPSS_THRESHOLD = 0.10  # 30 日以内に悪用される見込みが 10% 以上なら、急いで直す(まとまり「EPSS が高い」)
MANUAL_GROUP = "手動"
# Prowler の GitHub のチェックのうち、設定の変更でまとめて直せるもの
GH_BATCH = {
    "repository_default_branch_protection_enabled": "既定ブランチの保護",
    "repository_default_branch_disallows_force_push": "強制 push の禁止",
    "repository_default_branch_deletion_disabled": "既定ブランチの削除の禁止",
    "organization_repository_creation_limited": "メンバーによるリポジトリの作成の制限",
    "organization_repository_deletion_limited": "メンバーによるリポジトリの削除の制限",
    "repository_inactive_not_archived": "放置したリポジトリのアーカイブ",
}
# 体制(人数・開発の流れ)に合わせて決める運用の規則
GH_ACCEPT = {
    "repository_default_branch_requires_signed_commits": "コミットの署名",
    "repository_default_branch_requires_multiple_approvals": "2 人以上の承認",
    "repository_default_branch_dismisses_stale_reviews": "古い承認の取り消し",
    "repository_default_branch_protection_applies_to_admins": "管理者にも保護を適用",
    "repository_default_branch_requires_codeowners_review": "CODEOWNERS のレビュー",
    "repository_has_codeowners_file": "CODEOWNERS のファイル",
    "repository_default_branch_status_checks_required": "状態チェックの必須",
}
ROOT_USER = re.compile(r"\bDS-?0002\b", re.I)  # Trivy: Dockerfile で root のまま動かす
LOGGING = re.compile(r"\blog(s|ging)?\b", re.I)
VERSION = re.compile(r"^v?(\d+(?:\.\d+)*)")
FIX_OPERATOR = re.compile(r"^(?:>=|~>|==|=|>|\^|~)\s*")  # Ruby(Bundler)などの直した版は「>= 1.19.4」「~> 2.2.23」


@dataclass(frozen=True)
class Decision:
    key: str  # CATEGORIES の鍵
    reason: str
    group: str  # 理由のまとまり(リスク受容の名前と、報告書の集計に使う)


def cve_ids(finding: dict) -> list[str]:
    ids = [v.get("vulnerability_id") or "" for v in finding.get("vulnerability_ids") or []]
    ids.append(finding.get("vuln_id_from_tool") or "")
    return list(dict.fromkeys(i for i in ids if i.startswith("CVE-")))


def max_epss(cves: list[str], intel) -> tuple[str, tuple[float, float]] | None:
    """CVE のうち EPSS が最も高いもの(CVE, (EPSS, 百分位))。"""
    found = [(cve, intel.epss[cve]) for cve in cves if cve in intel.epss]
    return max(found, key=lambda item: item[1][0]) if found else None


def top_text(percentile: float) -> str:
    """EPSS の百分位を「上位 N%」で表す。"""
    top = (1 - percentile) * 100
    return f"上位 {top:.1f}%" if top < 1 else f"上位 {top:.0f}%"


def epss_text(score: float, percentile: float | None) -> str:
    """EPSS の値の説明(仕分けの理由と、報告書の「悪用の見込み」で同じ書き方にする)。"""
    rank = f"。{top_text(percentile)}" if percentile is not None else ""
    return f"EPSS {score:.1%}(30 日以内に悪用される見込み{rank})"


def parse_version(text: str | None) -> tuple[int, ...] | None:
    """版を数字の並びとして読む(先頭の v は外す)。epoch のある版(1:2.3.4-1。OS のパッケージ)は読まない。"""
    text = (text or "").strip()
    m = VERSION.match(text)
    return tuple(int(x) for x in m.group(1).split(".")) if m and ":" not in text else None


def _line(version: tuple[int, ...]) -> tuple[int, ...]:
    """系列。メジャー版(メジャー版が 0 ならマイナー版まで)。"""
    return version[:2] if version[0] == 0 else version[:1]


def fix_plan(installed: str | None, fixed: str | None) -> tuple[str, str]:
    """依存の直し方と、理由に出す版の文。

    same: 同じ系列に直した版がある / cross: 系列の外にしかない / none: 直した版がない / unknown: 版を読めない
    """
    if not (fixed or "").strip():
        return "none", ""
    current = parse_version(installed)
    if current is None:
        return "unknown", f"{installed or '?'}、直した版 {fixed}"
    newer, revised = [], []
    for text in (FIX_OPERATOR.sub("", part.strip()) for part in fixed.split(",")):
        version = parse_version(text)
        if version and version > current:
            newer.append((version, text))
        elif version == current and text != installed.strip():
            revised.append(text)  # 数字が同じで後ろだけ違う(前リリースの正式版・パッケージの改訂)
    if not newer:
        return ("same", f"{installed} → {revised[0]}") if revised else ("unknown", f"{installed}、直した版 {fixed}")
    newer.sort()
    same = [text for version, text in newer if _line(version) == _line(current)]
    return ("same", f"{installed} → {same[0]}") if same else ("cross", f"{installed} → {newer[0][1]}")


def triage(finding: dict, scan_type: str, check_id: str, intel, ai_impact: bool, tier: int | None = None) -> Decision:
    """指摘 1 件を仕分ける。③ 低可能性はすべてリスク受容、①② は上の規則から順に当てはめる。

    check_id は Prowler のチェック(元の結果から引いたもの)、intel は intel.Intel、ai_impact は AI の確認が「影響あり」か、
    tier は分類(1〜3)。
    """
    if tier == 3:
        return Decision("accept", "低可能性(①② の経路が見当たらない)。原則として受け入れる", "低可能性")
    tags = set(finding.get("tags") or [])
    cves = cve_ids(finding)
    if scan_type == "Trivy Scan" and "secret" in tags:
        return Decision("fix", "秘密情報。鍵の失効(入れ替え)と、ソースと履歴からの削除が要る", "秘密情報")
    listed = sorted((intel.kev[cve].date_added or "9999", cve) for cve in cves if cve in intel.kev)
    if listed:
        added, cve = listed[0]
        when = "追加日は不明" if added == "9999" else f"{added} に追加"
        ransom = "。ランサムウェアでの悪用も確認" if any(intel.kev[c].ransomware for _, c in listed) else ""
        return Decision("fix", f"CISA KEV に載っている({cve}。実際の悪用を確認。{when}{ransom})", "CISA KEV")
    if ai_impact:
        return Decision("fix", "AI の確認で「影響あり」(ソースで影響の条件を確かめた)", "AI の確認で影響あり")
    best = max_epss(cves, intel)
    if best and best[1][0] >= EPSS_THRESHOLD:
        cve, (score, percentile) = best
        return Decision("fix", f"{cve} の {epss_text(score, percentile)}", "EPSS が高い")
    if scan_type == "Trivy Scan" and not tags & {"secret", "config"} and finding.get("component_name"):
        plan, text = fix_plan(finding.get("component_version"), finding.get("mitigation"))
        if plan == "same":
            return Decision("fix", f"同じ系列の版上げで直る({text})", "同じ系列の版上げ")
        if plan == "cross":
            return Decision("decide", f"系列をまたぐ版上げが要る({text})。互換性の確認が要る", "系列をまたぐ版上げ")
        if plan == "none":
            return Decision("decide", "直した版がない。回避策・置き換え・受け入れを決める", "直した版がない")
        return Decision("decide", f"版を読めない({text})。人が決める", "直した版がない")
    if scan_type == "Prowler Scan" and check_id in GH_BATCH:
        return Decision("fix", f"GitHub の設定でまとめて直せる({GH_BATCH[check_id]})", "GitHub の設定")
    if scan_type == "Prowler Scan" and check_id in GH_ACCEPT:
        return Decision("accept", f"体制に合わせて決める運用の規則({GH_ACCEPT[check_id]})", "GitHub の運用ルール")
    if scan_type == "Prowler Scan" and not check_id:
        return Decision("decide", "Prowler の元の結果が見つからず、チェックの種類を引けない(人が決める)", "規則なし")
    if scan_type == "Trivy Scan" and "config" in tags:
        title = finding.get("title") or ""
        if ROOT_USER.search(title) or ROOT_USER.search(finding.get("vuln_id_from_tool") or ""):
            return Decision("accept", "コンテナを root で動かす設定。侵入されたときの被害を広げるが、すぐ悪用される経路ではない",
                            "コンテナを root で動かす")
        if LOGGING.search(title):
            return Decision("accept", "記録(ログ)の設定。検知と調査を強める設定で、侵入を防ぐ設定ではない", "記録(ログ)の設定")
    return Decision("decide", "仕分けの規則がない(人が決める)", "規則なし")


def intel_fields(finding: dict, intel) -> dict:
    """DefectDojo の EPSS・KEV の欄に入れる値。データのない方の欄は含めない(今の値を変えない)。"""
    cves = cve_ids(finding)
    fields: dict = {}
    if intel.epss_version:
        best = max_epss(cves, intel)
        fields["epss_score"], fields["epss_percentile"] = best[1] if best else (None, None)
    if intel.kev_version:
        listed = [intel.kev[cve] for cve in cves if cve in intel.kev]
        fields["known_exploited"] = bool(listed)
        fields["ransomware_used"] = any(k.ransomware for k in listed)
        fields["kev_date"] = min((k.date_added for k in listed if k.date_added), default=None)
    return fields


def _tag_key(tag: str) -> str | None:
    """仕分けのタグの区分(前の 4 区分のタグも読み替える)。仕分けのタグでなければ None。"""
    return TAG_KEYS.get(tag) or LEGACY_TAGS.get(tag)


def _record_key(key: str | None) -> str | None:
    """triage.json の記録の区分(前の 4 区分の鍵も読み替える)。"""
    return LEGACY_KEYS.get(key, key) if key else None


def category_of(tags: list[str]) -> str:
    """タグの中の仕分けの区分(複数あれば急ぐ方)。なければ空。"""
    keys = [key for key in map(_tag_key, tags) if key]
    return min(keys, key=ORDER.index) if keys else ""


def more_urgent(key: str) -> list[str]:
    """key より急ぐ区分のタグ。仕分けのタグが複数ある指摘は急ぐ方に数える(category_of)ので、件数や一覧はこれを除く。"""
    return [TAGS[k] for k in ORDER[:ORDER.index(key)]]


def resolve(tags: list[str], record: dict | None, decision: Decision) -> tuple[list[str], dict]:
    """付けるタグと、triage.json の記録を決める。人が DefectDojo で変えた仕分けは残す(手動)。

    record["auto"] はキットが最後に付けた区分。仕分けのタグが空、またはキットが付けたものだけなら自動。
    手動の記録でなければ、タグが規則の結果と同じときも自動とみなす(記録をなくした、PATCH のあと記録を保存する前に
    止まった、並行して仕分けた、などで記録が古くても、手動に固まらないように)。
    """
    others = [t for t in tags if not _tag_key(t)]
    mine = list(dict.fromkeys(TAGS[key] for key in map(_tag_key, tags) if key))  # 前の区分のタグは今の名前に読み替える
    auto_tag = TAGS.get(_record_key((record or {}).get("auto")))
    new_tag = TAGS[decision.key]
    if not mine or set(mine) == {auto_tag} or (not (record or {}).get("manual") and mine == [new_tag]):
        return others + [new_tag], {"category": decision.key, "reason": decision.reason, "group": decision.group,
                                    "auto": decision.key, "manual": False}
    kept = [t for t in mine if t != auto_tag]
    reason = f"人が DefectDojo で決めた(規則では「{CATEGORIES[decision.key]}」: {decision.reason})"
    return others + kept, {"category": category_of(kept), "reason": reason, "group": MANUAL_GROUP,
                           "auto": None, "manual": True}


def current_record(tags: list[str], record: dict | None) -> dict | None:
    """記録が今のタグの区分と合っていれば、その記録(理由・まとまり)。人がタグを変えたあと、仕分けし直す前の
    古い記録は使わない。"""
    return record if record and _record_key(record.get("category")) == category_of(tags) else None


def untriage(tags: list[str], record: dict | None) -> list[str]:
    """分類(①〜③)がなくなった指摘から、キットが付けた仕分けのタグを外す(人が付けたタグは残す)。"""
    auto = _record_key((record or {}).get("auto"))
    return [t for t in tags if not (auto and _tag_key(t) == auto)]
