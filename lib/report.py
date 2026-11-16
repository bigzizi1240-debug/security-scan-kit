"""DefectDojo の指摘から、日本語の報告書(HTML と PDF)を作る。"""
from __future__ import annotations

import csv
import datetime as dt
import html
import io
import itertools
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import classify
import triage

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
SEVERITY_JA = {"Critical": "緊急", "High": "高", "Medium": "中", "Low": "低", "Info": "情報"}
DETAILED = ("Critical", "High")  # 詳細を載せる重大度(中以下は一覧だけ。詳細は DefectDojo)
TEXT_LIMIT = 800
LIST_TARGETS = 5  # 一覧に出す対象の数(残りは「ほか N 件」)
DETAIL_TARGETS = 50

CSS = """
@page { size: A4; margin: 16mm 14mm; }
body { font-family: "Hiragino Sans", "Hiragino Kaku Gothic ProN", sans-serif; font-size: 9.5pt;
       color: #1f2328; line-height: 1.6; margin: 0; }
h1 { font-size: 18pt; margin: 0 0 4pt; }
h2 { font-size: 13pt; border-bottom: 1px solid #d0d7de; padding-bottom: 2pt; margin-top: 18pt; }
h3 { font-size: 10.5pt; margin: 0 0 4pt; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0; }
th, td { border: 1px solid #d0d7de; padding: 3pt 5pt; vertical-align: top; text-align: left; }
th { background: #f6f8fa; white-space: nowrap; }
td.num, th.num { text-align: right; }
table.list { table-layout: fixed; font-size: 8.5pt; }
table.list td { overflow-wrap: break-word; }
td.path { overflow-wrap: anywhere; white-space: pre-line; }
.sev { display: inline-block; min-width: 2.6em; text-align: center; border-radius: 3pt; padding: 0 4pt;
       color: #fff; font-weight: 600; white-space: nowrap; }
.sev-Critical { background: #82071e; } .sev-High { background: #cf222e; } .sev-Medium { background: #bc4c00; }
.sev-Low { background: #4d7c0f; } .sev-Info { background: #57606a; }
.pri { display: inline-block; border: 1px solid #1f2328; border-radius: 3pt; padding: 0 3pt; margin-right: 4pt;
       font-size: 7.5pt; font-weight: 600; white-space: nowrap; }
.note { background: #fff8c5; border: 1px solid #d4a72c; padding: 6pt 8pt; }
.detail { border: 1px solid #d0d7de; padding: 6pt 8pt; margin: 8pt 0; }
.detail dt { font-weight: 600; margin-top: 4pt; }
.detail dd { margin: 0 0 0 1em; }
pre { white-space: pre-wrap; word-break: break-word; font-family: inherit; margin: 0; }
"""


@dataclass
class Finding:
    product: str
    engagement: str
    test: str
    title: str
    severity: str
    target: str
    vuln_ids: list[str]
    description: str
    mitigation: str
    references: str
    reason: str = ""  # 分類(①〜③)の理由
    ai: str = ""  # AI の確認(再現性)の判定と理由
    triage_key: str = ""  # 仕分けの区分(triage.CATEGORIES の鍵)
    triage_reason: str = ""
    epss: float | None = None  # EPSS(30 日以内に悪用される見込み)
    epss_percentile: float | None = None
    known_exploited: bool = False  # CISA KEV に載っている
    kev_date: str = ""  # CISA KEV に載った日(分からなければ空)
    tier: int | None = None  # 分類(大項目。1〜3)
    finding_id: int | None = None
    cvss: str = ""  # CVSS v3 のベクター
    cvss_score: float | None = None
    component: str = ""
    version: str = ""
    location: str = ""  # ファイルと行
    date: str = ""  # 見つけた日
    ai_impact: bool = False  # AI の確認で「影響あり」(DefectDojo のタグ)
    secret: bool = False  # 秘密情報(Trivy のタグ。③ の公開してよい種類の鍵は除く)


@dataclass
class Scope:
    """検査の範囲(報告書の 4 章)。"""
    scanned: list[tuple[str, str, str]]  # (対象システム, 検査, 日時)
    skipped: list[tuple[str, str]]  # 検査しなかった対象(名前, 理由)
    unjudged: list[dict]  # 判定できなかった項目(kit.exclude_unjudged が out-of-scope.json に残したもの)
    ai_dismissed: int = 0  # AI の確認で「影響なし」として誤検知にした数
    risk_accepted: int = 0  # DefectDojo でリスク受容した数
    intel: dict | None = None  # 仕分けに使った EPSS・KEV の版(triage.json の intel)


def finding_from_api(product: str, engagement: str, test: dict, f: dict, reason: str = "", ai: str = "",
                     triage_reason: str = "", ai_impact: bool = False, also: list[str] | None = None) -> Finding:
    """also は、この指摘に重複としてまとめたほかのロックファイルの場所(kit.duplicate_paths)。"""
    location = (f.get("file_path") or "") + (f":{f['line']}" if f.get("file_path") and f.get("line") else "")
    location = "、".join(filter(None, [location, *(also or [])]))
    parts = []
    if f.get("component_name"):
        parts.append(" ".join(x for x in (f["component_name"], f.get("component_version")) if x))
    if location:
        parts.append(location)
    ids = [v["vulnerability_id"] for v in f.get("vulnerability_ids") or [] if v.get("vulnerability_id")]
    return Finding(
        product=product, engagement=engagement, test=test.get("title") or test.get("scan_type") or "",
        title=f.get("title") or "", severity=f.get("severity") if f.get("severity") in SEVERITIES else "Info",
        target=" / ".join(parts), vuln_ids=ids, description=f.get("description") or "",
        mitigation=f.get("mitigation") or "", references=f.get("references") or "", reason=reason, ai=ai,
        triage_key=triage.category_of(f.get("tags") or []), triage_reason=triage_reason,
        epss=f.get("epss_score"), epss_percentile=f.get("epss_percentile"),
        known_exploited=bool(f.get("known_exploited")), kev_date=f.get("kev_date") or "",
        tier=classify.tier_of(f.get("tags") or []), finding_id=f.get("id"), cvss=f.get("cvssv3") or "",
        cvss_score=f.get("cvssv3_score"), component=f.get("component_name") or "", version=f.get("component_version") or "",
        location=location, date=f.get("date") or "", ai_impact=ai_impact,
        # ③ の秘密情報は、公開してよい種類の鍵(Stripe の公開鍵など)なので、先に直すものにしない
        secret="secret" in (f.get("tags") or []) and classify.tier_of(f.get("tags") or []) != 3)


EXPLOIT, SECRET, AI_IMPACT = "悪用の証拠", "秘密情報", "AI で影響あり"  # 直す順の理由(一覧と詳細の印、CSV の「優先」)
RANKS = {EXPLOIT: 1, SECRET: 1, AI_IMPACT: 2}  # そのほかは 3
EVIDENCE = f"CISA KEV・EPSS {triage.EPSS_THRESHOLD:.0%} 以上"


def _first_reason(f: Finding) -> str:
    """直す順の理由。悪用の証拠(CISA KEV に載っている・EPSS が高い)→ 秘密情報 → AI の確認で「影響あり」。なければ空。"""
    if f.known_exploited or (f.epss or 0) >= triage.EPSS_THRESHOLD:
        return EXPLOIT
    if f.secret:
        return SECRET
    return AI_IMPACT if f.ai_impact else ""


def priority(f: Finding) -> int:
    """直す順。1: 悪用の証拠・秘密情報(外の攻撃者がすぐ使える)、2: AI の確認で「影響あり」、3: そのほか。"""
    return RANKS.get(_first_reason(f), 3)


def _priority_badge(group: list[Finding]) -> str:
    reason = _first_reason(min(group, key=priority))
    return f'<span class="pri">{reason}</span>' if reason else ""


def _priority_note(rows: list[Finding]) -> str:
    """1 章の、先に直すものの件数(小項目が「リスク受容」のものは数えない)。どれもなければ空。"""
    counts = Counter(_first_reason(f) for f in rows if f.triage_key != "accept")
    if not (counts[EXPLOIT] or counts[SECRET] or counts[AI_IMPACT]):
        return ""
    return (f"<p>先に直すもの: 悪用の証拠({EVIDENCE}){counts[EXPLOIT]} 件、秘密情報 {counts[SECRET]} 件、"
            f"次に AI の確認で影響あり {counts[AI_IMPACT]} 件(前の 2 つに当たるものを除く)。</p>")


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    for f in findings:
        counts[f.severity] += 1
    return counts


def _clip(text: str) -> str:
    text = text.replace("**", "")  # パーサーが付ける Markdown の太字の記号
    return text if len(text) <= TEXT_LIMIT else text[:TEXT_LIMIT] + "\n…(以下省略。全文は DefectDojo で確認)"


def _badge(severity: str) -> str:
    return f'<span class="sev sev-{severity}">{SEVERITY_JA[severity]}</span>'


def group_findings(findings: list[Finding]) -> list[list[Finding]]:
    """同じ指摘(重大度と、CVE などの識別子。識別子がなければタイトル)を 1 つにまとめる。

    同じ CVE が多くのリポジトリや版に出るので、報告書では 1 行にまとめて対象を並べる。
    並びは直す順(priority。まとめた中で最も先のもの)、重大度、件数の多い順、タイトル。
    """
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault((f.severity, f.vuln_ids[0] if f.vuln_ids else f.title), []).append(f)
    return sorted(groups.values(),
                  key=lambda g: (min(map(priority, g)), SEVERITIES.index(g[0].severity), -len(g), g[0].title))


def _targets(group: list[Finding]) -> list[str]:
    seen: dict[str, None] = {}
    for f in group:
        seen[f"{f.product}: {f.target}" if f.target else f.product] = None
    return list(seen)


def _by_product(texts: list[tuple[str, str]], group: list[Finding]) -> str:
    """システムごとの文。1 つのシステムだけなら文だけ、複数のシステムなら [システム] を付けて並べる。"""
    if len(texts) == 1 and len({f.product for f in group}) == 1:
        return texts[0][1]
    return "\n\n".join(f"[{product}] {text}" for product, text in texts)


def _ai(group: list[Finding]) -> str:
    """AI の確認の欄。判定はシステムごとなので、まとめた指摘が複数のシステムにあるときは、システムの名前を付けて並べる。"""
    return _by_product(list(dict.fromkeys((f.product, f.ai) for f in group if f.ai)), group)


def _triage_reason(group: list[Finding]) -> str:
    """詳細の「仕分けの理由」(システムで違えば、システムごとに並べる)。"""
    return _by_product(list(dict.fromkeys((f.product, f.triage_reason) for f in group if f.triage_reason)), group)


def _section(f: Finding) -> tuple[int, int]:
    """一覧と詳細の節の並び(大項目 → 小項目。分類や仕分けのないものは後ろ)。"""
    return (f.tier or 9, triage.ORDER.index(f.triage_key) if f.triage_key else 9)


def scope_label(tier: int | None, key: str | None, everything: str = "すべて") -> str:
    """報告書に載せた指摘の範囲(例: ① 外部攻撃系統 › 直す)。大項目を選ばなかったときは everything で始める。"""
    return " › ".join([classify.TIER_NAMES[tier] if tier else everything] + ([triage.CATEGORIES[key]] if key else []))


def _title(tier: int | None, key: str) -> str:
    """節の名前(例: ① 外部攻撃系統 › 直す)。"""
    return f"{classify.TIER_NAMES[tier] if tier else '分類なし'} › {triage.CATEGORIES[key] if key else '仕分けなし'}"


def _exploit(group: list[Finding]) -> str:
    """詳細の「悪用の見込み」(EPSS と CISA KEV)。まとめた指摘は同じ CVE なので、最初に値のあるものを使う。"""
    parts = []
    if scored := next((f for f in group if f.epss is not None), None):
        parts.append(triage.epss_text(scored.epss, scored.epss_percentile))
    if any(f.known_exploited for f in group):
        added = next((f.kev_date for f in group if f.kev_date), "")
        parts.append(f"CISA KEV に載っている({added} に追加。実際の悪用を確認)" if added
                     else "CISA KEV に載っている(実際の悪用を確認。追加日は不明)")
    return "\n".join(parts)


def _intel_note(intel: dict | None, shown: bool) -> str:
    """4 章の注記: 仕分けと「悪用の見込み」に使った EPSS・CISA KEV の版(載せた指摘に関わるときだけ)。"""
    if not shown or intel is None:
        return ""
    used = [text for key, text in (("epss", f"EPSS {intel.get('epss')}"), ("kev", f"CISA KEV {intel.get('kev')} 版"))
            if intel.get(key)]
    missing = [name for key, name in (("epss", "EPSS"), ("kev", "CISA KEV")) if not intel.get(key)]
    if not used:
        return "<li>EPSS・CISA KEV のデータがなかったので、悪用の見込みは使っていません。</li>"
    tail = f"({'・'.join(missing)} のデータはありませんでした)" if missing else ""
    return f"<li>悪用の見込みには、{html.escape('、'.join(used))} を使いました{tail}。</li>"


def _count_table(head: str, pairs: list[tuple[str, list[Finding]]]) -> str:
    """重大度ごとの件数の表(行は pairs の名前)。"""
    rows = [f"<tr><th>{head}</th>" + "".join(f'<th class="num">{SEVERITY_JA[s]}</th>' for s in SEVERITIES)
            + '<th class="num">計</th></tr>']
    for name, part in pairs:
        counts = severity_counts(part)
        rows.append(f"<tr><td>{html.escape(name)}</td>" + "".join(f'<td class="num">{counts[s]}</td>' for s in SEVERITIES)
                    + f'<td class="num">{len(part)}</td></tr>')
    return f"<table>{''.join(rows)}</table>"


def _tier_triage_table(rows: list[Finding], triage_key: str | None = None) -> str:
    """1 章の「大項目・小項目ごとの件数」(重大度ごと)。載せた大項目には小項目を 3 つとも並べる
    (小項目で絞った報告書では、その小項目だけ。外した小項目を 0 件とは書かない)。"""
    pairs = []
    for tier in sorted({f.tier for f in rows}, key=lambda t: t or 9):
        in_tier = [f for f in rows if f.tier == tier]
        keys = [triage_key] if triage_key else [*triage.CATEGORIES, *([""] if any(not f.triage_key for f in in_tier) else [])]
        pairs += [(_title(tier, key), [f for f in in_tier if f.triage_key == key]) for key in keys]
    return "<h3>大項目・小項目ごとの件数</h3>" + _count_table("大項目 › 小項目", pairs) if pairs else ""


def _more(items: list[str], limit: int, sep: str) -> str:
    rest = len(items) - limit
    return sep.join(items[:limit]) + (f"{sep}ほか {rest} 件" if rest > 0 else "")


TIER_CRITERIA = """
<h2>{num}. 分類(①〜③)の基準</h2>
<p>攻撃者からの届き方で、指摘を 3 つに分けています。機械のルールによる推定で、実際に悪用できるかまでは確かめていません。
根拠が足りないものには「分類を要確認」を付けています。</p>
<table>
<tr><th>分類</th><th>意味</th><th>主な判断の材料</th></tr>
<tr><td>{t1}</td><td>外部の攻撃者の入力が、そのまま届く可能性がある</td>
<td>外部に公開しているシステムの依存で、ネットワーク越しに悪用できるもの(CVSS の攻撃元が N)。
外部への公開に関わる設定。公開リポジトリやブラウザに配られるファイルの秘密情報</td></tr>
<tr><td>{t2}</td><td>フィッシングなどで中に入った攻撃者や、盗まれたアカウントが悪用できる</td>
<td>内部だけのシステムや、ログインが要る画面の、ログイン後の依存。権限・アカウント・変更の管理に関わる設定。非公開リポジトリの秘密情報</td></tr>
<tr><td>{t3}</td><td>①②の経路が見当たらない既知の脆弱性・弱点</td>
<td>テスト・文書・配備していない場所の依存。物理的な接触が要るもの。堅牢化の推奨。公開してよい種類の鍵</td></tr>
</table>
<p>システムごとの公開範囲(外部に公開・ログインが要る・内部だけ・配備していない)は、キットの「分類の設定」で決めています。
依存の脆弱性を ① から外すのは、外から届かないという根拠(公開範囲の設定・配備していない場所・
CVSS の攻撃元がネットワーク以外・AI の確認の「影響なし」)があるものだけです。</p>
"""

TRIAGE_CRITERIA = """
<h2>{num}. 仕分け(直すか、受け入れるか)の基準</h2>
<p>①② の指摘を、次の規則で上から順に仕分けています。③ 低可能性の指摘は、すべて「リスク受容」です。
機械のルールによる推定です。DefectDojo で人が変えた仕分けは、そのまま載せています。</p>
<table>
<tr><th>仕分け</th><th>主な条件</th></tr>
<tr><td>直す</td><td>秘密情報。CISA KEV に載っている(実際の悪用を確認)。AI の確認で「影響あり」。
EPSS が 10% 以上(30 日以内に悪用される見込み)。ここまでは急いで直すもので、詳細の理由に出ます。
同じ系列(メジャー版。0.x はマイナー版)の版上げで直る依存。GitHub の設定(既定ブランチの保護など)でまとめて直せるもの</td></tr>
<tr><td>システムごとに決める</td><td>系列をまたぐ版上げが要る依存(互換性の確認が要る)。直した版がない依存。
規則のないもの</td></tr>
<tr><td>リスク受容</td><td>体制に合わせて決める運用の規則(コミットの署名・承認の人数・CODEOWNERS など)。
コンテナを root で動かす設定と、記録(ログ)の設定</td></tr>
</table>
"""


def _scope_html(scope: Scope) -> str:
    e = html.escape
    parts = []
    if scope.scanned:
        rows = "".join(f"<tr><td>{e(p)}</td><td>{e(t)}</td><td>{e(when)}</td></tr>"
                       for p, t, when in sorted(scope.scanned))
        parts.append("<h3>検査したもの</h3><table><thead><tr><th>対象システム</th><th>検査</th><th>検査日時</th></tr>"
                     f"</thead>{rows}</table>")
    if scope.skipped:
        rows = "".join(f"<tr><td>{e(name)}</td><td>{e(reason)}</td></tr>" for name, reason in scope.skipped)
        parts.append(f"<h3>検査しなかった対象</h3><table><thead><tr><th>対象</th><th>理由</th></tr></thead>{rows}</table>")
    if scope.unjudged:
        # 理由ごとに 1 行(同じ理由で、多くのチェックと対象が並ぶので)
        groups: dict[str, list[dict]] = {}
        for item in scope.unjudged:
            groups.setdefault(item.get("reason") or "", []).append(item)
        rows = []
        for reason, items in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            resources = sorted({i.get("resource") or "" for i in items})
            checks = list(dict.fromkeys(i.get("title") or i.get("check") or "" for i in items))
            rows.append(f'<tr><td>{e(reason)}</td><td class="num">{len(items)}</td>'
                        f'<td class="path">{e(_more(resources, LIST_TARGETS, chr(10)))}</td>'
                        f'<td class="path">{e(chr(10).join(checks))}</td></tr>')
        parts.append("<h3>判定できなかった項目</h3><p>今の権限では読めない設定(Prowler が結果を出さなかったチェックを含む)、"
                     "実行していない検査、当てはまらないもの(空のリポジトリなど)です。指摘には数えていません。</p>"
                     '<table class="list"><colgroup><col style="width:24%"><col style="width:7%">'
                     '<col style="width:27%"><col style="width:42%"></colgroup>'
                     "<thead><tr><th>理由</th><th>件数</th><th>対象</th><th>チェック</th></tr></thead>"
                     f"{''.join(rows)}</table>")
    return "".join(parts) + ("<h3>注意</h3>" if parts else "")


CSV_HEAD = ["大項目", "小項目", "優先", "仕分けの理由", "重大度", "CVSS v3 スコア", "CVSS v3 ベクター", "識別子(CVE など)",
            "CISA KEV", "EPSS", "タイトル", "対象システム", "検査", "部品", "版", "対策(直した版など)", "場所",
            "分類の理由", "AI の確認", "見つけた日", "DefectDojo", "説明", "参考"]
CSV_CELL_LIMIT = 32000  # Excel の 1 つのセルの上限(32,767 文字)より少なく


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_section(f), priority(f), SEVERITIES.index(f.severity), f.product, f.title))


def _cell(value) -> str:
    """CSV の値。数式として読まれないよう、=・+・-・@ などで始まる値の頭に ' を付ける。長すぎる値は切る。"""
    text = "" if value is None else str(value)
    text = text if len(text) <= CSV_CELL_LIMIT else text[:CSV_CELL_LIMIT] + "…"
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def render_csv(findings: list[Finding], base_url: str) -> str:
    """報告書と同じ範囲の指摘を、1 行 1 指摘の CSV にする(大項目 → 小項目 → 優先 → 重大度の順)。"""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_HEAD)
    for f in _sorted(findings):
        kev = ("載っている" + (f"({f.kev_date} に追加)" if f.kev_date else "")) if f.known_exploited else ""
        writer.writerow(_cell(v) for v in (
            classify.TIER_NAMES[f.tier] if f.tier else "", triage.CATEGORIES[f.triage_key] if f.triage_key else "",
            f"{priority(f)}: {_first_reason(f) or 'そのほか'}", f.triage_reason, SEVERITY_JA[f.severity], f.cvss_score, f.cvss,
            ", ".join(f.vuln_ids), kev,
            f"{f.epss:.1%}" if f.epss is not None else "", f.title, f.product, f.test, f.component, f.version,
            f.mitigation, f.location, f.reason, f.ai, f.date, f"{base_url}/finding/{f.finding_id}" if f.finding_id else "",
            f.description.replace("**", ""), f.references))
    return out.getvalue()


def render_html(client: str, findings: list[Finding], tools: dict[str, str], generated: dt.datetime,
                tier: int | None = None, scope: Scope | None = None, triage_key: str | None = None) -> str:
    e = html.escape
    rows = _sorted(findings)
    products = sorted({f.product for f in rows})
    engagements = sorted({f.engagement for f in rows})
    summary = _count_table("対象システム", [(p, [f for f in rows if f.product == p]) for p in products] + [("合計", rows)])
    has_triage = any(f.triage_key for f in rows)

    # 一覧と詳細は「大項目 › 小項目」の節に分ける(節の番号は一覧と詳細で同じ。No. は通し番号)
    widths = (6, 8, 32, 16, 6, 32)  # No.・重大度・指摘・識別子・件数・対象(%)
    head = ("<colgroup>" + "".join(f'<col style="width:{w}%">' for w in widths) + "</colgroup>"
            "<tr><th>No.</th><th>重大度</th><th>指摘</th><th>識別子</th><th>件数</th><th>対象</th></tr>")
    listing, details, number = [], [], 0
    for index, (_, section) in enumerate(itertools.groupby(rows, key=_section), 1):
        items = list(section)
        title = e(f"{_title(items[0].tier, items[0].triage_key)}({len(items)} 件)")
        lines, blocks = [head], []
        for group in group_findings(items):
            number += 1
            first = group[0]
            ids = ", ".join(dict.fromkeys(vid for f in group for vid in f.vuln_ids))
            targets = _targets(group)
            lines.append(f'<tr><td class="num">{number}</td><td>{_badge(first.severity)}</td>'
                         f'<td>{_priority_badge(group)}{e(first.title)}</td><td>{e(ids)}</td><td class="num">{len(group)}</td>'
                         f'<td class="path">{e(_more(targets, LIST_TARGETS, chr(10)))}</td></tr>')
            if first.severity in DETAILED:
                fields = [("識別子", ids), ("対象", _more(targets, DETAIL_TARGETS, "\n")), ("分類の理由", first.reason),
                          ("仕分けの理由", _triage_reason(group)), ("悪用の見込み", _exploit(group)), ("AI の確認", _ai(group)),
                          ("検査", "、".join(dict.fromkeys(f.test for f in group))), ("説明", _clip(first.description)),
                          ("対策", _clip(first.mitigation)), ("参考", _clip("\n".join(first.references.splitlines()[:5])))]
                body = "".join(f"<dt>{label}</dt><dd><pre>{e(value)}</pre></dd>" for label, value in fields if value)
                blocks.append(f'<div class="detail"><h3>No.{number} {_badge(first.severity)} '
                              f"{_priority_badge(group)}{e(first.title)}</h3><dl>{body}</dl></div>")
        listing.append(f'<h3>2.{index} {title}</h3><table class="list">{"".join(lines)}</table>')
        if blocks:
            details.append(f"<h3>3.{index} {title}</h3>" + "".join(blocks))

    tool_text = "、".join(f"{name} {version}" for name, version in tools.items())
    no_findings = "<p>有効な指摘はありませんでした。</p>"
    shown = scope_label(tier, triage_key, "すべての指摘")
    unjudged_note = f"。ほかに、判定できなかった項目が {len(scope.unjudged)} 件(4 章)" if scope and scope.unjudged else ""
    ai_note = (f"<li>AI の確認で「影響なし」(本番で再現しない)とした {scope.ai_dismissed} 件は、誤検知として載せていません。"
               "DefectDojo のその指摘のメモで、理由と根拠を見られます。</li>"
               if scope and scope.ai_dismissed else "")
    intel_note = _intel_note(scope.intel if scope else None,
                             has_triage or any(f.epss is not None or f.known_exploited for f in rows))
    accepted_note = (f"<li>DefectDojo でリスク受容した {scope.risk_accepted} 件は載せていません"
                     "(案件の「リスク受容」で、理由と期限を見られます)。</li>" if scope and scope.risk_accepted else "")
    tier_criteria = TIER_CRITERIA.format(num=5, **{f"t{tier}": name for tier, name in classify.TIER_NAMES.items()})
    triage_criteria = TRIAGE_CRITERIA.format(num=6) if has_triage else ""
    return f"""<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>脆弱性診断 結果報告書 - {e(client)}({e(shown)})</title>
<style>{CSS}</style></head><body>
<h1>脆弱性診断 結果報告書</h1>
<p class="note">自動の検査の結果から作った下書きです。誤検知を含むことがあるため、内容を確かめてから提出してください。</p>
<table>
<tr><th>顧客</th><td>{e(client)}</td></tr>
<tr><th>載せた指摘</th><td>{e(shown)}</td></tr>
<tr><th>対象システム</th><td>{e("、".join(products)) or "-"}</td></tr>
<tr><th>案件</th><td>{e("、".join(engagements)) or "-"}</td></tr>
<tr><th>作成日時</th><td>{generated:%Y-%m-%d %H:%M}</td></tr>
<tr><th>使用したツール</th><td>{e(tool_text)}</td></tr>
<tr><th>指摘の件数</th><td>{len(rows)} 件(同じ指摘をまとめて {number} 種類){unjudged_note}</td></tr>
</table>
<h2>1. 概要</h2>
{summary}{_tier_triage_table(rows, triage_key)}{_priority_note(rows)}
<h2>2. 指摘の一覧</h2>
<p>大項目(①〜③)と小項目(直す・システムごとに決める・リスク受容)の節に分けています。
同じ指摘(同じ CVE など)は 1 行にまとめ、件数と対象を並べています。
各節の中は、悪用の証拠({EVIDENCE})があるものと秘密情報、AI の確認で「影響あり」のもの、そのほかの順に、
それぞれ重大度の順で並べています(一覧と詳細に印を付けています)。</p>
{"".join(listing) or no_findings}
<h2>3. 指摘の詳細(緊急・高)</h2>
<p>中・低・情報は一覧だけです。詳細は DefectDojo で見られます。節の番号は 2 章と同じです。</p>
{"".join(details) or "<p>該当する指摘はありません。</p>"}
<h2>4. 検査の範囲と注意</h2>
{_scope_html(scope) if scope else ""}
<ul>
<li>既知の脆弱性(CVE など)と設定の不備を、自動の検査で調べた結果です。</li>
<li>Web アプリの論理的な欠陥や認可の不備など、手動の診断が必要なものは含みません。</li>
<li>自動の検査には誤検知と見逃しがあります。</li>
<li>DefectDojo で「有効」の指摘だけを載せています。対応済み・誤検知・重複などは含みません。</li>
<li>同じフォルダの 2 つのロックファイル(package-lock.json と yarn.lock など)に出た同じ脆弱性は 1 件にまとめ、
場所には同じフォルダのほかのロックファイルも載せています(まとめた側は DefectDojo の「重複」)。</li>
<li>結果は検査した時点のものです。</li>{ai_note}{intel_note}{accepted_note}
</ul>
{tier_criteria}{triage_criteria}
</body></html>
"""


def html_to_pdf(html_path: Path, pdf_path: Path, chrome: Path) -> bool:
    """Chrome のヘッドレス印刷で PDF にする。Chrome がなければ False。"""
    if not chrome.exists():
        return False
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as profile:
        cmd = [str(chrome), "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
               f"--user-data-dir={profile}", "--no-pdf-header-footer", f"--print-to-pdf={pdf_path}",
               html_path.as_uri()]
        try:
            subprocess.run(cmd, capture_output=True, timeout=180)
        except subprocess.TimeoutExpired:
            pass  # 印刷のあと終了しないことがある。PDF ができていれば使う
    return pdf_path.exists() and pdf_path.stat().st_size > 0
