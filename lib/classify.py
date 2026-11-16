"""指摘を、攻撃者からの届き方で 3 つに分ける(機械のルール)。

① 外部攻撃系統: 外部の攻撃者の入力が、そのまま届く可能性がある
② 横展開系統: フィッシングなどで中に入った攻撃者や、盗まれたアカウントが悪用できる
③ 低可能性: ①②の経路が見当たらない既知の脆弱性・弱点(配備していない場所、堅牢化の推奨など)

判断には、指摘そのもの(CVSS のベクター・ファイルの場所・チェックの種類)と、システムごとの
公開範囲(data/<顧客>/systems.json)を使う。根拠が足りないときは「分類を要確認」も付ける。
どれも「届く可能性」の推定で、実際に悪用できるかまでは確かめていない。
"""
from __future__ import annotations

import re

TIER_TAGS = {1: "①外部攻撃系統", 2: "②横展開系統", 3: "③低可能性"}
REVIEW_TAG = "分類を要確認"
# 前の名前(③ は 2026-10-30、①② は 2026-10-31 まで)。分類し直すときに今の名前に付け替える
LEGACY_TIER_TAGS = {"③可能性が低い": 3, "①外部から直接": 1, "②横展開": 2}
TIER_KEYS = {**{tag: tier for tier, tag in TIER_TAGS.items()}, **LEGACY_TIER_TAGS}
CLASS_TAGS = frozenset([*TIER_KEYS, REVIEW_TAG])
TIER_NAMES = {1: "① 外部攻撃系統", 2: "② 横展開系統", 3: "③ 低可能性"}  # 画面・メニュー・報告書の節の名前
TIER_MEANINGS = {
    1: "外部の攻撃者の入力が、そのまま届く可能性がある",
    2: "フィッシングなどで中に入った攻撃者や、盗まれたアカウントが悪用できる",
    3: "①② の経路が見当たらない(テスト・文書・配備していない場所、堅牢化の推奨など)",
}
EXPOSURES = {
    "external": "外部に公開(誰でも入力を送れる)",
    "external-auth": "外部に公開(組織のログインが要る)",
    "internal": "内部だけ(社内・バッチ・イベント処理)",
    "none": "配備していない(ツール・ライブラリ・定義・テスト)",
    "unknown": "未設定",
}
# 配備されない場所(テスト・文書・見本など)
NON_DEPLOYED = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|e2e|fixtures?|examples?|samples?|docs?|mocks?|\.?storybook|benchmarks?)(/|$)",
    re.I)
PUBLIC_BY_DESIGN = re.compile(r"publishable", re.I)  # Stripe の公開鍵など、公開してよい鍵
CONFIG_DIRECT = re.compile(r"0\.0\.0\.0/0|::/0|\bpublic|internet|unrestricted|anonymous|world-readable", re.I)
CONFIG_LATERAL = re.compile(r"\biam\b|privilege|\broot\b|admin|wildcard|\bmfa\b|secret|password|credential|token"
                            r"|logging|audit|sudo|\bssh\b", re.I)
# Prowler: 外部への公開を表す分類と、中に入った攻撃者に効く分類
PROWLER_DIRECT = re.compile(r"publicly_accessible|public_access|allusers|all_users|0_0_0_0|unrestricted|internet_facing")
PROWLER_LATERAL_CATEGORIES = {"identity-access", "secrets", "trustboundaries", "ci-cd", "software-supply-chain",
                              "logging", "forensics-ready", "privilege-escalation"}
PROWLER_LATERAL = re.compile(r"mfa|admin|privilege|root|iam|branch|force_push|codeowners|secret|workflow|token|credential"
                             r"|member|permission|repository_creation|deletion|review|status_checks")
# 堅牢化の推奨(すぐ悪用される経路ではない)として扱うチェック
PROWLER_HARDENING = {
    "repository_default_branch_requires_linear_history",
    "repository_branch_delete_on_merge_enabled",
    "repository_default_branch_requires_conversation_resolution",
    "repository_dependency_scanning_enabled",
    "organization_verified_badge",
}
NOT_CHECKED = re.compile(r"could not be checked|insufficient permission", re.I)


def tier_of(tags: list[str]) -> int | None:
    """タグの中の分類(1〜3。前の名前も読む)。なければ None。"""
    return next((TIER_KEYS[t] for t in tags if t in TIER_KEYS), None)


def parse_cvss(vector: str | None) -> tuple[str | None, str | None]:
    """CVSS v3 のベクターから、攻撃元(AV)と必要な権限(PR)を取る。"""
    parts = dict(p.split(":", 1) for p in (vector or "").split("/") if ":" in p)
    return parts.get("AV"), parts.get("PR")


def exposure_for(profile: dict, path: str) -> tuple[str, str]:
    """ファイルの場所に当てはまる公開範囲と、その理由。パスの例外は長く一致したものを使う。"""
    path = (path or "").removeprefix("./")
    if NON_DEPLOYED.search(path):
        return "none", "テスト・文書などの中"
    rules = [r for r in profile.get("paths") or [] if r.get("prefix") and path.startswith(r["prefix"])]
    if rules:
        rule = max(rules, key=lambda r: len(r["prefix"]))
        return rule.get("exposure", "unknown"), f"{rule['prefix']} は「{EXPOSURES.get(rule.get('exposure'), '?')}」"
    exposure = profile.get("exposure", "unknown")
    return exposure, f"システムは「{EXPOSURES.get(exposure, exposure)}」"


def package_tier(cvss: str | None, exposure: str, where: str) -> tuple[int, str, bool]:
    """依存やパッケージの脆弱性。システムの公開範囲と、CVSS の攻撃元・必要な権限で決める。"""
    av, pr = parse_cvss(cvss)
    if exposure == "none":
        return 3, f"配備していない場所の依存({where})", False
    if av == "P":
        return 3, "物理的に触れないと悪用できない", False
    review = exposure == "unknown" or av is None
    note = "" if av else "。CVSS のベクターがないのでネットワーク越しとみなした"
    if exposure in ("external", "unknown"):
        if av in ("N", None):
            return 1, f"外部に公開しているシステムの依存で、ネットワーク越しに悪用できる({where}){note}", review
        return 2, f"中に入った攻撃者が悪用できる(攻撃元が {av})({where})", review
    if exposure == "external-auth":
        if av in ("N", None) and pr in ("N", None):
            return 1, f"外部に公開している画面で、ログインの前に届く({where}){note}", review
        if av in ("N", None):
            return 2, f"ログインが要る。認証情報を盗まれると悪用される({where})", review
        return 2, f"中に入った攻撃者が悪用できる(攻撃元が {av})({where})", review
    return 2, f"内部のネットワークや、中に入った攻撃者から悪用できる({where})", review


def secret_tier(title: str, path: str, visibility: str, exposure: str) -> tuple[int, str, bool]:
    """ソースに書かれた秘密情報。誰がそのファイルを読めるかで決める。"""
    if PUBLIC_BY_DESIGN.search(title):
        return 3, "公開してよい種類の鍵(Stripe の公開鍵など)", False
    if visibility == "public":
        return 1, "公開リポジトリにあり、誰でも読める", False
    if exposure in ("external", "external-auth", "unknown") and path.lower().endswith((".html", ".htm", ".js")) \
            and not NON_DEPLOYED.search(path):
        return 1, "公開しているシステムで、ブラウザに配られるファイルにある可能性", True
    return 2, "非公開のリポジトリにある。リポジトリに入れる人や、盗まれた開発者のアカウントから使われる", \
        visibility != "private"


def config_tier(title: str, impact: str, path: str) -> tuple[int, str, bool]:
    """IaC・Dockerfile などの設定ミス。外部への公開か、権限や記録に関わるかで決める。"""
    if NON_DEPLOYED.search(path or ""):
        return 3, "テスト・文書などの中の設定", False
    text = f"{title} {impact}"
    if CONFIG_DIRECT.search(text):
        return 1, "外部への公開に関わる設定", False
    if CONFIG_LATERAL.search(text):
        return 2, "権限・認証・記録に関わる設定(中に入った攻撃者に有利)", False
    return 3, "堅牢化の推奨(すぐ悪用される経路ではない)", False


def prowler_tier(check_id: str, categories: list[str], detail: str, provider: str, title: str) -> tuple[int, str, bool]:
    """Prowler のチェック。チェックの分類(categories)と ID で決める。"""
    if NOT_CHECKED.search(detail or title):
        return 3, "権限が足りず、確かめられなかった", True
    if provider == "iac":
        return config_tier(title, detail, "")
    if "internet-exposed" in categories or PROWLER_DIRECT.search(check_id):
        return 1, "外部への公開に関わる設定", False
    if check_id in PROWLER_HARDENING:
        return 3, "堅牢化の推奨(すぐ悪用される経路ではない)", False
    if set(categories) & PROWLER_LATERAL_CATEGORIES or PROWLER_LATERAL.search(check_id):
        return 2, "アカウント・権限・変更の管理に関わる設定(中に入った攻撃者や盗まれたアカウントに有利)", False
    return 3, "堅牢化の推奨(すぐ悪用される経路ではない)", not check_id


def host_tier(severity: str, exposure: str) -> tuple[int, str, bool]:
    """サーバーの OS・パッケージ(Vuls)。CVSS のベクターがないので、公開範囲と重大度で決める。"""
    high = severity in ("Critical", "High")
    if exposure == "none":
        return 3, "配備していないサーバー", False
    if exposure in ("external", "external-auth", "unknown"):
        return (1 if high else 2), "外部に公開しているサーバー(重大度で判断)", True
    return (2 if high else 3), "内部のサーバー。中に入った攻撃者が悪用しうる(重大度で判断)", True


def classify(finding: dict, scan_type: str, profile: dict, prowler: dict | None = None,
             trivy: dict | None = None) -> tuple[int, str, bool]:
    """DefectDojo の指摘 1 件を分類する。(区分 1〜3, 理由, 要確認か)

    prowler・trivy は元の結果の索引(prowler_index・trivy_index)。DefectDojo に入らない情報を補う。
    """
    tags = set(finding.get("tags") or [])
    path = finding.get("file_path") or ""
    exposure, why = exposure_for(profile, path)
    if scan_type == "Trivy Scan":
        if "secret" in tags:
            return secret_tier(finding.get("title") or "", path, profile.get("visibility", ""), exposure)
        if "config" in tags:
            return config_tier(finding.get("title") or "", finding.get("impact") or "", path)
        cvss = finding.get("cvssv3") or (trivy or {}).get(_trivy_key(finding))
        return package_tier(cvss, exposure, f"{path}。{why}" if path else why)
    if scan_type == "Prowler Scan":
        info = prowler_info(prowler, finding)
        if info is None:
            text = f"{finding.get('title')} {finding.get('description')}"
            tier, reason, _ = config_tier(text, "", "")
            return tier, reason + "(元の結果が見つからず、文面で判断)", True
        if info["status"] == "MANUAL":
            return 3, "手動での確認が要るチェック(自動では判定できない)", True
        return prowler_tier(info["check_id"], info["categories"], info["detail"], info["provider"],
                            finding.get("title") or "")
    if scan_type == "Vuls Scan":
        return host_tier(finding.get("severity") or "", exposure)
    if scan_type == "Semgrep JSON Report":
        if exposure == "none":
            return 3, "配備していない場所の静的検査候補。" + why, True
        if exposure == "internal":
            return 2, "内部向けコードの静的検査候補。入力経路と成立条件を確認する。" + why, True
        return 1, "外部入力からの到達可能性を確認する静的検査候補。" + why, True
    return 3, "この検査の種類には分類のルールがない", True


def vuln_id(finding: dict) -> str:
    """指摘の脆弱性の ID(CVE など)。DefectDojo は vuln_id_from_tool ではなく vulnerability_ids に入れることがある。"""
    ids = [v.get("vulnerability_id") for v in finding.get("vulnerability_ids") or [] if v.get("vulnerability_id")]
    return (ids or [finding.get("vuln_id_from_tool") or ""])[0]


def _trivy_key(finding: dict) -> tuple[str, str, str, str]:
    return (vuln_id(finding), (finding.get("component_name") or "").lower(), finding.get("component_version") or "",
            finding.get("file_path") or "")


def trivy_index(data: dict) -> dict[tuple[str, str, str, str], str]:
    """Trivy の結果から、(脆弱性の ID, パッケージ名, 版, ファイル) → CVSS のベクター。

    DefectDojo は NVD の CVSS v3 しか取り込まないので、GHSA・Red Hat などのベクターで補う
    (優先: v3 → v4 → v2、それぞれ NVD → GHSA → Red Hat → ほか)。
    """
    index = {}
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            sources = v.get("CVSS") or {}
            ordered = [sources.get(s) or {} for s in ("nvd", "ghsa", "redhat")] + \
                [c for k, c in sources.items() if k not in ("nvd", "ghsa", "redhat")]
            vector = next((c[k] for k in ("V3Vector", "V40Vector", "V2Vector") for c in ordered if c.get(k)), None)
            if vector:
                index[(v.get("VulnerabilityID") or "", (v.get("PkgName") or "").lower(), v.get("InstalledVersion") or "",
                       result.get("Target") or "")] = vector
    return index


def prowler_info(index: dict | None, finding: dict) -> dict | None:
    """元の結果の索引(prowler_index)から、指摘の Prowler の結果(チェック・分類など)を引く。"""
    return (index or {}).get(_title_key(finding.get("title")))


def _title_key(title: str | None) -> str:
    # DefectDojo は指摘のタイトルの大文字・小文字を整える(例: "example-team allows" → "Example-Team Allows")ので、
    # 大文字・小文字を区別せずに突き合わせる
    return (title or "").strip().lower()


def prowler_index(entries: list[dict]) -> dict[str, dict]:
    """Prowler の OCSF の結果を、DefectDojo の指摘のタイトル(元は message)で引けるようにする。"""
    index = {}
    for e in entries:
        if e.get("status_code") == "PASS":  # DefectDojo は合格以外(不合格・手動確認)を取り込む
            continue
        index[_title_key(e.get("message"))] = {
            "status": e.get("status_code") or "",
            "check_id": (e.get("metadata") or {}).get("event_code") or "",
            "categories": (e.get("unmapped") or {}).get("categories") or [],
            "detail": e.get("status_detail") or "",
            "provider": (e.get("unmapped") or {}).get("provider") or (e.get("cloud") or {}).get("provider") or "",
        }
    return index
