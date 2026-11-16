"""検査の内容の組み立て。画面の入力やプリセット(data/targets.toml)から、kit のコマンドの引数を作る。

画面のサーバー(web.py)と、一括検査(kit.py の scan-all)の両方が使う。値はすべてここで確かめる。
"""
from __future__ import annotations

import re
import shlex
import tomllib
from pathlib import Path

import ai_review
import classify
import kit
import report
import triage

FIELD = re.compile(r"^(?!-)[^\x00-\x1f\x7f]{1,200}$")  # 先頭の - は kit の引数と取り違えるので断る
LABELS = {"client": "顧客", "product": "対象システム", "engagement": "案件", "target": "対象", "branch": "ブランチ",
          "config": "設定ファイル", "label": "検査の名前", "by": "受け入れた人"}


class BadRequest(Exception):
    pass


def field(payload: dict, key: str, required: bool = True) -> str:
    value = str(payload.get(key) or "").strip()
    if not value:
        if required:
            raise BadRequest(f"{LABELS.get(key, key)}を入力してください。")
        return ""
    if not FIELD.match(value):
        raise BadRequest(f"{LABELS.get(key, key)}に使えない文字があります(制御文字・先頭の - ・200 文字超)。")
    return value


def existing(payload: dict, key: str, kind: str) -> str:
    path = Path(field(payload, key)).expanduser()
    if not path.is_absolute():
        raise BadRequest(f"{LABELS[key]}はフルパスで指定してください。")
    if not (path.is_dir() if kind == "dir" else path.is_file()):
        raise BadRequest(f"{LABELS[key]}が見つかりません: {path}")
    return str(path.resolve())


def target_args(payload: dict) -> list[str]:
    args = ["--client", field(payload, "client")]
    for key in ("product", "engagement"):
        if value := field(payload, key, required=False):
            args += [f"--{key}", value]
    return args


def build_job(payload: dict) -> tuple[str, str, list[str]]:
    """画面の入力から(題名, 顧客, kit のコマンドの引数)を作る。"""
    tool = payload.get("tool")
    client = field(payload, "client")
    if tool == "all":
        if client not in preset_clients():
            raise BadRequest(f"顧客「{client}」のプリセットがありません(data/targets.toml)。")
        return f"一括検査: {client}", client, ["scan-all", "--client", client]
    if tool == "classify":
        return f"分類し直す: {client}", client, ["classify", "--client", client]
    if tool == "triage":
        return f"仕分けし直す: {client}", client, ["triage", "--client", client, "--refresh"]
    if tool == "accept":
        by = field(payload, "by")
        days = str(payload.get("days") or 180)
        if days not in {str(n) for n in kit.RISK_DAYS}:
            raise BadRequest("期限が正しくありません。")
        try:  # 画面で確かめた件数(違えば登録しない)
            expect = int(payload.get("expect"))
        except (TypeError, ValueError):
            expect = 0
        if expect < 1:
            raise BadRequest("見込みの件数がありません。見込みを確かめてから登録してください。")
        argv = ["accept-risk", "--client", client, "--by", by, "--days", days, "--expect", str(expect)]
        if product := field(payload, "product", required=False):
            argv += ["--product", product]
        if payload.get("reactivate") is False:
            argv.append("--no-reactivate")
        if tier := str(payload.get("tier") or ""):
            if tier not in ("1", "2", "3"):
                raise BadRequest("大項目の指定が正しくありません。")
            argv += ["--tier", tier]
        scope = f"{classify.TIER_NAMES[int(tier)]}、" if tier else ""
        return f"リスク受容: {client}({scope}受け入れた人: {by})", client, argv
    if tool == "ai":
        scope = payload.get("scope") or "critical"
        if scope not in ai_review.SCOPES:
            raise BadRequest("AI に確かめさせる範囲が正しくありません。")
        return (f"AI の確認: {client}({ai_review.SCOPES[scope]})", client,
                ["ai-review", "--client", client, "--scope", scope])
    if tool == "trivy":
        kind = payload.get("kind")
        if kind not in kit.TRIVY_KINDS:
            raise BadRequest("Trivy の種類が正しくありません。")
        target = existing(payload, "target", "dir") if kind in ("fs", "git") else field(payload, "target")
        argv = ["trivy", kind, target, *target_args(payload)]
        if kind == "git" and (branch := field(payload, "branch", required=False)):
            argv += ["--branch", branch]
        name = Path(target).name if kind in ("fs", "git") else kit.redact_url(target)
        return f"Trivy {kind}: {name}", client, argv
    if tool == "repository":
        import repository_scan
        value = field(payload, "target")
        try:
            target = repository_scan.github_url(value) if value.startswith("https://") else existing(payload, "target", "dir")
            branch = repository_scan.validate_branch(field(payload, "branch", required=False))
        except kit.KitError as error:
            raise BadRequest(str(error)) from None
        argv = ["repository-scan", target, *target_args(payload)]
        if branch:
            argv += ["--branch", branch]
        return f"リポジトリ検査: {Path(target).name.removesuffix('.git')}", client, argv
    if tool == "vuls":
        config = existing(payload, "config", "file")
        return f"Vuls: {Path(config).name}", client, ["vuls", "--config", config, *target_args(payload)]
    if tool == "prowler":
        provider = payload.get("provider")
        if provider not in kit.PROWLER_PROVIDERS:
            raise BadRequest("Prowler の対象が正しくありません。")
        raw = payload.get("args") or ""
        raw = shlex.join(raw) if isinstance(raw, list) else str(raw)
        if len(raw) > 2000 or re.search(r"[\x00-\x1f\x7f]", raw):
            raise BadRequest("Prowler の引数が長すぎるか、制御文字を含んでいます。")
        try:
            extra = shlex.split(raw)
        except ValueError as e:
            raise BadRequest(f"Prowler の引数を読めません({e})。") from None
        label = field(payload, "label", required=False) or provider
        return (f"Prowler {provider}: {label}", client,
                ["prowler", provider, *target_args(payload), "--label", label, "--", *extra])
    if tool == "report":
        argv = ["report", *target_args(payload)]
        tier, key = str(payload.get("tier") or ""), str(payload.get("triage") or "")
        if tier and tier not in ("1", "2", "3"):
            raise BadRequest("大項目の指定が正しくありません。")
        if key and key not in triage.CATEGORIES:
            raise BadRequest("小項目の指定が正しくありません。")
        argv += (["--tier", tier] if tier else []) + (["--triage", key] if key else [])
        scope = f"({report.scope_label(int(tier) if tier else None, key or None)})" if tier or key else ""
        return f"報告書: {client}{scope}", client, argv
    raise BadRequest("ツールが正しくありません。")


# ---- プリセット(data/targets.toml) ----

def load_presets() -> list[dict]:
    if not kit.TARGETS.exists():
        return []
    try:
        return tomllib.loads(kit.TARGETS.read_text(encoding="utf-8")).get("preset", [])
    except tomllib.TOMLDecodeError as e:
        raise kit.KitError(f"data/targets.toml を読めません: {e}") from None


def preset_clients() -> list[str]:
    return sorted({p.get("client", "") for p in load_presets() if p.get("client")})


def preset_payload(preset: dict) -> dict:
    payload = {k: v for k, v in preset.items() if k not in ("name", "note")}
    payload.setdefault("engagement", kit.default_engagement())
    return payload


def blocker(preset: dict) -> str | None:
    """プリセットを今すぐ実行できなければ、その理由を返す(報告書の「検査しなかった対象」にも載る)。"""
    tool, provider = preset.get("tool"), preset.get("provider")
    args = preset.get("args") or []
    if tool == "accept":
        return "リスク受容はプリセットにできない(画面で見込みを確かめてから登録する)"
    if tool == "trivy" and preset.get("kind") in ("fs", "git") and not Path(preset.get("target", "")).expanduser().is_dir():
        return "フォルダが見つからない"
    if tool == "vuls" and not Path(preset.get("config", "")).expanduser().is_file():
        return "Vuls の設定ファイルが見つからない"
    if tool != "prowler":
        return None
    if provider == "github" and not kit.github_token():
        return "GitHub の認証情報がない(使うには、ターミナルで gh auth login)"
    if provider == "gcp" and not kit.gcp_ready():
        return "GCP の認証情報(ADC)がない(使うには、ターミナルで gcloud auth application-default login)"
    if provider == "aws":
        profile = args[args.index("--profile") + 1] if "--profile" in args[:-1] else None
        if profile and profile not in kit.aws_profiles():
            return f"AWS のプロファイル {profile} がない(使うには、aws configure sso で作る)"
    return None
