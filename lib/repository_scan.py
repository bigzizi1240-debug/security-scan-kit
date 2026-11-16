"""One Git revision, independent scanners, and a private repository result bundle."""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import shlex
import signal
import subprocess
import tempfile
import urllib.parse
import uuid
from pathlib import Path

import dojo
import kit
import sast

RUN_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{12}$")
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
CATEGORIES = ("dependency", "code", "secret", "config")
MAX_RESULT_BYTES = 64 * 1024 * 1024
STAGE_NAMES = {"source": "リポジトリの取得", "trivy": "依存・秘密情報・設定の検査", "sast": "コードの検査",
               "sbom": "SBOMの保存", "import_trivy": "対応履歴への登録（依存・秘密情報・設定）",
               "import_sast": "対応履歴への登録（コード）"}


def github_url(value: str) -> str:
    match = re.fullmatch(r"https://github\.com/([A-Za-z0-9][A-Za-z0-9_.-]{0,99})/([A-Za-z0-9_.-]{1,100})/?", value)
    if not match or match[2] in (".", ".."):
        raise kit.KitError("GitHubのリポジトリURL（https://github.com/所有者/名前）を指定してください。")
    name = match[2].removesuffix(".git")
    if not name or name in (".", ".."):
        raise kit.KitError("GitHubのリポジトリ名が正しくありません。")
    return f"https://github.com/{match[1]}/{name}.git"


def validate_branch(branch: str | None) -> str | None:
    if not branch:
        return None
    if len(branch) > 200 or branch.startswith("-") or any(ord(c) < 32 for c in branch):
        raise kit.KitError("ブランチ名が正しくありません。")
    checked = subprocess.run(["git", "check-ref-format", "--branch", branch], capture_output=True,
                             stdin=subprocess.DEVNULL, timeout=10)
    if checked.returncode:
        raise kit.KitError("ブランチ名が正しくありません。")
    return branch


def run_command(argv: list[str], *, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run([str(a) for a in argv], capture_output=True, text=True, stdin=subprocess.DEVNULL,
                          timeout=timeout, cwd=kit.KIT, env={**kit.tool_env(), "GIT_TERMINAL_PROMPT": "0"})


def _write(path: Path, data: dict) -> None:
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with os.fdopen(os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600), "w", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(data, stream, ensure_ascii=False)
    os.replace(temp, path)


def _read(path: Path) -> dict:
    if path.stat().st_size > MAX_RESULT_BYTES:
        raise ValueError("result too large")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("invalid result")
    return data


def _safe_text(value) -> str:
    return kit.redact_url(re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(value or "")))


def _relative(value, source: Path | None = None) -> str:
    text = _safe_text(value).replace("\\", "/")
    if source and text.startswith(str(source) + "/"):
        text = text[len(str(source)) + 1:]
    if text.startswith("/") or ".." in Path(text).parts:
        return Path(text).name
    return text.removeprefix("./")


def sanitize_trivy(raw: dict, product: str, source: Path | None = None) -> dict:
    empty_report = raw.get("ArtifactType") == "filesystem" and isinstance(raw.get("ArtifactName"), str)
    if (not isinstance(raw.get("SchemaVersion"), int) or not isinstance(raw.get("Results"), (list, type(None)))
            or "Results" not in raw and not empty_report):
        raise ValueError("not a Trivy result")
    for entry in raw.get("Results") or []:
        if not isinstance(entry, dict):
            raise ValueError("invalid Trivy result entry")
        for key in ("Packages", "Vulnerabilities", "Secrets", "Misconfigurations"):
            items = entry.get(key)
            if items is not None and (not isinstance(items, list) or any(not isinstance(item, dict) for item in items)):
                raise ValueError("invalid Trivy findings")
        for item in entry.get("Misconfigurations") or []:
            if item.get("CauseMetadata") is not None and not isinstance(item["CauseMetadata"], dict):
                raise ValueError("invalid cause metadata")

    def clean(value):
        if isinstance(value, dict):
            return {key: ("(値は伏せた)" if key == "Match" else
                          _relative(item, source) if key in ("Target", "FilePath") else clean(item))
                    for key, item in value.items() if key not in ("Code", "CodeLines", "Snippet", "SnippetCode")}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return _safe_text(value) if isinstance(value, str) else value

    data = clean(raw)
    data["ArtifactName"] = product
    data.setdefault("Results", [])
    return data


def _finding(category: str, item: dict, target: str) -> dict:
    dependency = category == "dependency"
    severity = _safe_text(item.get("Severity", "Info")).title()
    vid = item.get("VulnerabilityID") if dependency else item.get("RuleID") or item.get("ID")
    description = item.get("Description", "") if category != "secret" else "秘密情報の候補です。値は保存していません。"
    mitigation = ("修正版への更新と互換性を確認してください。" if dependency else
                  "資格情報の有効性を確認し、必要なら失効・再発行してください。" if category == "secret" else item.get("Resolution", "設定を確認してください。"))
    return {"category": category, "tool": "Trivy", "id": _safe_text(vid),
            "title": _safe_text(item.get("Title") or vid), "severity": severity if severity in SEVERITIES else "Info",
            "file": _relative(target), "line": item.get("StartLine") or (item.get("CauseMetadata") or {}).get("StartLine"),
            "component": _safe_text(item.get("PkgName", "")), "installed_version": _safe_text(item.get("InstalledVersion", "")),
            "fixed_version": _safe_text(item.get("FixedVersion", "")), "description": _safe_text(description),
            "mitigation": _safe_text(mitigation)}


def trivy_findings(data: dict) -> list[dict]:
    result = []
    for entry in data.get("Results") or []:
        for key, category in (("Vulnerabilities", "dependency"), ("Secrets", "secret"), ("Misconfigurations", "config")):
            result.extend(_finding(category, item, entry.get("Target", "")) for item in entry.get(key) or [])
    return result


def sanitize_sbom(raw: dict, product: str, commit: str, branch: str) -> dict:
    if raw.get("bomFormat") != "CycloneDX" or not isinstance(raw.get("components", []), list):
        raise ValueError("not a CycloneDX BOM")

    def clean(value):
        if isinstance(value, dict):
            return {key: clean(item) for key, item in value.items()
                    if key not in ("externalReferences", "description", "evidence", "releaseNotes", "text")}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return _safe_text(value) if isinstance(value, str) else value

    data = clean(raw)
    metadata = data.setdefault("metadata", {})
    original_ref = (metadata.get("component") or {}).get("bom-ref")
    metadata["component"] = {"type": "application", "name": product, "version": commit,
                             **({"bom-ref": original_ref} if original_ref else {}),
                             "properties": [{"name": "security-scan-kit:git-branch", "value": branch},
                                            {"name": "security-scan-kit:scope", "value": "source-repository"}]}
    return data


def _counts(findings: list[dict]) -> dict:
    return {"total": len(findings), "severity": {s: sum(f["severity"] == s for f in findings) for s in SEVERITIES},
            "category": {c: sum(f["category"] == c for f in findings) for c in CATEGORIES}}


def _stage(record: dict, directory: Path, key: str, status: str, *, message: str = "", count=None, version: str = "") -> None:
    item = {"id": key, "name": STAGE_NAMES.get(key, key), "status": status,
            "message": message, "count": count, "version": version}
    index = next((i for i, old in enumerate(record["stages"]) if old["id"] == key), len(record["stages"]))
    if index == len(record["stages"]):
        record["stages"].append(item)
    else:
        record["stages"][index] = item
    record["counts"] = _counts(record["findings"])
    _write(directory / "result.json", record)


def trivy_analysis_incomplete(diagnostics: str) -> bool:
    for line in diagnostics.splitlines():
        columns = line.split("\t", 3)
        if len(columns) < 3:
            continue
        level = columns[1].strip()
        message = re.sub(r"^(?:\[[^\]]+\]\s*)+", "", columns[2].strip())
        if level in ("ERROR", "FATAL") or message in ("Walk error", "Analysis error"):
            return True
        if level == "WARN":
            try:
                fields = shlex.split(columns[3]) if len(columns) == 4 else []
            except ValueError:
                return True
            for field in fields:
                key, _, value = field.partition("=")
                if key in ("err", "error") and value:
                    return True
            if re.search(r"\b(?:(?:failed|unable) to|could not|cannot) (?:analy[sz]e|parse|scan)\b", message, re.I):
                return True
    return False


def _scan_stages(source: Path, directory: Path, scratch: Path, record: dict, target: kit.Target,
                 repo: Path, import_results: bool) -> None:
    reports = []
    trivy_path = directory / "trivy.json"
    raw_path = scratch / "trivy.json"
    _stage(record, directory, "trivy", "running")
    try:
        trivy = kit.check_trivy()
        version = kit.tool_version("trivy", "--version")
        kit.log_scan(target, "Trivy repository", version, f"{repo}@{record['branch']} {record['commit']}", directory)
        command = [trivy, "fs", "--debug", "--scanners", "vuln,secret,misconfig", "--list-all-pkgs", "--format", "json",
                   "--no-progress", "--disable-telemetry", "--skip-version-check", "--ignorefile", os.devnull,
                   "--output", str(raw_path), str(source)]
        result = run_command(command)
        data = sanitize_trivy(_read(raw_path), target.product, source)
        findings = trivy_findings(data)
        trivy_partial = result.returncode != 0 or trivy_analysis_incomplete(result.stderr)
        _write(trivy_path, data)
        record["findings"].extend(findings)
        _stage(record, directory, "trivy", "partial" if trivy_partial else "completed",
               message="一部の解析・検査が未完了です。保存できた指摘を表示します。" if trivy_partial else "",
               count=len(findings), version=version)
        reports.append(("trivy", "Trivy Scan", trivy_path))
    except (kit.KitError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        _stage(record, directory, "trivy", "failed", message="検査結果を取得できませんでした。Trivyの準備・DB・実行状態を確認してください。")

    _stage(record, directory, "sast", "running")
    try:
        result = sast.scan(source, directory)
        kit.log_scan(target, "Semgrep CE", result.get("version", ""), f"{repo}@{record['branch']} {record['commit']}", directory)
        record["findings"].extend(result["findings"])
        _stage(record, directory, "sast", result["status"], message=result["message"],
               count=len(result["findings"]), version=result.get("version", ""))
        if result.get("report"):
            reports.append(("sast", "Semgrep JSON Report", Path(result["report"])))
    except (kit.KitError, OSError, RuntimeError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        _stage(record, directory, "sast", "failed", message="コードの検査を完了できませんでした。SASTの準備を確認してください。")

    _stage(record, directory, "sbom", "running")
    if trivy_path.exists():
        try:
            raw_bom = scratch / "sbom.json"
            result = run_command([trivy, "convert", "--format", "cyclonedx", "--output", str(raw_bom), str(trivy_path)])
            if result.returncode:
                raise ValueError("conversion failed")
            bom = sanitize_sbom(_read(raw_bom), target.product, record["commit"], record["branch"])
            _write(directory / "sbom.cdx.json", bom)
            record["sbom"] = "sbom.cdx.json"
            _stage(record, directory, "sbom", "partial" if trivy_partial else "completed",
                   message="依存検査が未完了のため、部品一覧にも未確認の範囲があります。" if trivy_partial else "",
                   count=len(bom.get("components", [])), version=version)
        except (OSError, ValueError, TypeError, subprocess.SubprocessError):
            _stage(record, directory, "sbom", "failed", message="SBOMを保存できませんでした。部品の一覧は未確認です。")
    else:
        _stage(record, directory, "sbom", "unavailable", message="依存検査の結果がないため、SBOMを生成していません。")

    if import_results:
        kit.note_system(target.client, target.product, visibility=kit.repo_visibility(repo))
        for key, scan_type, path in reports:
            import_key = f"import_{key}"
            _stage(record, directory, import_key, "running")
            try:
                kit.import_result(scan_type, path, target, f"リポジトリ検査: {repo.name}@{record['branch']} ({key})",
                                  source_repo=repo, source_literal=True,
                                  commit_hash=record["commit"], branch_tag=record["branch"], close_old_findings="false")
                _stage(record, directory, import_key, "completed")
            except (kit.KitError, dojo.DojoError, OSError, ValueError):
                _stage(record, directory, import_key, "failed", message="結果は保存済みです。DefectDojoへの登録は完了していません。")


def scan_repository(repo: Path, target: kit.Target, branch: str | None = None, *, import_results: bool = True) -> dict:
    branch = validate_branch(branch)
    run_id = f"{dt.datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:12]}"
    parent = kit.client_dir(target.client) / "repository-scans"
    parent.mkdir(mode=0o700, exist_ok=True)
    directory = parent / run_id
    directory.mkdir(mode=0o700)
    record = {"schema_version": 1, "id": run_id, "client": target.client, "product": target.product,
              "created": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "branch": branch or "", "commit": "",
              "fresh": False, "status": "running",
              "worker": {"pid": os.getpid(), "started": process_started(os.getpid())},
              "stages": [{"id": key, "name": STAGE_NAMES[key], "status": "queued", "message": "", "count": None, "version": ""}
                         for key in ("source", "trivy", "sast", "sbom")], "findings": [], "counts": _counts([]),
              "sbom": None, "results": "result.json", "scope": "source-repository"}
    _write(directory / "result.json", record)
    try:
        with tempfile.TemporaryDirectory(prefix="kit-repository-") as scratch:
            source = Path(scratch) / "source"
            try:
                used_branch, commit, fresh = kit.remote_tip(repo, branch)
                exported = kit.export_tree(repo, commit, source, literal=True)
            except (kit.KitError, OSError, subprocess.SubprocessError):
                record["status"] = "failed"
                _stage(record, directory, "source", "failed", message="ソースを取得・書き出しできませんでした。origin・ブランチ・対象サイズを確認してください。")
                for stage in record["stages"]:
                    if stage["status"] == "queued":
                        stage.update(status="unavailable", message="ソースを取得できなかったため未実施です。")
                return record
            record.update(branch=used_branch, commit=commit, fresh=fresh)
            excluded = (exported or {}).get("excluded", 0)
            _stage(record, directory, "source", "partial" if excluded else "completed",
                   count=(exported or {}).get("files"), message=f"リンク・submodule {excluded} 件の実体は検査対象外です。" if excluded else "")
            _scan_stages(source, directory, Path(scratch), record, target, repo, import_results)
    except KeyboardInterrupt:
        record["status"] = "interrupted"
        for stage in record["stages"]:
            if stage["status"] == "running":
                stage.update(status="interrupted", message="検査を中断しました。")
            elif stage["status"] == "queued":
                stage.update(status="unavailable", message="中断のため未実施です。")
        raise
    finally:
        if record["status"] == "running":
            states = [s["status"] for s in record["stages"]]
            record["status"] = "completed" if states and all(s == "completed" for s in states) else "partial"
        _write(directory / "result.json", record)
    return record


def _artifact_url(directory: Path, name: str | None) -> str | None:
    if not name:
        return None
    path = directory / name
    if path.is_symlink() or not path.is_file() or path.resolve().parent != directory.resolve():
        return None
    return "/kit/files/" + urllib.parse.quote(path.relative_to(kit.DATA).as_posix())


def _public(record: dict, directory: Path, *, detail: bool = False) -> dict:
    data = {key: value for key, value in record.items() if key != "worker" and (detail or key != "findings")}
    data["sbom"] = _artifact_url(directory, "sbom.cdx.json" if record.get("sbom") else None)
    data["results"] = _artifact_url(directory, "result.json")
    return data


def process_started(pid: int) -> str | None:
    try:
        result = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "lstart="], capture_output=True, text=True,
                                timeout=3, env={**os.environ, "LC_ALL": "C"})
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _read_record(directory: Path) -> dict:
    record = _read(directory / "result.json")
    if record.get("status") == "running":
        worker = record.get("worker") or {}
        pid = worker.get("pid")
        valid_pid = isinstance(pid, int) and not isinstance(pid, bool) and pid > 0
        observed = process_started(pid) if valid_pid else None
        alive = valid_pid and kit.jobs._alive(pid) and (not observed or not worker.get("started") or observed == worker["started"])
        if not alive:
            # The owner can finish while ps is checked; never replace its final result with an older snapshot.
            current = _read(directory / "result.json")
            if current.get("status") != "running" or current.get("worker") != worker:
                return current
            record = current
            record["status"] = "interrupted"
            for stage in record.get("stages", []):
                if stage.get("status") in ("queued", "running"):
                    stage.update(status="interrupted", message="元の検査プロセスが終了しています。保存済みの指摘を確認してください。")
            _write(directory / "result.json", record)
    return record


def _directories():
    root = kit.DATA.resolve()
    for path in kit.DATA.glob("*/repository-scans/*/result.json"):
        if RUN_ID.fullmatch(path.parent.name) and not any(p.is_symlink() for p in (path, path.parent, path.parent.parent, path.parent.parent.parent)):
            if root in path.resolve().parents:
                yield path.parent


def list_scans(client: str = "", limit: int = 200) -> list[dict]:
    scans = []
    for directory in sorted(_directories(), key=lambda p: p.name, reverse=True):
        try:
            record = _read_record(directory)
            if record.get("id") != directory.name or client and record.get("client") != client:
                continue
            scans.append(_public(record, directory))
            if len(scans) >= limit:
                break
        except (OSError, ValueError):
            continue
    return scans


def get_scan(run_id: str) -> dict | None:
    if not RUN_ID.fullmatch(run_id):
        return None
    for directory in _directories():
        if directory.name == run_id:
            try:
                record = _read_record(directory)
                return _public(record, directory, detail=True) if record.get("id") == run_id else None
            except (OSError, ValueError):
                return None
    return None


def command(args) -> None:
    branch = validate_branch(args.branch)
    target = kit.target_from(args)
    records = []

    def scan_local(path: Path) -> None:
        repos = kit.git_repos(path)
        if not repos:
            raise kit.KitError("Gitのclone、またはcloneを並べたフォルダを指定してください。")
        for repo in repos:
            product = args.product if args.product and len(repos) == 1 else repo.name
            kit.say(f"リポジトリを検査します: {repo.name}")
            record = scan_repository(repo, kit.Target(target.client, product, target.engagement), branch,
                                     import_results=not args.no_import)
            records.append(record)
            kit.say(f"結果を保存しました: {record['id']}（{record['status']}、指摘 {record['counts']['total']} 件）")

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    old_handler = signal.signal(signal.SIGTERM, interrupted)
    try:
        if args.target.startswith("https://"):
            url = github_url(args.target)
            with tempfile.TemporaryDirectory(prefix="kit-github-") as scratch:
                destination = Path(scratch) / url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
                argv = ["git", "clone", "--quiet", "--no-checkout", "--depth=1"]
                if branch:
                    argv += ["--branch", branch]
                result = run_command([*argv, "--", url, str(destination)])
                if result.returncode:
                    raise kit.KitError("GitHubから取得できませんでした。URLとGitの認証を確認してください。")
                scan_local(destination)
        else:
            path = Path(args.target).expanduser().resolve()
            if not path.is_dir():
                raise kit.KitError("指定されたフォルダが見つかりません。")
            scan_local(path)
    finally:
        signal.signal(signal.SIGTERM, old_handler)
    if any(record["status"] != "completed" for record in records):
        raise kit.KitError("一部の検査が未完了です。「リポジトリ結果」で各工程と保存済みの指摘を確認してください。")
