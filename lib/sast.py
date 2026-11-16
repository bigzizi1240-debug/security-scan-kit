"""固定したMITルールでSASTを行い、コード本文を含まない結果だけを残す。"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import subprocess
import tempfile
import uuid
from pathlib import Path, PurePosixPath

import kit

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
CONFIG = ROOT / "config" / "scanners.json"
MAX_REPORT_BYTES = 32 * 1024 * 1024
SCAN_TIMEOUT = 600
SEVERITIES = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}
EXCLUDES = (".git", "node_modules", "vendor", ".venv", "venv", ".env", ".env.*", "*.pem", "*.key")


def validate_rules(root: Path, config: dict) -> dict:
    """固定manifestの外にあるルールや、変更されたファイルを実行しない。"""
    root = root.resolve()
    manifest = root / "manifest.json"
    catalog_file = root / "catalog.json"
    for path, key in ((manifest, "manifest_sha256"), (catalog_file, "catalog_sha256")):
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != config.get(key):
            raise ValueError("SASTのルール定義が固定した版と一致しません。")
    definition = json.loads(manifest.read_bytes())
    expected = set()
    for entry in definition["files"]:
        relative = PurePosixPath(entry["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("SASTのルール一覧のパスが正しくありません。")
        path = root / relative
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("SASTのルールが固定フォルダの外を指しています。")
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError("SASTのルールが固定した版と一致しません。")
        if path.suffix in (".yaml", ".yml"):
            expected.add(path.relative_to(root).as_posix())
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.suffix in (".yaml", ".yml")}
    if actual != expected:
        raise ValueError("固定manifestにないSASTルールがあります。")
    catalog = json.loads(catalog_file.read_bytes())
    if not isinstance(catalog, dict) or not catalog or not set(catalog) <= set(definition["rule_ids"]):
        raise ValueError("SASTの表示用ルール定義が正しくありません。")
    return catalog


def configuration() -> tuple[dict, dict]:
    config = json.loads(CONFIG.read_bytes())["semgrep"]
    if not re.fullmatch(r"semgrep/semgrep@sha256:[0-9a-f]{64}", config.get("image", "")):
        raise ValueError("SASTイメージが公式リポジトリのdigestで固定されていません。")
    return config, validate_rules(RULES, config)


def _mount(source: Path, destination: str, readonly: bool = False) -> str:
    output = io.StringIO()
    csv.writer(output, lineterminator="").writerow(
        ["type=bind", f"src={source}", f"dst={destination}"] + (["readonly"] if readonly else []))
    return output.getvalue()


def command(image: str, source: Path, rules: Path, output: Path, name: str) -> list[str]:
    return ["docker", "run", "--rm", "--pull=never", "--name", name, "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=2g", "--cpus=2", "--pids-limit=128",
            f"--user={os.getuid()}:{os.getgid()}",
            "--tmpfs=/tmp:rw,nosuid,nodev,size=512m", "--env=HOME=/tmp", "--env=SEMGREP_SEND_METRICS=off",
            "--env=SEMGREP_ENABLE_VERSION_CHECK=0", "--workdir=/src",
            "--mount", _mount(source, "/src", True), "--mount", _mount(rules, "/rules", True),
            "--mount", _mount(output, "/out"), "--entrypoint=semgrep", image, "scan", "--config=/rules",
            "--oss-only", "--json", "--output=/out/semgrep.json", "--metrics=off", "--disable-version-check",
            "--no-rewrite-rule-ids", "--no-git-ignore", "--x-ignore-semgrepignore-files", "--jobs=2", "--timeout=10", "--max-memory=1024",
            "--max-target-bytes=1000000", *[f"--exclude={pattern}" for pattern in EXCLUDES], "/src"]


def _relative_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or re.search(r"[\x00-\x1f\x7f]", value):
        return None
    if value.startswith("/src/"):
        value = value[5:]
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "\\" in value or value == ".":
        return None
    return path.as_posix()


def sanitize_report(data: dict, catalog: dict) -> tuple[dict, list[dict], int, int]:
    """scannerの動的message・source・metavariable・traceを転記しない。"""
    if (not isinstance(data.get("results"), list) or not isinstance(data.get("errors"), list)
            or not isinstance(data.get("paths"), dict) or not isinstance(data["paths"].get("scanned"), list)):
        raise ValueError("incomplete report")
    results, findings, invalid = [], [], 0
    for item in data["results"]:
        if not isinstance(item, dict):
            invalid += 1
            continue
        rule = item.get("check_id")
        relative = _relative_path(item.get("path"))
        start = item.get("start") or {}
        if not isinstance(start, dict):
            invalid += 1
            continue
        line = start.get("line")
        if rule not in catalog or not relative or not isinstance(line, int) or isinstance(line, bool) or line < 1:
            invalid += 1
            continue
        definition = catalog[rule]
        message = definition["message"]
        severity = definition["severity"]
        point = {"line": line, "col": 1}
        results.append({"check_id": rule, "path": relative, "start": point, "end": point,
                        "extra": {"severity": severity, "message": message, "metadata": {"category": "security"}}})
        findings.append({"category": "code", "tool": "Semgrep CE", "id": rule, "title": message.split("。")[0][:160],
                         "severity": SEVERITIES.get(severity, "Info"), "file": relative, "line": line,
                         "component": "", "installed_version": "", "fixed_version": "",
                         "description": "固定ルールによる静的検出候補です。悪用の成立は未確認です。 " + message,
                         "mitigation": "該当行と呼び出し元を確認し、安全なAPIや入力の扱いへの修正を検討してください。"})
    scanned = {_relative_path(path) for path in (data.get("paths") or {}).get("scanned", [])}
    scanned.discard(None)
    errors = [{"type": "scan_error"} for _ in data.get("errors", [])]
    report = {"version": str(data.get("version", "")), "results": results, "errors": errors,
              "paths": {"scanned": sorted(scanned)}}
    return report, findings, len(scanned), invalid


def scan(source: Path, directory: Path) -> dict:
    result = {"status": "failed", "tool": "Semgrep CE", "version": "", "message": "",
              "findings": [], "report": None, "scanned_files": 0}
    source, directory = Path(source), Path(directory)
    if source.is_symlink() or not source.is_dir() or directory.is_symlink():
        result["message"] = "SASTの入力または保存先が通常のフォルダではありません。"
        return result
    source, directory = source.resolve(), directory.resolve()
    if directory.is_relative_to(source):
        result["message"] = "SASTの保存先を検査ソースの外に指定してください。"
        return result
    try:
        config, catalog = configuration()
    except (OSError, ValueError, KeyError, TypeError):
        result["message"] = "固定したSAST設定・ルールを検証できませんでした。"
        return result
    docker = kit.which("docker")
    if not docker:
        result.update(status="unavailable", message="Dockerが見つかりません。SASTは未実施です。")
        return result
    environment = kit.tool_env()
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    except OSError:
        result["message"] = "SAST結果の保存先を準備できませんでした。"
        return result
    name = "kit-sast-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="kit-sast-") as temporary:
        output = Path(temporary)
        try:
            argv = command(config["image"], source, RULES.resolve(), output, name)
            argv[0] = docker
            completed = subprocess.run(argv, env=environment,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       timeout=SCAN_TIMEOUT, check=False)
            raw = output / "semgrep.json"
            if not raw.is_file() or raw.is_symlink() or raw.stat().st_size > MAX_REPORT_BYTES:
                status = "unavailable" if completed.returncode == 125 else "failed"
                result.update(status=status, message="Docker・固定イメージ、またはSAST結果を確認できませんでした。")
                return result
            data = json.loads(raw.read_bytes())
            if not isinstance(data, dict) or not isinstance(data.get("results"), list):
                raise ValueError("invalid report")
            report, findings, scanned, invalid = sanitize_report(data, catalog)
            if report["version"] != config["version"]:
                result["message"] = "SASTの実測バージョンが固定設定と一致しません。"
                return result
            destination = directory / "semgrep.json"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            with os.fdopen(os.open(destination, flags, 0o600), "w", encoding="utf-8") as stream:
                json.dump(report, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
            if completed.returncode or report["errors"] or invalid:
                status = "partial"
                message = "SASTに実行・解析・結果検証の未完了があります。保存済みの指摘は確認候補です。"
            elif not scanned:
                status, message = "not_applicable", "固定ルールで解析できたファイルがありません。検査済みの安全判定ではありません。"
            else:
                status, message = "completed", "固定ルールによるSASTを実施しました。対象外の言語・経路と悪用の成立は未確認です。"
            result.update(status=status, version=report["version"], message=message, findings=findings,
                          report=destination, scanned_files=scanned)
        except subprocess.TimeoutExpired:
            result["message"] = "SASTが時間上限に達しました。検査は未完了です。"
        except (OSError, ValueError, KeyError, TypeError):
            result["message"] = "SASTの実行または結果の検証に失敗しました。"
        finally:
            # docker CLIが終了してもdaemon上の検査が残らないよう、この実行だけを片付ける。
            try:
                subprocess.run([docker, "container", "rm", "--force", name], env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
            except (OSError, subprocess.TimeoutExpired):
                pass
    return result
