"""security-scan-kit のコマンド本体。

Trivy・Vuls・Prowler で検査し、結果を DefectDojo に取り込み、日本語の報告書を作る。
画面(http://127.0.0.1:18080/kit/)は lib/web.py、裏で動く検査の管理は lib/jobs.py。
入口は bin/kit。使い方は README.md。
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import math
import os
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import classify
import dedupe
import dojo
import intel
import jobs
import report
import triage

KIT = Path(__file__).resolve().parent.parent
DATA = KIT / "data"
JOBS_DIR = DATA / "jobs"
TOOLS_BIN = KIT / "tools" / "bin"
DD_DIR = KIT / "defectdojo"
VULS_DIR = KIT / "vuls"
VULS_DB = DATA / "vuls-db" / "vuls.db"
TARGETS = DATA / "targets.toml"
WEB_PID = DATA / "web.pid"
CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")

PROJECT = "security-scan-kit"
DD_PORT = os.environ.get("KIT_DD_PORT", "18080")
DD_URL = f"http://127.0.0.1:{DD_PORT}"
KIT_URL = f"{DD_URL}/kit/"
WEB_PORT = os.environ.get("KIT_WEB_PORT", "18081")
WEB_URL = f"http://127.0.0.1:{WEB_PORT}"
DD_ADMIN = "admin"
DD_VERSION = "3.4.303"  # イメージの digest は defectdojo/docker-compose.override.yml で固定
KEYCHAIN_SERVICE = "security-scan-kit"
VULS_VERSION = "v0.42.0"
PROWLER_VERSION = "5.46.0"
# 2026-03 のサプライチェーン侵害で配られた版(GHSA-69fq-xp46-6x23)
COMPROMISED_TRIVY = frozenset({"0.69.4", "0.69.5", "0.69.6"})
STACK = {"gateway", "nginx", "uwsgi", "celeryworker", "celerybeat", "postgres", "valkey"}

# git = 手元の clone を、origin の既定のブランチの最新の状態で検査する(作業ツリーと ref は変えない)
TRIVY_KINDS = {"fs": "vuln,secret,misconfig", "git": "vuln,secret,misconfig",
               "repo": "vuln,secret,misconfig", "image": "vuln,secret"}
PROWLER_PROVIDERS = ("aws", "azure", "gcp", "kubernetes", "github", "m365", "iac")
RISK_DAYS = (90, 180, 365)  # リスク受容の期限の選択肢(日)
TIER_HELP = "大項目で絞る(" + "、".join(f"{t}={name.split(' ', 1)[1]}" for t, name in classify.TIER_NAMES.items()) + ")"
TRIAGE_HELP = "小項目で絞る(" + "、".join(f"{key}={label}" for key, label in triage.CATEGORIES.items()) + ")"

# 秘密情報。初回の起動で作り、macOS のキーチェーンに置く。
# 2 つ目の値が True のものは DefectDojo のデータと結び付くので、データがある状態では作り直せない
SECRETS = {
    "DD_SECRET_KEY": (lambda: secrets.token_hex(32), True),
    "DD_CREDENTIAL_AES_256_KEY": (lambda: secrets.token_hex(16), True),
    "DD_DATABASE_PASSWORD": (lambda: secrets.token_hex(24), True),
    "DD_ADMIN_PASSWORD": (lambda: secrets.token_urlsafe(18), True),
    "KIT_GATEWAY_TOKEN": (lambda: secrets.token_urlsafe(32), False),  # 入口の nginx と画面のサーバーの合言葉
}


class KitError(Exception):
    pass


class EmptyRepo(KitError):
    """origin にブランチが 1 つもない(空のリポジトリ)。検査するものがないので飛ばす。"""


class OutOfScope(KitError):
    """今の権限では検査できない。失敗ではなく検査の範囲外として扱う(一括検査は止めずに次へ進む)。"""


@dataclass
class Target:
    client: str
    product: str
    engagement: str


def say(msg: str = "") -> None:
    print(msg, flush=True)


# ---- 外部コマンド ----

def tool_env() -> dict[str, str]:
    env = os.environ.copy()
    extra = [str(TOOLS_BIN), "/opt/homebrew/bin", "/usr/local/bin", str(Path.home() / ".local" / "bin")]
    env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")])
    return env


def which(name: str) -> str | None:
    return shutil.which(name, path=tool_env()["PATH"])


def need(name: str) -> str:
    path = which(name)
    if not path:
        raise KitError(f"{name} が見つかりません。`bin/kit install` を実行してください。")
    return path


def run(cmd: list, *, ok: tuple[int, ...] = (0,), cwd: Path | None = None, env: dict | None = None,
        show: str | None = None) -> None:
    cmd = [str(c) for c in cmd]
    say("$ " + (show or shlex.join(cmd)))
    rc = subprocess.run(cmd, cwd=cwd, env=env or tool_env()).returncode
    if rc not in ok:
        raise KitError(f"{Path(cmd[0]).name} が失敗しました(終了コード {rc})。")


def tool_version(name: str, flag: str) -> str:
    """ツールの版(x.y.z)。未導入か、確かめられなければ空文字。"""
    path = which(name)
    if not path:
        return ""
    try:
        r = subprocess.run([path, flag], capture_output=True, text=True, env=tool_env(), timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    m = re.search(r"v?(\d+\.\d+\.\d+)", r.stdout or r.stderr)
    return m.group(1) if m else ""


def check_trivy() -> str:
    path = need("trivy")
    version = tool_version("trivy", "--version")
    if not version:
        raise KitError("Trivy の版を確かめられません。")
    if version in COMPROMISED_TRIVY:
        raise KitError(f"Trivy {version} は 2026-03 の侵害で配られた版です(GHSA-69fq-xp46-6x23)。"
                       "`brew reinstall trivy` で入れ直してください。")
    return path


# ---- 認証情報の有無(画面のプリセットと状態の確認で使う) ----

def gcp_ready() -> bool:
    adc = Path.home() / ".config" / "gcloud" / "application_default_credentials.json"
    return bool(os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")) or adc.exists()


def aws_profiles() -> set[str]:
    names: set[str] = set()
    for path, pattern in ((Path.home() / ".aws" / "config", r"^\[(?:profile )?([^\]]+)\]"),
                          (Path.home() / ".aws" / "credentials", r"^\[([^\]]+)\]")):
        if path.exists():
            names |= set(re.findall(pattern, path.read_text(encoding="utf-8", errors="replace"), re.M))
    return names


def github_token() -> str | None:
    """Prowler の GitHub の検査に使うトークン。環境変数か、gh のログインから取る。"""
    if os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN"):
        return os.environ["GITHUB_PERSONAL_ACCESS_TOKEN"]
    gh = which("gh")
    if not gh:
        return None
    r = subprocess.run([gh, "auth", "token"], capture_output=True, text=True, timeout=30)
    token = r.stdout.strip()
    return token if r.returncode == 0 and token else None


# ---- キーチェーン ----

def keychain_get(name: str) -> str | None:
    r = subprocess.run(["/usr/bin/security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", name, "-w"],
                       capture_output=True, text=True)
    value = r.stdout.rstrip("\n")
    return value if r.returncode == 0 and value else None


def keychain_put(name: str, value: str) -> None:
    # -w を最後に置くと、値を標準入力から読む(コマンドの引数に値を出さない)
    r = subprocess.run(["/usr/bin/security", "add-generic-password", "-U", "-s", KEYCHAIN_SERVICE, "-a", name,
                        "-l", f"{KEYCHAIN_SERVICE} {name}", "-w"],
                       input=f"{value}\n{value}\n", capture_output=True, text=True)
    if r.returncode != 0:
        raise KitError(f"キーチェーンに保存できませんでした({name})。")


def ensure_secrets() -> dict[str, str]:
    values = {name: keychain_get(name) for name in SECRETS}
    missing = [name for name, value in values.items() if value is None]
    bound = [name for name in missing if SECRETS[name][1]]
    if bound and postgres_volume_exists():
        raise KitError("キーチェーンに DefectDojo の秘密情報がありません(" + "、".join(bound) + ")。"
                       "既存のデータベースは元の値で作られているので、新しい値では開けません。"
                       "README の「作り直す」を参照してください。")
    for name in missing:
        values[name] = SECRETS[name][0]()
        keychain_put(name, values[name])
    return values


# ---- Docker と DefectDojo ----

def docker_ready() -> bool:
    return subprocess.run(["docker", "info"], capture_output=True, env=tool_env()).returncode == 0


def ensure_docker() -> None:
    if docker_ready():
        return
    say("Docker Desktop を起動します…")
    subprocess.run(["/usr/bin/open", "-a", "Docker"], check=False)
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        time.sleep(3)
        if docker_ready():
            return
    raise KitError("Docker Desktop が起動しませんでした。手動で起動してから、やり直してください。")


def postgres_volume_exists() -> bool:
    return subprocess.run(["docker", "volume", "inspect", f"{PROJECT}_defectdojo_postgres"],
                          capture_output=True, env=tool_env()).returncode == 0


def running_services() -> set[str]:
    r = subprocess.run(["docker", "ps", "--filter", f"label=com.docker.compose.project={PROJECT}",
                        "--format", '{{.Label "com.docker.compose.service"}}'],
                       capture_output=True, text=True, env=tool_env())
    return set(r.stdout.split())


def compose(*args: str) -> None:
    env = tool_env()
    env.update(ensure_secrets())
    env["KIT_DD_PORT"] = DD_PORT
    env["KIT_WEB_PORT"] = WEB_PORT
    run(["docker", "compose", "-p", PROJECT, "-f", DD_DIR / "docker-compose.yml",
         "-f", DD_DIR / "docker-compose.override.yml", *args], env=env, show="docker compose " + " ".join(args))


def dd_alive() -> bool:
    try:
        with dojo.OPENER.open(DD_URL + "/login", timeout=3) as resp:
            return resp.status == 200
    except OSError:
        return False


def wait_for_dojo(timeout: int) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if dd_alive():
            return
        time.sleep(3)
    raise KitError(f"DefectDojo が {timeout} 秒たっても応答しません。`bin/kit logs` でログを見てください。")


def connect() -> dojo.Dojo:
    if not dd_alive():
        raise KitError("DefectDojo が起動していません。`bin/kit up` を実行してください。")
    password = keychain_get("DD_ADMIN_PASSWORD")
    if not password:
        raise KitError("キーチェーンに管理者のパスワードがありません。")
    return dojo.Dojo.login(DD_URL, DD_ADMIN, password)


# ---- 画面のサーバー ----

def code_version() -> str:
    """lib と web の中身から作る版。変わっていれば `bin/kit up` がサーバーを入れ替える。"""
    h = hashlib.sha256()
    for path in sorted([*(KIT / "lib").glob("*.py"), *(p for p in (KIT / "web").glob("*") if p.is_file())]):
        h.update(path.name.encode())
        h.update(path.read_bytes())
    return h.hexdigest()[:12]


def web_version() -> str | None:
    token = keychain_get("KIT_GATEWAY_TOKEN")
    if not token:
        return None
    req = urllib.request.Request(WEB_URL + "/kit/healthz", headers={"X-Kit-Gateway": token})
    try:
        with dojo.OPENER.open(req, timeout=2) as resp:
            return json.load(resp).get("version")
    except (OSError, ValueError):
        return None


def stop_web() -> None:
    pid = int(WEB_PID.read_text()) if WEB_PID.exists() else 0
    command = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True).stdout
    if pid and "kit.py serve" in command:  # 別のプロセスに番号が再利用されていたら止めない
        os.kill(pid, signal.SIGTERM)
    WEB_PID.unlink(missing_ok=True)


def start_web() -> None:
    version = code_version()
    running = web_version()
    if running == version:
        return
    if running:
        stop_web()
        time.sleep(0.5)
    with (DATA / "web.log").open("ab") as log:
        proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "serve"], start_new_session=True,
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, cwd=KIT)
    WEB_PID.write_text(str(proc.pid))
    for _ in range(50):
        time.sleep(0.2)
        if web_version() == version:
            return
    raise KitError("画面のサーバーが起動しませんでした。data/web.log を見てください。")


# ---- 検査の記録と取り込み ----

def safe_name(name: str) -> str:
    """顧客名をフォルダ名にする。パスの区切りと先頭の . を除く。"""
    name = re.sub(r"[\x00-\x1f/\\:]", "_", name.strip()).lstrip(".")
    return name[:80] or "_"


def redact_url(text: str) -> str:
    """URL の利用者情報(トークンなど)を伏せる。"""
    return re.sub(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/@\s]+@", r"\1***@", text)


SECRET_FLAG = re.compile(r"^--[\w-]*(token|key|secret|password|shodan)[\w-]*$", re.I)


def redact_args(args: list[str]) -> list[str]:
    """--personal-access-token などの秘密の値を、画面と記録に出さない形にする。"""
    out: list[str] = []
    hide_next = False
    for arg in args:
        flag, eq, _ = arg.partition("=")
        if hide_next and not arg.startswith("-"):
            out.append("***")
        elif eq and SECRET_FLAG.match(flag):
            out.append(f"{flag}=***")
        else:
            out.append(redact_url(arg))
        hide_next = bool(SECRET_FLAG.match(arg))
    return out


def default_engagement() -> str:
    return f"診断 {dt.date.today():%Y-%m}"


def target_from(args: argparse.Namespace) -> Target:
    client = (args.client or "").strip()
    if not client:
        raise KitError("--client(顧客名)を指定してください。")
    return Target(client, (args.product or client).strip(), (args.engagement or default_engagement()).strip())


def require_dojo() -> None:
    if not dd_alive():
        raise KitError("DefectDojo が起動していません。先に `bin/kit up` を実行してください。")


def client_dir(client: str) -> Path:
    path = DATA / safe_name(client)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def new_run_dir(client: str, tool: str) -> Path:
    base = client_dir(client)
    stamp = f"{dt.datetime.now():%Y%m%d-%H%M%S}-{tool}"
    for suffix in ("", "-2", "-3", "-4"):
        try:
            path = base / (stamp + suffix)
            path.mkdir(mode=0o700)
            return path
        except FileExistsError:
            continue
    raise KitError(f"結果のフォルダを作れません: {base / stamp}")


def log_scan(t: Target, tool: str, version: str, target: str, run_dir: Path) -> None:
    """いつ・何で・何を検査したかを、顧客のフォルダに残す。"""
    entry = {"time": dt.datetime.now().isoformat(timespec="seconds"), "tool": tool, "version": version,
             "target": redact_url(target), "product": t.product, "engagement": t.engagement, "output": str(run_dir)}
    with (client_dir(t.client) / "scan-log.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return default


def save_json(path: Path, data) -> None:
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")  # 並行したジョブと書き込みが混ざらないように
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, path)


def load_systems(client: str) -> dict:
    """システム(DefectDojo の製品)ごとの公開範囲など。分類の前提になる(data/<顧客>/systems.json)。"""
    return load_json(client_dir(client) / "systems.json", {})


def save_systems(client: str, systems: dict) -> None:
    save_json(client_dir(client) / "systems.json", systems)


def note_system(client: str, product: str, **known: str) -> None:
    """初めて見るシステムを「未設定」で登録し、分かった事実(公開・非公開など)を書き足す。"""
    systems = load_systems(client)
    entry = systems.get(product)
    updates = {k: v for k, v in known.items() if v and (entry or {}).get(k) != v}
    if entry is None or updates:
        systems[product] = {**(entry or {"exposure": "unknown", "reason": "", "source": "auto"}), **updates}
        save_systems(client, systems)


def tier_summary(counts: Counter) -> str:
    return "、".join(f"{classify.TIER_TAGS[k]} {counts[k]}" for k in sorted(counts)) or "有効な指摘なし"


def classify_test(d: dojo.Dojo, client: str, product: str, test_id: int, scan_type: str) -> Counter:
    """検査 1 つ分の有効な指摘を分類し、DefectDojo のタグ(①〜③と「分類を要確認」)を付け直す。"""
    profile = load_systems(client).get(product, {})
    raw = load_json(client_dir(client) / "tests.json", {}).get(str(test_id), {}).get("raw")
    prowler = trivy = None  # 元の結果から、DefectDojo に入らない情報(Prowler の分類・Trivy の CVSS)を補う
    if scan_type == "Prowler Scan":
        prowler = classify.prowler_index(load_json(Path(raw), [])) if raw else {}
    elif scan_type == "Trivy Scan" and raw:
        trivy = classify.trivy_index(load_json(Path(raw), {}))
    counts: Counter = Counter()
    reasons, updates = {}, []
    # 重複は除く(DefectDojo は、重複を持つ指摘を重複にすると有効のまま残し、その指摘への PATCH を拒む)
    for f in d.iterate("/api/v2/findings/", {"test": test_id, "active": "true", "duplicate": "false"}):
        tier, reason, review = classify.classify(f, scan_type, profile, prowler, trivy)
        counts[tier] += 1
        reasons[str(f["id"])] = [tier, reason, review]
        old = f.get("tags") or []
        new = [t for t in old if t not in classify.CLASS_TAGS] + [classify.TIER_TAGS[tier]] \
            + ([classify.REVIEW_TAG] if review else [])
        if sorted(new) != sorted(old):
            updates.append((f["id"], new))
    # 有効でない指摘(誤検知・重複・リスク受容・直ったもの)は分類し直さないが、前の名前のタグは今の名前に付け替える
    legacy = classify.LEGACY_TIER_TAGS
    for f in d.iterate("/api/v2/findings/", {"test": test_id, "active": "false", "tags": ",".join(legacy)}):  # OR
        tags = f.get("tags") or []
        renamed = list(dict.fromkeys(classify.TIER_TAGS[legacy[t]] if t in legacy else t for t in tags))
        if renamed != tags:
            updates.append((f["id"], renamed))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda u: d.call("PATCH", f"/api/v2/findings/{u[0]}/", json_body={"tags": u[1]}), updates))
    path = client_dir(client) / "classification.json"
    save_json(path, {**load_json(path, {}), **reasons})
    return counts


def dedupe_test(d: dojo.Dojo, client: str, product: str, test_id: int, scan_type: str) -> tuple[int, int, str]:
    """検査 1 つ分の二重の数え(同じフォルダのロックファイルに出た同じ脆弱性)を、DefectDojo の「重複」にまとめる。
    元が直ったなど、元と同じものとは言えなくなった重複は、有効に戻す(dedupe.to_restore)。分類の前に使う。
    (まとめた数, 戻した数, 失敗の説明。失敗がなければ空)"""
    if scan_type != "Trivy Scan":
        return 0, 0, ""
    import ai_review  # ai_review は kit を読み込むので、使うときに読む
    manual = {key for key, record in load_json(client_dir(client) / "triage.json", {}).get("findings", {}).items()
              if record.get("manual")}
    findings = list(d.iterate("/api/v2/findings/", {"test": test_id}))  # 有効でないもの(重複とその元)も引く
    # すでに重複を持つ元(DefectDojo は、重複を持つ指摘を重複にすると有効のまま残す)と、人が仕分けを変えたものは隠さない
    originals = {f.get("duplicate_finding") for f in findings if f.get("duplicate")}
    failed: list[Exception] = []

    def post(path: str) -> bool:
        try:
            d.call("POST", path)
            return True
        except Exception as e:  # 1 件の失敗(dojo.request が包まない例外も)で、ほかの指摘を止めない
            failed.append(e)
            return False

    profile = load_systems(client).get(product, {})
    restored = [i for i in dedupe.to_restore(findings, profile) if post(f"/api/v2/findings/{i}/duplicate/reset/")]
    open_now = [f for f in findings if f["id"] in restored or (f.get("active") and not f.get("duplicate"))]

    def pinned(f: dict) -> bool:
        return f["id"] in originals or str(f["id"]) in manual

    def rank(f: dict) -> tuple:  # 残す方: 隠さないもの → AI の確認で影響あり → 要確認 → ID の小さいもの
        tags = f.get("tags") or []
        return pinned(f), ai_review.TAGS["影響あり"] in tags, ai_review.TAGS["要確認"] in tags, -f["id"]

    marks = dedupe.plan(open_now, rank, profile, pinned)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        merged = sum(pool.map(lambda m: post(f"/api/v2/findings/{m[0]}/original/{m[1]}/"), marks.items()))
    problem = f"{len(failed)} 件の重複を更新できませんでした(例: {failed[0]})" if failed else ""
    return merged, len(restored), problem


def dedupe_summary(merged: int, restored: int) -> str:
    """重複のまとめの結果(例: 3 件をまとめ、1 件を戻した)。何もしなければ空。"""
    if merged and restored:
        return f"{merged} 件をまとめ、{restored} 件を戻した"
    return f"{merged} 件をまとめた" if merged else f"{restored} 件を戻した" if restored else ""


def triage_summary(counts: Counter) -> str:
    return "、".join(f"{label} {counts[key]}" for key, label in triage.CATEGORIES.items() if counts[key]) \
        or "分類のある有効な指摘なし"


_intel: intel.Intel | None = None


def load_intel(refresh: bool = False) -> intel.Intel:
    """EPSS・CISA KEV(このプロセスでは 1 度だけ読む。refresh のときは取り直す)。"""
    global _intel
    if _intel is None or refresh:
        _intel = intel.load(DATA / "intel", refresh=refresh)
        for note in _intel.notes:
            say(f"  注意: {note}")
    return _intel


def _same(old, new) -> bool:
    if isinstance(old, float) and isinstance(new, float):
        return math.isclose(old, new, abs_tol=1e-9)
    return old == new


def triage_test(d: dojo.Dojo, client: str, test_id: int, scan_type: str, info: intel.Intel) -> Counter:
    """検査 1 つ分の有効な指摘に、EPSS・KEV の欄と、仕分けのタグ(分類 ①〜③ のあるもの)を付け直す。"""
    import ai_review  # ai_review は kit を読み込むので、使うときに読む
    raw = load_json(client_dir(client) / "tests.json", {}).get(str(test_id), {}).get("raw")
    prowler = classify.prowler_index(load_json(Path(raw), [])) if scan_type == "Prowler Scan" and raw else {}
    path = client_dir(client) / "triage.json"
    records = load_json(path, {}).get("findings", {})
    changed: dict[str, dict | None] = {}  # 記録の変更(None は消す)
    counts: Counter = Counter()
    updates = []
    # 重複は除く(classify_test と同じ)
    for f in d.iterate("/api/v2/findings/", {"test": test_id, "active": "true", "duplicate": "false"}):
        key, tags = str(f["id"]), f.get("tags") or []
        body = {k: v for k, v in triage.intel_fields(f, info).items() if not _same(f.get(k), v)}
        if tier := classify.tier_of(tags):
            check = (classify.prowler_info(prowler, f) or {}).get("check_id", "")
            decision = triage.triage(f, scan_type, check, info, ai_review.TAGS["影響あり"] in tags, tier)
            new_tags, changed[key] = triage.resolve(tags, records.get(key), decision)
            counts[changed[key]["category"]] += 1
        else:
            new_tags = triage.untriage(tags, records.get(key))
            if key in records:
                changed[key] = None
        if sorted(new_tags) != sorted(tags):
            body["tags"] = new_tags
        if body:
            updates.append((key, body))
    done: set[str] = changed.keys() - {key for key, _ in updates}  # 送るもののない指摘は、記録だけ変える
    failed: dict[str, Exception] = {}

    def patch(update: tuple[str, dict]) -> None:
        try:
            d.call("PATCH", f"/api/v2/findings/{update[0]}/", json_body=update[1])
            done.add(update[0])
        except Exception as e:  # 1 件の失敗(dojo.request が包まない例外も)で、ほかの指摘の記録を失わない
            failed[update[0]] = e

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(patch, updates))
    finally:
        # 記録は、付け直せた指摘の分だけ変える(止まったときも、済んだ分は残す)
        data = load_json(path, {})
        saved = data.setdefault("findings", {})
        for key in done & changed.keys():
            if changed[key] is None:
                saved.pop(key, None)
            else:
                saved[key] = changed[key]
        data["intel"] = {**info.summary(), "at": dt.datetime.now().isoformat(timespec="seconds")}
        save_json(path, data)
    if failed:
        raise KitError(f"{len(failed)} 件の指摘を更新できませんでした(例: {next(iter(failed.values()))})")
    return counts


def triage_client(d: dojo.Dojo, client: str, refresh: bool = False, quiet: bool = False) -> Counter:
    """顧客のすべての検査を仕分けし直す。"""
    info = load_intel(refresh)
    total: Counter = Counter()
    for prod, _, test in client_tests(d, client):
        counts = triage_test(d, client, test["id"], test.get("scan_type") or "", info)
        total.update(counts)
        if not quiet:
            say(f"{prod['name']} / {test.get('title')}: {triage_summary(counts)}")
    return total


def note_skipped(t: Target, reason: str | None) -> None:
    """今の権限で検査できなかった対象と理由を残す(報告書の「検査しなかった対象」)。検査できたら消す。"""
    path = client_dir(t.client) / "skipped.json"
    skipped = load_json(path, {})
    if reason:
        skipped[t.product] = {"reason": reason, "time": dt.datetime.now().isoformat(timespec="minutes")}
    elif skipped.pop(t.product, None) is None:
        return
    save_json(path, skipped)


def import_result(scan_type: str, file: Path, t: Target, test_title: str, out_of_scope: Path | None = None,
                  *, source_repo: Path | None = None, source_literal: bool = False, **extra: str) -> None:
    if not file.is_file() or file.stat().st_size == 0:
        raise KitError(f"結果のファイルがありません: {file}")
    d = connect()
    res = d.reimport(scan_type, file, product_type=t.client, product=t.product, engagement=t.engagement,
                     test_title=test_title, scan_date=dt.datetime.now(dt.timezone.utc).date().isoformat(), extra=extra)
    say(f"DefectDojo に取り込みました: {t.client} / {t.product} / {t.engagement} / {test_title}")
    note_skipped(t, None)
    test_id = res.get("test")
    if not test_id:
        return
    say(f"  {DD_URL}/test/{test_id}")
    note_system(t.client, t.product)
    # 分類し直すときに元の結果(Prowler の分類など)を、報告書で判定できなかった項目を引く
    index_path = client_dir(t.client) / "tests.json"
    entry = {"scan_type": scan_type, "product": t.product, "raw": str(file),
             **({"out_of_scope": str(out_of_scope)} if out_of_scope else {})}
    if source_repo is not None:
        entry["source"] = {"repo": str(source_repo.resolve()), "commit": extra.get("commit_hash", ""),
                           "literal": source_literal}
    save_json(index_path, {**load_json(index_path, {}), str(test_id): entry})
    try:
        merged, restored, problem = dedupe_test(d, t.client, t.product, test_id, scan_type)
    except dojo.DojoError as e:  # まとめられなくても、分類と仕分けは続ける(二重の数えが残るだけ)
        merged, restored, problem = 0, 0, str(e)
    if summary := dedupe_summary(merged, restored):
        say(f"  重複: {summary}")
    if problem:
        say(f"  重複のまとめに失敗しました(`bin/kit classify` でやり直せる): {problem}")
    say("  分類: " + tier_summary(classify_test(d, t.client, t.product, test_id, scan_type)))
    say("  仕分け: " + triage_summary(triage_test(d, t.client, test_id, scan_type, load_intel())))


def sanitize_trivy_secrets(path: Path) -> int:
    """Trivy は秘密情報の、規則に一致した部分しか伏せない(同じ行の残りは平文で残る)。
    DefectDojo・報告書・手元の結果に値を残さないよう、値を含む欄を消す。場所(ファイルと行)は残す。"""
    if not path.exists():
        return 0
    data = json.loads(path.read_text(encoding="utf-8"))
    count = 0
    for result in data.get("Results") or []:
        for secret in result.get("Secrets") or []:
            secret["Match"] = f"(値は伏せた。{secret.get('StartLine')} 行目)"
            secret.pop("Code", None)
            count += 1
    if count:
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return count


def repo_visibility(repo: Path) -> str:
    """origin が GitHub なら、リポジトリの公開・非公開(public / private / internal)。分からなければ空。"""
    url = subprocess.run(["git", "-C", str(repo), "remote", "get-url", "origin"], capture_output=True,
                         text=True).stdout.strip()
    m = re.search(r"github\.com[:/]([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", url)
    gh = which("gh")
    if not (m and gh):
        return ""
    try:
        r = subprocess.run([gh, "api", f"repos/{m.group(1)}/{m.group(2)}", "--jq", ".visibility"],
                           capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return ""
    return r.stdout.strip() if r.returncode == 0 else ""


# ---- Git の clone を、手元を変えずに書き出す ----

def git_repos(path: Path) -> list[Path]:
    """path が Git リポジトリならそれを、そうでなければ直下の Git リポジトリを返す。"""
    if (path / ".git").exists():
        return [path]
    return sorted(p for p in path.iterdir() if (p / ".git").exists())


def remote_tip(repo: Path, branch: str | None) -> tuple[str, str, bool]:
    """origin のブランチの先端を、手元の ref と作業ツリーを変えずに取る。(ブランチ, SHA, 最新か)"""
    git = ["git", "-C", str(repo), "-c", "gc.auto=0", "-c", "maintenance.auto=false"]
    # 画面から動かすと入力ができないので、認証を聞かれたら待たずに失敗させる
    env = {**tool_env(), "GIT_TERMINAL_PROMPT": "0", "GIT_SSH_COMMAND": "ssh -o BatchMode=yes"}

    def out(*args: str, timeout: int = 60) -> str:
        return subprocess.run([*git, *args], capture_output=True, text=True, timeout=timeout, check=True,
                              env=env).stdout

    try:
        if not branch:
            m = re.search(r"^ref: refs/heads/(\S+)\s+HEAD", out("ls-remote", "--symref", "origin", "HEAD"), re.M)
            branch = m.group(1) if m else None
            if not branch and not out("ls-remote", "--heads", "origin").strip():
                raise EmptyRepo(f"{repo.name}: origin にブランチがありません(空のリポジトリ)。")
        if branch:
            sha = out("ls-remote", "origin", f"refs/heads/{branch}").split()[0]
            out("fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "origin", sha, timeout=900)
            return branch, sha, True
    except (subprocess.SubprocessError, OSError, IndexError):
        pass
    # origin に届かないときは、手元にある origin の ref を使う(古い可能性がある)
    ref = f"refs/remotes/origin/{branch}" if branch else "refs/remotes/origin/HEAD"
    try:
        sha = out("rev-parse", "--verify", f"{ref}^{{commit}}").strip()
        branch = branch or out("rev-parse", "--abbrev-ref", ref).strip().removeprefix("origin/")
    except (subprocess.SubprocessError, OSError):
        raise KitError(f"{repo.name}: origin のブランチを確かめられません。") from None
    return branch, sha, False


def skip_unsafe(member: tarfile.TarInfo, dest: str) -> tarfile.TarInfo | None:
    """tarfile の data フィルターで弾かれるもの(外を指すリンク・絶対パスなど)は、止めずに飛ばす。"""
    try:
        return tarfile.data_filter(member, dest)
    except tarfile.FilterError:
        return None


def export_tree(repo: Path, sha: str, dest: Path, *, literal: bool = False) -> dict | None:
    """コミットの中身だけを dest に書き出す(git archive)。危ないパスとリンクは書き出さない。"""
    if literal:
        return export_literal_tree(repo, sha, dest)
    dest.mkdir(mode=0o700)
    proc = subprocess.Popen(["git", "-C", str(repo), "archive", "--format=tar", sha], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:
            tar.extractall(dest, filter=skip_unsafe)
    finally:
        proc.stdout.close()
    if proc.wait() != 0:
        raise KitError(f"{repo.name}: git archive が失敗しました。")


def export_literal_tree(repo: Path, sha: str, dest: Path) -> dict:
    """Git属性で検査を省略・改変させず、通常ファイルのblobだけを書き出す。"""
    env = {**tool_env(), "GIT_NO_REPLACE_OBJECTS": "1"}
    tree = subprocess.run(["git", "-C", str(repo), "ls-tree", "-rz", "--full-tree", sha],
                          capture_output=True, check=True, env=env, timeout=60)
    entries, excluded = [], 0
    for item in tree.stdout.split(b"\0"):
        if not item:
            continue
        header, raw_name = item.split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split()
        relative = Path(os.fsdecode(raw_name))
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise KitError("安全に書き出せないGitのパスがあります。")
        if mode not in ("100644", "100755") or kind != "blob" or ".git" in relative.parts:
            excluded += 1
            continue
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid):
            raise KitError("GitのオブジェクトIDが正しくありません。")
        entries.append((mode, oid, relative))
    if len(entries) > 50000:
        raise KitError("ソースのファイル数が安全な書き出し上限（50,000件）を超えています。")
    dest.mkdir(mode=0o700)
    total = 0
    proc = subprocess.Popen(["git", "-C", str(repo), "cat-file", "--batch"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    try:
        for mode, oid, relative in entries:
            proc.stdin.write((oid + "\n").encode())
            proc.stdin.flush()
            returned = proc.stdout.readline().decode("ascii").strip().split()
            if len(returned) != 3 or returned[:2] != [oid, "blob"]:
                raise KitError("Gitのファイル内容を取得できませんでした。")
            size = int(returned[2])
            total += size
            if size > 16 * 1024 * 1024 or total > 256 * 1024 * 1024:
                raise KitError("ソースが安全な書き出し上限（単一16MiB・合計256MiB）を超えています。")
            path = dest / relative
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            if not path.resolve().is_relative_to(dest.resolve()):
                raise KitError("ソースの書き出し先が範囲外です。")
            with path.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o700 if mode == "100755" else 0o600)
                remaining = size
                while remaining:
                    block = proc.stdout.read(min(remaining, 65536))
                    if not block:
                        raise KitError("Gitのファイル内容が途中で終わりました。")
                    stream.write(block)
                    remaining -= len(block)
            if proc.stdout.read(1) != b"\n":
                raise KitError("Gitのファイル境界を確認できませんでした。")
    finally:
        proc.stdin.close()
        proc.stdout.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    if proc.returncode:
        raise KitError("Gitの書き出しを完了できませんでした。")
    return {"files": len(entries), "excluded": excluded}


# ---- 検査 ----

def cmd_repository_scan(args: argparse.Namespace) -> None:
    import repository_scan
    repository_scan.command(args)


def cmd_trivy(args: argparse.Namespace) -> None:
    require_dojo()
    trivy = check_trivy()
    version = tool_version("trivy", "--version")
    base_cmd = [trivy, "--scanners", TRIVY_KINDS[args.kind], "--format", "json", "--no-progress",
                "--disable-telemetry", "--skip-version-check"]
    if args.kind == "git":
        return trivy_git(args, base_cmd, version)
    t = target_from(args)
    target = args.target
    if args.kind == "fs":
        path = Path(target).expanduser().resolve()
        if not path.is_dir():
            raise KitError(f"フォルダが見つかりません: {path}")
        target, label = str(path), path.name
    else:
        label = redact_url(target)
    run_dir = new_run_dir(t.client, f"trivy-{args.kind}")
    out = run_dir / "trivy.json"
    log_scan(t, f"Trivy {args.kind}", version, target, run_dir)
    cmd = [base_cmd[0], args.kind, *base_cmd[1:], "--output", out, target]
    run(cmd, show=redact_url(shlex.join(map(str, cmd))))
    sanitize_trivy_secrets(out)
    import_result("Trivy Scan", out, t, f"Trivy {args.kind}: {label}")


def trivy_git(args: argparse.Namespace, base_cmd: list[str], version: str) -> None:
    """clone(または clone を並べたフォルダ)を、origin の最新の状態で 1 つずつ検査する。"""
    root = Path(args.target).expanduser().resolve()
    if not root.is_dir():
        raise KitError(f"フォルダが見つかりません: {root}")
    repos = git_repos(root)
    if not repos:
        raise KitError(f"Git リポジトリが見つかりません: {root}")
    base = target_from(args)
    failed, skipped = [], []
    for i, repo in enumerate(repos, 1):
        say(f"\n==== [{i}/{len(repos)}] {repo.name} ====")
        # 対象システム名は、1 つだけで --product の指定があればそれ、ほかはリポジトリ名
        t = Target(base.client, args.product if len(repos) == 1 and args.product else repo.name, base.engagement)
        try:
            branch, sha, fresh = remote_tip(repo, args.branch)
            say(f"{branch} の {sha[:12]} を検査します" + ("" if fresh else "(origin に届かないので手元の ref。古い可能性あり)"))
            run_dir = new_run_dir(t.client, f"trivy-git-{safe_name(repo.name)}")
            src = run_dir / "src"
            export_tree(repo, sha, src)
            out = run_dir / "trivy.json"
            log_scan(t, "Trivy git", version, f"{repo}@{branch} {sha}", run_dir)
            try:
                run([base_cmd[0], "fs", *base_cmd[1:], "--output", out, src])
            finally:
                shutil.rmtree(src, ignore_errors=True)  # ソースの写しは残さない(結果の JSON だけ残す)
            sanitize_trivy_secrets(out)
            note_system(t.client, t.product, visibility=repo_visibility(repo))
            import_result("Trivy Scan", out, t, f"Trivy git: {repo.name}@{branch}", commit_hash=sha, branch_tag=branch)
        except EmptyRepo as e:
            say(f"飛ばします: {e}")
            skipped.append(repo.name)
        except (KitError, dojo.DojoError) as e:
            say(f"エラー: {e}")
            failed.append(repo.name)
    say(f"\n検査 {len(repos) - len(failed) - len(skipped)} 件、飛ばした {len(skipped)} 件、失敗 {len(failed)} 件")
    if failed:
        raise KitError(f"{len(failed)}/{len(repos)} 件が失敗しました: " + "、".join(failed))


def vuls_config_with_db(cfg: Path, run_dir: Path) -> Path:
    """[vuls2] の指定がなければ、キットの DB を使う設定の写しを作る。"""
    text = cfg.read_text(encoding="utf-8")
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise KitError(f"Vuls の設定ファイルを読めません: {cfg}({e})") from None
    if "vuls2" in parsed:
        return cfg
    VULS_DB.parent.mkdir(parents=True, exist_ok=True)
    out = run_dir / "vuls-config.toml"
    out.write_text(text.rstrip("\n") + f"\n\n[vuls2]\npath = {json.dumps(str(VULS_DB))}\n", encoding="utf-8")
    return out


def cmd_vuls(args: argparse.Namespace) -> None:
    require_dojo()
    vuls = need("vuls")
    t = target_from(args)
    cfg = Path(args.config).expanduser().resolve()
    if not cfg.is_file():
        raise KitError(f"設定ファイルが見つかりません: {cfg}")
    run_dir = new_run_dir(t.client, "vuls")
    used = vuls_config_with_db(cfg, run_dir)
    results = run_dir / "results"
    results.mkdir(mode=0o700)
    log_scan(t, "Vuls", tool_version("vuls", "-v"), str(cfg), run_dir)
    # 鍵のパスなどの相対指定が効くよう、設定ファイルのフォルダで動かす
    run([vuls, "configtest", f"-config={used}"], cwd=cfg.parent)
    run([vuls, "scan", f"-config={used}", f"-results-dir={results}"], cwd=cfg.parent)
    run([vuls, "report", f"-config={used}", f"-results-dir={results}", "-format-json", "-to-localfile",
         "-no-progress"], cwd=cfg.parent)
    files = sorted(f for d in results.iterdir() if d.is_dir() and not d.is_symlink() for f in d.glob("*.json"))
    if not files:
        raise KitError("Vuls の結果(JSON)が見つかりません。")
    for f in files:
        import_result("Vuls Scan", f, t, f"Vuls: {f.stem}")


GCP_NEEDED = ("resourcemanager.projects.get", "serviceusage.services.list", "iam.serviceAccounts.list")
GCP_CHECK = """
import json, sys, warnings
warnings.filterwarnings("ignore")
import google.auth, google.auth.transport.requests, requests
creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
creds.refresh(google.auth.transport.requests.Request())
auth = {"Authorization": "Bearer " + creds.token}
email = requests.get("https://oauth2.googleapis.com/tokeninfo", params={"access_token": creds.token},
                     timeout=30).json().get("email", "")
need, missing = sys.argv[2:], {}
for project in sys.argv[1].split(","):
    r = requests.post(f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}:testIamPermissions",
                      headers=auth, json={"permissions": need}, timeout=30)
    have = set(r.json().get("permissions") or []) if r.ok else set()
    missing[project] = [p for p in need if p not in have]
print(json.dumps({"account": email, "missing": missing}))
"""


def option_values(args: list[str], *names: str) -> list[str]:
    """--project-id a b のように、オプションの後に続く値(次の -- まで)を集める。"""
    values, taking = [], False
    for arg in args:
        if arg.startswith("-"):
            taking = arg in names
        elif taking:
            values.append(arg)
    return values


def gcp_preflight(projects: list[str]) -> None:
    """GCP の読み取りの権限を先に確かめる。権限が足りないと Prowler は、何も検査できていないのに
    「指摘なし」で終わる(サービスの一覧を読めず、どのサービスも使っていないとみなす)ため、ここで止める。"""
    python = KIT / "tools" / "uv" / "prowler" / "bin" / "python"  # google-auth は Prowler の環境にある
    if not projects or not python.exists():
        return
    r = subprocess.run([str(python), "-c", GCP_CHECK, ",".join(projects), *GCP_NEEDED],
                       capture_output=True, text=True, timeout=120, env=tool_env())
    if r.returncode != 0:
        raise KitError("GCP の認証情報(ADC)を確かめられません。`gcloud auth application-default login` を"
                       "やり直してください。")
    result = json.loads(r.stdout)
    say(f"GCP: ADC のアカウント {result['account']} の権限を確かめました。")
    missing = {p: m for p, m in result["missing"].items() if m}
    if missing:
        detail = "、".join(f"{p}({', '.join(m)})" for p, m in missing.items())
        # 報告書にも載る文なので、アカウントは入れない
        raise OutOfScope(f"今の権限では検査できない。読み取りの権限が足りない: {detail}"
                         "(閲覧者とセキュリティ審査担当者の権限が要る)")


def github_get(path: str, token: str) -> tuple[int, dict]:
    """GitHub の REST API を GET する。(HTTP の状態, 本文)。読めないとき(404 など)も本文を返す。"""
    req = urllib.request.Request("https://api.github.com" + path, headers={
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "security-scan-kit"})
    req.add_unredirected_header("Authorization", f"Bearer {token}")  # 転送先(リダイレクト)には付けない
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            status, body = res.status, res.read()
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read()
    except urllib.error.URLError as e:
        raise KitError(f"GitHub に接続できません({e.reason})。") from None
    try:
        data = json.loads(body or b"{}")
    except ValueError:
        data = {}
    return status, data if isinstance(data, dict) else {}


def github_access(repos: set[str], token: str) -> dict[str, dict]:
    """リポジトリごとに、このトークンで何を読めるかを確かめる。

    branch: missing(ブランチがない) / unprotected / protected(保護の中身を読める) /
            protected-unreadable(保護されているが、中身は管理者でないと読めない)
    security: secret scanning などの設定(security_and_analysis)を読めるか
    """
    def one(full_name: str) -> tuple[str, dict]:
        status, repo = github_get(f"/repos/{full_name}", token)
        if status != 200:
            raise KitError(f"GitHub のリポジトリ {full_name} を読めません(HTTP {status})。")
        branch = f"/repos/{full_name}/branches/{urllib.parse.quote(repo.get('default_branch') or '', safe='')}"
        status, info = github_get(branch, token)
        if status == 404:
            state = "missing"
        elif status != 200:
            raise KitError(f"GitHub のリポジトリ {full_name} のブランチを読めません(HTTP {status})。")
        elif not info.get("protected"):
            state = "unprotected"
        else:
            # 管理者には、旧来の保護がなければ「Branch not protected」と返る(読めている)。管理者でなければ「Not Found」
            status, body = github_get(branch + "/protection", token)
            readable = status == 200 or body.get("message") == "Branch not protected"
            state = "protected" if readable else "protected-unreadable"
        return full_name, {"branch": state, "security": repo.get("security_and_analysis") is not None}

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        return dict(pool.map(one, sorted(repos)))


def _resource(entry: dict) -> dict:
    """Prowler の GitHub の結果の、対象(リポジトリ・組織)の情報。"""
    return (((entry.get("resources") or [{}])[0].get("data") or {}).get("metadata")) or {}


def github_unjudged(entry: dict, access: dict[str, dict]) -> str | None:
    """今のトークンでは判定できない(か、当てはまらない)GitHub の結果なら、その理由を返す。

    Prowler 5.46 は、管理者でないと読めない設定を「無効」とみなして不合格にする。
    secret scanning の設定と、保護されたブランチの保護の中身がそれにあたる。
    """
    status = entry.get("status_code")
    if status == "PASS":
        return None
    if status == "MANUAL":
        return "権限が足りず、Prowler が確かめられなかった"
    check = (entry.get("metadata") or {}).get("event_code") or ""
    repo = access.get(_resource(entry).get("full_name") or "")
    if repo is None:  # 組織の設定など。読めない設定は Prowler が自分で飛ばす
        return None
    branch_check = check.startswith("repository_default_branch_")
    if repo["branch"] == "missing" and (branch_check or check == "repository_has_codeowners_file"):
        return "空のリポジトリ(ブランチがない)"
    if check == "repository_secret_scanning_enabled" and not repo["security"]:
        return "secret scanning の設定は、管理者でないと読めない"
    if branch_check and repo["branch"] == "protected-unreadable":
        return "既定のブランチは保護されているが、保護の中身は管理者でないと読めない"
    return None


# Prowler 5.46 の GitHub のチェックのうち、設定を読めないと結果を出さずに飛ばすもの(値は CheckTitle)
SILENT_CHECKS = {
    "organization_members_mfa_required": "Organization requires members to have two-factor authentication enabled",
    "organization_default_repository_permission_strict": "Organization base repository permission is read or none",
    "organization_actions_pull_request_approval_disabled": "Organization prevents GitHub Actions from approving pull "
                                                           "requests",
    "organization_default_workflow_permissions_read_only": "Organization grants workflows a read-only default "
                                                           "GITHUB_TOKEN",
    "repository_default_workflow_permissions_read_only": "Repository grants workflows a read-only default GITHUB_TOKEN",
    "repository_immutable_releases_enabled": "Repository has immutable releases enabled",
    "repository_dependency_scanning_enabled": "Repository has package vulnerability scanning (Dependabot alerts) "
                                              "enabled",
}
SKIPPED_BY_DESIGN = {"repository_has_codeowners_file", "repository_public_has_securitymd_file"}  # 保管・非公開は対象外
ZIZMOR_CHECK = ("githubactions_workflow_security_scan",
                "GitHub Actions workflows have no security issues detected by zizmor")
# チェックや結果を絞る Prowler のオプション。絞ったときは、結果が出なかったチェックを数えない
PROWLER_FILTERS = {"--check", "--checks", "-c", "--checks-file", "-C", "--checks-folder", "-x", "--excluded-check",
                   "--excluded-checks", "-e", "--excluded-checks-file", "--service", "--services", "-s",
                   "--excluded-service", "--excluded-services", "--severity", "--severities", "--compliance",
                   "--category", "--categories", "--resource-group", "--resource-groups", "--status",
                   "--mutelist-file", "-w"}


def _entry(e: dict, reason: str, status: str | None = None) -> dict:
    """判定できなかった項目の記録(out-of-scope.json の 1 件)。"""
    res = _resource(e)
    return {"check": (e.get("metadata") or {}).get("event_code") or "",
            "title": (e.get("finding_info") or {}).get("title") or "",
            "resource": res.get("full_name") or ((e.get("resources") or [{}])[0].get("name")) or "",
            "status": status or e.get("status_code"), "message": e.get("message") or "", "reason": reason}


def github_missing(entries: list[dict], repos: set[str], prowler_args: list[str]) -> list[dict]:
    """結果が 1 件も出なかった(チェック, 組織かリポジトリ)。Prowler は、読めない設定を黙って飛ばすので数える。"""
    flags = {a.split("=", 1)[0] for a in prowler_args}
    if flags & PROWLER_FILTERS:
        return []
    seen, titles, orgs = set(), dict(SILENT_CHECKS), set()
    for e in entries:
        record = _entry(e, "")
        seen.add((record["check"], record["resource"]))
        titles.setdefault(record["check"], record["title"] or record["check"])
        if record["check"].startswith("organization_"):
            orgs.add(record["resource"])
    ran = {check for check, _ in seen}

    def not_run(check: str, title: str, names: set[str], reason: str) -> list[dict]:
        return [{"check": check, "title": title, "resource": name, "status": "NOT_RUN", "message": "",
                 "reason": reason} for name in sorted(names) if (check, name) not in seen]

    missing = []
    for check in sorted((ran | set(SILENT_CHECKS)) - SKIPPED_BY_DESIGN):
        names = orgs if check.startswith("organization_") else repos if check.startswith("repository_") else set()
        missing += not_run(check, titles[check], names, "今の権限では設定を読めず、Prowler が結果を出さなかった")
    if ZIZMOR_CHECK[0] not in ran:
        why = ("--no-github-actions で止めた" if "--no-github-actions" in flags
               else "zizmor が入っていない" if not which("zizmor") else "zizmor の結果が出なかった")
        missing += not_run(*ZIZMOR_CHECK, repos, f"GitHub Actions のワークフローの検査をしていない({why})")
    return missing


def exclude_unjudged(path: Path, token: str, prowler_args: list[str]) -> int:
    """判定できない GitHub の結果を、DefectDojo に取り込む前に外す。結果が出なかったチェックも数える。

    どちらも同じフォルダの out-of-scope.json に残し、報告書の「判定できなかった項目」に載せる。
    """
    entries = json.loads(path.read_text(encoding="utf-8"))
    repos = {n for e in entries if (n := _resource(e).get("full_name"))}
    access = github_access(repos, token)
    kept, excluded = [], []
    for e in entries:
        if reason := github_unjudged(e, access):
            excluded.append(_entry(e, reason))
        else:
            kept.append(e)
    if excluded:
        path.write_text(json.dumps(kept, ensure_ascii=False), encoding="utf-8")
    excluded += github_missing(entries, repos, prowler_args)
    save_json(path.with_name("out-of-scope.json"), excluded)
    return len(excluded)


def cmd_prowler(args: argparse.Namespace) -> None:
    require_dojo()
    prowler = need("prowler")
    t = target_from(args)
    if args.provider == "gcp":
        try:
            gcp_preflight(option_values(args.passthrough, "--project-id", "--project-ids"))
        except OutOfScope as e:
            note_skipped(t, str(e))
            raise
    env = tool_env()
    if args.provider == "github" and "GITHUB_PERSONAL_ACCESS_TOKEN" not in env:
        token = github_token()  # 引数には載せず、環境変数で Prowler だけに渡す
        if not token:
            raise KitError("GitHub のトークンがありません。`gh auth login` でログインしてください。")
        env["GITHUB_PERSONAL_ACCESS_TOKEN"] = token
    run_dir = new_run_dir(t.client, f"prowler-{args.provider}")
    log_scan(t, f"Prowler {args.provider}", tool_version("prowler", "--version"),
             shlex.join(redact_args(args.passthrough)), run_dir)
    tail = ["--output-formats", "json-ocsf", "--output-directory", str(run_dir), "--output-filename", "prowler",
            "--no-banner", "--no-color"]
    run([prowler, args.provider, *args.passthrough, *tail], ok=(0, 3), env=env,  # 3 は「不合格のチェックがあった」
        show=shlex.join([prowler, args.provider, *redact_args(args.passthrough), *tail]))
    raw, out_of_scope = run_dir / "prowler.ocsf.json", None
    if args.provider == "github" and raw.is_file():
        count = exclude_unjudged(raw, env["GITHUB_PERSONAL_ACCESS_TOKEN"], args.passthrough)
        out_of_scope = raw.with_name("out-of-scope.json")
        say(f"判定できなかった項目が {count} 件あります(今の権限では読めない設定など。指摘には数えず、"
            "報告書の「判定できなかった項目」に載る)。")
    import_result("Prowler Scan", raw, t, f"Prowler {args.provider}: {args.label or args.provider}",
                  out_of_scope=out_of_scope)


# ---- 報告書 ----

def client_products(d: dojo.Dojo, client: str) -> list[dict]:
    types = [pt for pt in d.iterate("/api/v2/product_types/", {"name": client}) if pt["name"] == client]
    if not types:
        raise KitError(f"DefectDojo に顧客「{client}」がありません。")
    return list(d.iterate("/api/v2/products/", {"prod_type": types[0]["id"]}))


def client_tests(d: dojo.Dojo, client: str):
    """顧客の(製品, 案件, 検査)を順に返す。"""
    for prod in client_products(d, client):
        for eng in d.iterate("/api/v2/engagements/", {"product": prod["id"]}):
            for test in d.iterate("/api/v2/tests/", {"engagement": eng["id"]}):
                yield prod, eng, test


def collect_findings(d: dojo.Dojo, client: str, product: str | None, engagement: str | None,
                     tier: int | None = None, triage_key: str | None = None
                     ) -> tuple[list[report.Finding], list[tuple[str, dict]]]:
    """報告書に載せる有効な指摘と、対象にした検査((対象システム, DefectDojo の検査))。"""
    import ai_review  # ai_review は kit を読み込むので、使うときに読む
    reasons = load_json(client_dir(client) / "classification.json", {})
    ai = load_json(client_dir(client) / "ai-review.json", {})
    triaged = load_json(client_dir(client) / "triage.json", {}).get("findings", {})
    tags = [t for t in (classify.TIER_TAGS[tier] if tier else "", triage.TAGS[triage_key] if triage_key else "") if t]
    urgent = triage.more_urgent(triage_key) if triage_key else []
    params = {"active": "true", "duplicate": "false",
              **({"tags__and": ",".join(tags)} if len(tags) > 1 else {"tags": tags[0]} if tags else {}),
              **({"not_tags": ",".join(urgent)} if urgent else {})}
    found, tests = [], []
    for prod in client_products(d, client):
        if product and prod["name"] != product:
            continue
        for eng in d.iterate("/api/v2/engagements/", {"product": prod["id"]}):
            if engagement and eng["name"] != engagement:
                continue
            for test in d.iterate("/api/v2/tests/", {"engagement": eng["id"]}):
                tests.append((prod["name"], test))
                also = duplicate_paths(d, test["id"])
                for f in d.iterate("/api/v2/findings/", {"test": test["id"], **params}):
                    reason = (reasons.get(str(f["id"])) or [None, ""])[1]
                    # 仕分けの理由は、記録が今のタグの区分と合うときだけ載せる(人がタグを変えたあとの古い理由は載せない)
                    triaged_now = triage.current_record(f.get("tags") or [], triaged.get(str(f["id"]))) or {}
                    found.append(report.finding_from_api(
                        prod["name"], eng["name"], test, f, reason, ai_text(ai.get(str(f["id"]))),
                        triaged_now.get("reason", ""), ai_impact=ai_review.TAGS["影響あり"] in (f.get("tags") or []),
                        also=also.get(f["id"], [])))
    return found, tests


def duplicate_paths(d: dojo.Dojo, test_id: int) -> dict[int, list[str]]:
    """残した指摘 → 重複にまとめた指摘の場所(同じフォルダのほかのロックファイル。閉じたものは除く)。
    報告書の場所に並べて、直す人がどのファイルも直せるようにする。"""
    paths: dict[int, list[str]] = {}
    for dup in d.iterate("/api/v2/findings/", {"test": test_id, "duplicate": "true"}):
        if dup.get("duplicate_finding") and dup.get("file_path") and dedupe.still_open(dup):
            paths.setdefault(dup["duplicate_finding"], []).append(dup["file_path"])
    return paths


def ai_text(judged: dict | None) -> str:
    """報告書の「AI の確認」の欄。AI の判定と、抜き取りで確かめた補足(ai-review.json の review。あれば)。"""
    if not judged:
        return ""
    text = f"{judged['verdict']}: {judged['reason']}"
    if review := judged.get("review"):
        text += f"\n\n抜き取りの確認({review.get('by') or '?'}、{(review.get('at') or '')[:10]}): {review['text']}"
    return text


def scope_summary(client: str, products: set[str], test_ids: set[int] | None = None,
                  with_skipped: bool = True) -> tuple[list[tuple[str, str]], list[dict]]:
    """検査の範囲外のもの: (検査しなかった対象と理由, 判定できなかった項目)。

    検査しなかった対象は、対象システムを決めてあるプリセットのうち、products に結果がないもの。
    判定できなかった項目は、取り込みの前に外した結果と、結果が出なかったチェック(out-of-scope.json)。
    """
    import targets  # targets は kit を読み込むので、使うときに読む
    skipped = []
    if with_skipped:
        log = load_json(client_dir(client) / "skipped.json", {})
        for p in targets.load_presets():
            if p.get("client") == client and p.get("product") and p["product"] not in products:
                reason = (log.get(p["product"]) or {}).get("reason") or targets.blocker(p) or "まだ検査していない"
                skipped.append((p.get("name") or p["product"], reason))
    unjudged = []
    for test_id, entry in load_json(client_dir(client) / "tests.json", {}).items():
        if entry.get("out_of_scope") and entry.get("product") in products \
                and (test_ids is None or int(test_id) in test_ids):
            unjudged += load_json(Path(entry["out_of_scope"]), [])
    return skipped, unjudged


def local_time(iso: str | None) -> str:
    """DefectDojo の日時(UTC)を、この Mac の時刻で表す。"""
    if not iso:
        return ""
    return dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M")


def used_tool_versions(client: str, product: str | None, engagement: str | None) -> dict[str, str]:
    """検査の記録から、使ったツールと版を集める(報告書の「使用したツール」)。"""
    versions: dict[str, set[str]] = {}
    log = DATA / safe_name(client) / "scan-log.jsonl"
    for line in log.read_text(encoding="utf-8").splitlines() if log.exists() else []:
        entry = json.loads(line)
        if (product and entry["product"] != product) or (engagement and entry["engagement"] != engagement):
            continue
        versions.setdefault(entry["tool"].split()[0], set()).add(entry.get("version") or "?")
    return {"DefectDojo": DD_VERSION, **{name: "・".join(sorted(v)) for name, v in sorted(versions.items())}}


def count_closed(d: dojo.Dojo, client: str, tests: list[tuple[str, dict]], tier: int | None,
                 triage_key: str | None = None, **params: str) -> int:
    """報告書の範囲(対象にした検査・大項目・小項目)のうち、params に当てはまる指摘の数。
    手元の記録ではなく DefectDojo の今の状態で数える(人が状態を戻したものは数えない)。"""
    products = client_products(d, client)
    test_ids = {t["id"] for _, t in tests}
    if not products or not test_ids:
        return 0
    query = {"test__engagement__product__prod_type": products[0]["prod_type"], "duplicate": "false", **params}
    return sum(1 for f in d.iterate("/api/v2/findings/", query)
               if f["test"] in test_ids and (not tier or classify.tier_of(f.get("tags") or []) == tier)
               and (not triage_key or triage.category_of(f.get("tags") or []) == triage_key))


def count_ai_dismissed(d: dojo.Dojo, client: str, tests: list[tuple[str, dict]], tier: int | None = None,
                       triage_key: str | None = None) -> int:
    """AI の確認で「影響なし」として誤検知にした指摘の数(報告書の範囲)。"""
    import ai_review  # ai_review は kit を読み込むので、使うときに読む
    return count_closed(d, client, tests, tier, triage_key, tags=ai_review.TAGS["影響なし"], false_p="true")


REPORT_DONE = "報告書を作りました"  # 画面(web.job_report)は、ジョブのログのこの行から作った報告書を探す


def new_report_path(out_dir: Path, now: dt.datetime, suffix: str) -> Path:
    """報告書の HTML のパスを決め、空のファイルを作って押さえる。同じ秒に同じ範囲の報告書が重なったら、
    名前の時刻を 1 秒ずらす(ほかのジョブの報告書を上書きしたり、取り違えたりしない)。"""
    while True:
        path = out_dir / f"report-{now:%Y%m%d-%H%M%S}{suffix}.html"
        try:
            path.touch(exist_ok=False)
            return path
        except FileExistsError:
            now += dt.timedelta(seconds=1)


def cmd_report(args: argparse.Namespace) -> None:
    d = connect()
    findings, tests = collect_findings(d, args.client, args.product, args.engagement, args.tier, args.triage)
    products = {p for p, _ in tests}
    skipped, unjudged = scope_summary(args.client, products, {t["id"] for _, t in tests}, with_skipped=not args.product)
    scope = report.Scope(scanned=[(p, t.get("title") or "", local_time(t.get("updated"))) for p, t in tests],
                         skipped=skipped, unjudged=unjudged,
                         ai_dismissed=count_ai_dismissed(d, args.client, tests, args.tier, args.triage),
                         risk_accepted=count_closed(d, args.client, tests, args.tier, args.triage, risk_accepted="true"),
                         intel=load_json(client_dir(args.client) / "triage.json", {}).get("intel"))
    out_dir = client_dir(args.client) / "reports"
    out_dir.mkdir(mode=0o700, exist_ok=True)
    suffix = (f"-tier{args.tier}" if args.tier else "") + (f"-{args.triage}" if args.triage else "")
    tools = used_tool_versions(args.client, args.product, args.engagement)
    now = dt.datetime.now()
    page = report.render_html(args.client, findings, tools, now, args.tier, scope, args.triage)
    html_path = new_report_path(out_dir, now, suffix)  # 作り終えてから名前を押さえる(失敗しても空の報告書を残さない)
    html_path.write_text(page, encoding="utf-8")
    csv_path = html_path.with_suffix(".csv")  # 同じ範囲の CSV(Excel で開けるよう BOM 付き)
    csv_path.write_text(report.render_csv(findings, DD_URL), encoding="utf-8-sig")
    pdf_path = html_path.with_suffix(".pdf")
    made_pdf = report.html_to_pdf(html_path, pdf_path, CHROME)
    say(f"{REPORT_DONE}({len(findings)} 件): {html_path}")
    say(f"CSV: {csv_path}")
    say(f"PDF: {pdf_path}" if made_pdf else "PDF は作れませんでした(Chrome が必要)。HTML をブラウザで印刷してください。")
    if args.open:
        subprocess.run(["/usr/bin/open", str(pdf_path if made_pdf else html_path)], check=False)


# ---- 一括検査と分類 ----

def cmd_scan_all(args: argparse.Namespace) -> None:
    """顧客のプリセット(data/targets.toml)を、順にすべて検査する。準備が足りないものと、
    今の権限では検査できないもの(範囲外)は飛ばす。"""
    import targets  # targets は kit を読み込むので、使うときに読む
    presets = [p for p in targets.load_presets() if p.get("client") == args.client]
    if not presets:
        raise KitError(f"顧客「{args.client}」のプリセットがありません(data/targets.toml)。")
    done, skipped, failed = [], [], []
    for i, preset in enumerate(presets, 1):
        name = preset.get("name") or f"プリセット {i}"
        say(f"\n######## [{i}/{len(presets)}] {name} ########")
        if reason := targets.blocker(preset):
            say(f"飛ばします: {reason}")
            skipped.append(name)
            continue
        try:
            argv = targets.build_job(targets.preset_payload(preset))[2]
        except targets.BadRequest as e:
            say(f"エラー: {e}")
            failed.append(name)
            continue
        rc = main(argv)
        (done if rc == 0 else skipped if rc == jobs.EXIT_OUT_OF_SCOPE else failed).append(name)
    say(f"\n一括検査({args.client}): 完了 {len(done)} 件、飛ばした {len(skipped)} 件、失敗 {len(failed)} 件")
    for name in skipped:
        say(f"  飛ばした: {name}")
    if failed:
        raise KitError("失敗: " + "、".join(failed))


def cmd_classify(args: argparse.Namespace) -> None:
    """顧客のすべての検査を、今の公開範囲の設定で分類し直し、仕分けし直す(設定を変えたあとに使う)。"""
    d = connect()
    info = load_intel()
    tiers: Counter = Counter()
    triaged: Counter = Counter()
    merged_total = restored_total = 0  # 重複にまとめた数、有効に戻した数
    failed = []
    for prod in client_products(d, args.client):
        note_system(args.client, prod["name"])
        for eng in d.iterate("/api/v2/engagements/", {"product": prod["id"]}):
            for test in d.iterate("/api/v2/tests/", {"engagement": eng["id"]}):
                scan_type, label = test.get("scan_type") or "", f"{prod['name']} / {test.get('title')}"
                try:
                    merged, restored, problem = dedupe_test(d, args.client, prod["name"], test["id"], scan_type)
                except dojo.DojoError as e:  # まとめられなくても、分類と仕分けは続ける(二重の数えが残るだけ)
                    merged, restored, problem = 0, 0, str(e)
                if problem:
                    say(f"  重複のまとめに失敗しました: {problem}")
                    failed.append(label)
                merged_total += merged
                restored_total += restored
                counts = classify_test(d, args.client, prod["name"], test["id"], scan_type)
                tiers.update(counts)
                try:
                    sorted_out = triage_test(d, args.client, test["id"], scan_type, info)
                except KitError as e:  # 仕分けに失敗しても、残りの検査の分類し直しは続ける
                    say(f"  仕分けに失敗しました: {e}")
                    if label not in failed:
                        failed.append(label)
                    sorted_out = Counter()
                triaged.update(sorted_out)
                note = dedupe_summary(merged, restored)
                say(f"{label}: {tier_summary(counts)}。仕分け: {triage_summary(sorted_out)}"
                    + (f"。重複: {note}" if note else ""))
    note = dedupe_summary(merged_total, restored_total)
    say(f"\n合計: {tier_summary(tiers)}。仕分け: {triage_summary(triaged)}" + (f"。重複: {note}" if note else ""))
    if failed:
        raise KitError("重複のまとめか仕分けに失敗した検査があります(`bin/kit classify` でやり直せる): " + "、".join(failed))


def cmd_triage(args: argparse.Namespace) -> None:
    """顧客の指摘を仕分けし直す(EPSS・KEV を最新にするときは --refresh)。"""
    say(f"\n合計: {triage_summary(triage_client(connect(), args.client, refresh=args.refresh))}")


def cmd_accept_risk(args: argparse.Namespace) -> None:
    import accept  # accept は kit を読み込むので、使うときに読む
    accept.run(connect(), args.client, args.by, days=args.days, reactivate=not args.no_reactivate,
               product=args.product, dry_run=args.dry_run, expect=args.expect, tier=args.tier)


def cmd_ai_review(args: argparse.Namespace) -> None:
    import ai_review  # ai_review は kit を読み込むので、使うときに読む
    ai_review.run(connect(), args.client, args.scope, args.limit)


# ---- 起動・停止・確認 ----

def cmd_up(args: argparse.Namespace) -> None:
    ensure_docker()
    DATA.mkdir(mode=0o700, exist_ok=True)
    ensure_secrets()
    start_web()
    if not (STACK <= running_services() and dd_alive()):
        say("DefectDojo を起動します。初回はデータベースの準備に数分かかります。")
        try:
            compose("up", "-d")
        except KitError:
            # 設定の変更でコンテナを作り直した回に、初期化の完了後に失敗したことがある(2 回目は成功)
            say("起動に失敗したので、もう一度試します…")
            time.sleep(5)
            compose("up", "-d")
        wait_for_dojo(timeout=900)
    say(f"画面: {KIT_URL}(DefectDojo の左のメニューの「スキャンと報告書」)")
    say(f"ユーザー名: {DD_ADMIN}(パスワードは `bin/kit password` でコピー)")
    if args.open:
        subprocess.run(["/usr/bin/open", KIT_URL], check=False)


def cmd_down(args: argparse.Namespace) -> None:
    running = [j["title"] for j in jobs.list_jobs(JOBS_DIR) if j["status"] in ("queued", "running")]
    stop_web()
    if docker_ready():
        compose("stop")
    say("DefectDojo と画面を止めました(データは残っています)。")
    if running:
        say("実行中の検査は、結果の取り込みで失敗します: " + "、".join(running))


def cmd_logs(args: argparse.Namespace) -> None:
    compose("logs", "--tail", "100", "initializer", "uwsgi", "nginx", "gateway")


def cmd_password(args: argparse.Namespace) -> None:
    password = keychain_get("DD_ADMIN_PASSWORD")
    if not password:
        raise KitError("まだパスワードがありません。先に DefectDojo を起動してください。")
    subprocess.run(["/usr/bin/pbcopy"], input=password, text=True, check=True)
    # 45 秒後、まだこのパスワードが残っていればクリップボードを空にする(比べるのはハッシュだけ)
    digest = hashlib.sha256(password.encode()).hexdigest()
    clear = (f'sleep 45; [ "$(/usr/bin/pbpaste | /usr/bin/shasum -a 256 | /usr/bin/cut -d" " -f1)" = "{digest}" ]'
             ' && printf "" | /usr/bin/pbcopy')
    subprocess.Popen(["/bin/sh", "-c", clear], start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    say(f"管理者({DD_ADMIN})のパスワードをクリップボードにコピーしました。45 秒後に消します。")


def cmd_doctor(args: argparse.Namespace) -> None:
    trivy_ver = tool_version("trivy", "--version")
    trivy_text = "未導入" if not trivy_ver else trivy_ver + (" ← 侵害版。入れ直すこと" if trivy_ver in COMPROMISED_TRIVY else "")
    web = web_version()
    rows = [
        ("Docker", "起動中" if docker_ready() else "停止中"),
        ("DefectDojo", f"応答あり {DD_URL}" if dd_alive() else "停止中"),
        ("画面のサーバー", ("動いている" if web == code_version() else "古い版が動いている(`bin/kit up` で入れ替え)")
         if web else "停止中"),
        ("DefectDojo の版", f"{DD_VERSION}(イメージは digest で固定)"),
        ("Trivy", trivy_text),
        ("Vuls", tool_version("vuls", "-v") or "未導入"),
        ("Prowler", tool_version("prowler", "--version") or "未導入"),
        ("GitHub(gh)", "使える" if github_token() else "ログインしていない"),
        ("GCP(ADC)", "あり(プロジェクトの権限は検査の前に確かめる)" if gcp_ready()
         else "未設定(gcloud auth application-default login)"),
        ("AWS のプロファイル", "、".join(sorted(aws_profiles())) or "なし"),
        ("キーチェーンの秘密情報", "揃っている" if all(keychain_get(n) for n in SECRETS) else "未作成(初回の起動で作る)"),
        ("data フォルダの権限", oct(DATA.stat().st_mode & 0o777) if DATA.exists() else "未作成"),
        ("PDF の出力(Chrome)", "使える" if CHROME.exists() else "使えない(HTML だけ)"),
    ]
    for name, value in rows:
        say(f"  {name}: {value}")


def cmd_install(args: argparse.Namespace) -> None:
    env = tool_env()
    if not which("trivy"):
        # Homebrew core の formula はソースからビルドされる(2026-03 の侵害の影響を受けていない経路)
        run(["brew", "install", "trivy"], env={**env, "HOMEBREW_NO_AUTO_UPDATE": "1"})
    check_trivy()
    if tool_version("vuls", "-v") != VULS_VERSION.lstrip("v"):
        ldflags = (f"-X 'github.com/future-architect/vuls/config.Version={VULS_VERSION}' "
                   "-X 'github.com/future-architect/vuls/config.Revision=source-build'")
        run(["go", "install", "-trimpath", "-ldflags", ldflags, f"github.com/future-architect/vuls/cmd/vuls@{VULS_VERSION}"],
            env={**env, "GOBIN": str(TOOLS_BIN), "CGO_ENABLED": "0", "GOEXPERIMENT": "jsonv2"}, cwd=KIT)
    if tool_version("prowler", "--version") != PROWLER_VERSION:
        run(["uv", "tool", "install", "--force", "--python", "3.12", f"prowler=={PROWLER_VERSION}"],
            env={**env, "UV_TOOL_DIR": str(KIT / "tools" / "uv"), "UV_TOOL_BIN_DIR": str(TOOLS_BIN)})
    DATA.mkdir(mode=0o700, exist_ok=True)
    ensure_docker()
    import sast
    try:
        scanner_config, _ = sast.configuration()
    except (OSError, ValueError, KeyError) as error:
        raise KitError("SASTの固定設定・ルールを確認できません。") from error
    run(["docker", "pull", scanner_config["image"]])
    compose("pull")
    say("導入が終わりました。")


def cmd_serve(args: argparse.Namespace) -> None:
    import web  # 画面のサーバーを動かすときだけ読む
    web.serve()


def cmd_job_run(args: argparse.Namespace) -> None:
    jobs.run(JOBS_DIR, args.job_id, [sys.executable, str(Path(__file__).resolve())])


# ---- 引数 ----

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kit", description="Trivy・Vuls・Prowler で検査し、DefectDojo に集めて報告書を作る")
    parser.set_defaults(func=lambda a: parser.print_help())
    sub = parser.add_subparsers(title="コマンド")

    def add(name, func, text):
        sp = sub.add_parser(name, help=text, description=text)
        sp.set_defaults(func=func)
        return sp

    def add_target(sp):
        sp.add_argument("--client", required=True, help="顧客名(DefectDojo の組織)")
        sp.add_argument("--product", help="対象システム名(省略時は顧客名。git でフォルダを渡したときはリポジトリ名)")
        sp.add_argument("--engagement", help="案件名(省略時は「診断 YYYY-MM」)")

    add("up", cmd_up, "DefectDojo と画面を起動する").add_argument("--open", action="store_true", help="ブラウザで画面を開く")
    # 以前のターミナルのメニューの起動ファイル(デスクトップの .command)が呼ぶので、画面を開く別名として残す
    add("menu", lambda a: cmd_up(argparse.Namespace(open=True)), "画面を開く(`up --open` と同じ)")
    add("down", cmd_down, "DefectDojo と画面を止める(データは残る)")
    add("logs", cmd_logs, "DefectDojo のログを見る")
    add("password", cmd_password, "管理者のパスワードをクリップボードにコピーする")
    add("doctor", cmd_doctor, "ツールの版と、DefectDojo・認証情報の状態を確かめる")
    add("install", cmd_install, "ツールを導入し、DefectDojo のイメージを取る")
    add("serve", cmd_serve, "画面のサーバーを動かす(`bin/kit up` が裏で使う)")
    add("job-run", cmd_job_run, "画面から始めた検査を動かす(画面のサーバーが使う)").add_argument("job_id")

    rs = add("repository-scan", cmd_repository_scan, "同じ版のリポジトリをまとめて検査し、結果とSBOMを保存する")
    rs.add_argument("target", help="Gitのclone・cloneを並べたフォルダ・GitHubのHTTPSリポジトリURL")
    rs.add_argument("--branch", help="検査するブランチ（省略時はoriginの既定のブランチ）")
    rs.add_argument("--no-import", action="store_true", help="DefectDojoには登録せず、結果とSBOMをローカルに保存する")
    add_target(rs)

    tv = add("trivy", cmd_trivy, "Trivy で検査して取り込む")
    tv.add_argument("kind", choices=sorted(TRIVY_KINDS),
                    help="fs=フォルダ、git=clone(を並べたフォルダ)を origin の最新で、"
                         "image=コンテナイメージ、repo=リポジトリの URL")
    tv.add_argument("target", help="フォルダのパス、イメージ名、またはリポジトリの URL")
    tv.add_argument("--branch", help="git のとき、検査するブランチ(省略時は origin の既定のブランチ)")
    add_target(tv)

    vs = add("vuls", cmd_vuls, "Vuls でサーバーを検査して取り込む")
    vs.add_argument("--config", required=True, help="Vuls の設定ファイル(見本は vuls/config.example.toml)")
    add_target(vs)

    pr = add("prowler", cmd_prowler, "Prowler でクラウドなどを検査して取り込む(Prowler の引数は -- の後に書く)")
    pr.add_argument("provider", choices=PROWLER_PROVIDERS)
    pr.add_argument("--label", help="検査の名前(報告書に出る。省略時は provider)")
    add_target(pr)

    rp = add("report", cmd_report, "顧客ごとの報告書(HTML と PDF)を作る")
    rp.add_argument("--client", required=True, help="顧客名")
    rp.add_argument("--product", help="対象システム名で絞る")
    rp.add_argument("--engagement", help="案件名で絞る")
    rp.add_argument("--tier", type=int, choices=(1, 2, 3), help=TIER_HELP)
    rp.add_argument("--triage", choices=list(triage.CATEGORIES),
                    help=TRIAGE_HELP)
    rp.add_argument("--open", action="store_true", help="作った報告書を開く")

    add("scan-all", cmd_scan_all, "顧客のプリセットをすべて検査する(一括検査)").add_argument(
        "--client", required=True, help="顧客名(data/targets.toml の client)")
    add("classify", cmd_classify, "顧客の指摘を、今の公開範囲の設定で分類し直す").add_argument(
        "--client", required=True, help="顧客名")
    tr = add("triage", cmd_triage, "顧客の指摘を、直すか受け入れるかで仕分けし直す")
    tr.add_argument("--client", required=True, help="顧客名")
    tr.add_argument("--refresh", action="store_true", help="EPSS・CISA KEV の一覧を取り直す(ふだんは 24 時間使い回す)")
    ac = add("accept-risk", cmd_accept_risk, "仕分けが「リスク受容」の指摘を、DefectDojo のリスク受容としてまとめて登録する")
    ac.add_argument("--client", required=True, help="顧客名")
    ac.add_argument("--by", required=True, help="受け入れた人(DefectDojo の accepted_by)")
    ac.add_argument("--product", help="対象システム名で絞る")
    ac.add_argument("--tier", type=int, choices=(1, 2, 3), help=TIER_HELP)
    ac.add_argument("--days", type=int, choices=RISK_DAYS, default=180, help="期限(日)")
    ac.add_argument("--no-reactivate", action="store_true", help="期限が来ても指摘を有効に戻さない")
    ac.add_argument("--dry-run", action="store_true", help="件数を見るだけで登録しない")
    ac.add_argument("--expect", type=int, help="確かめた件数(今の「リスク受容」の指摘の件数と違えば登録しない)")
    ai = add("ai-review", cmd_ai_review, "依存の脆弱性が本番で再現するかを、AI(Claude Code)に確かめさせる")
    ai.add_argument("--client", required=True, help="顧客名")
    ai.add_argument("--scope", choices=("critical", "high", "all"), default="critical",
                    help="critical=① の緊急、high=① の緊急・高、all=依存の脆弱性すべて")
    ai.add_argument("--limit", type=int, help="確かめる単位(対象システム × 部品)の数の上限(試すとき)")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    passthrough: list[str] = []
    if "--" in argv:
        i = argv.index("--")
        argv, passthrough = argv[:i], argv[i + 1:]
    args = build_parser().parse_args(argv)
    args.passthrough = passthrough
    try:
        args.func(args)
    except OutOfScope as e:
        say(f"範囲外: {e}")
        return jobs.EXIT_OUT_OF_SCOPE
    except (KitError, dojo.DojoError) as e:
        say(f"エラー: {e}")
        return 1
    except KeyboardInterrupt:
        say("\n中止しました。")
        return 130
    return 0


if __name__ == "__main__":
    # 「kit」という名前で読み直して動かす。web・targets が読む kit と同じモジュールにして、
    # KitError などが二重に定義されるのを避ける
    import kit as _kit
    sys.exit(_kit.main())
