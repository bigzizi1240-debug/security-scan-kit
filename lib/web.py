"""キットの画面(http://127.0.0.1:18080/kit/)のサーバー。

入口の nginx(gateway)が DefectDojo の管理者のログインを確かめてから、合言葉のヘッダー
(X-Kit-Gateway)を付けて、ここ(ホストの 127.0.0.1:18081)へ渡す。
合言葉のない要求と、この画面以外からの書き込みの要求は断る。入力の確かめは targets.py。
"""
from __future__ import annotations

import concurrent.futures
import datetime as dt
import hmac
import json
import re
import subprocess
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import accept
import classify
import dojo
import jobs
import kit
import report
import repository_scan
import targets
import triage
from targets import BadRequest

WEB_DIR = kit.KIT / "web"
STATIC = {"app.js": "text/javascript; charset=utf-8", "app.css": "text/css; charset=utf-8",
          "sidebar.js": "text/javascript; charset=utf-8"}  # sidebar.js は DefectDojo の左のメニューが読む
CLIENT_PARAM = "test__engagement__product__prod_type"  # DefectDojo の検出事項の一覧の、顧客(Product Type)の絞り込み
ORIGINS = {f"http://127.0.0.1:{kit.DD_PORT}", f"http://localhost:{kit.DD_PORT}"}
MAX_BODY = 256 * 1024
FILE_TYPES = {".html": "text/html; charset=utf-8", ".pdf": "application/pdf", ".json": "application/json",
              ".csv": "text/csv; charset=utf-8"}
INDEX_CSP = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
FILE_CSP = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:"  # 報告書を DefectDojo から切り離す
TOP_SYSTEMS = 10  # ダッシュボードの「システムごと」に出す数(残りは「その他」)
PATH_RULE = re.compile(r"^([^=#\s][^=#]*?)\s*=\s*([a-z-]+)\s*(?:#\s*(.*))?$")
PROWLER_HINTS = {
    "aws": "--profile <プロファイル名>",
    "azure": "--az-cli-auth(先に az login)",
    "gcp": "--project-id <プロジェクト ID>(先に gcloud auth application-default login)",
    "kubernetes": "--kubeconfig-file <パス> --context <コンテキスト名>",
    "github": "--organization <組織名>(トークンは gh のログインから自動で渡す)",
    "m365": "--az-cli-auth(先に az login)",
    "iac": "--scan-path <フォルダ>",
}


# ---- 要求の確認 ----

def gateway_ok(headers, token: str) -> bool:
    return hmac.compare_digest(headers.get("X-Kit-Gateway", ""), token)


def write_ok(headers) -> bool:
    """書き込みの要求は、この画面から fetch で送られたものだけを受ける(CSRF 対策)。"""
    return headers.get("Origin") in ORIGINS and headers.get("X-Kit-Request") == "1"


# ---- 画面に出す情報 ----

def overview() -> dict:
    presets = []
    for i, preset in enumerate(targets.load_presets()):
        presets.append({"index": i, "name": preset.get("name", f"プリセット {i + 1}"), "client": preset.get("client", ""),
                        "tool": preset.get("tool", ""), "note": preset.get("note", ""),
                        "blocker": targets.blocker(preset)})
    try:
        grouped = client_products(kit.connect())
    except (kit.KitError, dojo.DojoError):
        grouped = {}
    return {"presets": presets, "clients": sorted(grouped),
            "products": {client: sorted(p["name"] for p in items) for client, items in grouped.items()},
            "preset_clients": targets.preset_clients(), "default_engagement": kit.default_engagement(),
            "prowler_hints": PROWLER_HINTS, "exposures": classify.EXPOSURES}


def client_products(d: dojo.Dojo) -> dict[str, list[dict]]:
    """顧客(DefectDojo の Product Type)ごとの製品。結果のある顧客だけ
    (DefectDojo が最初から作る空の「Research and Development」などは出さない)。"""
    names = {pt["id"]: pt["name"] for pt in d.iterate("/api/v2/product_types/")}
    grouped: dict[str, list[dict]] = {}
    for prod in d.iterate("/api/v2/products/"):
        if prod["prod_type"] in names:
            grouped.setdefault(names[prod["prod_type"]], []).append(prod)
    return grouped


def client_list(d: dojo.Dojo) -> list[dict]:
    """顧客の名前と番号(左のメニューの、顧客を選ぶ欄に出す)。"""
    return [{"id": items[0]["prod_type"], "name": name} for name, items in sorted(client_products(d).items())]


def findings_url(client: int | str | None, *tags: str, not_tags: list[str] | None = None) -> str:
    """DefectDojo の有効な検出事項の一覧の URL。タグが 1 つなら tags、複数なら tags_and(すべてを持つもの)で絞る。
    not_tags のタグを持つものは除く(一覧の画面は not_tags を 1 つの値として読むので、カンマでつなぐ)。"""
    query = [("tags", tags[0])] if len(tags) == 1 else [("tags_and", tag) for tag in tags]
    query += [("not_tags", ",".join(not_tags))] if not_tags else []
    return "/finding/open?" + urllib.parse.urlencode(query + ([(CLIENT_PARAM, client)] if client else []))


def dashboard(tier: str, client: str) -> dict:
    """大項目のページの数(重大度ごと・システムごと・小項目ごと、分類を要確認)。

    client は顧客(Product Type)の番号(空ならすべての顧客)。DefectDojo の件数の API(limit=1 の count)を並列に引く。
    """
    if tier not in ("1", "2", "3"):
        raise BadRequest("大項目の指定が正しくありません。")
    d = kit.connect()
    grouped = client_products(d)
    names = {str(items[0]["prod_type"]): name for name, items in grouped.items()}
    if client and client not in names:
        raise BadRequest("顧客の指定が正しくありません。")
    number, tag = int(tier), classify.TIER_TAGS[int(tier)]
    products = [p for items in grouped.values() for p in items if not client or str(p["prod_type"]) == client]
    scope = {"active": "true", "duplicate": "false", "limit": 1, **({CLIENT_PARAM: client} if client else {})}
    queries: dict[tuple, dict] = {("severity", sev): {"tags": tag, "severity": sev} for sev in report.SEVERITIES}
    queries[("review",)] = {"tags__and": f"{tag},{classify.REVIEW_TAG}"}
    for key in triage.CATEGORIES:  # 1 件は 1 つの小項目にだけ数える(タグが 2 つなら急ぐ方。報告書・リスク受容と同じ)
        urgent = ",".join(triage.more_urgent(key))
        for sev in report.SEVERITIES:
            queries[("triage", key, sev)] = {"tags__and": f"{tag},{triage.TAGS[key]}", "severity": sev,
                                             **({"not_tags": urgent} if urgent else {})}
    for prod in products:
        queries[("system", prod["id"])] = {"tags": tag, "test__engagement__product": prod["id"]}

    def count(params: dict) -> int:
        return d.call("GET", "/api/v2/findings/", params={**scope, **params}).get("count", 0)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        counts = dict(zip(queries, pool.map(count, queries.values()), strict=True))
    severities = {sev: counts[("severity", sev)] for sev in report.SEVERITIES}
    systems = sorted(({"name": p["name"], "client": names[str(p["prod_type"])], "count": counts[("system", p["id"])],
                       "url": f"/product/{p['id']}/finding/open?" + urllib.parse.urlencode({"tags": tag})}
                      for p in products if counts[("system", p["id"])]), key=lambda r: (-r["count"], r["name"]))
    tail = systems[TOP_SYSTEMS:]
    by_triage = {key: {sev: counts[("triage", key, sev)] for sev in report.SEVERITIES} for key in triage.CATEGORIES}
    scope_notes = []
    for client_id, name in sorted(names.items(), key=lambda kv: kv[1]):
        if client and client_id != client:
            continue
        skipped, unjudged = kit.scope_summary(name, {p["name"] for p in grouped[name]})
        if skipped or unjudged:
            scope_notes.append({"client": name, "skipped": [{"name": n, "reason": r} for n, r in skipped],
                                "unjudged": len(unjudged)})
    return {
        "tier": number, "name": classify.TIER_NAMES[number], "meaning": classify.TIER_MEANINGS[number],
        "total": sum(severities.values()),
        "severities": severities, "review": counts[("review",)], "findings_url": findings_url(client, tag),
        "systems": systems[:TOP_SYSTEMS], "other": {"count": sum(r["count"] for r in tail), "systems": len(tail)},
        "triage": [{"key": key, "label": label, "severities": by_triage[key], "total": sum(by_triage[key].values()),
                    "findings_url": findings_url(client, tag, triage.TAGS[key], not_tags=triage.more_urgent(key))}
                   for key, label in triage.CATEGORIES.items()],
        # 仕分けのない指摘(小項目のどれにも入らない分。数え直しの間に仕分けが変わっても負にしない)
        "untriaged": max(0, sum(severities.values()) - sum(sum(v.values()) for v in by_triage.values())),
        "scope": scope_notes,
    }


def accept_preview(client: str, product: str, tier: str) -> dict:
    """リスク受容の見込み(仕分けが「リスク受容」の指摘の件数と、案件 × 理由のまとまり)。読むだけ。"""
    if tier not in ("", "1", "2", "3"):
        raise BadRequest("大項目の指定が正しくありません。")
    batches = accept.plan(kit.connect(), client, product or None, int(tier) if tier else None)
    return {"summary": accept.describe(batches), "total": accept.accepted_count(batches),
            "batches": [{"product": b.product, "engagement": b.engagement, "group": b.group,
                         "count": len(b.findings), "enabled": b.enabled} for b in batches]}


def systems_view() -> list[dict]:
    """顧客ごとに、システム(DefectDojo の製品)と公開範囲の設定を並べる。"""
    out = []
    for client, products in sorted(client_products(kit.connect()).items()):
        systems = kit.load_systems(client)
        rows = []
        for name in sorted(p["name"] for p in products):
            s = systems.get(name, {})
            paths = "\n".join(f"{r['prefix']}={r['exposure']}" + (f"  # {r['note']}" if r.get("note") else "")
                              for r in s.get("paths") or [])
            rows.append({"name": name, "exposure": s.get("exposure", "unknown"), "visibility": s.get("visibility", ""),
                         "reason": s.get("reason", ""), "source": s.get("source", ""), "paths": paths})
        out.append({"client": client, "systems": rows})
    return out


def parse_paths(text: str) -> list[dict]:
    """「パス=公開範囲  # メモ」の行を読む。"""
    rules = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        m = PATH_RULE.match(line)
        if not m or m.group(2) not in classify.EXPOSURES or len(line) > 300 or re.search(r"[\x00-\x1f\x7f]", line):
            raise BadRequest(f"パスの例外の {n} 行目を読めません。「パス=公開範囲」の形で、公開範囲は "
                             + "・".join(classify.EXPOSURES) + " のどれかです。")
        rules.append({"prefix": m.group(1).strip(), "exposure": m.group(2),
                      **({"note": m.group(3).strip()} if m.group(3) else {})})
    return rules


def save_systems(payload: dict) -> str:
    """画面で変えた公開範囲を保存する(変えたものは出典を「手動」にする)。"""
    client = targets.field(payload, "client")
    rows = payload.get("systems")
    if not isinstance(rows, list):
        raise BadRequest("システムの一覧の形が正しくありません。")
    systems = kit.load_systems(client)
    for row in rows:
        if not isinstance(row, dict):
            raise BadRequest("システムの一覧の形が正しくありません。")
        name = targets.field(row, "product")
        exposure = row.get("exposure")
        if exposure not in classify.EXPOSURES:
            raise BadRequest(f"{name}: 公開範囲が正しくありません。")
        paths = parse_paths(str(row.get("paths") or ""))
        reason = re.sub(r"[\x00-\x1f\x7f]", " ", str(row.get("reason") or ""))[:500]
        entry = systems.get(name, {})
        if (entry.get("exposure"), entry.get("paths") or [], entry.get("reason", "")) != (exposure, paths, reason):
            systems[name] = {**entry, "exposure": exposure, "paths": paths, "reason": reason, "source": "user"}
    kit.save_systems(client, systems)
    return client


def file_url(path: Path) -> str:
    return "/kit/files/" + urllib.parse.quote(path.relative_to(kit.DATA).as_posix())


def report_scope(path: Path) -> tuple[int | None, str | None, str]:
    """報告書のファイル名(report-<日時>[-tier<大項目>][-<小項目>])から、(大項目, 小項目, 表示)を読む。"""
    tier = re.search(r"-tier([123])(?=-|$)", path.stem)
    key = re.search(r"-(" + "|".join(triage.CATEGORIES) + r")$", path.stem)
    number, key = (int(tier.group(1)) if tier else None), (key.group(1) if key else None)
    return number, key, report.scope_label(number, key)


def download_name(path: Path) -> str:
    """保存するときのファイル名(例: DEMO_脆弱性診断_①外部攻撃系統_直す_20261029-1730.pdf)。"""
    relative = path.relative_to(kit.DATA.resolve())
    client = relative.parts[0]
    if len(relative.parts) == 4 and relative.parts[1] == "repository-scans" and repository_scan.RUN_ID.fullmatch(relative.parts[2]):
        kind = "SBOM" if path.name == "sbom.cdx.json" else "検査結果"
        return f"{client}_{kind}_{relative.parts[2]}_{path.name}"
    tier, key, _ = report_scope(path)
    stamp = re.search(r"report-(\d{8}-\d{4})", path.stem)
    scope = (classify.TIER_TAGS[tier] if tier else "すべて") + (f"_{triage.CATEGORIES[key]}" if key else "")
    return f"{client}_脆弱性診断_{scope}_{stamp.group(1) if stamp else ''}{path.suffix}"


def list_reports() -> list[dict]:
    found = []
    for html_path in kit.DATA.glob("*/reports/report-*.html"):
        pdf, csv_path = html_path.with_suffix(".pdf"), html_path.with_suffix(".csv")
        found.append({"client": html_path.parent.parent.name, "scope": report_scope(html_path)[2],
                      "created": dt.datetime.fromtimestamp(html_path.stat().st_mtime).isoformat(timespec="minutes"),
                      "html": file_url(html_path), "pdf": file_url(pdf) if pdf.exists() else None,
                      "csv": file_url(csv_path) if csv_path.exists() else None})
    return sorted(found, key=lambda r: r["created"], reverse=True)


def resolve_data_file(rel: str) -> Path | None:
    """/kit/files/ で返してよいファイル(報告書と結果の JSON)だけを data/ の中から探す。"""
    data = kit.DATA.resolve()
    path = (data / urllib.parse.unquote(rel)).resolve()
    if data not in path.parents or not path.is_file() or path.suffix not in FILE_TYPES:
        return None
    if path.suffix == ".csv" and path.parent.name != "reports":  # CSV は報告書のものだけ(検査の結果の CSV は出さない)
        return None
    if path.relative_to(data).parts[0] in ("jobs", "vuls-db") or path.name in ("systems.json", "tests.json",
                                                                               "skipped.json"):
        return None
    return path


def job_report(job_id: str) -> dict:
    """報告書のジョブが作ったファイル(HTML・PDF・CSV の URL。作れなかったものは None)。
    ジョブのログの「報告書を作りました(N 件): <HTML のパス>」の行から探す(同じ範囲の、ほかのジョブの報告書と取り違えない)。"""
    log = kit.JOBS_DIR / job_id / "log.txt"
    text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    found = re.findall(rf"^{re.escape(kit.REPORT_DONE)}\(\d+ 件\): (.+\.html)$", text, re.M)
    data = kit.DATA.resolve()
    path = Path(found[-1]).resolve() if found else None
    rel = path.relative_to(data) if path and data in path.parents else None
    html_path = resolve_data_file(urllib.parse.quote(rel.as_posix())) if rel else None  # URL の形(%xx)で渡す
    if not html_path or html_path.parent.name != "reports":
        raise BadRequest("このジョブが作った報告書が見つかりません。「実行状況」のログを見てください。")
    return {kind: file_url(kit.DATA / rel.with_suffix(ext)) if html_path.with_suffix(ext).is_file() else None
            for kind, ext in (("html", ".html"), ("pdf", ".pdf"), ("csv", ".csv"))}


def pick(kind: str) -> str:
    """Mac のファイル選択の画面を出して、選ばれたパスを返す(サーバーは同じ Mac で動いている)。"""
    if kind not in ("folder", "file"):
        raise BadRequest("選ぶものが正しくありません。")
    prompt = "検査するフォルダを選んでください" if kind == "folder" else "ファイルを選んでください"
    try:
        r = subprocess.run(["/usr/bin/osascript", "-e", f'POSIX path of (choose {kind} with prompt "{prompt}")'],
                           capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        raise BadRequest("選ぶ画面が時間切れになりました。") from None
    if r.returncode != 0:
        raise BadRequest("選ばれませんでした。")
    return r.stdout.strip()


# ---- HTTP ----

class Handler(BaseHTTPRequestHandler):
    server_version = "security-scan-kit"

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"{self.log_date_time_string()} {fmt % args}\n")

    def _dispatch(self, method: str) -> None:
        if not gateway_ok(self.headers, self.server.token):
            return self._json(403, {"error": "forbidden"})
        if method == "POST" and not write_ok(self.headers):
            return self._json(403, {"error": "この画面からの操作だけを受け付けます。"})
        url = urllib.parse.urlsplit(self.path)
        try:
            self._route(method, url.path, urllib.parse.parse_qs(url.query))
        except BadRequest as e:
            self._json(400, {"error": str(e)})
        except (kit.KitError, dojo.DojoError) as e:
            self._json(503, {"error": str(e)})
        except Exception as e:  # 1 つの要求の失敗で、サーバーを止めない
            self.log_message("error: %s: %s", type(e).__name__, e)
            self._json(500, {"error": f"{type(e).__name__}: {e}"})

    def _route(self, method: str, path: str, query: dict) -> None:
        arg = lambda name: (query.get(name) or [""])[0]  # noqa: E731
        if method == "GET" and path in ("/kit", "/kit/"):
            return self._file(WEB_DIR / "index.html", "text/html; charset=utf-8", csp=INDEX_CSP)
        if method == "GET" and path.startswith("/kit/static/") and path.rsplit("/", 1)[1] in STATIC:
            name = path.rsplit("/", 1)[1]
            return self._file(WEB_DIR / name, STATIC[name])
        if method == "GET" and path == "/kit/healthz":
            return self._json(200, {"ok": True, "version": self.server.version})
        if method == "GET" and path == "/kit/api/overview":
            return self._json(200, overview())
        if method == "GET" and path == "/kit/api/clients":
            return self._json(200, {"clients": client_list(kit.connect())})
        if method == "GET" and path == "/kit/api/dashboard":
            return self._json(200, dashboard(arg("tier"), arg("client")))
        if method == "GET" and path == "/kit/api/accept-preview":
            fields = {"client": arg("client"), "product": arg("product")}
            return self._json(200, accept_preview(targets.field(fields, "client"),
                                                  targets.field(fields, "product", required=False), arg("tier")))
        if method == "GET" and path == "/kit/api/reports":
            return self._json(200, {"reports": list_reports()})
        if method == "GET" and path == "/kit/api/repository-scans":
            return self._json(200, {"scans": repository_scan.list_scans(arg("client"))})
        if method == "GET" and path.startswith("/kit/api/repository-scans/"):
            run_id = path.removeprefix("/kit/api/repository-scans/")
            scan = repository_scan.get_scan(run_id)
            return self._json(200, {"scan": scan}) if scan else self._json(404, {"error": "検査結果が見つかりません。"})
        if path == "/kit/api/systems":
            if method == "GET":
                return self._json(200, {"clients": systems_view(), "exposures": classify.EXPOSURES})
            client = save_systems(self._body())
            return self._start_job({"tool": "classify", "client": client})
        if path == "/kit/api/jobs":
            if method == "GET":
                return self._json(200, {"jobs": jobs.list_jobs(kit.JOBS_DIR)})
            return self._start_job(self._body())
        m = re.fullmatch(r"/kit/api/jobs/([^/]+)(?:/(log|cancel|report))?", path)
        if m and jobs.valid_id(m.group(1)) and (kit.JOBS_DIR / m.group(1)).is_dir():
            job_id, action = m.groups()
            if action is None and method == "GET":
                return self._json(200, {"job": jobs.get(kit.JOBS_DIR, job_id)})
            if action == "log" and method == "GET":
                text, offset = jobs.read_log(kit.JOBS_DIR, job_id, int(arg("offset") or 0))
                return self._json(200, {"text": text, "offset": offset, "job": jobs.get(kit.JOBS_DIR, job_id)})
            if action == "report" and method == "GET":
                return self._json(200, job_report(job_id))
            if action == "cancel" and method == "POST":
                jobs.cancel(kit.JOBS_DIR, job_id)
                return self._json(200, {"job": jobs.get(kit.JOBS_DIR, job_id)})
        if method == "POST" and path == "/kit/api/pick":
            return self._json(200, {"path": pick(self._body().get("kind", ""))})
        if method == "GET" and path.startswith("/kit/files/"):
            target = resolve_data_file(path.removeprefix("/kit/files/"))
            if target:
                csp = FILE_CSP if target.suffix == ".html" else None
                attach = download_name(target) if arg("download") == "1" else None
                return self._file(target, FILE_TYPES[target.suffix], csp=csp, attachment=attach)
        self._json(404, {"error": "not found"})

    def _start_job(self, payload: dict) -> None:
        preset = None
        if "preset" in payload:
            presets = targets.load_presets()
            index = payload["preset"]
            if not isinstance(index, int) or not 0 <= index < len(presets):
                raise BadRequest("プリセットが見つかりません。")
            preset = presets[index]
            if reason := targets.blocker(preset):
                raise BadRequest(reason)
            payload = targets.preset_payload(preset)
        title, client, argv = targets.build_job(payload)
        if preset and preset.get("name"):
            title = preset["name"]  # 実行状況にはプリセットの名前を出す(DefectDojo の検査名は変えない)
        job = jobs.create(kit.JOBS_DIR, title, client, argv)
        jobs.spawn(kit.JOBS_DIR, job["id"], [sys.executable, str(kit.KIT / "lib" / "kit.py"), "job-run"])
        self._json(201, {"job": job})

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise BadRequest("要求が大きすぎます。")
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            raise BadRequest("JSON を読めません。") from None
        if not isinstance(data, dict):
            raise BadRequest("JSON の形が正しくありません。")
        return data

    def _headers(self, status: int, ctype: str, length: int, csp: str | None, attachment: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        if csp:
            self.send_header("Content-Security-Policy", csp)
        if attachment:
            self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + urllib.parse.quote(attachment))
        self.end_headers()

    def _json(self, status: int, data: dict) -> None:
        body = json.dumps(data, ensure_ascii=False).encode()
        self._headers(status, "application/json; charset=utf-8", len(body), None)
        self.wfile.write(body)

    def _file(self, path: Path, ctype: str, csp: str | None = None, attachment: str | None = None) -> None:
        body = path.read_bytes()
        self._headers(200, ctype, len(body), csp, attachment)
        self.wfile.write(body)


def serve() -> None:
    token = kit.keychain_get("KIT_GATEWAY_TOKEN")
    if not token:
        raise kit.KitError("合言葉がありません。`bin/kit up` から起動してください。")
    server = ThreadingHTTPServer(("127.0.0.1", int(kit.WEB_PORT)), Handler)
    server.daemon_threads = True
    server.token = token
    server.version = kit.code_version()
    print(f"{dt.datetime.now():%Y-%m-%d %H:%M:%S} 画面のサーバーを起動しました: {kit.WEB_URL} (版 {server.version})",
          flush=True)
    server.serve_forever()
