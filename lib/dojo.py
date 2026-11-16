"""DefectDojo API v2 の最小限のクライアント。標準ライブラリだけで書く。"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


class DojoError(Exception):
    pass


# 127.0.0.1 へは必ず直接つなぐ。OS や環境変数のプロキシ(Burp など)を通すと、
# 管理者のパスワードや検査結果がプロキシに渡るため
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def multipart(fields: dict[str, str], files: dict[str, Path]) -> tuple[bytes, str]:
    """multipart/form-data の本文と Content-Type を返す。"""
    boundary = uuid.uuid4().hex
    parts = []
    for name, value in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
                     + str(value).encode("utf-8") + b"\r\n")
    for name, path in files.items():
        filename = path.name.replace('"', "_")
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                     "Content-Type: application/octet-stream\r\n\r\n".encode()
                     + path.read_bytes() + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def request(url: str, method: str, *, token: str | None = None, json_body: dict | None = None,
            form: dict[str, str] | None = None, files: dict[str, Path] | None = None, timeout: int = 120) -> dict:
    headers = {"Accept": "application/json"}
    body = None
    if json_body is not None:
        body = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
    elif form is not None:
        body, headers["Content-Type"] = multipart(form, files or {})
    if token:
        headers["Authorization"] = f"Token {token}"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    path = urllib.parse.urlsplit(url).path
    try:
        with OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:800]
        raise DojoError(f"DefectDojo API {method} {path} が失敗しました(HTTP {e.code}): {detail}") from None
    except urllib.error.URLError as e:
        raise DojoError(f"DefectDojo に接続できません({e.reason})。`bin/kit up` で起動してください。") from None
    return json.loads(raw) if raw else {}


class Dojo:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.token = token

    @classmethod
    def login(cls, base_url: str, username: str, password: str) -> Dojo:
        data = request(base_url.rstrip("/") + "/api/v2/api-token-auth/", "POST",
                       json_body={"username": username, "password": password})
        return cls(base_url, data["token"])

    def call(self, method: str, path: str, *, params: dict | None = None, **kw) -> dict:
        url = self.base_url + path + ("?" + urllib.parse.urlencode(params) if params else "")
        return request(url, method, token=self.token, **kw)

    def iterate(self, path: str, params: dict | None = None):
        """一覧 API の全ページを順に返す。"""
        url = self.base_url + path + "?" + urllib.parse.urlencode({**(params or {}), "limit": 200})
        while url:
            page = request(url, "GET", token=self.token)
            yield from page.get("results", [])
            url = self._next_url(page.get("next"))

    def _next_url(self, nxt: str | None) -> str | None:
        # 次ページの URL はサーバーが組み立てる。トークンを外へ送らないよう、API のパスだけを使う
        if not nxt:
            return None
        parts = urllib.parse.urlsplit(nxt)
        if not parts.path.startswith("/api/v2/"):
            raise DojoError(f"想定外の次ページ URL です: {nxt}")
        return self.base_url + parts.path + ("?" + parts.query if parts.query else "")

    def reimport(self, scan_type: str, file: Path, *, product_type: str, product: str, engagement: str,
                 test_title: str, scan_date: str, extra: dict[str, str] | None = None) -> dict:
        """同じ検査名の結果があれば更新し(消えた指摘は閉じる)、なければ顧客・対象・案件ごと作る。

        extra には commit_hash・branch_tag など、検査に付ける情報を入れられる。
        """
        form = {
            "scan_type": scan_type,
            "product_type_name": product_type,
            "product_name": product,
            "engagement_name": engagement,
            "test_title": test_title,
            "auto_create_context": "true",
            "active": "true",
            "verified": "false",
            "close_old_findings": "true",
            "minimum_severity": "Info",
            "scan_date": scan_date,
            **(extra or {}),
        }
        return self.call("POST", "/api/v2/reimport-scan/", form=form, files={"file": file}, timeout=900)
