"""悪用の見込み(EPSS)と、悪用が確認された脆弱性の一覧(CISA KEV)を読む。

どちらも一覧をまるごと取る(CVE ごとに問い合わせないので、顧客の CVE の一覧は外に出ない)。
取ったファイルは data/intel/ に置き、24 時間は取り直さない。取れないときは前のファイルを使う。
"""
from __future__ import annotations

import csv
import datetime as dt
import gzip
import http.client
import io
import json
import os
import re
import time
import urllib.request
import zlib
from dataclasses import dataclass, field
from pathlib import Path

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_AGE = 24 * 3600  # 取り直すまでの時間(EPSS は毎日、KEV は週に数回更新される)
MAX_BYTES = 100 * 1024 * 1024
TIMEOUT = 60
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class IntelError(Exception):
    pass


@dataclass(frozen=True)
class Kev:
    date_added: str  # CISA KEV に載った日(YYYY-MM-DD。読めなければ空)
    ransomware: bool  # ランサムウェアでの悪用が確認されている


@dataclass
class Intel:
    epss: dict[str, tuple[float, float]] = field(default_factory=dict)  # CVE → (EPSS, 百分位)
    kev: dict[str, Kev] = field(default_factory=dict)
    epss_version: str = ""  # 例: v2026.06.15(2026-10-29 の値)。空ならデータがない
    kev_version: str = ""  # 例: 2026.10.29。空ならデータがない
    notes: list[str] = field(default_factory=list)  # 取れなかった、前のファイルを使った、など

    def summary(self) -> dict:
        """triage.json と報告書に残す、使ったデータの版。"""
        return {"epss": self.epss_version, "kev": self.kev_version}


def _gunzip(raw: bytes) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as f:
        data = f.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise IntelError("展開すると大きすぎます。")
    return data


def parse_epss(raw: bytes) -> tuple[dict[str, tuple[float, float]], str]:
    """EPSS の一覧(gzip の CSV)を読む。(CVE → (EPSS, 百分位), 版)"""
    try:
        lines = _gunzip(raw).decode("utf-8").splitlines()
        if len(lines) < 2 or not lines[0].startswith("#") or lines[1].strip() != "cve,epss,percentile":
            raise IntelError("見出しの行が想定と違います。")
        meta = dict(part.split(":", 1) for part in lines[0].lstrip("#").split(",") if ":" in part)
        scores = {}
        for row in csv.reader(lines[2:]):
            if len(row) != 3 or not CVE.match(row[0]):
                continue
            score, percentile = float(row[1]), float(row[2])
            if not (0 <= score <= 1 and 0 <= percentile <= 1):
                raise IntelError(f"{row[0]} の値が 0〜1 の外です。")
            scores[row[0]] = (score, percentile)
    except (OSError, EOFError, ValueError, csv.Error, zlib.error) as e:
        raise IntelError(f"読めません({e})。") from None
    if not scores:
        raise IntelError("CVE が 1 件もありません。")
    return scores, f"{meta.get('model_version', '?')}({meta.get('score_date', '?')[:10]} の値)"


def parse_kev(raw: bytes) -> tuple[dict[str, Kev], str]:
    """CISA KEV の一覧(JSON)を読む。(CVE → Kev, 版)"""
    try:
        doc = json.loads(raw)
    except (ValueError, RecursionError) as e:
        raise IntelError(f"読めません({e})。") from None
    items = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(items, list) or not doc.get("catalogVersion"):
        raise IntelError("形が想定と違います。")
    kev = {}
    for item in items:
        cve = item.get("cveID") if isinstance(item, dict) else None
        if isinstance(cve, str) and CVE.match(cve):
            added = str(item.get("dateAdded") or "")[:10]
            kev[cve] = Kev(added if DATE.match(added) else "", item.get("knownRansomwareCampaignUse") == "Known")
    if not kev:
        raise IntelError("CVE が 1 件もありません。")
    return kev, str(doc["catalogVersion"])


SOURCES = {  # 鍵 → (表示名, URL, 保存するファイル名, 読み方)
    "epss": ("EPSS", EPSS_URL, "epss.csv.gz", parse_epss),
    "kev": ("CISA KEV", KEV_URL, "kev.json", parse_kev),
}


def download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "security-scan-kit"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        if not resp.geturl().startswith("https://"):  # 転送で HTTPS から外れたものは使わない
            raise IntelError(f"HTTPS 以外へ転送されました: {resp.geturl()}")
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise IntelError("大きすぎます。")
    return data


def _load(directory: Path, key: str, refresh: bool, notes: list[str]) -> tuple[dict, str]:
    label, url, filename, parse = SOURCES[key]
    path = directory / filename
    stale = not path.exists() or time.time() - path.stat().st_mtime >= MAX_AGE
    if refresh or stale:
        try:
            raw = download(url)
            parsed = parse(raw)  # 形を確かめてから、前のファイルと入れ替える
            tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")  # 並行したジョブと書き込みが混ざらないように
            tmp.write_bytes(raw)
            os.replace(tmp, path)
            return parsed
        except (OSError, http.client.HTTPException, IntelError) as e:
            notes.append(f"{label} の一覧を取れませんでした({e})")
    if not path.exists():
        notes.append(f"{label} のデータがないので、{label} を使わずに仕分けました")
        return {}, ""
    try:
        parsed = parse(path.read_bytes())
    except (OSError, IntelError) as e:
        notes.append(f"保存した {label} の一覧を読めません({e})")
        return {}, ""
    if refresh or stale:  # 取り直せず、前のファイルを使った
        saved = dt.datetime.fromtimestamp(path.stat().st_mtime)
        notes.append(f"{label} は {saved:%Y-%m-%d %H:%M} に取った一覧を使いました")
    return parsed


def load(directory: Path, refresh: bool = False) -> Intel:
    """EPSS と CISA KEV を読む(24 時間たったもの、refresh のときは取り直す)。"""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    notes: list[str] = []
    epss, epss_version = _load(directory, "epss", refresh, notes)
    kev, kev_version = _load(directory, "kev", refresh, notes)
    return Intel(epss, kev, epss_version, kev_version, notes)
