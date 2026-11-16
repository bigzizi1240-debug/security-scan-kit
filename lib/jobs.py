"""画面から始めた検査や報告書の作成を、裏で動かす仕組み。

ジョブごとに <jobs_dir>/<id>/ を作り、job.json(内容と状態)と log.txt(出力)を置く。
処理は `kit.py job-run <id>` が別のプロセス(新しいセッション)として動かすので、
画面のサーバーを止めても検査は続き、結果と状態はファイルに残る。
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import signal
import subprocess
import uuid
from pathlib import Path

LOG_CHUNK = 256 * 1024
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
EXIT_OUT_OF_SCOPE = 4  # kit が「今の権限では検査できない(範囲外)」で終わったときの終了コード


def now() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def _read(job_dir: Path) -> dict:
    return json.loads((job_dir / "job.json").read_text(encoding="utf-8"))


def _write(job_dir: Path, job: dict) -> None:
    tmp = job_dir / "job.json.tmp"
    tmp.write_text(json.dumps(job, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, job_dir / "job.json")


def _alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def create(jobs_dir: Path, title: str, client: str, argv: list[str]) -> dict:
    job_id = f"{dt.datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6]}"
    job_dir = jobs_dir / job_id
    job_dir.mkdir(parents=True, mode=0o700)
    job = {"id": job_id, "title": title, "client": client, "argv": argv, "status": "queued", "created": now()}
    _write(job_dir, job)
    return job


def spawn(jobs_dir: Path, job_id: str, command: list[str]) -> subprocess.Popen:
    """command(例: [python, kit.py, "job-run"])に job_id を付けて、切り離して動かす。"""
    return subprocess.Popen([*command, job_id], start_new_session=True, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=jobs_dir)


def run(jobs_dir: Path, job_id: str, command: list[str]) -> int:
    """ジョブを実行し、終わったら状態を書く(job-run のプロセスの中で呼ぶ)。"""
    job_dir = jobs_dir / job_id
    job = _read(job_dir)
    job.update(status="running", pid=os.getpid(), started=now())
    _write(job_dir, job)
    with (job_dir / "log.txt").open("ab") as log:
        proc = subprocess.Popen([*command, *job["argv"]], stdout=log, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, env={**os.environ, "PYTHONUNBUFFERED": "1"})
        signal.signal(signal.SIGTERM, lambda *_: proc.terminate())
        rc = proc.wait()
    job = _read(job_dir)
    status = "canceled" if job.get("cancel_requested") else \
        {0: "succeeded", EXIT_OUT_OF_SCOPE: "out_of_scope"}.get(rc, "failed")
    # 取り込んだ DefectDojo の検査(kit が「  http://…/test/<番号>」と出す)を、画面のリンク用に残す
    tests = re.findall(r"/test/(\d+)\s*$", (job_dir / "log.txt").read_text(encoding="utf-8", errors="replace"), re.M)
    job.update(status=status, exit_code=rc, ended=now(), tests=sorted(set(map(int, tests))))
    _write(job_dir, job)
    return rc


def cancel(jobs_dir: Path, job_id: str) -> None:
    job_dir = jobs_dir / job_id
    job = _read(job_dir)
    if job["status"] not in ("queued", "running"):
        return
    job["cancel_requested"] = True
    _write(job_dir, job)
    if _alive(job.get("pid")):
        os.killpg(job["pid"], signal.SIGTERM)  # job-run はセッションの先頭なので、子の検査ツールまで止まる


def get(jobs_dir: Path, job_id: str) -> dict:
    job = _read(jobs_dir / job_id)
    if job["status"] == "running" and not _alive(job.get("pid")):
        job["status"] = "interrupted"  # 途中で落ちた(Mac の再起動など)
    return job


def list_jobs(jobs_dir: Path, limit: int = 200) -> list[dict]:
    if not jobs_dir.exists():
        return []
    ids = sorted((d.name for d in jobs_dir.iterdir() if (d / "job.json").exists()), reverse=True)[:limit]
    return [get(jobs_dir, i) for i in ids]


def read_log(jobs_dir: Path, job_id: str, offset: int) -> tuple[str, int]:
    """offset バイト目からのログ(色の制御文字は除く)と、次の offset を返す。"""
    path = jobs_dir / job_id / "log.txt"
    if not path.exists():
        return "", 0
    with path.open("rb") as f:
        f.seek(max(0, offset))
        data = f.read(LOG_CHUNK)
    return ANSI.sub("", data.decode("utf-8", "replace")), max(0, offset) + len(data)


def valid_id(job_id: str) -> bool:
    return bool(re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{6}", job_id))
