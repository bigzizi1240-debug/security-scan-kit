"""仕分けが「リスク受容」の指摘を、DefectDojo のリスク受容としてまとめて登録する。

DefectDojo のリスク受容には 1 つの案件の指摘しか入れられないので、「案件 × 理由のまとまり」ごとに 1 つ作る。
受け入れた指摘は DefectDojo で有効でなくなり、報告書から外れる。取り消しは DefectDojo の画面(案件のリスク受容)で行う。
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

import classify
import dojo
import kit
import targets
import triage


@dataclass
class Batch:
    product: str
    engagement_id: int
    engagement: str
    group: str  # 理由のまとまり(triage.json の group)
    enabled: bool  # 対象システムでリスク受容(full)が使えるか
    findings: list[int] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)  # 規則の理由(重ねない)

    @property
    def name(self) -> str:
        return f"{self.product} / {self.engagement} / {self.group}"


def plan(d: dojo.Dojo, client: str, product: str | None = None, tier: int | None = None) -> list[Batch]:
    """今の仕分けが「リスク受容」の有効な指摘を、案件 × 理由のまとまりに分ける(読むだけ)。"""
    products = kit.client_products(d, client)  # 顧客がなければ、ここで止まる(data/ にフォルダを作らない)
    if product and product not in {p["name"] for p in products}:
        raise kit.KitError(f"顧客「{client}」に対象システム「{product}」がありません。")
    if not products:
        return []
    records = kit.load_json(kit.client_dir(client) / "triage.json", {}).get("findings", {})
    place = {test["id"]: (prod, eng) for prod, eng, test in kit.client_tests(d, client)
             if not product or prod["name"] == product}
    query = {"test__engagement__product__prod_type": products[0]["prod_type"], "active": "true", "duplicate": "false",
             "tags": triage.TAGS["accept"]}
    batches: dict[tuple[int, str], Batch] = {}
    for f in d.iterate("/api/v2/findings/", query):
        tags = f.get("tags") or []
        # 人が「直す」なども付けた指摘は、今の仕分け(急ぐ方)が「リスク受容」でないので入れない
        if f["test"] not in place or triage.category_of(tags) != "accept" or (tier and classify.tier_of(tags) != tier):
            continue
        prod, eng = place[f["test"]]
        record = triage.current_record(tags, records.get(str(f["id"]))) or {}
        group = record.get("group") or triage.MANUAL_GROUP
        batch = batches.setdefault((eng["id"], group), Batch(prod["name"], eng["id"], eng["name"], group,
                                                              bool(prod.get("enable_full_risk_acceptance"))))
        batch.findings.append(f["id"])
        if record.get("reason") and record["reason"] not in batch.reasons:
            batch.reasons.append(record["reason"])
    return sorted(batches.values(), key=lambda b: (b.product, b.engagement, b.group))


def accepted_count(batches: list[Batch]) -> int:
    """登録する指摘の数(リスク受容(full)が無効な対象システムの分は数えない)。"""
    return sum(len(b.findings) for b in batches if b.enabled)


def describe(batches: list[Batch]) -> str:
    total = sum(len(b.findings) for b in batches)
    skipped = total - accepted_count(batches)
    text = f"リスク受容 {total} 件({len({b.engagement_id for b in batches})} 案件、{len(batches)} まとまり)"
    return text + (f"。うち {skipped} 件はリスク受容(full)が無効なので飛ばす" if skipped else "")


def payload(batch: Batch, by: str, days: int, reactivate: bool, owner: int, today: dt.date) -> dict:
    """DefectDojo のリスク受容(POST /api/v2/risk_acceptance/)に送る値。期限はその日の 0 時(この Mac の時刻)。"""
    expires = dt.datetime.combine(today + dt.timedelta(days=days), dt.time()).astimezone()
    return {"name": f"リスク受容: {batch.group}({today:%Y-%m-%d})", "owner": owner,
            "accepted_findings": batch.findings, "accepted_by": by, "recommendation": "A",
            "recommendation_details": "security-scan-kit の仕分け: " + " / ".join(batch.reasons[:20]),
            "decision": "A", "decision_details": f"security-scan-kit の仕分けで「リスク受容」にした指摘を、{by} が受け入れた。",
            "expiration_date": expires.isoformat(), "reactivate_expired": reactivate, "restart_sla_expired": False}


def admin_id(d: dojo.Dojo) -> int:
    for user in d.iterate("/api/v2/users/", {"username": kit.DD_ADMIN}):
        if user.get("username") == kit.DD_ADMIN:
            return user["id"]
    raise kit.KitError("DefectDojo に管理者のユーザーが見つかりません。")


def run(d: dojo.Dojo, client: str, by: str, days: int = 180, reactivate: bool = True, product: str | None = None,
        dry_run: bool = False, expect: int | None = None, tier: int | None = None) -> None:
    """登録する。expect は画面で確かめた件数で、今の件数と違えば登録しない(確かめたあとに仕分けが変わったとき)。"""
    if not targets.FIELD.fullmatch(by or ""):  # match だと、末尾の改行を $ が見逃す
        raise kit.KitError("受け入れた人は 1〜200 文字で書いてください(制御文字と先頭の - は使えません)。")
    batches = plan(d, client, product, tier)
    kit.say(describe(batches))
    for b in batches:
        kit.say(f"  {b.name}: {len(b.findings)} 件" + ("" if b.enabled else "(リスク受容(full)が無効なので飛ばす)"))
    if dry_run:
        return
    count = accepted_count(batches)
    if expect is not None and count != expect:
        raise kit.KitError(f"確かめた見込み({expect} 件)と、今の「リスク受容」の指摘({count} 件)が違います。"
                           "見込みを確かめてから、もう一度登録してください。")
    if not count:
        return
    owner, today, failed = admin_id(d), dt.date.today(), []
    for b in batches:
        if not b.enabled:
            continue
        try:
            ra = d.call("POST", "/api/v2/risk_acceptance/", json_body=payload(b, by, days, reactivate, owner, today))
        except Exception as e:  # 1 つの案件で失敗しても、ほかの案件は続ける(最後にまとめて失敗にする)
            kit.say(f"  失敗: {b.name}: {e}")
            failed.append(b.name)
            continue
        kit.say(f"  登録しました: {b.name}: {len(b.findings)} 件(期限 {today + dt.timedelta(days=days)})")
        kit.say(f"  {kit.DD_URL}/engagement/{b.engagement_id}/risk_acceptance/{ra.get('id')}")
    if failed:
        raise kit.KitError(f"{len(failed)} 件のリスク受容を登録できませんでした: " + "、".join(failed))
