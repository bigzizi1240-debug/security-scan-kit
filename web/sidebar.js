"use strict";
// DefectDojo の左のメニュー「スキャンと報告書」に、顧客を選ぶ欄を足す(入口の nginx が、メニューと一緒に
// この <script> を差し込む)。選んだ顧客は、①〜③ のページ(キットの画面のダッシュボード)が同じ保存先から読む。
// キットを使えない人(DefectDojo の superuser でない人)には、欄を出さない。
(() => {
  const KEY = "kit-client";  // キットの画面(app.js)と同じ保存先
  const box = document.getElementById("kit-client");
  if (!box) return;

  const stored = () => {
    try { return localStorage.getItem(KEY) || ""; } catch { return ""; }
  };
  const store = (id) => {
    try { localStorage.setItem(KEY, id); } catch { /* 保存できなくても、メニューのリンクは使える */ }
  };

  async function load() {
    const res = await fetch("/kit/api/clients", {credentials: "same-origin", headers: {Accept: "application/json"}});
    if (!res.ok || !(res.headers.get("Content-Type") || "").includes("application/json")) return;
    const {clients} = await res.json();
    const ids = clients.map((c) => String(c.id));
    const select = document.createElement("select");
    select.title = "①〜③ のページを、この顧客で開く";
    // DefectDojo の CSS は select の矢印を消すので、ブラウザの標準の見た目に戻す
    select.style.cssText = "flex:1;min-width:0;font-size:12px;padding:2px 4px;border:1px solid currentColor;" +
      "border-radius:4px;background:transparent;color:inherit;appearance:auto;-webkit-appearance:menulist";
    select.append(new Option("すべての顧客", ""), ...clients.map((c) => new Option(c.name, String(c.id))));
    const label = document.createElement("span");
    label.textContent = "顧客";
    label.style.cssText = "font-size:12px;white-space:nowrap";
    select.value = ids.includes(stored()) ? stored() : "";
    select.addEventListener("change", () => store(select.value));
    box.style.cssText = "display:flex;align-items:center;gap:6px";
    box.replaceChildren(label, select);
    box.hidden = false;
  }

  load().catch(() => { /* 出せなくても、メニューのリンクは使える(顧客は前に選んだまま) */ });
})();
