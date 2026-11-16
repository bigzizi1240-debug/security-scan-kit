"use strict";
// スキャンと報告書の画面。サーバー(lib/web.py)の API を呼び、表示する値はすべて textContent で入れる。

const SEVERITIES = [["Critical", "緊急"], ["High", "高"], ["Medium", "中"], ["Low", "低"], ["Info", "情報"]];
const STATUS = {queued: "待機中", running: "実行中", succeeded: "完了", failed: "失敗", canceled: "中止", interrupted: "中断",
                out_of_scope: "範囲外"};
const TOOLS = {repository: "リポジトリ一括検査", trivy: "Trivy", vuls: "Vuls", prowler: "Prowler", report: "報告書"};
const REPOSITORY_CATEGORIES = {dependency: "依存ライブラリ", code: "コード", secret: "秘密情報", config: "設定"};
const REPOSITORY_STATUSES = {completed: "検査完了", partial: "一部未完了", failed: "失敗", unavailable: "未実施",
  not_applicable: "対象なし", running: "検査中", queued: "待機中", canceled: "中止", cancelled: "中止", interrupted: "中断"};
const SOURCES = {ai: "AI の推定", user: "手動", auto: "未設定(自動で追加)"};
const TRIAGE_KEYS = ["fix", "decide", "accept"];
const SEV_COLORS = {Critical: "var(--sev-critical)", High: "var(--sev-high)", Medium: "var(--sev-medium)",
                    Low: "var(--sev-low)", Info: "var(--sev-info)"};
const CLIENT_KEY = "kit-client";  // 左のメニューの顧客の欄(sidebar.js)と同じ保存先
const state = {overview: null, log: {id: null, offset: 0, timer: null}, jobsTimer: null, acceptTotal: null, previewSeq: 0,
               dash: {tier: "1", client: "", clients: null, focus: null, open: false, seq: 0},
               repository: {scans: [], selected: null, detail: null, clients: [], listSeq: 0, detailSeq: 0, limit: 100, timer: null}};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];
const active = (job) => job.status === "running" || job.status === "queued";
const fmt = (n) => Number(n || 0).toLocaleString("ja-JP");

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "value") node.value = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children) if (child !== null && child !== undefined) node.append(child);
  return node;
}

// 同じサイトの中だけを指すリンク(サーバーが作るパスは / で始まる)
function link(href, text, attrs = {}) {
  return el("a", {href: href.startsWith("/") ? href : "#", text, target: "_blank", rel: "noopener", ...attrs});
}

// 保存するリンク(download があると、サーバーが失敗しても画面を離れず、ブラウザのダウンロードの失敗として出る)
function saveLink(href, text) {
  return link(`${href}?download=1`, text, {target: null, rel: null, download: ""});
}

function emptyRow(columns, text) {
  return el("tr", {}, el("td", {colspan: columns, class: "hint", text}));
}

function fmtTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getMonth() + 1}/${d.getDate()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function duration(job) {
  if (!job.started) return "";
  const seconds = Math.max(0, Math.round(((job.ended ? new Date(job.ended) : new Date()) - new Date(job.started)) / 1000));
  return seconds < 60 ? `${seconds} 秒` : `${Math.floor(seconds / 60)} 分 ${seconds % 60} 秒`;
}

async function api(path, options = {}) {
  const init = {credentials: "same-origin", headers: {Accept: "application/json"}};
  if (options.body !== undefined) {
    init.method = "POST";
    init.headers["Content-Type"] = "application/json";
    init.headers["X-Kit-Request"] = "1";  // サーバーはこのヘッダーのない書き込みを断る
    init.body = JSON.stringify(options.body);
  }
  const res = await fetch(path, init);
  if (!(res.headers.get("Content-Type") || "").includes("application/json")) {
    location.reload();  // ログインが切れると DefectDojo のログイン画面が返る
    throw new Error("ログインし直してください。");
  }
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function waitJob(job) {
  while (active(job)) {
    await new Promise((resolve) => setTimeout(resolve, 1500));
    ({job} = await api(`/kit/api/jobs/${encodeURIComponent(job.id)}`));
  }
  return job;
}

// ---- タブ ----

function showTab(name) {
  for (const button of $$(".tabs button")) button.classList.toggle("active", button.dataset.tab === name);
  for (const section of $$(".tab")) section.hidden = section.id !== `tab-${name}`;
  const hash = name === "dashboard" ? ["dashboard", state.dash.tier, state.dash.focus].filter(Boolean).join("/") : name;
  history.replaceState(null, "", `#${hash}`);
  if (name !== "repository-results") clearTimeout(state.repository.timer);
  const load = {jobs: refreshJobs, "repository-results": refreshRepositoryScans,
                reports: refreshReports, dashboard: refreshDashboard, systems: refreshSystems}[name];
  if (load) load().catch((e) => alert(e.message));
}

// #dashboard/<大項目>[/<小項目>] を読む(左のメニューのリンク。前の「結果」の #results も受ける)
function route(hash) {
  const [name, tier, focus] = hash.split("/");
  if (name === "dashboard" || name === "results") {
    if (["1", "2", "3"].includes(tier)) state.dash.tier = tier;
    state.dash.focus = TRIAGE_KEYS.includes(focus) ? focus : null;
    if (state.dash.focus) state.dash.open = true;
    return "dashboard";
  }
  return ["scan", "jobs", "repository-results", "reports", "systems"].includes(name) ? name : "scan";
}

// ---- 検査する ----

async function loadOverview() {
  const data = await api("/kit/api/overview");
  state.overview = data;
  renderPresets(data.presets);
  $("#clients").replaceChildren(...data.clients.map((c) => el("option", {value: c})));
  $("#report-client").replaceChildren(...data.clients.map((c) => el("option", {value: c, text: c})));
  $("#bulk-client").replaceChildren(...data.preset_clients.map((c) => el("option", {value: c, text: c})));
  $("#ai-client").replaceChildren(...data.clients.map((c) => el("option", {value: c, text: c})));
  for (const id of ["#triage-client", "#accept-client"]) {
    $(id).replaceChildren(...data.clients.map((c) => el("option", {value: c, text: c})));
  }
  renderAcceptProducts();
  $("#engagement").placeholder = data.default_engagement;
  updateProwlerHint();
  renderBulkPreview();
}

function presetStatus(p) {
  return p.blocker ? el("span", {class: "warn", text: `飛ばす: ${p.blocker}`}) : el("span", {class: "ok", text: "実行できる"});
}

function renderPresets(presets) {
  const box = $("#presets");
  if (!presets.length) {
    box.replaceChildren(el("p", {class: "hint", text: "プリセットはまだありません。"}));
    return;
  }
  box.replaceChildren(...presets.map((p) => el("div", {class: p.blocker ? "card blocked" : "card"},
    el("div", {class: "card-title", text: p.name}),
    el("div", {class: "card-meta", text: `${p.client} ・ ${TOOLS[p.tool] || p.tool}`}),
    p.note ? el("div", {class: "card-note", text: p.note}) : null,
    p.blocker
      ? el("div", {class: "card-blocker", text: p.blocker})
      : el("button", {type: "button", class: "primary", text: "実行", onclick: (e) => runPreset(p, e.currentTarget)}),
  )));
}

function renderBulkPreview() {
  const client = $("#bulk-client").value;
  const presets = (state.overview ? state.overview.presets : []).filter((p) => p.client === client);
  $("#bulk-preview").replaceChildren(...(presets.length
    ? presets.map((p) => el("li", {}, el("span", {text: `${p.name}(${TOOLS[p.tool] || p.tool})`}), " ", presetStatus(p)))
    : [el("li", {class: "hint", text: "この顧客のプリセットはありません。"})]));
}

function fillAcceptProducts() {
  const products = ((state.overview && state.overview.products) || {})[$("#accept-client").value] || [];
  $("#accept-product").replaceChildren(el("option", {value: "", text: "すべて"}),
    ...products.map((p) => el("option", {value: p, text: p})));
}

function renderAcceptProducts() {
  fillAcceptProducts();
  refreshAcceptPreview();
}

// リスク受容の見込み(仕分けが「リスク受容」の指摘の件数と、案件 × 理由のまとまり)
async function refreshAcceptPreview() {
  if ($("#tool").value !== "accept" || !$("#accept-client").value) return;
  const seq = ++state.previewSeq;
  const box = $("#accept-preview");
  box.replaceChildren(el("li", {class: "hint", text: "数えています…"}));
  state.acceptTotal = null;
  const query = new URLSearchParams({client: $("#accept-client").value, product: $("#accept-product").value,
                                     tier: $("#accept-tier").value});
  try {
    const data = await api(`/kit/api/accept-preview?${query}`);
    if (seq !== state.previewSeq) return;  // 選び直したあとの古い答え
    state.acceptTotal = data.total;
    box.replaceChildren(el("li", {text: data.summary}), ...data.batches.map((b) => el("li", {},
      el("span", {text: `${b.product} / ${b.engagement} / ${b.group}: ${b.count} 件`}), " ",
      b.enabled ? null : el("span", {class: "warn", text: "リスク受容(full)が無効なので飛ばす"}))));
  } catch (e) {
    if (seq === state.previewSeq) box.replaceChildren(el("li", {class: "warn", text: e.message}));
  }
}

async function runPreset(preset, button) {
  button.disabled = true;
  try {
    const {job} = await api("/kit/api/jobs", {body: {preset: preset.index}});
    showTab("jobs");
    openLog(job);
  } catch (e) {
    alert(e.message);
  } finally {
    button.disabled = false;
  }
}

function updateToolFields() {
  const tool = $("#tool").value;
  for (const box of $$(".tool-fields")) box.hidden = box.dataset.tool !== tool;
  $(".common-fields").hidden = ["all", "ai", "triage", "accept"].includes(tool);
  $("#scan-form button[type=submit]").textContent =
    {repository: "まとめて検査する", triage: "仕分けし直す", accept: "リスク受容を登録する"}[tool] || "検査を始める";
  if (tool === "accept") refreshAcceptPreview();
  const kind = $("#trivy-kind").value;
  $(".git-only").hidden = kind !== "git";
  $('.tool-fields[data-tool="trivy"] [data-pick="folder"]').hidden = !["git", "fs"].includes(kind);
}

function updateProwlerHint() {
  const hints = (state.overview && state.overview.prowler_hints) || {};
  $("#prowler-hint").textContent = `例: ${hints[$("#provider").value] || ""}`;
}

async function pickPath(button) {
  button.disabled = true;
  try {
    const {path} = await api("/kit/api/pick", {body: {kind: button.dataset.pick}});
    $(`[name="${button.dataset.for}"]`).value = path;
  } catch (e) {
    alert(e.message);
  } finally {
    button.disabled = false;
  }
}

async function submitScan(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.currentTarget));
  if (data.tool === "repository") {
    data.repository_target = (data.repository_target || "").trim();
    if (!data.repository_target) {
      $("#scan-message").className = "message error";
      $("#scan-message").textContent = "リポジトリのフォルダ、またはGitHubのURLを入力してください。";
      $('[name="repository_target"]').focus();
      return;
    }
  }
  let payload;
  if (data.tool === "all") {
    payload = {tool: "all", client: data.bulk_client};
  } else if (data.tool === "ai") {
    payload = {tool: "ai", client: data.ai_client, scope: data.ai_scope};
  } else if (data.tool === "triage") {
    payload = {tool: "triage", client: data.triage_client};
  } else if (data.tool === "accept") {
    const by = (data.accept_by || "").trim();
    if (!by) {
      $("#scan-message").className = "message error";
      $("#scan-message").textContent = "受け入れた人を入力してください。";
      return;
    }
    if (!state.acceptTotal) {
      $("#scan-message").className = "message error";
      $("#scan-message").textContent = "仕分けが「リスク受容」の有効な指摘がありません(見込みを確かめてください)。";
      return;
    }
    const tierName = $("#accept-tier").selectedOptions[0].text;
    if (!confirm(`仕分けが「リスク受容」の ${state.acceptTotal} 件(大項目: ${tierName})を、DefectDojo のリスク受容として登録します`
                 + `(受け入れた人: ${by}、期限: ${data.accept_days} 日)。よろしいですか?`)) return;
    // expect: 確かめた件数。登録のときに件数が変わっていれば(その間に仕分けし直したなど)、登録しない
    payload = {tool: "accept", client: data.accept_client, product: data.accept_product, by,
               days: data.accept_days, reactivate: data.accept_reactivate === "on", expect: state.acceptTotal,
               tier: data.accept_tier};
  } else {
    payload = {tool: data.tool, client: data.client, product: data.product,
               engagement: data.engagement || (state.overview && state.overview.default_engagement) || ""};
    if (data.tool === "repository") Object.assign(payload, {target: data.repository_target, branch: data.repository_branch});
    if (data.tool === "trivy") Object.assign(payload, {kind: data.kind, target: data.target, branch: data.branch});
    if (data.tool === "vuls") payload.config = data.config;
    if (data.tool === "prowler") Object.assign(payload, {provider: data.provider, args: data.args, label: data.label});
  }
  const message = $("#scan-message");
  message.className = "message";
  message.textContent = "始めています…";
  try {
    const {job} = await api("/kit/api/jobs", {body: payload});
    message.textContent = `始めました: ${job.title}`;
    showTab("jobs");
    openLog(job);
  } catch (e) {
    message.className = "message error";
    message.textContent = e.message;
  }
}

// ---- 実行状況 ----

async function refreshJobs() {
  const {jobs} = await api("/kit/api/jobs");
  const running = jobs.filter(active).length;
  const badge = $("#running-badge");
  badge.hidden = !running;
  badge.textContent = String(running);
  $("#jobs").replaceChildren(...(jobs.length ? jobs.map(jobRow) : [emptyRow(7, "まだ検査していません。")]));
  clearTimeout(state.jobsTimer);
  state.jobsTimer = setTimeout(() => refreshJobs().catch(() => {}), running ? 3000 : 15000);
}

function jobRow(job) {
  return el("tr", {},
    el("td", {text: fmtTime(job.started || job.created)}),
    el("td", {text: job.title}),
    el("td", {text: job.client}),
    el("td", {}, el("span", {class: `status ${job.status}`, text: STATUS[job.status] || job.status})),
    el("td", {text: duration(job)}),
    el("td", {}, el("div", {class: "links"}, ...(job.tests || []).map((id) => link(`/test/${id}`, `#${id}`)),
      job.argv && job.argv[0] === "repository-scan"
        ? el("button", {type: "button", text: "リポジトリ結果", onclick: () => showTab("repository-results")}) : null)),
    el("td", {class: "row-actions"},
      el("button", {type: "button", text: "ログ", onclick: () => openLog(job)}),
      active(job) ? el("button", {type: "button", text: "中止", onclick: () => cancelJob(job)}) : null),
  );
}

function openLog(job) {
  clearTimeout(state.log.timer);
  Object.assign(state.log, {id: job.id, offset: 0});
  $("#log-title").textContent = job.title;
  $("#log").textContent = "";
  $("#log-panel").hidden = false;
  pollLog();
}

async function pollLog() {
  const log = state.log;
  const id = log.id;
  if (!id) return;
  try {
    const data = await api(`/kit/api/jobs/${encodeURIComponent(id)}/log?offset=${log.offset}`);
    if (log.id !== id) return;
    if (data.text) {
      const pre = $("#log");
      const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 30;
      pre.append(data.text);
      if (atBottom) pre.scrollTop = pre.scrollHeight;
    }
    log.offset = data.offset;
    if (active(data.job) || data.text) log.timer = setTimeout(pollLog, active(data.job) ? 2000 : 300);
    else refreshJobs().catch(() => {});
  } catch (e) {
    $("#log").append(`\n[ログを読めません: ${e.message}]`);
  }
}

async function cancelJob(job) {
  if (!confirm(`「${job.title}」を中止しますか?`)) return;
  await api(`/kit/api/jobs/${encodeURIComponent(job.id)}/cancel`, {body: {}});
  await refreshJobs();
}

// ---- リポジトリの統合結果 ----

function filterRepositoryFindings(findings, {severity = "", category = "", query = ""} = {}) {
  const search = query.trim().toLocaleLowerCase();
  const order = SEVERITIES.map(([key]) => key);
  return findings.filter((f) => (!severity || f.severity === severity) && (!category || f.category === category)
    && (!search || [f.id, f.title, f.file, f.component, f.installed_version, f.fixed_version, f.description, f.mitigation]
      .map((value) => String(value || "")).join(" ").toLocaleLowerCase().includes(search)))
    .sort((a, b) => (order.indexOf(a.severity) < 0 ? 5 : order.indexOf(a.severity))
      - (order.indexOf(b.severity) < 0 ? 5 : order.indexOf(b.severity))
      || String(a.file || "").localeCompare(String(b.file || "")) || (a.line || 0) - (b.line || 0));
}

function repositoryScanMessage(scan) {
  const status = REPOSITORY_STATUSES[scan.status] || "状態未確認";
  const count = scan.counts && Number.isFinite(scan.counts.total) ? scan.counts.total : null;
  if (scan.status === "completed") return count === null ? `${status}・件数未確定` : `${status}・検出${fmt(count)}件`;
  return count === null ? status : `${status}・取得済みの検出候補${fmt(count)}件`;
}

function repositoryArtifactLink(href, label) {
  if (typeof href !== "string" || !href.startsWith("/kit/files/") || /[\\\x00-\x20\x7f?#]/.test(href)) return null;
  try {
    const parts = decodeURIComponent(href.slice("/kit/files/".length)).split("/");
    if (parts.some((part) => !part || part === "." || part === ".." || part.includes("\\"))) return null;
  } catch { return null; }
  return saveLink(href, label);
}

function repositoryBadge(status) {
  const known = Object.prototype.hasOwnProperty.call(REPOSITORY_STATUSES, status);
  return el("span", {class: `status ${known ? status : "partial"}`, text: known ? REPOSITORY_STATUSES[status] : "状態未確認"});
}

function repositoryFindingCard(finding) {
  const severity = SEVERITIES.some(([key]) => key === finding.severity) ? finding.severity : "Info";
  const severityName = SEVERITIES.find(([key]) => key === severity)[1];
  const location = finding.file ? `${finding.file}${Number.isInteger(finding.line) && finding.line > 0 ? `:${finding.line}` : ""}`
    : "場所の情報なし";
  const component = finding.component
    ? `${finding.component}${finding.installed_version ? ` ${finding.installed_version}` : ""}` : "";
  return el("article", {class: `panel repository-finding sev-${severity}`},
    el("div", {class: "repository-finding-meta"},
      el("span", {class: "status", text: `重大度: ${severityName}`}),
      el("span", {text: REPOSITORY_CATEGORIES[finding.category] || "種類未確認"}),
      el("span", {class: "hint", text: finding.tool || ""})),
    el("h3", {text: finding.title || finding.id || "検出候補"}),
    el("p", {class: "repository-location", text: location}),
    finding.id ? el("p", {class: "hint", text: `識別子: ${finding.id}`}) : null,
    component ? el("p", {text: `対象の部品: ${component}`}) : null,
    finding.fixed_version ? el("p", {text: `修正版: ${finding.fixed_version}`}) : null,
    finding.description ? el("div", {class: "repository-explanation"},
      el("strong", {text: "検出した理由"}), el("p", {text: finding.description})) : null,
    finding.mitigation ? el("div", {class: "repository-explanation"},
      el("strong", {text: "確認・修正の方針"}), el("p", {text: finding.mitigation})) : null);
}

function renderRepositoryScans() {
  const client = $("#repository-client").value;
  const scans = state.repository.scans.filter((scan) => !client || scan.client === client);
  $("#repository-scans").replaceChildren(...(scans.length ? scans.map((scan) => el("tr", {
    class: scan.id === state.repository.selected ? "selected" : ""},
    el("td", {text: fmtTime(scan.created)}),
    el("td", {}, el("strong", {text: scan.product}), el("div", {class: "hint", text: scan.client})),
    el("td", {}, el("code", {text: String(scan.commit || "未確定").slice(0, 12)}),
      el("div", {class: "hint", text: scan.branch || ""}),
      scan.fresh === false && scan.commit ? el("div", {class: "warn", text: "最新か未確認"}) : null),
    el("td", {}, repositoryBadge(scan.status), el("div", {class: "hint", text: repositoryScanMessage(scan)})),
    el("td", {}, el("button", {type: "button", text: "結果を見る", onclick: () => openRepositoryScan(scan.id)}))))
    : [emptyRow(5, "まだリポジトリの検査結果はありません。「検査する」から始められます。") ]));
}

async function refreshRepositoryScans() {
  const repo = state.repository;
  const seq = ++repo.listSeq;
  clearTimeout(repo.timer);
  const client = $("#repository-client").value;
  const message = $("#repository-message");
  message.className = "message";
  message.textContent = "一覧を取得しています…";
  try {
    const query = client ? `?${new URLSearchParams({client})}` : "";
    const {scans} = await api(`/kit/api/repository-scans${query}`);
    if (seq !== repo.listSeq) return;
    repo.scans = scans;
    repo.clients = [...new Set([...repo.clients, ...((state.overview && state.overview.clients) || []),
      ...scans.map((scan) => scan.client)])].sort();
    $("#repository-client").replaceChildren(el("option", {value: "", text: "すべての顧客"}),
      ...repo.clients.map((name) => el("option", {value: name, text: name})));
    $("#repository-client").value = client;
    renderRepositoryScans();
    message.textContent = `${fmt(scans.length)}件の検査結果。コードの検査結果であり、Webの安全性を保証するものではありません。`;
    const selected = scans.find((scan) => scan.id === repo.selected) || scans[0];
    if (selected) await openRepositoryScan(selected.id);
    else {
      repo.detailSeq++;
      repo.selected = null;
      repo.detail = null;
      $("#repository-detail").hidden = true;
    }
    if (seq === repo.listSeq && !$("#tab-repository-results").hidden
        && scans.some((scan) => ["queued", "running"].includes(scan.status))) {
      repo.timer = setTimeout(refreshRepositoryScans, 5000);
    }
  } catch (e) {
    if (seq !== repo.listSeq) return;
    message.className = "message error";
    message.textContent = `一覧を更新できませんでした: ${e.message}`;
  }
}

async function openRepositoryScan(id) {
  const repo = state.repository;
  const seq = ++repo.detailSeq;
  const changed = repo.selected !== id;
  repo.selected = id;
  if (changed) {
    repo.detail = null;
    repo.limit = 100;
    $("#repository-detail").hidden = true;
    $("#repository-message").textContent = "検査結果を取得しています…";
  }
  renderRepositoryScans();
  try {
    const {scan} = await api(`/kit/api/repository-scans/${encodeURIComponent(id)}`);
    if (seq !== repo.detailSeq) return;
    repo.detail = scan;
    $("#repository-detail").hidden = false;
    $("#repository-message").className = "message";
    $("#repository-message").textContent = "検出候補と、各検査の実施状況を確認してください。";
    renderRepositorySummary(scan);
    renderRepositoryFindings();
  } catch (e) {
    if (seq !== repo.detailSeq) return;
    $("#repository-message").className = "message error";
    $("#repository-message").textContent = `結果を取得できませんでした: ${e.message}`;
  }
}

function renderRepositorySummary(scan) {
  const categories = (scan.counts && scan.counts.category) || {};
  $("#repository-summary").replaceChildren(
    el("div", {class: "panel repository-summary"},
      el("h2", {text: `${scan.client} / ${scan.product}`}),
      el("p", {}, repositoryBadge(scan.status), " ", repositoryScanMessage(scan)),
      el("p", {class: "repository-location", text: `検査した版: ${scan.commit || "未確定"}（${scan.branch || "ブランチ未確定"}）`}),
      scan.fresh === false && scan.commit ? el("p", {class: "warn", text: "originに接続できず、手元に残る版で検査しました。最新かどうかは未確認です。"}) : null,
      el("div", {class: "repository-counts"}, ...Object.entries(REPOSITORY_CATEGORIES)
        .map(([key, label]) => el("span", {text: `${label}: ${fmt(categories[key])}件`}))),
      el("div", {class: "links"}, repositoryArtifactLink(scan.sbom, "SBOMを保存"), repositoryArtifactLink(scan.results, "結果JSONを保存")),
      el("p", {class: "hint", text: "SBOMは検査したリポジトリの部品一覧です。配備中の実体との一致や、すべての依存を網羅したことは保証しません。"})),
    el("h3", {text: "検査の実施状況"}),
    el("div", {class: "cards repository-stages"}, ...(scan.stages || []).map((stage) => el("div", {class: "card"},
      el("strong", {text: stage.name}), repositoryBadge(stage.status),
      el("p", {text: stage.message || ""}),
      Number.isFinite(stage.count) ? el("p", {class: "hint", text: `件数: ${fmt(stage.count)}件`}) : null,
      stage.version ? el("p", {class: "hint", text: `使用した版: ${stage.version}`}) : null))),
    el("p", {class: "hint", text: "検出候補は、周囲のコードや利用条件を確認して判断します。指摘0件でも、失敗・未実施・対象外の工程は検査済みとして扱いません。"}));
}

function renderRepositoryFindings() {
  const repo = state.repository;
  if (!repo.detail) return;
  const findings = filterRepositoryFindings(repo.detail.findings || [], {
    severity: $("#repository-severity").value, category: $("#repository-category").value, query: $("#repository-query").value});
  const shown = findings.slice(0, repo.limit);
  $("#repository-findings-count").textContent = `${fmt(shown.length)}件を表示 / 絞り込み後${fmt(findings.length)}件（全検出候補${fmt((repo.detail.findings || []).length)}件）`;
  $("#repository-findings").replaceChildren(...(shown.length ? shown.map(repositoryFindingCard)
    : [el("p", {class: "panel hint", text: "表示する検出候補はありません。上の検査状況と、絞り込み条件を確認してください。"})]));
  $("#repository-more").hidden = findings.length <= repo.limit;
}

// ---- 報告書 ----

async function refreshReports() {
  const {reports} = await api("/kit/api/reports");
  $("#reports").replaceChildren(...(reports.length ? reports.map((r) => el("tr", {},
    el("td", {text: fmtTime(r.created)}),
    el("td", {text: r.client}),
    el("td", {text: r.scope}),
    el("td", {class: "row-actions"},
      r.pdf ? link(r.pdf, "PDF を開く") : null,
      r.pdf ? saveLink(r.pdf, "PDF を保存") : null,
      r.csv ? saveLink(r.csv, "CSV を保存") : null,
      link(r.html, "HTML")),
  )) : [emptyRow(4, "まだ報告書はありません。")]));
}

async function submitReport(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;  // 2 度押しで、同じ秒に同じ名前の報告書を 2 つ作らない
  const message = $("#report-message");
  message.className = "message";
  message.textContent = "作っています…";
  try {
    const {job} = await api("/kit/api/jobs", {body: {tool: "report", client: data.client, tier: data.tier,
                                                     triage: data.triage, engagement: data.engagement}});
    const done = await waitJob(job);
    if (done.status !== "succeeded") throw new Error("作れませんでした。「実行状況」のログを見てください。");
    message.textContent = "できました。下の一覧から開くか、保存してください。";
    await refreshReports();
  } catch (e) {
    message.className = "message error";
    message.textContent = e.message;
  } finally {
    button.disabled = false;
  }
}

// ---- ダッシュボード(大項目のページ) ----

function storedClient() {
  try { return localStorage.getItem(CLIENT_KEY) || ""; } catch { return ""; }
}

async function loadDashClients() {
  const {clients} = await api("/kit/api/clients");
  state.dash.clients = clients;
  const select = $("#dash-client");
  select.replaceChildren(el("option", {value: "", text: "すべての顧客"}),
    ...clients.map((c) => el("option", {value: String(c.id), text: c.name})));
  const stored = storedClient();
  select.value = clients.some((c) => String(c.id) === stored) ? stored : "";
  state.dash.client = select.value;
}

function clientName() {
  const found = (state.dash.clients || []).find((c) => String(c.id) === state.dash.client);
  return found ? found.name : "";
}

async function refreshDashboard() {
  if (!state.dash.clients) await loadDashClients();
  for (const chip of $$("#tier-chips button")) chip.classList.toggle("active", chip.dataset.tier === state.dash.tier);
  const box = $("#dashboard");
  const seq = ++state.dash.seq;
  box.classList.add("loading");  // 読み込み直しの間は、前の描画を薄くして残す(押せないようにする)
  box.inert = true;
  try {
    const query = new URLSearchParams({tier: state.dash.tier, client: state.dash.client});
    const data = await api(`/kit/api/dashboard?${query}`);
    if (seq !== state.dash.seq) return;  // 選び直したあとの古い答え
    box.replaceChildren(...renderDashboard(data));
    if (state.dash.focus) focusSubitem(state.dash.focus);
  } catch (e) {
    // 前の描画は残さない(ボタンが前の顧客・大項目のまま押せてしまう)。選び直したあとの古い要求の失敗は出さない
    if (seq === state.dash.seq) box.replaceChildren(el("p", {class: "message error", text: `集計できませんでした: ${e.message}`}));
  } finally {
    if (seq === state.dash.seq) {
      box.classList.remove("loading");
      box.inert = false;
    }
  }
}

// 値を持つ印(棒の行・積み上げの区切り)。マウスでもキーボードのフォーカスでも、同じツールチップを出す
function tipped(node, value, label) {
  node.tabIndex = 0;
  node.dataset.tipValue = value;
  node.dataset.tipLabel = label;
  return node;
}

// 横棒(系列は 1 つ)。値は棒の先に書く。棒の行(余白を含む)をツールチップの当たり判定にする
function barList(rows) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  const list = el("div", {class: "bars"});
  for (const r of rows) {
    const bar = el("span", {class: "bar"});
    bar.style.width = `calc((100% - 4.5em) * ${r.value / max})`;
    bar.style.background = r.color;
    const track = tipped(el("span", {class: "bar-track"}, r.value ? bar : null,
                            el("span", {class: "bar-value", text: fmt(r.value)})), `${fmt(r.value)} 件`, r.tip);
    if (r.href) {  // 棒を押しても、名前のリンクと同じ一覧を開く(キーボードでは名前のリンクを使う)
      track.classList.add("clickable");
      track.addEventListener("click", () => window.open(r.href, "_blank", "noopener"));
    }
    list.append(el("span", {class: "bar-label"}, r.label), track);
  }
  return list;
}

// 積み上げの横棒(小項目 × 重大度)。区切りは 2px のすき間
function stackList(rows) {
  const max = Math.max(1, ...rows.map((r) => r.total));
  const list = el("div", {class: "bars"});
  for (const r of rows) {
    const stack = el("span", {class: "stack"});
    stack.style.width = `calc((100% - 4.5em) * ${r.total / max})`;
    for (const part of r.segments.filter((x) => x.value)) {
      const segment = tipped(el("span"), `${fmt(part.value)} 件`, part.tip);
      segment.style.flex = `${part.value} 1 0`;
      segment.style.background = part.color;
      stack.append(segment);
    }
    list.append(el("span", {class: "bar-label", text: r.label}),
      el("span", {class: "bar-track"}, r.total ? stack : null, el("span", {class: "bar-value", text: fmt(r.total)})));
  }
  return list;
}

function legend() {
  return el("div", {class: "legend"}, ...SEVERITIES.map(([key, ja]) => {
    const swatch = el("i");
    swatch.style.background = SEV_COLORS[key];
    return el("span", {}, swatch, ja);
  }));
}

// グラフと同じ数の表(ツールチップに頼らずに読める)
function tableView(head, rows) {
  return el("details", {class: "table-view"}, el("summary", {text: "表で見る"}),
    el("table", {class: "list"},
      el("thead", {}, el("tr", {}, ...head.map((h, i) => el("th", {class: i ? "num" : null, text: h})))),
      el("tbody", {}, ...rows.map((row) => el("tr", {},
        ...row.map((v, i) => el("td", {class: i ? "num" : null, text: i ? fmt(v) : v})))))));
}

function chartCard(title, ...children) {
  return el("figure", {class: "chart-card"}, el("figcaption", {text: title}), ...children);
}

function renderDashboard(data) {
  const scope = {tier: state.dash.tier, client: clientName()};  // 描いたときの範囲(ボタンはこの範囲で動く)
  const sevRows = SEVERITIES.map(([key, ja]) => ({label: ja, value: data.severities[key], color: SEV_COLORS[key], tip: ja}));
  const systemRows = data.systems.map((s) => ({label: link(s.url, s.name, {title: `${s.client} / ${s.name}`}), href: s.url,
                                                value: s.count, color: "var(--series-1)", tip: `${s.name}(${s.client})`}));
  if (data.other.count) {
    systemRows.push({label: el("span", {text: `その他(${data.other.systems} システム)`}), value: data.other.count,
                     color: "var(--series-1)", tip: "その他"});
  }
  const message = el("p", {class: "message", role: "status"});
  const toggle = el("button", {type: "button", "aria-expanded": String(state.dash.open)});
  const details = el("section", {class: "subitems", hidden: !state.dash.open},
    chartCard("小項目ごとの件数(重大度の内訳)", legend(),
      stackList(data.triage.map((t) => ({label: t.label, total: t.total, segments: SEVERITIES.map(([key, ja]) => (
        {value: t.severities[key], color: SEV_COLORS[key], tip: `${t.label} · ${ja}`}))}))),
      tableView(["小項目", ...SEVERITIES.map(([, ja]) => ja), "計"],
        data.triage.map((t) => [t.label, ...SEVERITIES.map(([key]) => t.severities[key]), t.total]))),
    data.untriaged ? el("p", {class: "hint", text: `仕分けのない指摘が ${fmt(data.untriaged)} 件あります(どの小項目にも`
                                                    + "入っていません。「検査する」の「仕分けし直す」で付きます)。"}) : null,
    el("div", {class: "sub-cards"}, ...data.triage.map((t) => subCard(scope, t))));
  const setOpen = (open) => {
    state.dash.open = open;
    details.hidden = !open;
    toggle.setAttribute("aria-expanded", String(open));
    toggle.textContent = open ? "詳細(小項目)を閉じる" : "詳細(小項目)を見る";
  };
  toggle.addEventListener("click", () => setOpen(!state.dash.open));
  setOpen(state.dash.open);
  const notes = data.scope.flatMap((c) => [
    ...c.skipped.map((s) => `${c.client}: 検査しなかった対象 ${s.name}(${s.reason})`),
    ...(c.unjudged ? [`${c.client}: 判定できなかった項目 ${c.unjudged} 件(今の権限では読めない設定など。指摘には数えない)`] : [])]);
  return [
    el("div", {class: "dash-head"}, el("h2", {text: data.name}), el("p", {text: data.meaning})),
    el("div", {class: "kpis"},
      el("div", {}, el("div", {class: "hero-label", text: "有効な指摘"}), el("div", {class: "hero-value", text: fmt(data.total)})),
      el("div", {class: "kpi-side"},
        data.review ? el("a", {href: "#systems", text: `うち分類を要確認 ${fmt(data.review)} 件(「分類の設定」で直す)`,
                               onclick: (e) => { e.preventDefault(); showTab("systems"); }}) : null,
        // 0 件の範囲は一覧のリンクを出さない(小項目の tags_and は、DefectDojo にまだないタグがあると絞り込みが外れ、
        // 関係のない一覧が開く。大項目もそろえる)
        el("div", {class: "links"}, data.total ? link(data.findings_url, "一覧を開く(DefectDojo)") : null,
          ...saveButtons(scope, message)),
        message)),
    el("div", {class: "charts"},
      chartCard("重大度ごとの件数", barList(sevRows), tableView(["重大度", "件数"], sevRows.map((r) => [r.label, r.value]))),
      chartCard(`システムごとの件数(多い順に ${data.systems.length} システム${data.other.count ? "と、その他" : ""})`,
        data.systems.length ? barList(systemRows) : el("p", {class: "hint", text: "有効な指摘はありません。"}),
        tableView(["システム", "件数"], [...data.systems.map((s) => [s.name, s.count]),
                                        ...(data.other.count ? [["その他", data.other.count]] : [])]))),
    el("div", {class: "detail-toggle"}, toggle),
    details,
    notes.length ? el("ul", {class: "hint scope-note"}, ...notes.map((text) => el("li", {text}))) : null,
  ].filter(Boolean);
}

function subCard(scope, t) {
  const message = el("p", {class: "message", role: "status"});
  return el("div", {class: "sub-card", "data-key": t.key},
    el("div", {class: "sub-label", text: t.label}),
    el("div", {class: "sub-value", text: `${fmt(t.total)} 件`}),
    el("div", {class: "links"}, t.total ? link(t.findings_url, "一覧を開く") : null,
      ...saveButtons({...scope, triage: t.key}, message),
      t.key === "accept" ? el("button", {type: "button", text: "登録へ", onclick: () => goAccept(scope)}) : null),
    message);
}

function focusSubitem(key) {
  const card = $(`.sub-card[data-key="${key}"]`);  // key は TRIAGE_KEYS のどれか(route で確かめた)
  if (!card) return;
  for (const other of $$(".sub-card")) other.classList.toggle("focus", other === card);
  card.scrollIntoView({block: "center"});
}

// 範囲(顧客・大項目・小項目)の PDF と CSV のボタン。作っている間は、両方とも押せない
function saveButtons(scope, message) {
  const buttons = ["PDF", "CSV"].map((text) => el("button", {type: "button", text}));
  for (const button of buttons) {
    button.addEventListener("click", () => downloadScope(scope, button.textContent.toLowerCase(), message, buttons));
  }
  return buttons;
}

// 範囲の報告書を作り、PDF か CSV を保存する(報告書は顧客ごとに作る。保存するのは、このジョブが作ったもの)
async function downloadScope(scope, kind, message, buttons) {
  if (!scope.client) {
    message.className = "message error";
    message.textContent = "PDF・CSV は顧客ごとに作ります。上の「顧客」で選んでください。";
    return;
  }
  for (const button of buttons) button.disabled = true;
  message.className = "message";
  message.textContent = "作っています…(件数が多いと数十秒かかります)";
  try {
    const {job} = await api("/kit/api/jobs", {body: {tool: "report", client: scope.client, tier: scope.tier,
                                                     triage: scope.triage || ""}});
    const done = await waitJob(job);
    if (done.status !== "succeeded") throw new Error("作れませんでした。「実行状況」のログを見てください。");
    const files = await api(`/kit/api/jobs/${encodeURIComponent(job.id)}/report`);
    if (!files[kind]) {
      throw new Error(kind === "pdf" ? "PDF を作れませんでした(Chrome が要ります)。「報告書」のタブの HTML を印刷してください。"
        : "CSV が見つかりません。「実行状況」のログを見てください。");
    }
    message.textContent = "できました。保存します(「報告書」のタブにも残ります)。";
    saveLink(files[kind], "").click();
  } catch (e) {
    message.className = "message error";
    message.textContent = e.message;
  } finally {
    for (const button of buttons) button.disabled = false;
  }
}

// リスク受容の登録(検査するのタブ)へ、顧客と大項目を選んだ状態で移る
function goAccept(scope) {
  showTab("scan");
  $("#tool").value = "accept";
  if (scope.client) $("#accept-client").value = scope.client;
  $("#accept-tier").value = scope.tier;
  fillAcceptProducts();  // 顧客のシステムの一覧を入れ替える
  updateToolFields();  // 入力欄とボタンを「リスク受容を登録する」に切り替え、見込みを数える
}

function setupTooltips() {
  const tip = el("div", {class: "tip", role: "tooltip", hidden: true});
  document.body.append(tip);
  const show = (target, x, y) => {
    tip.replaceChildren(el("strong", {text: target.dataset.tipValue}), el("span", {text: target.dataset.tipLabel}));
    tip.hidden = false;
    tip.style.left = `${Math.min(x, innerWidth - tip.offsetWidth - 8)}px`;
    tip.style.top = `${Math.min(y, innerHeight - tip.offsetHeight - 8)}px`;
  };
  const marked = (node) => (node instanceof Element ? node.closest("[data-tip-value]") : null);
  document.addEventListener("pointermove", (e) => {
    const target = marked(e.target);
    if (target) show(target, e.clientX + 12, e.clientY + 12);
    else tip.hidden = true;
  });
  document.addEventListener("focusin", (e) => {
    const target = marked(e.target);
    if (!target) return;
    const box = target.getBoundingClientRect();
    show(target, box.left + 8, box.bottom + 6);
  });
  document.addEventListener("focusout", () => { tip.hidden = true; });
}

// ---- 分類の設定 ----

async function refreshSystems() {
  const box = $("#systems");
  box.replaceChildren(el("p", {class: "hint", text: "読み込んでいます…"}));
  const {clients, exposures} = await api("/kit/api/systems");
  box.replaceChildren(...clients.map((c) => systemsPanel(c, exposures)));
}

function systemsPanel(client, exposures) {
  const rows = client.systems.map((s) => {
    const select = el("select", {name: "exposure"},
      ...Object.entries(exposures).map(([key, label]) => el("option", {value: key, text: label})));
    select.value = s.exposure;
    return el("tr", {"data-product": s.name},
      el("td", {text: s.name}),
      el("td", {}, select),
      el("td", {text: {private: "非公開", public: "公開", internal: "組織内"}[s.visibility] || "-"}),
      el("td", {text: SOURCES[s.source] || s.source || "-"}),
      el("td", {}, el("input", {name: "reason", value: s.reason})),
      el("td", {}, el("textarea", {name: "paths", rows: Math.max(1, s.paths.split("\n").length), value: s.paths,
                                   placeholder: "パス=公開範囲"})));
  });
  const message = el("p", {class: "message", role: "status"});
  const save = el("button", {type: "button", class: "primary", text: "保存して分類し直す"});
  const panel = el("div", {class: "panel"},
    el("h3", {text: client.client}),
    el("div", {class: "scroll-x"}, el("table", {class: "list systems"},
      el("thead", {}, el("tr", {}, ...["システム", "公開範囲", "リポジトリ", "出典", "根拠", "パスの例外"]
        .map((t) => el("th", {text: t})))),
      el("tbody", {}, ...rows))),
    el("div", {class: "actions"}, save), message);
  save.addEventListener("click", async () => {
    save.disabled = true;
    message.className = "message";
    message.textContent = "保存しています…";
    const systems = rows.map((tr) => ({product: tr.dataset.product, exposure: tr.querySelector("[name=exposure]").value,
      reason: tr.querySelector("[name=reason]").value, paths: tr.querySelector("[name=paths]").value}));
    try {
      const {job} = await api("/kit/api/systems", {body: {client: client.client, systems}});
      message.textContent = "保存しました。分類し直しています…(実行状況でも見られます)";
      const done = await waitJob(job);
      message.textContent = done.status === "succeeded" ? "分類し直しました。「ダッシュボード」で確かめられます。"
        : "分類し直せませんでした。「実行状況」のログを見てください。";
    } catch (e) {
      message.className = "message error";
      message.textContent = e.message;
    } finally {
      save.disabled = false;
    }
  });
  return panel;
}

// ---- 初期化 ----

document.addEventListener("DOMContentLoaded", () => {
  for (const button of $$(".tabs button")) button.addEventListener("click", () => showTab(button.dataset.tab));
  $("#tool").addEventListener("change", updateToolFields);
  $("#trivy-kind").addEventListener("change", updateToolFields);
  $("#provider").addEventListener("change", updateProwlerHint);
  $("#repository-refresh").addEventListener("click", refreshRepositoryScans);
  $("#repository-client").addEventListener("change", () => {
    state.repository.selected = null;
    state.repository.detailSeq++;
    $("#repository-detail").hidden = true;
    refreshRepositoryScans();
  });
  for (const id of ["#repository-severity", "#repository-category", "#repository-query"]) {
    $(id).addEventListener(id === "#repository-query" ? "input" : "change", () => {
      state.repository.limit = 100;
      renderRepositoryFindings();
    });
  }
  $("#repository-more").addEventListener("click", () => {
    state.repository.limit += 100;
    renderRepositoryFindings();
  });
  $("#bulk-client").addEventListener("change", renderBulkPreview);
  $("#accept-client").addEventListener("change", renderAcceptProducts);
  $("#accept-product").addEventListener("change", refreshAcceptPreview);
  for (const button of $$("[data-pick]")) button.addEventListener("click", () => pickPath(button));
  for (const chip of $$("#tier-chips button")) {
    chip.addEventListener("click", () => {
      state.dash.tier = chip.dataset.tier;
      state.dash.focus = null;
      showTab("dashboard");
    });
  }
  $("#dash-client").addEventListener("change", (event) => {
    state.dash.client = event.target.value;
    try { localStorage.setItem(CLIENT_KEY, state.dash.client); } catch { /* 保存できなくても、この画面では効く */ }
    refreshDashboard().catch((e) => alert(e.message));
  });
  $("#accept-tier").addEventListener("change", refreshAcceptPreview);
  window.addEventListener("hashchange", () => showTab(route(location.hash.slice(1))));
  setupTooltips();
  $("#scan-form").addEventListener("submit", submitScan);
  $("#report-form").addEventListener("submit", submitReport);
  $("#log-close").addEventListener("click", () => {
    clearTimeout(state.log.timer);
    state.log.id = null;
    $("#log-panel").hidden = true;
  });
  updateToolFields();
  loadOverview().catch((e) => alert(e.message));
  const tab = route(location.hash.slice(1));
  showTab(tab);
  if (tab !== "jobs") refreshJobs().catch(() => {});
});
