"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.attributes = {}; this.events = {}; this.text = ""; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map((c) => typeof c === "string" ? c : c.textContent).join(""); }
  set innerHTML(_) { throw new Error("Scanner text must not become HTML"); }
  setAttribute(name, value) { this.attributes[name] = value; }
  addEventListener(name, handler) { this.events[name] = handler; }
  append(...children) { this.children.push(...children.map((c) => typeof c === "object" ? c : String(c))); }
  replaceChildren(...children) { this.children = []; this.text = ""; this.append(...children); }
  focus() { this.focused = true; }
}

const document = {addEventListener() {}, createElement: (tag) => new Element(tag)};
class FormDataMock {
  constructor(form) { this.entries = Object.entries(form); }
  [Symbol.iterator]() { return this.entries[Symbol.iterator](); }
}
const context = vm.createContext({document, FormData: FormDataMock, URLSearchParams, setTimeout, clearTimeout});
vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/app.js"), "utf8"), context);

const findings = [
  {id: "CVE-a", category: "dependency", severity: "High", component: "lodash", installed_version: "4.0.0",
    file: "web/package-lock.json", title: "Prototype pollution"},
  {id: "sql", category: "code", severity: "High", file: "api/query.py", title: "SQL input", description: "外部入力"},
  {id: "debug", category: "config", severity: "Medium", file: "api/Dockerfile", title: "debug enabled"},
];

test("filters the complete findings by severity, category and searchable context together", () => {
  const matched = context.filterRepositoryFindings(findings, {severity: "High", category: "dependency", query: "LODASH"});
  assert.deepEqual(Array.from(matched, (f) => f.id), ["CVE-a"]);
  assert.equal(context.filterRepositoryFindings(findings, {severity: "High", category: "code", query: "外部入力"}).length, 1);
  assert.equal(context.filterRepositoryFindings(findings, {severity: "Low", category: "", query: ""}).length, 0);
});

test("search also matches paths and installed versions without changing the original findings", () => {
  const original = JSON.stringify(findings);
  assert.equal(context.filterRepositoryFindings(findings, {query: "package-lock"})[0].id, "CVE-a");
  assert.equal(context.filterRepositoryFindings(findings, {query: "4.0.0"})[0].id, "CVE-a");
  assert.equal(JSON.stringify(findings), original);
});

test("zero findings do not turn failed, incomplete or unexecuted scans into a clean result", () => {
  assert.match(context.repositoryScanMessage({status: "failed", counts: {total: 0}}), /失敗/);
  assert.match(context.repositoryScanMessage({status: "partial", counts: {total: 0}}), /未完了/);
  assert.match(context.repositoryScanMessage({status: "unavailable", counts: {total: 0}}), /未実施/);
  assert.match(context.repositoryScanMessage({status: "not_applicable", counts: {total: 0}}), /対象/);
  assert.match(context.repositoryScanMessage({status: "interrupted", counts: {total: 0}}), /中断/);
  assert.match(context.repositoryScanMessage({status: "canceled", counts: {total: 0}}), /中止/);
  const completed = context.repositoryScanMessage({status: "completed", counts: {total: 0}});
  assert.match(completed, /検出0件/);
  assert.doesNotMatch(completed, /安全|問題なし/);
});

test("SBOM and results downloads only link to internal artifact paths", () => {
  const link = context.repositoryArtifactLink("/kit/files/A/repository-scans/scan-a/sbom.json", "SBOMを保存");
  assert.equal(link.attributes.href, "/kit/files/A/repository-scans/scan-a/sbom.json?download=1");
  assert.equal(link.textContent, "SBOMを保存");
  for (const href of [null, "https://evil.test/a", "//evil.test/a", "javascript:alert(1)",
    "/kit/files/../secret.json", "/kit/files/%2e%2e/secret.json", "/kit/files/a\\b.json", "/kit/files/a.json#x"]) {
    assert.equal(context.repositoryArtifactLink(href, "download"), null, String(href));
  }
});

test("hostile scanner values stay text throughout a finding card", () => {
  const attack = '<img src=x onerror="alert(1)">';
  const card = context.repositoryFindingCard({id: attack, title: attack, category: "code", severity: "High",
    file: attack, line: 7, description: attack, mitigation: attack});
  assert.match(card.textContent, /<img src=x/);
  const descendants = (node) => [node, ...node.children.flatMap((c) => typeof c === "object" ? descendants(c) : [])];
  assert.equal(descendants(card).filter((n) => n.tagName === "img" || n.tagName === "script" || n.tagName === "a").length, 0);
  assert.match(card.textContent, /7/);
});

test("repository submission selects its own fields even when hidden Trivy values remain in the form", async () => {
  const message = new Element("p");
  const bodies = [];
  document.querySelector = () => message;
  context.fetch = async (_url, options) => {
    bodies.push(JSON.parse(options.body));
    return {ok: true, headers: {get: () => "application/json"}, json: async () => ({job: {title: "検査"}})};
  };
  const showTab = context.showTab;
  const openLog = context.openLog;
  context.showTab = () => {};
  context.openLog = () => {};
  try {
    await context.submitScan({preventDefault() {}, currentTarget: {tool: "repository", client: "A",
      repository_target: "/repos/current", repository_branch: "main", target: "/repos/hidden-old", branch: "dev"}});
    assert.equal(bodies[0].target, "/repos/current");
    assert.equal(bodies[0].branch, "main");
    assert.equal(bodies[0].tool, "repository");
    await context.submitScan({preventDefault() {}, currentTarget: {tool: "trivy", client: "A", kind: "git",
      target: "/repos/existing", branch: "dev", repository_target: "/repos/hidden-new"}});
    assert.equal(bodies[1].target, "/repos/existing");
    assert.equal(bodies[1].branch, "dev");
    assert.equal(bodies[1].tool, "trivy");
  } finally {
    context.showTab = showTab;
    context.openLog = openLog;
  }
});

test("an empty repository target shows an actionable message without starting a job", async () => {
  const message = new Element("p");
  const input = new Element("input");
  document.querySelector = (selector) => selector === "#scan-message" ? message : input;
  let requests = 0;
  context.fetch = async () => {
    requests++;
    return {ok: true, headers: {get: () => "application/json"}, json: async () => ({job: {title: "検査"}})};
  };
  await context.submitScan({preventDefault() {}, currentTarget: {tool: "repository", client: "A", repository_target: "  "}});
  assert.equal(requests, 0);
  assert.match(message.textContent, /リポジトリ/);
  assert.match(message.textContent, /入力/);
  assert.equal(input.focused, true);
});

test("a slower previous detail request cannot replace the repository selected afterward", async () => {
  const nodes = new Map();
  document.querySelector = (selector) => {
    if (!nodes.has(selector)) { const node = new Element("div"); node.value = ""; nodes.set(selector, node); }
    return nodes.get(selector);
  };
  const pending = new Map();
  context.fetch = (url) => new Promise((resolve) => pending.set(url, (scan) => resolve({
    ok: true, headers: {get: () => "application/json"}, json: async () => ({scan})})));
  const earlier = context.openRepositoryScan("earlier");
  const latest = context.openRepositoryScan("latest");
  const detail = (id) => ({id, client: "A", product: id, status: "completed", counts: {total: 0}, stages: [], findings: []});
  pending.get("/kit/api/repository-scans/latest")(detail("latest"));
  await latest;
  pending.get("/kit/api/repository-scans/earlier")(detail("earlier"));
  await earlier;
  assert.match(nodes.get("#repository-summary").textContent, /A \/ latest/);
  assert.doesNotMatch(nodes.get("#repository-summary").textContent, /earlier/);
});

test("source acquisition failure is not described as a scan of a local fallback commit", () => {
  const summary = new Element("div");
  document.querySelector = () => summary;
  const scan = {client: "A", product: "repo", status: "failed", fresh: false, commit: "", counts: {total: 0}, stages: []};
  context.renderRepositorySummary(scan);
  assert.doesNotMatch(summary.textContent, /手元に残る版で検査/);
  context.renderRepositorySummary({...scan, status: "partial", commit: "a".repeat(40)});
  assert.match(summary.textContent, /手元に残る版で検査/);
});
