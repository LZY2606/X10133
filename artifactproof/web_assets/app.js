"use strict";

const state = { a: null, b: null, session: null, archives: [] };

const VERDICT_TEXT = {
  reproducible: "可复现：两份归档在该策略下完全一致。",
  equivalent_under_policy: "策略等价：仅存在声明为可忽略的差异。",
  content_differs: "不可复现：存在真实内容差异。",
  quarantined: "无法判定：至少一份归档进入隔离状态。",
};

function toast(msg) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.style.display = "block";
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.style.display = "none"; }, 3200);
}

async function api(path, options) {
  const resp = await fetch(path, options || {});
  const text = await resp.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
  if (!resp.ok) {
    throw new Error((data && data.error) || ("HTTP " + resp.status));
  }
  return data;
}

function esc(value) {
  return String(value === null || value === undefined ? "" : value)
    .replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
}

async function refreshArchives(keepA, keepB) {
  const data = await api("/api/archives");
  state.archives = data.archives;
  for (const side of ["A", "B"]) {
    const select = document.getElementById("select" + side);
    select.innerHTML = '<option value="">— 已上传归档 —</option>';
    for (const arc of state.archives) {
      const opt = document.createElement("option");
      opt.value = arc.upload_id;
      opt.textContent = (arc.filename || arc.upload_id.slice(0, 8))
        + "  " + arc.content_hash.slice(0, 19)
        + (arc.quarantined ? "  [隔离]" : "");
      select.appendChild(opt);
    }
  }
  if (keepA) document.getElementById("selectA").value = keepA;
  if (keepB) document.getElementById("selectB").value = keepB;
  await refreshPolicies();
}

async function refreshPolicies() {
  const data = await api("/api/policies");
  const select = document.getElementById("policySelect");
  select.innerHTML = '<option value="">strict（默认，全部差异都算真实）</option>';
  for (const item of data.policies) {
    const opt = document.createElement("option");
    opt.value = item.id;
    opt.dataset.version = item.version;
    opt.textContent = item.id + " v" + item.version;
    select.appendChild(opt);
  }
}

function describeArchive(arc) {
  const m = arc.manifest;
  const quar = m.quarantine;
  let lines = [
    "sha256: " + arc.content_hash,
    "清单哈希: " + arc.manifest_hash,
    "格式: " + m.format + " / " + m.compression,
    "大小: " + arc.size_bytes + " 字节，成员: " + m.entries.length,
  ];
  if (quar) {
    lines.push("隔离原因: " + quar.code + " — " + quar.reason
      + "（安全前缀 " + quar.prefix_length + " 个成员）");
  }
  if (arc.blob_reused) lines.push("（相同字节已存在，复用 blob）");
  return lines.join("<br>");
}

function setSide(side, arc) {
  const key = side.toLowerCase();
  state[key] = arc;
  const drop = document.getElementById("drop" + side);
  const info = document.getElementById("info" + side);
  drop.classList.add("uploaded");
  drop.classList.toggle("quarantined", !!arc.manifest.quarantine);
  drop.innerHTML = "<strong>" + esc(arc.filename || arc.upload_id.slice(0, 8))
    + "</strong><br><span class='muted'>点击可重新选择</span>";
  info.innerHTML = describeArchive(arc);
  document.getElementById("select" + side).value = arc.upload_id;
}

async function uploadFile(side, file) {
  const drop = document.getElementById("drop" + side);
  drop.textContent = "上传中…";
  try {
    const data = await file.arrayBuffer();
    const url = "/api/archives?filename=" + encodeURIComponent(file.name);
    const arc = await api(url, { method: "POST", body: data });
    arc.filename = file.name;
    await refreshArchives(arc.upload_id, state.b ? state.b.upload_id : null);
    setSide(side, arc);
  } catch (e) {
    drop.textContent = "拖入归档，或点击选择";
    toast("上传失败: " + e.message);
  }
}

function bindDrop(side) {
  const drop = document.getElementById("drop" + side);
  const input = document.getElementById("file" + side);
  drop.addEventListener("click", () => input.click());
  input.addEventListener("change", () => {
    if (input.files[0]) uploadFile(side, input.files[0]);
  });
  drop.addEventListener("dragover", (e) => {
    e.preventDefault(); drop.classList.add("dragover");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("dragover"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("dragover");
    const file = e.dataTransfer.files[0];
    if (file) uploadFile(side, file);
  });
}

function readPolicyForm() {
  let modeMask = 0;
  const raw = document.getElementById("modeMask").value.trim();
  if (raw) {
    modeMask = parseInt(raw.startsWith("0") ? raw : raw, raw.match(/^[0-7]+$/) ? 8 : 16);
    if (Number.isNaN(modeMask)) modeMask = 0;
  }
  return {
    ignore_mtime: document.getElementById("igMtime").checked,
    ignore_uidgid: document.getElementById("igUidGid").checked,
    ignore_compression_params: document.getElementById("igComp").checked,
    ignore_order: document.getElementById("igOrder").checked,
    mode_mask: modeMask,
  };
}

function applyPolicyForm(p) {
  document.getElementById("igMtime").checked = !!p.ignore_mtime;
  document.getElementById("igUidGid").checked = !!p.ignore_uidgid;
  document.getElementById("igComp").checked = !!p.ignore_compression_params;
  document.getElementById("igOrder").checked = !!p.ignore_order;
  document.getElementById("modeMask").value = (p.mode_mask || 0).toString(8);
}

async function savePolicy() {
  const name = document.getElementById("newPolicyName").value.trim();
  if (!name) { toast("请填写策略 id"); return null; }
  const saved = await api("/api/policies", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: name, policy: readPolicyForm() }),
  });
  await refreshPolicies();
  document.getElementById("policySelect").value = name;
  toast("已保存 " + name + " v" + saved.version);
  return name;
}

function diffLine(diff) {
  const tag = diff.ignored
    ? "<span class='tag ignored'>可忽略</span>"
    : "<span class='tag real'>真实</span>";
  const field = esc(diff.field);
  const lv = diff.left === undefined ? "∅" : esc(JSON.stringify(diff.left));
  const rv = diff.right === undefined ? "∅" : esc(JSON.stringify(diff.right));
  return "<span class='pill'>" + tag + " " + field
    + ": <span class='mono'>" + lv + "</span>"
    + " → <span class='mono'>" + rv + "</span></span>";
}

function renderSession(session) {
  state.session = session;
  const result = session.result;

  const verdict = document.getElementById("verdict");
  verdict.hidden = false;
  verdict.className = "verdict " + result.verdict;
  verdict.textContent = "结论：" + (VERDICT_TEXT[result.verdict] || result.verdict);

  const quar = document.getElementById("quarantinePanel");
  if (result.quarantine_notes.length) {
    quar.innerHTML = result.quarantine_notes.map((n) =>
      "<div class='card'><span class='tag quar'>隔离 · 侧 " + esc(n.side) + "</span> "
      + esc(n.code) + " — " + esc(n.reason)
      + "（已扫描安全前缀 " + n.prefix_length + " 个成员，未在磁盘留下解压文件）</div>"
    ).join("");
  } else {
    quar.innerHTML = "";
  }

  const panels = document.getElementById("diffPanels");
  const archReal = (result.real_differences || []).map(diffLine).join("");
  const archIgn = (result.ignorable_differences || []).map(diffLine).join("");

  const memberRows = result.member_diffs.map((md) => {
    const realPills = md.real.map(diffLine).join(" ");
    const ignPills = md.ignorable.map(diffLine).join(" ");
    return "<tr><td class='path mono'>" + esc(md.path) + "</td>"
      + "<td><div class='diff-fields'>" + realPills + "</div></td>"
      + "<td><div class='diff-fields'>" + ignPills + "</div></td></tr>";
  }).join("");

  const onlyA = result.only_in_a.map((p) =>
    "<span class='pill tag real'>仅 A</span> <span class='mono'>" + esc(p) + "</span>")
    .join("<br>");
  const onlyB = result.only_in_b.map((p) =>
    "<span class='pill tag real'>仅 B</span> <span class='mono'>" + esc(p) + "</span>")
    .join("<br>");

  panels.innerHTML =
    "<h2 class='section-title'>归档级差异</h2>"
    + "<div class='card'><b>真实内容差异</b><div class='diff-fields' style='margin-top:6px'>"
    + (archReal || "<span class='tag good'>无</span>") + "</div>"
    + "<b style='display:block;margin-top:10px'>可忽略差异</b>"
    + "<div class='diff-fields' style='margin-top:6px'>"
    + (archIgn || "<span class='tag good'>无</span>") + "</div></div>"

    + "<h2 class='section-title'>逐成员差异</h2>"
    + "<div class='card'><table><thead><tr><th>路径</th><th>真实内容差异</th>"
    + "<th>可忽略差异</th></tr></thead><tbody>"
    + (memberRows || "<tr><td colspan='3'><span class='tag good'>成员一致</span></td></tr>")
    + "</tbody></table></div>"

    + "<h2 class='section-title'>成员集合差异</h2>"
    + "<div class='card grid'><div><b>仅存在于 A</b><br>"
    + (onlyA || "<span class='muted'>无</span>") + "</div>"
    + "<div><b>仅存在于 B</b><br>" + (onlyB || "<span class='muted'>无</span>")
    + "</div></div>"

    + "<div class='toolbar'><a href='/api/sessions/"
    + encodeURIComponent(session.session_id)
    + "/proof' download><button type='button'>导出字节稳定 JSON 证明</button></a>"
    + "<span class='kv mono'>proof_hash: " + esc(session.proof.proof_hash) + "</span></div>";
}

async function compare() {
  if (!state.a || !state.b) { toast("请先选择或拖入两份归档"); return; }
  const policySel = document.getElementById("policySelect");
  const body = {
    archive_a: state.a.upload_id,
    archive_b: state.b.upload_id,
  };
  if (policySel.value) {
    body.policy_id = policySel.value;
    body.policy_version = parseInt(
      policySel.selectedOptions[0].dataset.version || "0", 10
    );
  }
  try {
    const session = await api("/api/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    renderSession(session);
  } catch (e) {
    toast("比较失败: " + e.message);
  }
}

async function loadSelected(side) {
  const id = document.getElementById("select" + side).value;
  if (!id) return;
  const arc = await api("/api/archives/" + encodeURIComponent(id));
  state[side.toLowerCase()] = arc;
  const drop = document.getElementById("drop" + side);
  drop.classList.add("uploaded");
  drop.classList.toggle("quarantined", !!arc.manifest.quarantine);
  drop.innerHTML = "<strong>" + esc(arc.filename || id.slice(0, 8))
    + "</strong><br><span class='muted'>已选择</span>";
  document.getElementById("info" + side).innerHTML = describeArchive(arc);
}

async function init() {
  bindDrop("A");
  bindDrop("B");
  document.getElementById("selectA").addEventListener(
    "change", () => loadSelected("A"));
  document.getElementById("selectB").addEventListener(
    "change", () => loadSelected("B"));
  document.getElementById("compareBtn").addEventListener("click", compare);
  document.getElementById("newPolicyBtn").addEventListener(
    "click", savePolicy);
  document.getElementById("policySelect").addEventListener("change", async () => {
    const sel = document.getElementById("policySelect");
    if (!sel.value) { applyPolicyForm({}); return; }
    const data = await api("/api/policies");
    const item = data.policies.find((p) => p.id === sel.value);
    if (item) applyPolicyForm(item.policy);
  });
  await refreshArchives();
}

init();
