"use strict";

const state = { a: null, b: null, lastProof: null, lastSession: null };

function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.style.display = "block";
  clearTimeout(t._timer);
  t._timer = setTimeout(() => (t.style.display = "none"), 2600);
}

async function api(path, opts) {
  const res = await fetch(path, opts || {});
  const ct = res.headers.get("content-type") || "";
  const data = ct.includes("json") ? await res.json() : await res.text();
  if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
  return data;
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function short(h) { return h ? h.slice(0, 12) + "…" : "—"; }
function oct(m) { return m == null ? "—" : ("0000" + m.toString(8)).slice(-4); }
function fmtTime(ts) {
  if (ts == null) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function bindDrop(role, dropId, inputId, metaId) {
  const drop = document.getElementById(dropId);
  const input = document.getElementById(inputId);
  drop.addEventListener("click", () => input.click());
  drop.addEventListener("dragover", e => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", e => {
    e.preventDefault();
    drop.classList.remove("over");
    if (e.dataTransfer.files.length) uploadFile(role, e.dataTransfer.files[0], metaId);
  });
  input.addEventListener("change", () => {
    if (input.files.length) uploadFile(role, input.files[0], metaId);
  });
}

async function uploadFile(role, file, metaId) {
  const fd = new FormData();
  fd.append("file", file, file.name);
  document.getElementById(metaId).textContent = "上传并安全扫描中…";
  try {
    const data = await api("/api/archives", { method: "POST", body: fd });
    const rec = data.archives[0];
    state[role] = rec;
    const statusHtml = rec.quarantined
      ? '<span class="chip q">已隔离</span><div>' + esc(rec.quarantine_reason) +
        (rec.quarantine_path ? '（' + esc(rec.quarantine_path) + '）' : '') +
        '<div class="muted">安全前缀：' + (rec.safe_prefix.map(esc).join(" / ") || "（无）") + '</div></div>'
      : '<span class="chip">成员 ' + rec.member_count + '</span>';
    document.getElementById(metaId).innerHTML =
      '<div><b>' + esc(rec.filename) + '</b> ' + statusHtml + '</div>' +
      '<div class="mono">' + esc(rec.family) + '/' + esc(rec.compression) +
      ' · ' + rec.blob_size + ' B · ' + short(rec.blob_sha256) +
      (rec.blob_reused ? ' · <b>blob 复用</b>' : '') + '</div>';
    refreshReady();
    await loadArchives();
  } catch (e) {
    document.getElementById(metaId).textContent = "上传失败：" + e.message;
  }
}

function refreshReady() {
  document.getElementById("compareBtn").disabled = !(state.a && state.b);
}

async function loadPolicies() {
  const data = await api("/api/policies");
  const sel = document.getElementById("policySel");
  sel.innerHTML = "";
  for (const p of data.policies) {
    const latest = p.versions[p.versions.length - 1];
    const opt = document.createElement("option");
    opt.value = p.name + "@" + latest.version;
    opt.textContent = p.name + " (v" + latest.version + ")";
    sel.appendChild(opt);
  }
}

async function createPolicy() {
  const name = document.getElementById("newPolicyName").value.trim();
  if (!name) return toast("请填写策略名");
  let mask = document.getElementById("np_mask").value.trim() || "7777";
  if (!mask.startsWith("0o")) mask = mask;
  const body = {
    ignore_mtime: document.getElementById("np_mtime").checked,
    ignore_uid_gid: document.getElementById("np_uidgid").checked,
    ignore_compression: document.getElementById("np_comp").checked,
    ignore_order: document.getElementById("np_order").checked,
    mode_mask: parseInt(mask, 8)
  };
  try {
    await api("/api/policies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, body })
    });
    toast("策略已创建");
    await loadPolicies();
    document.getElementById("policySel").value = name + "@1";
  } catch (e) { toast(e.message); }
}

async function runCompare() {
  const [name, ver] = document.getElementById("policySel").value.split("@");
  try {
    const data = await api("/api/compare", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        archive_a: state.a.id, archive_b: state.b.id,
        policy_name: name, policy_version: Number(ver)
      })
    });
    state.lastProof = data.proof_bytes;
    state.lastSession = data.session;
    renderResult(data.session);
    document.getElementById("exportProofBtn").disabled = false;
    await loadSessions();
  } catch (e) { toast(e.message); }
}

function factorChips(eff, ign) {
  let html = "";
  for (const f of eff) html += '<span class="factor eff">' + esc(f.factor) + '</span>';
  for (const f of ign) html += '<span class="factor ign">' + esc(f.factor) + '</span>';
  return html || "—";
}

function memberBrief(m) {
  if (!m) return "—";
  return '<span class="tag ' + m.type + '">' + m.type + '</span> ' +
    'mode ' + oct(m.mode) + ' size ' + m.size +
    (m.link_target ? ' → ' + esc(m.link_target) : "") +
    '<div class="mono muted">' + short(m.sha256) + '</div>';
}

function renderResult(session) {
  const cmp = session.comparison;
  document.getElementById("verdictSection").classList.remove("hidden");
  document.getElementById("diffSection").classList.remove("hidden");
  const box = document.getElementById("verdictBox");
  box.className = "verdict " + cmp.verdict;
  box.textContent = cmp.verdict_text;

  const s = cmp.summary;
  document.getElementById("counts").innerHTML =
    '<span class="n-c">真实内容差异 ' + s.content_diff_count + '</span>' +
    '<span class="n-m">生效元数据差异 ' + s.effective_metadata_diff_count + '</span>' +
    '<span class="n-i">可忽略元数据差异 ' + s.ignorable_metadata_diff_count + '</span>';

  const q = cmp.quarantine;
  const qbox = document.getElementById("quarantineInfo");
  qbox.innerHTML = "";
  if (q) {
    for (const side of ["a", "b"]) {
      const info = q[side];
      if (info.quarantined) {
        qbox.innerHTML += '<div class="diffbox"><b>归档 ' + side.toUpperCase() + ' 已隔离：</b>' +
          esc(info.reason) + (info.path ? '（' + esc(info.path) + '）' : '') +
          '<div class="muted">安全扫描前缀：' +
          (info.safe_prefix.map(esc).join(" / ") || "（无）") + '</div></div>';
      }
    }
  }
  const oi = document.getElementById("orderInfo");
  if (cmp.order_factor) {
    oi.textContent = "成员打包顺序不同（" +
      (cmp.order_factor.ignored ? "已被策略忽略" : "策略未忽略，参与结论") + "）";
  } else { oi.textContent = ""; }

  const tbody = document.querySelector("#diffTable tbody");
  tbody.innerHTML = "";
  for (const e of cmp.entries) {
    const tr = document.createElement("tr");
    tr.className = e.status;
    const statusText = {
      same: "一致", content_differs: "内容不同", metadata_differs: "元数据不同",
      ignorable_only: "仅可忽略差异", added_in_b: "仅 B 有", removed_in_b: "仅 A 有"
    }[e.status] || e.status;
    tr.innerHTML =
      '<td class="mono">' + esc(e.path) + '</td>' +
      '<td>' + esc(statusText) +
        (e.content_diffs.length ? '<div class="factor eff">' + e.content_diffs.map(esc).join(",") + '</div>' : "") +
      '</td>' +
      '<td>' + memberBrief(e.a) + '</td>' +
      '<td>' + memberBrief(e.b) + '</td>' +
      '<td>' + factorChips(e.effective_metadata, e.ignorable_metadata) + '</td>';
    tbody.appendChild(tr);
  }
}

async function exportProof() {
  if (!state.lastProof) return;
  const blob = new Blob([state.lastProof], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "artifactproof-" + state.lastSession.id.slice(0, 8) + ".proof.json";
  a.click();
  URL.revokeObjectURL(a.href);
}

async function loadArchives() {
  const data = await api("/api/archives");
  const body = document.getElementById("archiveBody");
  body.innerHTML = "";
  for (const r of data.archives) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      '<td>' + esc(r.filename) + '</td>' +
      '<td class="mono">' + esc(r.family) + '/' + esc(r.compression) + '</td>' +
      '<td>' + r.blob_size + '</td>' +
      '<td class="mono">' + short(r.blob_sha256) + (r.blob_reused ? " (复用)" : "") + '</td>' +
      '<td>' + (r.quarantined
        ? '<span class="chip q">隔离</span><div class="qreason">' + esc(r.quarantine_reason) + '</div>'
        : '<span class="chip">正常 · ' + r.member_count + ' 成员</span>') + '</td>' +
      '<td><button data-id="' + r.id + '" class="delArch">删除</button></td>';
    body.appendChild(tr);
  }
  body.querySelectorAll(".delArch").forEach(btn =>
    btn.addEventListener("click", async () => {
      try { await api("/api/archives/" + btn.dataset.id, { method: "DELETE" }); await loadArchives(); }
      catch (e) { toast(e.message); }
    }));
}

async function loadSessions() {
  const data = await api("/api/sessions");
  const body = document.getElementById("sessionBody");
  body.innerHTML = "";
  for (const s of data.sessions) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      '<td>' + fmtTime(s.created_at) + '</td>' +
      '<td class="mono">' + short(s.archive_a_id) + '</td>' +
      '<td class="mono">' + short(s.archive_b_id) + '</td>' +
      '<td>' + esc(s.policy_name) + ' v' + s.policy_version + '</td>' +
      '<td>' + esc(s.verdict_text) + '</td>' +
      '<td><a href="/api/sessions/' + s.id + '/proof" target="_blank">证明</a> ' +
          '<button data-id="' + s.id + '" class="delSess">删除</button></td>';
    body.appendChild(tr);
  }
  body.querySelectorAll(".delSess").forEach(btn =>
    btn.addEventListener("click", async () => {
      await api("/api/sessions/" + btn.dataset.id, { method: "DELETE" });
      await loadSessions();
    }));
}

bindDrop("a", "dropA", "fileA", "metaA");
bindDrop("b", "dropB", "fileB", "metaB");
document.getElementById("compareBtn").addEventListener("click", runCompare);
document.getElementById("exportProofBtn").addEventListener("click", exportProof);
document.getElementById("createPolicyBtn").addEventListener("click", createPolicy);

(async function init() {
  await loadPolicies();
  await loadArchives();
  await loadSessions();
})();
