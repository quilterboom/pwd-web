"use strict";

const TOKEN_KEY = "passwdpm_token";
const USER_KEY = "passwdpm_user";

const $ = (id) => document.getElementById(id);

let state = {
  token: localStorage.getItem(TOKEN_KEY) || "",
  user: localStorage.getItem(USER_KEY) || "",
  isAdmin: false,
  groups: [], // 当前用户可见分组（管理员为全部）
  users: [], // 管理员视角下的全部用户
  entries: [],
  editingId: null,
  viewingId: null,
  originalSecret: "",
  originalAlgorithm: "",
};

/* ---------- 工具函数 ---------- */
function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  if (state.token) headers["Authorization"] = "Bearer " + state.token;
  if (opts.body && !(opts.body instanceof FormData)) headers["Content-Type"] = "application/json";
  return fetch(path, Object.assign({}, opts, { headers })).then(async (res) => {
    let data = null;
    try { data = await res.json(); } catch (e) { /* empty body */ }
    if (!res.ok) {
      const msg = (data && (data.detail || data.message)) || ("请求失败 (" + res.status + ")");
      throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
    }
    return data;
  });
}

function showToast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => t.classList.add("hidden"), 2200);
}

/* 全屏等待窗口：等待后台解析（加解密 / 网络）完成或失败后关闭 */
function showWait(text) {
  const m = $("wait-modal");
  if (!m) return;
  $("wait-text").textContent = text || "正在处理…";
  m.classList.remove("hidden");
}
function hideWait() {
  const m = $("wait-modal");
  if (m) m.classList.add("hidden");
}

function algoBadge(a) {
  if (a === "symmetric") return `<span class="badge entry">🔑 条目密码</span>`;
  const label = a === "sm2" ? "SM2" : "GPG";
  return `<span class="badge ${a}">${label}</span>`;
}

function groupName(id) {
  const g = state.groups.find((x) => x.id === id);
  return g ? g.name : "—";
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function fmtTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleString("zh-CN", { hour12: false });
}

function isAuthErr(e) {
  return String((e && e.message) || "").includes("401") || String((e && e.message) || "").includes("令牌");
}

/* ---------- 登录 / 登出 ---------- */
async function doLogin(e) {
  e.preventDefault();
  $("login-error").textContent = "";
  try {
    const data = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: $("login-username").value,
        password: $("login-password").value,
      }),
    });
    state.token = data.access_token;
    localStorage.setItem(TOKEN_KEY, state.token);
    await refreshMe();
    enterApp();
  } catch (err) {
    $("login-error").textContent = err.message;
  }
}

function doLogout() {
  state.token = "";
  state.user = "";
  state.isAdmin = false;
  state.groups = [];
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  $("app-view").classList.add("hidden");
  $("login-view").classList.remove("hidden");
}

async function refreshMe() {
  const me = await api("/api/auth/me");
  state.user = me.username;
  state.isAdmin = !!me.is_admin;
  state.groups = me.groups || [];
  localStorage.setItem(USER_KEY, me.username);
}

async function loadMe() {
  try {
    await refreshMe();
  } catch (e) { /* token 失效 */ }
}

/* ---------- 主界面 ---------- */
function enterApp() {
  $("login-view").classList.add("hidden");
  $("app-view").classList.remove("hidden");
  $("current-user").textContent = "👤 " + state.user + (state.isAdmin ? "（管理员）" : "");
  if (state.isAdmin) $("admin-btn").classList.remove("hidden");
  else $("admin-btn").classList.add("hidden");
  loadKeysStatus();
  loadEntries();
  loadFiles();
}

async function loadKeysStatus() {
  try {
    const s = await api("/api/keys/status");
    const gpg = s.gpg ? '<span class="ok">● GPG 就绪</span>' : '<span class="no">● GPG 缺失</span>';
    const sm2 = s.sm2 ? '<span class="ok">● SM2 就绪</span>' : '<span class="no">● SM2 缺失</span>';
    $("keys-status").innerHTML = `服务端密钥：${gpg}　${sm2}`;
  } catch (e) {
    $("keys-status").textContent = "密钥状态获取失败";
  }
}

async function loadEntries() {
  try {
    state.entries = await api("/api/passwords");
    renderTable();
  } catch (e) {
    if (isAuthErr(e)) doLogout();
    else showToast("加载失败：" + e.message);
  }
}

function renderTable() {
  const q = ($("search-input").value || "").trim().toLowerCase();
  const rows = state.entries.filter((e) =>
    !q || (e.username || "").toLowerCase().includes(q) || (e.key_name || "").toLowerCase().includes(q)
  );
  const tbody = $("pw-tbody");
  tbody.innerHTML = "";
  $("empty-hint").classList.toggle("hidden", state.entries.length > 0);
  if (!rows.length && state.entries.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="color:#6b7280">无匹配结果</td></tr>`;
    return;
  }
  for (const e of rows) {
    const tr = document.createElement("tr");
    const keyTip = e.key_name ? `<div style="font-size:11px;color:#6b7280;margin-top:2px">🔑 ${esc(e.key_name)}</div>` : "";
    tr.innerHTML = `
      <td>${esc(e.username) || "<span style='color:#9ca3af'>未填</span>"}</td>
      <td>${algoBadge(e.algorithm)}${keyTip}</td>
      <td>${esc(groupName(e.group_id))}</td>
      <td>${fmtTime(e.updated_at)}</td>
      <td>${esc(e.updated_by || e.created_by || "")}</td>
      <td><div class="ops">
        <button class="btn ghost small" data-act="view" data-id="${e.id}">查看</button>
        <button class="btn ghost small" data-act="edit" data-id="${e.id}">编辑</button>
        <button class="btn ghost small" data-act="hist" data-id="${e.id}">记录</button>
        <button class="btn danger small" data-act="del" data-id="${e.id}">删除</button>
      </div></td>`;
    tbody.appendChild(tr);
  }
}

/* ---------- 分组下拉填充 ---------- */
function fillGroupSelect(selId, selectedId) {
  const sel = $(selId);
  sel.innerHTML = "";
  if (!state.groups.length) {
    sel.innerHTML = `<option value="">（无可用分组，请联系管理员）</option>`;
    sel.disabled = true;
    return;
  }
  sel.disabled = false;
  for (const g of state.groups) {
    const opt = document.createElement("option");
    opt.value = g.id;
    opt.textContent = g.name;
    if (selectedId != null && g.id === selectedId) opt.selected = true;
    sel.appendChild(opt);
  }
}

/* ---------- 加密方式 ↔ 条目密码框 + OrgKey 选择联动 ---------- */
async function loadOrgkeysForSelect() {
  const sel = $("f-orgkey");
  sel.innerHTML = "";
  const groupId = Number($("f-group").value || 0);
  if (!groupId) {
    sel.innerHTML = `<option value="">（请先选择分组）</option>`;
    return;
  }
  sel.disabled = true;
  try {
    const rows = await api(`/api/orgkeys?group_id=${groupId}`);
    sel.innerHTML = `<option value="">（默认：服务端密钥）</option>`;
    for (const k of rows) {
      const opt = document.createElement("option");
      opt.value = k.id;
      const hasLabel = k.has_private ? "（含私钥）" : "（仅公钥）";
      opt.textContent = `${k.name} · ${k.algorithm.toUpperCase()} ${hasLabel}`;
      sel.appendChild(opt);
    }
    sel.disabled = false;
  } catch (e) {
    sel.innerHTML = `<option value="">（加载失败：${esc(e.message)}）</option>`;
  }
}

function applyAlgoUI() {
  const algo = $("f-algorithm").value;
  const isSymmetric = algo === "symmetric";
  $("f-entry-pw-label").classList.toggle("hidden", !isSymmetric);
  $("f-entry-password").classList.toggle("hidden", !isSymmetric);
  $("f-entry-password").required = isSymmetric;
  $("f-new-pw-label").classList.toggle("hidden", !isSymmetric || state.editingId == null);
  $("f-new-entry-password").classList.toggle("hidden", !isSymmetric || state.editingId == null);
  // OrgKey 选取：gpg/sm2 显示（用本组织密钥），symmetric 隐藏
  $("f-orgkey-label").classList.toggle("hidden", isSymmetric);
  $("f-orgkey").classList.toggle("hidden", isSymmetric);
  $("f-orgkey-hint").classList.toggle("hidden", isSymmetric);
  if (!isSymmetric) loadOrgkeysForSelect();
}

/* ---------- 表单弹窗（新增 / 编辑） ---------- */
function openAdd() {
  state.editingId = null;
  state.originalSecret = "";
  state.originalAlgorithm = "";
  $("form-title").textContent = "新增密码";
  $("f-username").value = "";
  $("f-secret").value = "";
  $("f-secret").type = "password";
  $("f-reveal").textContent = "显示";
  $("f-algorithm").value = "symmetric";
  $("f-entry-password").value = "";
  $("f-new-entry-password").value = "";
  $("f-notes").value = "";
  $("f-comment").value = "";
  $("f-group").disabled = false;
  fillGroupSelect("f-group", null);
  $("form-error").textContent = "";
  applyAlgoUI();
  $("form-modal").classList.remove("hidden");
  $("f-username").focus();
}

async function openEdit(id) {
  const rec = state.entries.find((e) => e.id === id);
  if (!rec) return;
  state.editingId = id;
  state.originalAlgorithm = rec.algorithm;
  $("form-title").textContent = rec.scheme === "entry" ? "编辑密码（需条目密码）" : "编辑密码";
  $("f-username").value = rec.username;
  $("f-notes").value = rec.notes || "";
  $("f-comment").value = "";
  $("f-entry-password").value = "";
  $("f-new-entry-password").value = "";
  fillGroupSelect("f-group", rec.group_id);
  $("f-group").disabled = true; // 数据归属固定
  $("form-error").textContent = "";

  // 根据当前方案选择默认算法
  $("f-algorithm").value = rec.algorithm; // 'symmetric' | 'gpg' | 'sm2'

  if (rec.scheme === "entry") {
    // entry 方案：不预填明文，必须输入当前条目密码才能修改
    state.originalSecret = "";
    $("f-secret").value = "";
  } else {
    // legacy：服务端密钥 / OrgKey 私钥，可直接取明文
    try {
      const full = await api("/api/passwords/" + id);
      state.originalSecret = full.secret;
    } catch (e) {
      showToast("加载失败：" + e.message);
      return;
    }
    $("f-secret").value = state.originalSecret;
  }
  $("f-secret").type = "password";
  $("f-reveal").textContent = "显示";
  applyAlgoUI();
  // 编辑现有 legacy 记录时，把 orgkey 下拉默认选中这条记录曾经用过的密钥
  if (!rec.scheme || rec.scheme !== "entry") {
    setTimeout(() => {
      const sel = $("f-orgkey");
      if (sel && rec.orgkey_id) {
        sel.value = String(rec.orgkey_id);
      }
    }, 200); // 等 loadOrgkeysForSelect 异步完成
  }
  $("form-modal").classList.remove("hidden");
  if (rec.scheme === "entry") $("f-entry-password").focus();
  else $("f-username").focus();
}

function closeForm() { $("form-modal").classList.add("hidden"); }

async function saveForm() {
  $("form-error").textContent = "";
  const secret = $("f-secret").value;
  const algo = $("f-algorithm").value;
  const entryPassword = $("f-entry-password").value;
  const newEntryPassword = $("f-new-entry-password").value;
  const orgkeyVal = $("f-orgkey").value;
  const orgkeyId = orgkeyVal ? Number(orgkeyVal) : null;
  if (!secret) return ($("form-error").textContent = "请输入密码 / 密钥明文");
  if (!state.groups.length) return ($("form-error").textContent = "你没有可用的分组，无法创建");

  const payload = {
    username: $("f-username").value.trim(),
    notes: $("f-notes").value,
    comment: $("f-comment").value,
  };

  if (state.editingId == null) {
    // 新增
    if (algo === "symmetric" && !entryPassword)
      return ($("form-error").textContent = "请输入条目密码");
    const groupId = Number($("f-group").value);
    payload.group_id = groupId;
    payload.secret = secret;
    payload.algorithm = algo;
    if (algo === "symmetric") payload.entry_password = entryPassword;
    if (algo !== "symmetric" && orgkeyId) payload.orgkey_id = orgkeyId;
  } else {
    const rec = state.entries.find((e) => e.id === state.editingId);
    // entry 当前方案：必须提供当前条目密码
    if (rec && rec.scheme === "entry" && !entryPassword)
      return ($("form-error").textContent = "请输入当前条目密码才能修改");
    // 目标 symmetric 必须有可用的条目密码（沿用当前或新设）
    if (algo === "symmetric" && !entryPassword && !newEntryPassword)
      return ($("form-error").textContent = "切换到「对称加密」必须提供条目密码或新条目密码");
    payload.algorithm = algo;
    payload.secret = secret;
    if (entryPassword) payload.entry_password = entryPassword;
    if (newEntryPassword) payload.new_entry_password = newEntryPassword;
    if (algo !== "symmetric" && orgkeyId) payload.orgkey_id = orgkeyId;
  }

  const waitText = state.editingId == null ? "正在加密保存…" : "正在解密并重新加密…";
  showWait(waitText);
  try {
    if (state.editingId == null) {
      await api("/api/passwords", { method: "POST", body: JSON.stringify(payload) });
      showToast("已新增");
    } else {
      await api("/api/passwords/" + state.editingId, { method: "PUT", body: JSON.stringify(payload) });
      showToast("已保存");
    }
    closeForm();
    loadEntries();
  } catch (e) {
    $("form-error").textContent = e.message;
    showToast("保存失败：" + e.message);
  } finally {
    hideWait();
  }
}

/* ---------- 查看弹窗 ---------- */
async function openView(id) {
  const rec = state.entries.find((e) => e.id === id);
  if (!rec) return;
  state.viewingId = id;
  $("view-title").textContent = "查看：" + (rec.username || rec.id);
  $("view-username").textContent = rec.username || "—";
  const keyTip = rec.key_name ? ` <span style="color:#6b7280;font-size:13px">🔑 ${esc(rec.key_name)}</span>` : "";
  $("view-algorithm").innerHTML = algoBadge(rec.algorithm) + keyTip;
  $("view-group").textContent = groupName(rec.group_id);
  $("view-notes").textContent = rec.notes || "—";
  $("view-lock-error").textContent = "";
  $("view-entry-password").value = "";

  if (rec.scheme === "entry") {
    // 需输入条目密码才能查看
    $("view-lock").classList.remove("hidden");
    $("view-secret-wrap").classList.add("hidden");
    $("view-secret").textContent = "";
    $("view-modal").classList.remove("hidden");
    $("view-entry-password").focus();
  } else {
    // legacy：服务端密钥，直接取明文（带等待窗口）
    showWait("正在解密…");
    try {
      const full = await api("/api/passwords/" + id);
      $("view-lock").classList.add("hidden");
      $("view-secret-wrap").classList.remove("hidden");
      $("view-secret").textContent = full.secret;
      $("view-modal").classList.remove("hidden");
    } catch (e) {
      showToast("加载失败：" + e.message);
    } finally {
      hideWait();
    }
  }
}

async function viewUnlock() {
  const id = state.viewingId;
  const pw = $("view-entry-password").value;
  if (!pw) { $("view-lock-error").textContent = "请输入条目密码"; return; }
  showWait("正在解密…");
  try {
    const full = await api("/api/passwords/" + id + "?entry_password=" + encodeURIComponent(pw));
    $("view-lock").classList.add("hidden");
    $("view-secret-wrap").classList.remove("hidden");
    $("view-secret").textContent = full.secret;
  } catch (e) {
    $("view-lock-error").textContent = e.message;
  } finally {
    hideWait();
  }
}

function copySecret() {
  const text = $("view-secret").textContent;
  navigator.clipboard.writeText(text).then(() => showToast("已复制到剪贴板"), () => showToast("复制失败"));
}

/* ---------- 修改记录弹窗 ---------- */
async function openHistory(id) {
  try {
    const rows = await api("/api/passwords/" + id + "/history");
    const tbody = $("history-tbody");
    tbody.innerHTML = "";
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="6" style="color:#6b7280">暂无记录</td></tr>`;
    }
    const actLabel = { create: "新增", update: "修改", delete: "删除" };
    for (const r of rows) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${fmtTime(r.changed_at)}</td>
        <td class="act-${r.action}">${actLabel[r.action] || r.action}</td>
        <td>${esc(r.username || "")}</td>
        <td>${algoBadge(r.algorithm)}</td>
        <td>${esc(r.changed_by || "")}</td>
        <td>${esc(r.comment || "")}</td>`;
      tbody.appendChild(tr);
    }
    $("history-modal").classList.remove("hidden");
  } catch (e) {
    showToast("加载失败：" + e.message);
  }
}

/* ---------- 删除 ---------- */
async function doDelete(id) {
  if (!confirm("确认删除该密码记录？删除后会记入修改记录。")) return;
  try {
    await api("/api/passwords/" + id, { method: "DELETE" });
    showToast("已删除");
    loadEntries();
  } catch (e) {
    showToast("删除失败：" + e.message);
  }
}

/* ---------- 随机密码 ---------- */
function genRandom() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*";
  let s = "";
  for (let i = 0; i < 16; i++) s += chars[Math.floor(Math.random() * chars.length)];
  $("f-secret").value = s;
  $("f-secret").type = "text";
  $("f-reveal").textContent = "隐藏";
}

/* ---------- 文件保险箱 ---------- */
function fmtSize(n) {
  if (n == null) return "";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}

let fileState = { entries: [] };

async function loadFiles() {
  try {
    fileState.entries = await api("/api/files");
    renderFileTable();
  } catch (e) {
    if (isAuthErr(e)) doLogout();
    else showToast("加载失败：" + e.message);
  }
}

function renderFileTable() {
  const tbody = $("file-tbody");
  tbody.innerHTML = "";
  $("file-empty").classList.toggle("hidden", fileState.entries.length > 0);
  if (!fileState.entries.length) return;
  for (const f of fileState.entries) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${esc(f.filename)}</td>
      <td>${algoBadge(f.algorithm)}</td>
      <td>${esc(groupName(f.group_id))}</td>
      <td>${fmtSize(f.size)}</td>
      <td>${fmtTime(f.updated_at)}</td>
      <td>${esc(f.updated_by || f.created_by || "")}</td>
      <td><div class="ops">
        <button class="btn ghost small" data-fact="dl" data-id="${f.id}">下载密文</button>
        <button class="btn ghost small" data-fact="dec" data-id="${f.id}">解密下载</button>
        <button class="btn ghost small" data-fact="hist" data-id="${f.id}">记录</button>
        <button class="btn danger small" data-fact="del" data-id="${f.id}">删除</button>
      </div></td>`;
    tbody.appendChild(tr);
  }
}

async function uploadFile(file) {
  const algorithm = $("file-algorithm").value;
  if (!state.groups.length) { showToast("你没有可用的分组，无法上传"); return; }
  const groupId = Number($("file-group").value);
  const fd = new FormData();
  fd.append("file", file);
  fd.append("algorithm", algorithm);
  fd.append("group_id", String(groupId));
  try {
    await api("/api/files/upload", { method: "POST", body: fd });
    showToast("已加密上传：" + file.name);
    loadFiles();
  } catch (e) {
    showToast("上传失败：" + e.message);
  }
}

async function apiBlob(path) {
  const res = await fetch(path, { headers: { Authorization: "Bearer " + state.token } });
  // 一定要先按 Content-Type 分支消费 body；
  // 否则对非 JSON 响应（公钥文本/文件密文）盲目 res.json() 会消耗 stream，
  // 后续 res.blob() 抛 "body stream already read"。
  const ct = (res.headers.get("Content-Type") || "").toLowerCase();
  if (!res.ok) {
    let detail = null;
    if (ct.includes("json")) {
      try { detail = await res.json(); } catch (e) {}
      const msg = (detail && (detail.detail || detail.message)) || ("下载失败 (" + res.status + ")");
      throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
    }
    throw new Error("下载失败 (" + res.status + ")");
  }
  return { blob: await res.blob(), disposition: res.headers.get("Content-Disposition") };
}

function filenameFromDisposition(disp, fallback) {
  if (!disp) return fallback;
  const star = disp.match(/filename\*=UTF-8''([^;]+)/i);
  if (star) { try { return decodeURIComponent(star[1]); } catch (e) {} }
  const m = disp.match(/filename="?([^";]+)"?/i);
  if (m) return m[1];
  return fallback;
}

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function downloadCipher(id, fallbackName) {
  try {
    const { blob, disposition } = await apiBlob("/api/files/" + id + "/download");
    triggerDownload(blob, filenameFromDisposition(disposition, fallbackName + ".enc"));
  } catch (e) { showToast("下载失败：" + e.message); }
}

async function decryptDownload(id, fallbackName) {
  try {
    const { blob, disposition } = await apiBlob("/api/files/" + id + "/decrypt");
    triggerDownload(blob, filenameFromDisposition(disposition, fallbackName));
    showToast("已解密下载");
  } catch (e) { showToast("解密失败：" + e.message); }
}

async function openFileHistory(id) {
  try {
    const rows = await api("/api/files/" + id + "/history");
    const tbody = $("history-tbody");
    tbody.innerHTML = "";
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="7" style="color:#6b7280">暂无记录</td></tr>`;
    }
    const actLabel = { upload: "上传", decrypt: "解密", delete: "删除" };
    for (const r of rows) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${fmtTime(r.changed_at)}</td>
        <td class="act-${r.action}">${actLabel[r.action] || r.action}</td>
        <td>${esc(r.filename)}</td>
        <td>—</td>
        <td>${algoBadge(r.algorithm)}</td>
        <td>${esc(r.changed_by)}</td>
        <td>${esc(r.comment)}</td>`;
      tbody.appendChild(tr);
    }
    $("history-modal").classList.remove("hidden");
  } catch (e) {
    showToast("加载失败：" + e.message);
  }
}

async function deleteFile(id) {
  if (!confirm("确认删除该加密文件？删除后会记入修改记录。")) return;
  try {
    await api("/api/files/" + id, { method: "DELETE" });
    showToast("已删除");
    loadFiles();
  } catch (e) {
    showToast("删除失败：" + e.message);
  }
}

/* ---------- 密钥库（按组织维度） ---------- */
let keyState = { entries: [] };

async function loadOrgKeys() {
  try {
    fillGroupSelect("key-group-filter", null);
    keyState.entries = await api("/api/orgkeys");
    renderKeyTable();
  } catch (e) {
    if (isAuthErr(e)) doLogout();
    else showToast("加载密钥库失败：" + e.message);
  }
}

function renderKeyTable() {
  const tbody = $("key-tbody");
  tbody.innerHTML = "";
  const filterGid = Number($("key-group-filter").value || 0);
  const q = ($("key-search").value || "").trim().toLowerCase();
  let rows = keyState.entries;
  if (filterGid > 0) rows = rows.filter((k) => k.group_id === filterGid);
  if (q) rows = rows.filter((k) => (k.name + " " + (k.created_by || "")).toLowerCase().includes(q));
  rows.forEach((k) => tbody.appendChild(keyRow(k)));
  $("key-empty").classList.toggle("hidden", keyState.entries.length > 0);
  if (!rows.length && keyState.entries.length) {
    tbody.innerHTML = `<tr><td colspan="8" style="color:#6b7280">无匹配结果</td></tr>`;
  } else if (!keyState.entries.length) {
    tbody.innerHTML = "";
  }
}

function keyRow(k) {
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td>${esc(k.name)}</td>
    <td>${algoBadge(k.algorithm)}</td>
    <td>${esc(groupName(k.group_id))}</td>
    <td><code style="font-size:11px">${esc(k.fingerprint)}</code></td>
    <td>${k.has_private ? '<span class="ok">✓ 有</span>' : '<span style="color:#9ca3af">— 无</span>'}</td>
    <td>${fmtTime(k.created_at)}</td>
    <td>${esc(k.created_by || "")}</td>
    <td><div class="ops">
      <button class="btn ghost small" data-kact="pub"  data-id="${k.id}">导出公钥</button>
      ${k.has_private ? `<button class="btn ghost small" data-kact="priv" data-id="${k.id}">导出私钥</button>` : ""}
      <button class="btn danger small" data-kact="del" data-id="${k.id}">删除</button>
    </div></td>`;
  return tr;
}

function openKeyGen() {
  if (!state.groups.length) { showToast("你没有可用的分组，无法生成"); return; }
  $("kg-name").value = "";
  $("kg-algorithm").value = "gpg";
  fillGroupSelect("kg-group", state.isAdmin ? null : state.groups[0].id);
  $("kg-error").textContent = "";
  $("keygen-modal").classList.remove("hidden");
  $("kg-name").focus();
}
function closeKeyGen() { $("keygen-modal").classList.add("hidden"); }

async function saveKeyGen() {
  $("kg-error").textContent = "";
  const name = $("kg-name").value.trim();
  const algorithm = $("kg-algorithm").value;
  const groupId = Number($("kg-group").value);
  if (!name) return ($("kg-error").textContent = "请输入密钥名称");
  if (!groupId) return ($("kg-error").textContent = "请选择所属分组");
  showWait("正在生成密钥对…");
  try {
    await api("/api/orgkeys/generate", {
      method: "POST",
      body: JSON.stringify({ name, algorithm, group_id: groupId }),
    });
    showToast("已生成并保存密钥对");
    closeKeyGen();
    loadOrgKeys();
  } catch (e) {
    $("kg-error").textContent = e.message;
  } finally {
    hideWait();
  }
}

function openKeyImport() {
  if (!state.groups.length) { showToast("你没有可用的分组，无法导入"); return; }
  $("ki-name").value = "";
  $("ki-algorithm").value = "gpg";
  fillGroupSelect("ki-group", state.isAdmin ? null : state.groups[0].id);
  $("ki-pub").value = "";
  $("ki-priv").value = "";
  $("ki-error").textContent = "";
  $("keyimport-modal").classList.remove("hidden");
  $("ki-name").focus();
}
function closeKeyImport() { $("keyimport-modal").classList.add("hidden"); }

async function saveKeyImport() {
  $("ki-error").textContent = "";
  const name = $("ki-name").value.trim();
  const algorithm = $("ki-algorithm").value;
  const groupId = Number($("ki-group").value);
  const publicKey = $("ki-pub").value;
  const privateKey = $("ki-priv").value;
  if (!name) return ($("ki-error").textContent = "请输入密钥名称");
  if (!publicKey) return ($("ki-error").textContent = "请粘贴公钥内容");
  if (!groupId) return ($("ki-error").textContent = "请选择所属分组");
  showWait("正在校验并导入密钥…");
  try {
    await api("/api/orgkeys/import", {
      method: "POST",
      body: JSON.stringify({
        name, algorithm, group_id: groupId,
        public_key: publicKey, private_key: privateKey,
      }),
    });
    showToast(privateKey ? "已导入公钥 + 私钥" : "已导入公钥（无私钥）");
    closeKeyImport();
    loadOrgKeys();
  } catch (e) {
    $("ki-error").textContent = e.message;
  } finally {
    hideWait();
  }
}

async function exportOrgKey(id, kind) {
  const entry = keyState.entries.find((k) => k.id === id);
  const defaultName = entry ? entry.name : "key";
  try {
    const { blob, disposition } = await apiBlob("/api/orgkeys/" + id + "/export?kind=" + kind);
    const suffix = kind === "public" ? "_pub" : "_priv";
    const ext = entry && entry.algorithm === "gpg" ? ".asc" : ".key";
    triggerDownload(blob, filenameFromDisposition(disposition, defaultName + suffix + ext));
    showToast(kind === "public" ? "公钥已导出" : "⚠ 私钥已导出，请妥善保管");
  } catch (e) {
    showToast("导出失败：" + e.message);
  }
}

async function deleteOrgKey(id) {
  if (!confirm("确认删除该密钥条目？该操作不可撤销。")) return;
  try {
    await api("/api/orgkeys/" + id, { method: "DELETE" });
    showToast("已删除");
    loadOrgKeys();
  } catch (e) {
    showToast("删除失败：" + e.message);
  }
}

function switchTab(tab) {
  document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  $("pw-panel").classList.toggle("hidden", tab !== "pw");
  $("file-panel").classList.toggle("hidden", tab !== "file");
  $("key-panel").classList.toggle("hidden", tab !== "key");
  if (tab === "file") {
    fillGroupSelect("file-group", null);
    loadFiles();
  } else if (tab === "key") {
    loadOrgKeys();
  }
}

/* ---------- 系统管理（管理员） ---------- */
function switchSub(sub) {
  document.querySelectorAll(".subtab").forEach((b) => b.classList.toggle("active", b.dataset.sub === sub));
  $("admin-users-sec").classList.toggle("hidden", sub !== "users");
  $("admin-groups-sec").classList.toggle("hidden", sub !== "groups");
}

async function openAdmin() {
  try {
    await Promise.all([loadAdminUsers(), loadAdminGroups()]);
    switchSub("users");
    $("admin-modal").classList.remove("hidden");
  } catch (e) { showToast("加载管理数据失败：" + e.message); }
}

async function loadAdminUsers() {
  state.users = await api("/api/admin/users");
  const tbody = $("admin-users-tbody");
  tbody.innerHTML = "";
  if (!state.users.length) {
    tbody.innerHTML = `<tr><td colspan="4" style="color:#6b7280">暂无用户</td></tr>`;
    return;
  }
  for (const u of state.users) {
    const tr = document.createElement("tr");
    const gnames = u.groups.map((g) => esc(g.name)).join("、") || "—";
    tr.innerHTML = `
      <td>${esc(u.username)}</td>
      <td>${u.is_admin ? "是" : "否"}</td>
      <td>${gnames}</td>
      <td><div class="ops">
        <button class="btn ghost small" data-uact="edit" data-id="${u.id}">编辑</button>
        <button class="btn danger small" data-uact="del" data-id="${u.id}">删除</button>
      </div></td>`;
    tbody.appendChild(tr);
  }
}

async function loadAdminGroups() {
  const groups = await api("/api/admin/groups");
  const tbody = $("admin-groups-tbody");
  tbody.innerHTML = "";
  if (!groups.length) {
    tbody.innerHTML = `<tr><td colspan="4" style="color:#6b7280">暂无分组</td></tr>`;
    return;
  }
  for (const g of groups) {
    const tr = document.createElement("tr");
    const mnames = g.members.map((m) => esc(m.username)).join("、") || "—";
    tr.innerHTML = `
      <td>${esc(g.name)}</td>
      <td>${g.member_count}</td>
      <td>${mnames}</td>
      <td><div class="ops">
        <button class="btn ghost small" data-gact="edit" data-id="${g.id}">编辑</button>
        <button class="btn danger small" data-gact="del" data-id="${g.id}">删除</button>
      </div></td>`;
    tbody.appendChild(tr);
  }
}

/* ----- 用户编辑 ----- */
let editingUserId = null;

function fillGroupChecks(containerId, selectedIds) {
  const box = $(containerId);
  box.innerHTML = "";
  if (!state.groups.length) {
    box.innerHTML = `<span style="color:#6b7280">暂无可分配的分组</span>`;
    return;
  }
  for (const g of state.groups) {
    const id = "grp-" + g.id;
    const label = document.createElement("label");
    label.className = "checkbox-item";
    label.innerHTML = `<input type="checkbox" id="${id}" value="${g.id}" ${selectedIds && selectedIds.includes(g.id) ? "checked" : ""}/> ${esc(g.name)}`;
    box.appendChild(label);
  }
}

function checkedGroupIds() {
  return Array.from(document.querySelectorAll("#u-groups input[type=checkbox]:checked")).map((c) => Number(c.value));
}

function openUserAdd() {
  editingUserId = null;
  $("user-modal-title").textContent = "新增用户";
  $("u-username").value = "";
  $("u-username").disabled = false;
  $("u-pwd-label").textContent = "密码 *";
  $("u-password").value = "";
  $("u-isadmin").checked = false;
  fillGroupChecks("u-groups", []);
  $("user-error").textContent = "";
  $("user-modal").classList.remove("hidden");
}

async function openUserEdit(id) {
  const u = state.users.find((x) => x.id === id);
  if (!u) return;
  editingUserId = id;
  $("user-modal-title").textContent = "编辑用户：" + u.username;
  $("u-username").value = u.username;
  $("u-username").disabled = true; // 用户名不可改
  $("u-pwd-label").textContent = "密码（留空则保持不变）";
  $("u-password").value = "";
  $("u-isadmin").checked = u.is_admin;
  fillGroupChecks("u-groups", u.groups.map((g) => g.id));
  $("user-error").textContent = "";
  $("user-modal").classList.remove("hidden");
}

async function saveUser() {
  $("user-error").textContent = "";
  const username = $("u-username").value.trim();
  const password = $("u-password").value;
  const isAdmin = $("u-isadmin").checked;
  const groupIds = checkedGroupIds();
  if (!username) return ($("user-error").textContent = "请输入用户名");
  if (editingUserId == null && !password) return ($("user-error").textContent = "请输入密码");

  const payload = { username, is_admin: isAdmin, group_ids: groupIds };
  if (password) payload.password = password;

  try {
    if (editingUserId == null) {
      await api("/api/admin/users", { method: "POST", body: JSON.stringify(payload) });
      showToast("已创建用户");
    } else {
      await api("/api/admin/users/" + editingUserId, { method: "PUT", body: JSON.stringify(payload) });
      showToast("已更新用户");
    }
    $("user-modal").classList.add("hidden");
    await loadAdminUsers();
    await refreshMe(); // 管理员分组列表可能变化
  } catch (e) {
    $("user-error").textContent = e.message;
  }
}

async function deleteUser(id) {
  if (!confirm("确认删除该用户？该用户的会话将失效。")) return;
  try {
    await api("/api/admin/users/" + id, { method: "DELETE" });
    showToast("已删除用户");
    await loadAdminUsers();
  } catch (e) {
    showToast("删除失败：" + e.message);
  }
}

/* ----- 分组编辑 ----- */
let editingGroupId = null;

function fillMemberChecks(containerId, selectedIds) {
  const box = $(containerId);
  box.innerHTML = "";
  if (!state.users.length) {
    box.innerHTML = `<span style="color:#6b7280">暂无可加入的用户</span>`;
    return;
  }
  for (const u of state.users) {
    const id = "mem-" + u.id;
    const label = document.createElement("label");
    label.className = "checkbox-item";
    label.innerHTML = `<input type="checkbox" id="${id}" value="${u.id}" ${selectedIds && selectedIds.includes(u.id) ? "checked" : ""}/> ${esc(u.username)}`;
    box.appendChild(label);
  }
}

function checkedMemberIds() {
  return Array.from(document.querySelectorAll("#g-members input[type=checkbox]:checked")).map((c) => Number(c.value));
}

function openGroupAdd() {
  editingGroupId = null;
  $("group-modal-title").textContent = "新增分组";
  $("g-name").value = "";
  $("g-desc").value = "";
  fillMemberChecks("g-members", []);
  $("group-error").textContent = "";
  $("group-modal").classList.remove("hidden");
}

async function openGroupEdit(id) {
  const groups = await api("/api/admin/groups");
  const g = groups.find((x) => x.id === id);
  if (!g) return;
  editingGroupId = id;
  $("group-modal-title").textContent = "编辑分组：" + g.name;
  $("g-name").value = g.name;
  $("g-desc").value = g.description || "";
  fillMemberChecks("g-members", g.members.map((m) => m.id));
  $("group-error").textContent = "";
  $("group-modal").classList.remove("hidden");
}

async function saveGroup() {
  $("group-error").textContent = "";
  const name = $("g-name").value.trim();
  const description = $("g-desc").value;
  const memberIds = checkedMemberIds();
  if (!name) return ($("group-error").textContent = "请输入分组名称");

  const payload = { name, description, member_ids: memberIds };
  try {
    if (editingGroupId == null) {
      await api("/api/admin/groups", { method: "POST", body: JSON.stringify(payload) });
      showToast("已创建分组");
    } else {
      await api("/api/admin/groups/" + editingGroupId, { method: "PUT", body: JSON.stringify(payload) });
      showToast("已更新分组");
    }
    $("group-modal").classList.add("hidden");
    await loadAdminGroups();
    await refreshMe();
  } catch (e) {
    $("group-error").textContent = e.message;
  }
}

async function deleteGroup(id) {
  if (!confirm("确认删除该分组？若分组仍绑定数据将被阻止。")) return;
  try {
    await api("/api/admin/groups/" + id, { method: "DELETE" });
    showToast("已删除分组");
    await loadAdminGroups();
    await refreshMe();
  } catch (e) {
    showToast("删除失败：" + e.message);
  }
}

/* ---------- 事件绑定 ---------- */
function bind() {
  $("login-form").addEventListener("submit", doLogin);
  $("logout-btn").addEventListener("click", doLogout);
  $("add-btn").addEventListener("click", openAdd);
  $("search-input").addEventListener("input", renderTable);
  $("form-cancel").addEventListener("click", closeForm);
  $("form-save").addEventListener("click", saveForm);
  $("f-reveal").addEventListener("click", () => {
    const inp = $("f-secret");
    if (inp.type === "password") { inp.type = "text"; $("f-reveal").textContent = "隐藏"; }
    else { inp.type = "password"; $("f-reveal").textContent = "显示"; }
  });
  $("f-gen").addEventListener("click", genRandom);
  $("f-algorithm").addEventListener("change", applyAlgoUI);
  $("f-group").addEventListener("change", () => {
    if ($("f-algorithm").value !== "symmetric") loadOrgkeysForSelect();
  });
  $("view-close").addEventListener("click", () => $("view-modal").classList.add("hidden"));
  $("view-unlock").addEventListener("click", viewUnlock);
  $("view-entry-password").addEventListener("keydown", (e) => { if (e.key === "Enter") viewUnlock(); });
  $("view-copy").addEventListener("click", copySecret);
  $("history-close").addEventListener("click", () => $("history-modal").classList.add("hidden"));

  $("pw-tbody").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-act]");
    if (!btn) return;
    const id = Number(btn.dataset.id);
    const act = btn.dataset.act;
    if (act === "view") openView(id);
    else if (act === "edit") openEdit(id);
    else if (act === "hist") openHistory(id);
    else if (act === "del") doDelete(id);
  });

  // 文件保险箱页签与操作
  document.querySelectorAll(".tab").forEach((b) =>
    b.addEventListener("click", () => switchTab(b.dataset.tab))
  );
  $("file-upload-btn").addEventListener("click", () => $("file-input").click());
  $("file-input").addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (file) uploadFile(file);
    e.target.value = ""; // 允许重复上传同名文件
  });
  $("file-tbody").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-fact]");
    if (!btn) return;
    const id = Number(btn.dataset.id);
    const act = btn.dataset.fact;
    const entry = fileState.entries.find((x) => x.id === id);
    const name = entry ? entry.filename : "file";
    if (act === "dl") downloadCipher(id, name);
    else if (act === "dec") decryptDownload(id, name);
    else if (act === "hist") openFileHistory(id);
    else if (act === "del") deleteFile(id);
  });

  // 系统管理
  $("admin-btn").addEventListener("click", openAdmin);
  $("admin-close").addEventListener("click", () => {
    $("admin-modal").classList.add("hidden");
    loadEntries();
    loadFiles();
  });
  document.querySelectorAll(".subtab").forEach((b) =>
    b.addEventListener("click", () => switchSub(b.dataset.sub))
  );
  $("add-user-btn").addEventListener("click", openUserAdd);
  $("add-group-btn").addEventListener("click", openGroupAdd);
  $("user-cancel").addEventListener("click", () => $("user-modal").classList.add("hidden"));
  $("user-save").addEventListener("click", saveUser);
  $("group-cancel").addEventListener("click", () => $("group-modal").classList.add("hidden"));
  $("group-save").addEventListener("click", saveGroup);

  // 密钥库
  $("key-gen-btn").addEventListener("click", openKeyGen);
  $("kg-cancel").addEventListener("click", closeKeyGen);
  $("kg-save").addEventListener("click", saveKeyGen);
  $("key-import-btn").addEventListener("click", openKeyImport);
  $("ki-cancel").addEventListener("click", closeKeyImport);
  $("ki-save").addEventListener("click", saveKeyImport);
  $("key-group-filter").addEventListener("change", renderKeyTable);
  $("key-search").addEventListener("input", renderKeyTable);
  $("key-tbody").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-kact]");
    if (!btn) return;
    const id = Number(btn.dataset.id);
    const act = btn.dataset.kact;
    if (act === "pub") exportOrgKey(id, "public");
    else if (act === "priv") exportOrgKey(id, "private");
    else if (act === "del") deleteOrgKey(id);
  });
  $("admin-users-tbody").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-uact]");
    if (!btn) return;
    const id = Number(btn.dataset.id);
    if (btn.dataset.uact === "edit") openUserEdit(id);
    else if (btn.dataset.uact === "del") deleteUser(id);
  });
  $("admin-groups-tbody").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-gact]");
    if (!btn) return;
    const id = Number(btn.dataset.id);
    if (btn.dataset.gact === "edit") openGroupEdit(id);
    else if (btn.dataset.gact === "del") deleteGroup(id);
  });

  // 点击遮罩关闭弹窗
  document.querySelectorAll(".modal").forEach((m) => {
    m.addEventListener("click", (e) => { if (e.target === m) m.classList.add("hidden"); });
  });
}

/* ---------- 启动 ---------- */
bind();
if (state.token) {
  loadMe().then(() => {
    if (state.token) enterApp();
    else { $("login-view").classList.remove("hidden"); }
  });
} else {
  $("login-view").classList.remove("hidden");
}
