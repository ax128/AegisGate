function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderInline(text) {
  return escapeHtml(text)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
}

function renderMarkdown(markdown) {
  const lines = String(markdown || "").replace(/\r\n/g, "\n").split("\n");
  const chunks = [];
  let inCode = false;
  let codeLines = [];
  let listType = null;
  let paragraph = [];

  function flushParagraph() {
    if (!paragraph.length) return;
    chunks.push(`<p>${renderInline(paragraph.join(" "))}</p>`);
    paragraph = [];
  }

  function flushList() {
    if (!listType) return;
    chunks.push(`</${listType}>`);
    listType = null;
  }

  function flushCode() {
    if (!inCode) return;
    chunks.push(`<pre><code>${escapeHtml(codeLines.join("\n"))}</code></pre>`);
    inCode = false;
    codeLines = [];
  }

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (line.startsWith("```")) {
      flushParagraph();
      flushList();
      if (inCode) flushCode();
      else inCode = true;
      continue;
    }
    if (inCode) {
      codeLines.push(rawLine);
      continue;
    }
    if (!line.trim()) {
      flushParagraph();
      flushList();
      continue;
    }
    const heading = line.match(/^(#{1,3})\s+(.*)$/);
    if (heading) {
      flushParagraph();
      flushList();
      const level = heading[1].length;
      chunks.push(`<h${level}>${renderInline(heading[2])}</h${level}>`);
      continue;
    }
    const bullet = line.match(/^[-*]\s+(.*)$/);
    if (bullet) {
      flushParagraph();
      if (listType !== "ul") {
        flushList();
        listType = "ul";
        chunks.push("<ul>");
      }
      chunks.push(`<li>${renderInline(bullet[1])}</li>`);
      continue;
    }
    const ordered = line.match(/^\d+\.\s+(.*)$/);
    if (ordered) {
      flushParagraph();
      if (listType !== "ol") {
        flushList();
        listType = "ol";
        chunks.push("<ol>");
      }
      chunks.push(`<li>${renderInline(ordered[1])}</li>`);
      continue;
    }
    flushList();
    paragraph.push(line.trim());
  }

  flushParagraph();
  flushList();
  flushCode();
  return chunks.join("\n") || '<p class="empty-note">暂无内容。</p>';
}

let uiCsrfToken = "";
let configState = [];

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    cache: "no-store",
    credentials: "same-origin",
    ...options,
  });
  if (response.status === 401) {
    window.location.href = "/__ui__/login";
    throw new Error("unauthorized");
  }
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const data = await response.json();
      if (data.detail) message = data.detail;
      else if (data.error) message = data.error;
    } catch (_error) {
      // noop
    }
    throw new Error(message);
  }
  return response.json();
}

// `level` accepts the legacy boolean (true = error) or "ok" | "warn" | "err".
function setStatus(id, message, level = false) {
  const node = document.getElementById(id);
  if (!node) return;
  const kind = level === true ? "err" : level === false ? (message ? "ok" : "") : String(level);
  const isError = kind === "err";
  node.textContent = message;
  node.className = "status-note " + kind;
  // Auto-clear success messages after 4 seconds
  if (kind === "ok" && message) {
    clearTimeout(node._clearTimer);
    node._clearTimer = setTimeout(() => {
      node.textContent = "";
      node.className = "status-note";
    }, 4000);
  }
}

function updateHeaderStatus(status) {
  const dot = document.getElementById("header-status-dot");
  const label = document.getElementById("status-text");
  if (dot) {
    dot.className = "status-dot " + (status === "running" ? "online" : status ? "error" : "");
  }
  if (label) {
    label.textContent = status === "running" ? "运行中" : (status || "未知");
  }
}

// ─── Config panels ─────────────────────────────
// Panels, nav entries and groups are all generated from /__ui__/api/config, so
// adding a field or a section server-side needs no change here.

let configSections = [];
const dirtyFields = new Set();

const SECTION_ICONS = {
  sliders: '<line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="20" y2="18"/><circle cx="9" cy="6" r="2.2" fill="currentColor" stroke="none"/><circle cx="15" cy="12" r="2.2" fill="currentColor" stroke="none"/><circle cx="9" cy="18" r="2.2" fill="currentColor" stroke="none"/>',
  database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.66 3.58 3 8 3s8-1.34 8-3V5"/><path d="M4 11v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6"/>',
  gauge: '<path d="M12 21a9 9 0 1 1 9-9"/><line x1="12" y1="12" x2="17" y2="8"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9,12 11,14 15,10"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  shuffle: '<polyline points="16,3 21,3 21,8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21,16 21,21 16,21"/><line x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" y2="9"/>',
  layers: '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1" fill="currentColor" stroke="none"/><circle cx="6" cy="18" r="1" fill="currentColor" stroke="none"/>',
  monitor: '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
};

function sectionIcon(key) {
  const body = SECTION_ICONS[key] || SECTION_ICONS.sliders;
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`;
}

function fieldId(field) {
  return `cfg-${field.field}`;
}

function cloneState(items) {
  configState = items.map((item) => ({ ...item }));
  dirtyFields.clear();
}

function findField(fieldName) {
  return configState.find((entry) => entry.field === fieldName);
}

function markDirty(fieldName, card) {
  dirtyFields.add(fieldName);
  if (card) card.classList.add("dirty");
  const item = findField(fieldName);
  if (item) applyDependencies(item.section);
}

function updateFieldValue(fieldName, value, card) {
  const item = findField(fieldName);
  if (!item) return;
  item.value = value;
  markDirty(fieldName, card);
}

// A field carrying `depends_on: {other_field: expected}` is only shown while the
// other field currently holds that value.
function applyDependencies(section) {
  configState
    .filter((item) => item.section === section && item.depends_on)
    .forEach((item) => {
      const card = document.getElementById(`card-${item.field}`);
      if (!card) return;
      const satisfied = Object.entries(item.depends_on).every(([dep, expected]) => {
        const depItem = findField(dep);
        return depItem && String(depItem.value) === String(expected);
      });
      card.classList.toggle("dep-hidden", !satisfied);
    });
}

function createBoolButton(item, card) {
  const button = document.createElement("button");
  button.type = "button";
  button.id = fieldId(item);
  button.className = `bool-button ${item.value ? "on" : "off"}`;
  // A switch announces its own state through role + aria-checked, so the old
  // "已开启 / 已关闭" text would be read out twice. The label comes from the
  // field name instead.
  button.setAttribute("role", "switch");
  button.setAttribute("aria-checked", item.value ? "true" : "false");
  button.setAttribute("aria-label", item.label);
  button.title = item.value ? "已开启" : "已关闭";
  button.addEventListener("click", () => {
    const next = !findField(item.field).value;
    updateFieldValue(item.field, next, card);
    button.className = `bool-button ${next ? "on" : "off"}`;
    button.setAttribute("aria-checked", next ? "true" : "false");
    button.title = next ? "已开启" : "已关闭";
  });
  return button;
}

function createInputField(item, card) {
  let input;
  if (item.type === "enum") {
    input = document.createElement("select");
    (item.options || []).forEach((option) => {
      const node = document.createElement("option");
      node.value = option;
      node.textContent = option;
      if (String(item.value) === String(option)) node.selected = true;
      input.appendChild(node);
    });
  } else {
    input = document.createElement("input");
    if (item.sensitive) {
      input.type = "password";
      input.autocomplete = "new-password";
      input.placeholder = item.has_value ? `已配置 ${item.masked}，留空表示不修改` : "未配置";
      input.value = "";
    } else if (item.type === "int" || item.type === "float") {
      input.type = "number";
      if (item.type === "float") input.step = "any";
      if (item.min !== undefined && item.min !== null) input.min = String(item.min);
      if (item.max !== undefined && item.max !== null) input.max = String(item.max);
      input.value = item.value ?? "";
    } else {
      input.type = "text";
      input.value = item.value ?? "";
    }
  }
  input.id = fieldId(item);
  const read = () => (item.type === "int" || item.type === "float" ? input.value : input.value);
  input.addEventListener("input", () => updateFieldValue(item.field, read(), card));
  input.addEventListener("change", () => updateFieldValue(item.field, read(), card));
  return input;
}

function buildFieldCard(item) {
  const card = document.createElement("div");
  card.id = `card-${item.field}`;
  card.className = `field-card ${item.type === "string" ? "wide" : ""}`;
  card.dataset.search = `${item.label} ${item.env} ${item.field} ${item.help || ""}`.toLowerCase();

  const meta = document.createElement("div");
  meta.className = "meta";
  const badges = [];
  if (item.requires_restart) {
    badges.push('<span class="field-badge restart" title="该字段被 hot_reload 固定，保存后需重启网关才生效">需重启</span>');
  }
  if (item.pending_value !== undefined) {
    badges.push('<span class="field-badge pending" title="已写入 config/.env，但当前进程仍在使用旧值">待生效</span>');
  }
  const defaultText = item.sensitive ? "" : `<span class="default">默认: ${escapeHtml(String(item.default))}</span>`;
  meta.innerHTML =
    `<strong>${escapeHtml(item.label)}${badges.join("")}</strong>` +
    `<span class="field-env">${escapeHtml(item.env)}</span>` +
    (item.help ? `<span class="field-help">${escapeHtml(item.help)}</span>` : "") +
    defaultText;
  card.appendChild(meta);
  card.appendChild(item.type === "bool" ? createBoolButton(item, card) : createInputField(item, card));
  return card;
}

function buildConfigPanel(section) {
  const panel = document.createElement("section");
  panel.id = section.id;
  panel.className = "panel";
  panel.innerHTML =
    `<div class="panel-head">` +
      `<div class="panel-head-icon">${sectionIcon(section.icon)}</div>` +
      `<div class="panel-head-info">` +
        `<h2>${escapeHtml(section.label)}</h2>` +
        `<p class="panel-desc">${escapeHtml(section.desc || "")}　修改后点击保存，写入 <code>config/.env</code></p>` +
      `</div>` +
    `</div>` +
    `<div class="config-toolbar">` +
      `<input type="search" class="config-search" id="search-${section.id}" placeholder="搜索本页配置项…" aria-label="搜索 ${escapeHtml(section.label)} 配置项">` +
      `<span class="config-count" id="count-${section.id}"></span>` +
    `</div>` +
    `<div class="restart-banner hidden" id="restart-banner-${section.id}" role="status"></div>` +
    `<div class="config-groups" id="groups-${section.id}"></div>` +
    `<div class="panel-actions">` +
      `<button id="save-${section.id}" class="btn-save" type="button">` +
        `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">` +
        `<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>` +
        `<polyline points="17,21 17,13 7,13 7,21"/><polyline points="7,3 7,8 15,8"/></svg>` +
        `保存${escapeHtml(section.label)}` +
      `</button>` +
      `<span id="${section.id}-save-status" class="status-note" aria-live="polite"></span>` +
    `</div>`;
  return panel;
}

function filterSection(sectionId, query) {
  const needle = String(query || "").trim().toLowerCase();
  const groups = document.getElementById(`groups-${sectionId}`);
  if (!groups) return;
  let visible = 0;
  groups.querySelectorAll(".config-group").forEach((group) => {
    let groupVisible = 0;
    group.querySelectorAll(".field-card").forEach((card) => {
      const hit = !needle || (card.dataset.search || "").includes(needle);
      card.classList.toggle("search-hidden", !hit);
      if (hit) groupVisible += 1;
    });
    group.classList.toggle("search-hidden", groupVisible === 0);
    visible += groupVisible;
  });
  const counter = document.getElementById(`count-${sectionId}`);
  if (counter) counter.textContent = needle ? `匹配 ${visible} 项` : `共 ${visible} 项`;
}

function renderConfig(payload) {
  const items = Array.isArray(payload) ? payload : payload.items || [];
  const sections = (Array.isArray(payload) ? configSections : payload.sections) || configSections;
  configSections = sections;
  cloneState(items);

  const navHost = document.getElementById("config-nav");
  const panelHost = document.getElementById("config-panels");
  if (!panelHost) return;
  if (navHost) navHost.innerHTML = "";
  panelHost.innerHTML = "";

  sections.forEach((section) => {
    const sectionItems = configState.filter((item) => item.section === section.id);
    if (!sectionItems.length) return;

    if (navHost) {
      const link = document.createElement("a");
      link.href = `#${section.id}`;
      link.className = "nav-item";
      link.innerHTML = `${sectionIcon(section.icon)}${escapeHtml(section.label)}`;
      navHost.appendChild(link);
    }

    const panel = buildConfigPanel(section);
    panelHost.appendChild(panel);

    const groupHost = panel.querySelector(`#groups-${section.id}`);
    const seen = new Map();
    sectionItems.forEach((item) => {
      const groupName = item.group || "其他";
      if (!seen.has(groupName)) {
        const group = document.createElement("div");
        group.className = "config-group";
        group.innerHTML = `<h3 class="config-group-title">${escapeHtml(groupName)}</h3><div class="form-grid dynamic-config"></div>`;
        groupHost.appendChild(group);
        seen.set(groupName, group.querySelector(".form-grid"));
      }
      seen.get(groupName).appendChild(buildFieldCard(item));
    });

    panel.querySelector(`#search-${section.id}`)
      .addEventListener("input", (event) => filterSection(section.id, event.target.value));
    panel.querySelector(`#save-${section.id}`)
      .addEventListener("click", () => saveSection(section.id, `${section.id}-save-status`));

    filterSection(section.id, "");
    applyDependencies(section.id);

    const pending = sectionItems.filter((item) => item.pending_value !== undefined);
    if (pending.length) showRestartBanner(section.id, pending.map((item) => item.label), true);
  });

  initScrollSpy();
}

function showRestartBanner(sectionId, labels, alreadyWritten) {
  const banner = document.getElementById(`restart-banner-${sectionId}`);
  if (!banner) return;
  const names = labels.map((l) => escapeHtml(l)).join("、");
  banner.innerHTML =
    `<span class="restart-banner-text">` +
      `<strong>${alreadyWritten ? "以下配置已写入但尚未生效" : "以下配置需要重启后才会生效"}：</strong>${names}` +
      `　—　这些字段被网关在启动时固定，热重载不会应用。` +
    `</span>` +
    `<button class="btn-sm restart-banner-btn" type="button">重启网关</button>`;
  banner.classList.remove("hidden");
  banner.querySelector(".restart-banner-btn").addEventListener("click", () => {
    const restartBtn = document.getElementById("restart-button");
    if (restartBtn) restartBtn.click();
  });
}

function collectSectionValues(section) {
  const values = {};
  configState.filter((item) => item.section === section).forEach((item) => {
    if (item.sensitive) {
      const input = document.getElementById(fieldId(item));
      const typed = input ? input.value.trim() : "";
      if (typed) values[item.field] = typed;
      return;
    }
    values[item.field] = item.type === "int" || item.type === "float"
      ? String(item.value).trim()
      : item.value;
  });
  return values;
}

async function saveSection(section, statusId) {
  setStatus(statusId, "保存中…");
  try {
    const data = await fetchJson("/__ui__/api/config", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-aegis-ui-csrf": uiCsrfToken,
      },
      body: JSON.stringify({ values: collectSectionValues(section) }),
    });
    const restartRequired = Array.isArray(data.restart_required) ? data.restart_required : [];
    const fieldMap = new Map(configState.map((item) => [item.field, item]));
    renderConfig(data.config);
    if (restartRequired.length) {
      showRestartBanner(
        section,
        restartRequired.map((name) => (fieldMap.get(name) || {}).label || name),
        false
      );
      setStatus(statusId, `已写入 config/.env；其中 ${restartRequired.length} 项需重启网关后生效。`, "warn");
    } else {
      setStatus(statusId, "已保存，配置已热重载。");
    }
    await loadBootstrap();
  } catch (error) {
    setStatus(statusId, `保存失败: ${error.message}`, true);
  }
}

function setActiveNav(hash) {
  document.querySelectorAll(".nav-item").forEach((link) => {
    const active = link.getAttribute("href") === hash;
    link.classList.toggle("active", active);
    // Colour alone does not tell a screen reader which section is showing.
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
}

function initScrollSpy() {
  function onScroll() {
    const sections = document.querySelectorAll("main section[id]");
    if (!sections.length) return;
    const offset = 80;
    let current = sections[0].id;
    sections.forEach((section) => {
      if (section.getBoundingClientRect().top <= offset) {
        current = section.id;
      }
    });
    setActiveNav(`#${current}`);
  }

  if (!initScrollSpy._bound) {
    window.addEventListener("scroll", onScroll, { passive: true });
    initScrollSpy._bound = true;
  }
  initScrollSpy._onScroll = onScroll;
  onScroll();
}

function setActiveDoc(docId) {
  document.querySelectorAll(".doc-link").forEach((button) => {
    button.classList.toggle("active", button.dataset.docId === docId);
  });
}

async function loadDoc(docId) {
  const data = await fetchJson(`/__ui__/api/docs/${encodeURIComponent(docId)}`);
  document.getElementById("doc-title").textContent = data.title || data.id;
  document.getElementById("doc-path").textContent = data.path || data.id;
  document.getElementById("doc-content").innerHTML = renderMarkdown(data.content);
  setActiveDoc(docId);
}

async function loadDocs(preferredDocId) {
  const container = document.getElementById("docs-list");
  container.innerHTML = "";
  const data = await fetchJson("/__ui__/api/docs");
  const items = Array.isArray(data.items) ? data.items : [];
  if (!items.length) {
    document.getElementById("doc-content").innerHTML = '<p class="empty-note">没有找到可展示的文档。</p>';
    return;
  }
  items.forEach((item) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "doc-link";
    button.dataset.docId = item.id;
    button.textContent = item.title || item.id;
    button.addEventListener("click", () => loadDoc(item.id).catch(showDocError));
    container.appendChild(button);
  });
  const first = items.find((item) => item.id === preferredDocId) || items[0];
  await loadDoc(first.id);
}

function showDocError(error) {
  document.getElementById("doc-content").innerHTML = `<p class="error-note">文档加载失败: ${escapeHtml(error.message)}</p>`;
}

function updateStatusBadge(status) {
  const badge = document.getElementById("status-badge");
  if (!badge) return;
  const isRunning = status === "running";
  badge.className = `badge ${isRunning ? "badge-success" : "badge-error"}`;
  badge.textContent = isRunning ? "运行中" : (status || "未知");
}

async function loadBootstrap() {
  const output = document.getElementById("bootstrap-output");
  const data = await fetchJson("/__ui__/api/bootstrap");

  updateHeaderStatus(data.status);
  updateStatusBadge(data.status);

  document.getElementById("server-text").textContent = `${data.server.host}:${data.server.port}`;
  document.getElementById("security-text").textContent = data.security.level || "-";
  document.getElementById("upstream-text").textContent = data.upstream_base_url || "(未配置)";

  uiCsrfToken = data.ui && data.ui.csrf_token ? data.ui.csrf_token : "";
  if (output) output.textContent = JSON.stringify(data, null, 2);

  const configData = await fetchJson("/__ui__/api/config");
  renderConfig(configData);

  const preferredDocId = Array.isArray(data.docs) && data.docs.length ? data.docs[0].id : null;
  await loadDocs(preferredDocId);
}

function getModalFocusableElements(container) {
  if (!container) return [];
  return Array.from(
    container.querySelectorAll(
      'button:not([disabled]), [href], input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    )
  ).filter((node) => !node.closest(".hidden"));
}

function openModal(modal, initialFocus) {
  if (!modal || !modal.classList.contains("hidden")) return;
  const active = document.activeElement;
  modal._returnFocus = active && typeof active.focus === "function" ? active : null;
  modal.classList.remove("hidden");
  const target = initialFocus || getModalFocusableElements(modal)[0];
  if (target && typeof target.focus === "function") target.focus();
}

function closeModal(modal) {
  if (!modal) return;
  modal.classList.add("hidden");
  const returnFocus = modal._returnFocus;
  modal._returnFocus = null;
  if (returnFocus && document.contains(returnFocus) && typeof returnFocus.focus === "function") {
    returnFocus.focus();
  }
}

function trapModalFocus(modal, event) {
  if (event.key !== "Tab") return;
  const focusable = getModalFocusableElements(modal);
  if (!focusable.length) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
    return;
  }
  if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

// ─── Token Management ────────────────────────

async function loadTokens() {
  const tbody = document.getElementById("token-tbody");
  const countEl = document.getElementById("token-count");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="4" class="token-table-empty">加载中…</td></tr>`;
  try {
    const data = await fetchJson("/__ui__/api/tokens");
    const items = Array.isArray(data.items) ? data.items : [];
    if (countEl) countEl.textContent = `共 ${items.length} 个 Token`;
    if (!items.length) {
      tbody.innerHTML = `<tr><td colspan="4" class="token-table-empty">暂无已注册的 Token，点击右上角「注册 Token」添加。</td></tr>`;
      return;
    }
    tbody.innerHTML = "";
    items.forEach((item) => {
      const tr = document.createElement("tr");
      const wlCount = Array.isArray(item.whitelist_keys) ? item.whitelist_keys.length : 0;
      const wlTitle = wlCount
        ? `脱敏豁免字段: ${item.whitelist_keys.join(", ")}`
        : "未设置豁免，所有字段均参与脱敏";
      tr.innerHTML = `
        <td>
          <button class="token-code" title="点击复制完整 Token" data-token="${escapeHtml(item.token)}">
            ${escapeHtml(item.token)}
          </button>
        </td>
        <td><div class="token-upstream" title="${escapeHtml(item.upstream_base)}">${escapeHtml(item.upstream_base)}</div></td>
        <td><span class="token-wl-count" title="${escapeHtml(wlTitle)}">${wlCount || "∞"}</span></td>
        <td style="white-space:nowrap;">
          <button class="btn-edit-sm" data-edit-token="${escapeHtml(item.token)}" data-edit-upstream="${escapeHtml(item.upstream_base)}" data-edit-whitelist="${escapeHtml((item.whitelist_keys||[]).join(', '))}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
              <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
            </svg>
            编辑
          </button>
          <button class="btn-danger-sm" data-del-token="${escapeHtml(item.token)}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="3,6 5,6 21,6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
              <path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/>
            </svg>
            删除
          </button>
        </td>`;
      // Copy token on click
      tr.querySelector(".token-code").addEventListener("click", (e) => {
        const t = e.currentTarget.dataset.token;
        navigator.clipboard.writeText(t).then(() => {
          e.currentTarget.textContent = "已复制!";
          setTimeout(() => { e.currentTarget.textContent = t; }, 1500);
        }).catch(() => {});
      });
      // Edit token
      tr.querySelector(".btn-edit-sm").addEventListener("click", (e) => {
        const btn = e.currentTarget;
        openEditModal({
          token: btn.dataset.editToken,
          upstream_base: btn.dataset.editUpstream,
          whitelist_keys: btn.dataset.editWhitelist ? btn.dataset.editWhitelist.split(",").map(s => s.trim()).filter(Boolean) : [],
        });
      });
      // Delete token
      tr.querySelector(".btn-danger-sm").addEventListener("click", async (e) => {
        const t = e.currentTarget.dataset.delToken;
        if (!confirm(`确认删除 Token\n${t}\n\n此操作不可撤销。`)) return;
        try {
          await fetchJson(`/__ui__/api/tokens/${encodeURIComponent(t)}`, {
            method: "DELETE",
            headers: { "x-aegis-ui-csrf": uiCsrfToken },
          });
          loadTokens();
        } catch (err) {
          alert(`删除失败: ${err.message}`);
        }
      });
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" class="token-table-empty" style="color:var(--error)">加载失败: ${escapeHtml(err.message)}</td></tr>`;
    if (countEl) countEl.textContent = "加载失败";
  }
}

function openTokenModal() {
  const modal = document.getElementById("token-modal");
  if (!modal) return;
  document.getElementById("modal-edit-token").value = "";
  document.getElementById("modal-title").textContent = "注册新 Token";
  document.getElementById("modal-token-input").value = "";
  document.getElementById("modal-upstream").value = "";
  document.getElementById("modal-whitelist").value = "";
  document.getElementById("modal-error").textContent = "";
  document.getElementById("modal-token-field").classList.add("hidden");
  document.getElementById("modal-submit").textContent = "注册";
  openModal(modal, document.getElementById("modal-upstream"));
}

function openEditModal(item) {
  const modal = document.getElementById("token-modal");
  if (!modal) return;
  document.getElementById("modal-edit-token").value = item.token;
  document.getElementById("modal-title").textContent = "编辑 Token";
  document.getElementById("modal-token-input").value = item.token;
  document.getElementById("modal-upstream").value = item.upstream_base || "";
  document.getElementById("modal-whitelist").value = (item.whitelist_keys || []).join(", ");
  document.getElementById("modal-error").textContent = "";
  document.getElementById("modal-token-field").classList.remove("hidden");
  document.getElementById("modal-submit").textContent = "保存";
  openModal(modal, document.getElementById("modal-upstream"));
}

function closeTokenModal() {
  closeModal(document.getElementById("token-modal"));
}

async function submitTokenModal() {
  const errorEl = document.getElementById("modal-error");
  const editToken = document.getElementById("modal-edit-token").value.trim();
  const isEdit = !!editToken;
  const newTokenInput = document.getElementById("modal-token-input").value.trim();
  const upstream = document.getElementById("modal-upstream").value.trim();
  const whitelist = document.getElementById("modal-whitelist").value.trim();
  const whitelistArr = whitelist ? whitelist.split(",").map((s) => s.trim()).filter(Boolean) : [];
  errorEl.textContent = "";
  if (!upstream) { errorEl.textContent = "请填写上游地址"; return; }

  const submitBtn = document.getElementById("modal-submit");

  if (isEdit) {
    // PATCH mode
    const body = { upstream_base: upstream, whitelist_key: whitelistArr };
    if (newTokenInput && newTokenInput !== editToken) body.new_token = newTokenInput;
    submitBtn.disabled = true;
    submitBtn.textContent = "保存中…";
    try {
      const data = await fetchJson(`/__ui__/api/tokens/${encodeURIComponent(editToken)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken },
        body: JSON.stringify(body),
      });
      closeTokenModal();
      loadTokens();
      if (body.new_token) {
        alert(`Token 已更新\n\n新 Base URL:\n${data.base_url}\n\n请同步更新客户端配置。`);
      }
    } catch (err) {
      errorEl.textContent = err.message;
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = "保存";
    }
  } else {
    // POST mode (register)
    const body = { upstream_base: upstream, whitelist_key: whitelistArr };
    submitBtn.disabled = true;
    submitBtn.textContent = "注册中…";
    try {
      const data = await fetchJson("/__ui__/api/tokens", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken },
        body: JSON.stringify(body),
      });
      closeTokenModal();
      loadTokens();
      if (data.already_registered) {
        alert(`Token 已存在（复用）：${data.token}\n\nBase URL:\n${data.base_url}`);
      } else {
        alert(`注册成功！\n\nToken: ${data.token}\nBase URL:\n${data.base_url}\n\n请妥善保存，Base URL 可直接作为 OpenAI 兼容 API 的 base_url 使用。`);
      }
    } catch (err) {
      errorEl.textContent = err.message;
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = "注册";
    }
  }
}

function bindTokenModal() {
  const addBtn     = document.getElementById("token-add");
  const refreshBtn = document.getElementById("token-refresh");
  const closeBtn   = document.getElementById("modal-close");
  const cancelBtn  = document.getElementById("modal-cancel");
  const submitBtn  = document.getElementById("modal-submit");
  const overlay    = document.getElementById("token-modal");

  if (addBtn)     addBtn.addEventListener("click", openTokenModal);
  if (refreshBtn) refreshBtn.addEventListener("click", loadTokens);
  if (closeBtn)   closeBtn.addEventListener("click", closeTokenModal);
  if (cancelBtn)  cancelBtn.addEventListener("click", closeTokenModal);
  if (submitBtn)  submitBtn.addEventListener("click", submitTokenModal);

  // Close on overlay click
  if (overlay) {
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) closeTokenModal();
    });
    overlay.addEventListener("keydown", (e) => {
      trapModalFocus(overlay, e);
      if (e.key === "Escape") {
        e.preventDefault();
        closeTokenModal();
        return;
      }
      const btn = overlay.querySelector("[data-action='submit-token']");
      if (e.key === "Enter" && !e.shiftKey && btn && !btn.disabled) {
        e.preventDefault();
        submitTokenModal();
      }
    });
  }
}

// ─── Actions ─────────────────────────────────

function bindActions() {
  document.getElementById("refresh-bootstrap").addEventListener("click", () => {
    loadBootstrap().catch((error) => {
      const output = document.getElementById("bootstrap-output");
      if (output) output.textContent = `加载失败: ${error.message}`;
      updateHeaderStatus("error");
    });
  });
  document.getElementById("open-health").addEventListener("click", () => {
    window.open("/__ui__/health", "_blank", "noopener,noreferrer");
  });
  document.getElementById("logout-button").addEventListener("click", async () => {
    if (!confirm("确认退出登录？")) return;
    await fetchJson("/__ui__/api/logout", {
      method: "POST",
      headers: { "x-aegis-ui-csrf": uiCsrfToken },
    });
    window.location.href = "/__ui__/login";
  });
}

bindActions();
bindTokenModal();
initScrollSpy();
loadTokens();
loadBootstrap().catch((error) => {
  const output = document.getElementById("bootstrap-output");
  if (output) output.textContent = `加载失败: ${error.message}`;
  updateHeaderStatus("error");
  showDocError(error);
});

// ─── Exact Value Redaction ─────────────────────

async function loadRedactValues() {
  const tbody = document.getElementById("redact-tbody");
  const countEl = document.getElementById("redact-count");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="4" class="token-table-empty">加载中…</td></tr>`;
  try {
    const data = await fetchJson("/__ui__/api/redact_values");
    const items = Array.isArray(data.items) ? data.items : [];
    if (countEl) countEl.textContent = `共 ${items.length} 条`;
    if (!items.length) {
      tbody.innerHTML = `<tr><td colspan="4" class="token-table-empty">暂无精确值脱敏配置，点击「添加值」新增。</td></tr>`;
      return;
    }
    tbody.innerHTML = "";
    items.forEach((item, idx) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${idx}</td>
        <td><code style="font-size:0.85rem;">${escapeHtml(item.masked)}</code></td>
        <td>${item.length}</td>
        <td>
          <button class="btn-danger-sm" data-del-redact="${idx}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="3,6 5,6 21,6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
              <path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/>
            </svg>
            删除
          </button>
        </td>`;
      tr.querySelector(".btn-danger-sm").addEventListener("click", async () => {
        if (!confirm(`确认删除第 ${idx} 条脱敏值？`)) return;
        try {
          await fetchJson(`/__ui__/api/redact_values/${idx}`, {
            method: "DELETE",
            headers: { "x-aegis-ui-csrf": uiCsrfToken },
          });
          loadRedactValues();
        } catch (err) {
          alert(`删除失败: ${err.message}`);
        }
      });
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" class="token-table-empty" style="color:var(--error)">加载失败: ${escapeHtml(err.message)}</td></tr>`;
    if (countEl) countEl.textContent = "加载失败";
  }
}

function openRedactModal() {
  const modal = document.getElementById("redact-modal");
  if (!modal) return;
  document.getElementById("redact-modal-value").value = "";
  document.getElementById("redact-modal-error").textContent = "";
  openModal(modal, document.getElementById("redact-modal-value"));
}

function closeRedactModal() {
  closeModal(document.getElementById("redact-modal"));
}

async function submitRedactModal() {
  const value = document.getElementById("redact-modal-value").value.trim();
  const errEl = document.getElementById("redact-modal-error");
  errEl.textContent = "";
  if (!value) { errEl.textContent = "请输入敏感值"; return; }
  if (value.length < 10) { errEl.textContent = "至少 10 个字符"; return; }
  const submitBtn = document.getElementById("redact-modal-submit");
  submitBtn.disabled = true;
  submitBtn.textContent = "添加中…";
  try {
    await fetchJson("/__ui__/api/redact_values", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken },
      body: JSON.stringify({ value }),
    });
    closeRedactModal();
    loadRedactValues();
  } catch (err) {
    errEl.textContent = err.message;
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "添加";
  }
}

function bindRedactUI() {
  const addBtn = document.getElementById("redact-add");
  const refreshBtn = document.getElementById("redact-refresh");
  if (addBtn) addBtn.addEventListener("click", openRedactModal);
  if (refreshBtn) refreshBtn.addEventListener("click", loadRedactValues);

  const closeBtn = document.getElementById("redact-modal-close");
  const cancelBtn = document.getElementById("redact-modal-cancel");
  const submitBtn = document.getElementById("redact-modal-submit");
  const modal = document.getElementById("redact-modal");
  if (closeBtn) closeBtn.addEventListener("click", closeRedactModal);
  if (cancelBtn) cancelBtn.addEventListener("click", closeRedactModal);
  if (submitBtn) submitBtn.addEventListener("click", submitRedactModal);
  if (modal) {
    modal.addEventListener("click", (e) => { if (e.target === modal) closeRedactModal(); });
    modal.addEventListener("keydown", (e) => {
      trapModalFocus(modal, e);
      if (e.key === "Escape") {
        e.preventDefault();
        closeRedactModal();
      }
      if (e.key === "Enter" && !e.shiftKey && submitBtn && !submitBtn.disabled) {
        e.preventDefault();
        submitRedactModal();
      }
    });
  }
  loadRedactValues();
}

bindRedactUI();

// ─── Security Rules ───────────────────────────

// ─── Security Rules ────────────────────────────
// Sections come from /__ui__/api/rules, which discovers them by walking
// security_filters.yaml — adding a rule group to the YAML surfaces it here with
// no change to this file.

let currentRulesSection = "";
let currentRulesReadonly = false;
let actionMapState = {};
let rulesSectionIndex = [];

const ACTION_MAP_SECTION = "action_map";

function renderRuleSectionList(sections, query) {
  const host = document.getElementById("rules-sections");
  if (!host) return;
  const needle = String(query || "").trim().toLowerCase();
  host.innerHTML = "";

  const byFilter = new Map();
  sections.forEach((section) => {
    if (needle && !`${section.label} ${section.id}`.toLowerCase().includes(needle)) return;
    if (!byFilter.has(section.filter)) byFilter.set(section.filter, []);
    byFilter.get(section.filter).push(section);
  });

  byFilter.forEach((group, filterKey) => {
    const wrap = document.createElement("div");
    wrap.className = "rules-filter-group";
    const total = group.reduce((sum, s) => sum + s.count, 0);
    wrap.innerHTML = `<div class="rules-filter-title">${escapeHtml(group[0].filter_label || filterKey)}<span>${total}</span></div>`;
    group.forEach((section) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `rules-section-item${section.id === currentRulesSection ? " active" : ""}`;
      button.dataset.rulesSection = section.id;
      button.setAttribute("role", "tab");
      button.setAttribute("aria-selected", section.id === currentRulesSection ? "true" : "false");
      button.innerHTML =
        `<span class="rules-section-name">${escapeHtml(section.label)}` +
        (section.readonly ? '<span class="rules-readonly-tag">只读</span>' : "") +
        `</span><span class="rules-section-count">${section.count}</span>`;
      button.addEventListener("click", () => selectRulesSection(section.id));
      wrap.appendChild(button);
    });
    host.appendChild(wrap);
  });

  const actionMap = document.createElement("div");
  actionMap.className = "rules-filter-group";
  actionMap.innerHTML = '<div class="rules-filter-title">处置<span></span></div>';
  const button = document.createElement("button");
  button.type = "button";
  button.className = `rules-section-item${currentRulesSection === ACTION_MAP_SECTION ? " active" : ""}`;
  button.dataset.rulesSection = ACTION_MAP_SECTION;
  button.setAttribute("role", "tab");
  button.setAttribute("aria-selected", currentRulesSection === ACTION_MAP_SECTION ? "true" : "false");
  button.innerHTML = '<span class="rules-section-name">动作映射</span>';
  button.addEventListener("click", () => selectRulesSection(ACTION_MAP_SECTION));
  actionMap.appendChild(button);
  host.appendChild(actionMap);

  if (!host.children.length) {
    host.innerHTML = '<p class="empty-note">没有匹配的规则组</p>';
  }
}

function selectRulesSection(sectionId) {
  currentRulesSection = sectionId;
  document.querySelectorAll("[data-rules-section]").forEach((node) => {
    const active = node.dataset.rulesSection === sectionId;
    node.classList.toggle("active", active);
    node.setAttribute("aria-selected", active ? "true" : "false");
  });
  const search = document.getElementById("rules-search");
  if (search) search.value = "";
  loadRules(sectionId);
}

async function loadRuleSections(preferredSection) {
  try {
    const data = await fetchJson("/__ui__/api/rules");
    rulesSectionIndex = Array.isArray(data.sections) ? data.sections : [];
    const fallback = rulesSectionIndex.length ? rulesSectionIndex[0].id : ACTION_MAP_SECTION;
    const target = preferredSection
      || (rulesSectionIndex.some((s) => s.id === currentRulesSection) ? currentRulesSection : null)
      || "redaction.pii_patterns";
    currentRulesSection = rulesSectionIndex.some((s) => s.id === target) ? target : fallback;
    renderRuleSectionList(rulesSectionIndex, "");
    await loadRules(currentRulesSection);
  } catch (err) {
    const host = document.getElementById("rules-sections");
    if (host) host.innerHTML = `<p class="error-note">规则组加载失败: ${escapeHtml(err.message)}</p>`;
  }
}

function filterRulesTable(query) {
  const needle = String(query || "").trim().toLowerCase();
  const tbody = document.getElementById("rules-tbody");
  const countEl = document.getElementById("rules-count");
  if (!tbody) return;
  let visible = 0;
  tbody.querySelectorAll("tr[data-search]").forEach((row) => {
    const hit = !needle || row.dataset.search.includes(needle);
    row.classList.toggle("search-hidden", !hit);
    if (hit) visible += 1;
  });
  if (countEl) {
    const total = tbody.querySelectorAll("tr[data-search]").length;
    countEl.textContent = needle ? `匹配 ${visible} / ${total} 条` : `共 ${total} 条规则`;
  }
}

async function loadRules(section) {
  if (section === ACTION_MAP_SECTION) {
    await loadActionMap();
    return;
  }
  const tbody = document.getElementById("rules-tbody");
  const countEl = document.getElementById("rules-count");
  const thead = document.getElementById("rules-thead");
  const tableEl = document.getElementById("rules-table");
  const actionMapPanel = document.getElementById("action-map-panel");
  const addBtn = document.getElementById("rules-add");
  const searchBox = document.getElementById("rules-search");
  const labelEl = document.getElementById("rules-section-label");
  if (tbody) tbody.innerHTML = `<tr><td colspan="4" class="token-table-empty">加载中…</td></tr>`;
  if (tableEl) tableEl.classList.remove("hidden");
  if (actionMapPanel) actionMapPanel.classList.add("hidden");
  if (searchBox) searchBox.classList.remove("hidden");

  try {
    const data = await fetchJson(`/__ui__/api/rules/${encodeURIComponent(section)}`);
    const items = Array.isArray(data.items) ? data.items : [];
    currentRulesReadonly = Boolean(data.readonly);
    if (labelEl) {
      labelEl.textContent = data.label || section;
      labelEl.title = section;
    }
    if (addBtn) addBtn.classList.toggle("hidden", currentRulesReadonly);

    // Columns beyond id/regex vary per group (kind, category, tool, param…);
    // derive them from the rules actually present instead of hard-coding.
    const extraKeys = [];
    items.forEach((item) => {
      Object.keys(item).forEach((key) => {
        if (key !== "id" && key !== "regex" && !extraKeys.includes(key)) extraKeys.push(key);
      });
    });

    if (thead) {
      thead.innerHTML =
        `<tr><th scope="col">ID</th><th scope="col">Regex</th>` +
        extraKeys.map((k) => `<th scope="col">${escapeHtml(k)}</th>`).join("") +
        (currentRulesReadonly ? "" : `<th scope="col">操作</th>`) +
        `</tr>`;
    }
    const colCount = 2 + extraKeys.length + (currentRulesReadonly ? 0 : 1);

    if (!items.length) {
      tbody.innerHTML = `<tr><td colspan="${colCount}" class="token-table-empty">暂无规则，点击「添加规则」新增。</td></tr>`;
      if (countEl) countEl.textContent = "共 0 条规则";
      return;
    }

    tbody.innerHTML = "";
    items.forEach((item) => {
      const tr = document.createElement("tr");
      tr.dataset.search = `${item.id || ""} ${item.regex || ""}`.toLowerCase();
      const idCell = `<td><code style="font-size:0.82rem;">${escapeHtml(item.id || "")}</code></td>`;
      const regexCell = `<td class="rule-regex-cell" title="${escapeHtml(item.regex || "")}"><code>${escapeHtml(item.regex || "")}</code></td>`;
      const extraCells = extraKeys
        .map((key) => `<td><span class="rule-extra">${escapeHtml(String(item[key] ?? ""))}</span></td>`)
        .join("");
      const actionCell = currentRulesReadonly ? "" : `<td style="white-space:nowrap;">
        <button class="btn-edit-sm" data-rule-id="${escapeHtml(item.id || "")}">编辑</button>
        <button class="btn-danger-sm" data-del-rule-id="${escapeHtml(item.id || "")}">删除</button>
      </td>`;
      tr.innerHTML = idCell + regexCell + extraCells + actionCell;

      if (!currentRulesReadonly) {
        tr.querySelector(".btn-edit-sm").addEventListener("click", () => {
          openRuleModal(section, item);
        });
        tr.querySelector(".btn-danger-sm").addEventListener("click", async (e) => {
          const ruleId = e.currentTarget.dataset.delRuleId;
          if (!confirm(`确认删除规则 "${ruleId}"？`)) return;
          try {
            await fetchJson(`/__ui__/api/rules/${encodeURIComponent(section)}/${encodeURIComponent(ruleId)}`, {
              method: "DELETE",
              headers: {"x-aegis-ui-csrf": uiCsrfToken},
            });
            await refreshRulesAfterWrite(section);
          } catch (err) {
            alert(`删除失败: ${err.message}`);
          }
        });
      }
      tbody.appendChild(tr);
    });
    filterRulesTable(searchBox ? searchBox.value : "");
  } catch (err) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="4" class="token-table-empty" style="color:var(--error)">加载失败: ${escapeHtml(err.message)}</td></tr>`;
    if (countEl) countEl.textContent = "加载失败";
  }
}

// Rule counts live in the sidebar, so a write has to refresh both views.
async function refreshRulesAfterWrite(section) {
  await loadRuleSections(section);
}

async function loadActionMap() {
  const tableEl = document.getElementById("rules-table");
  const actionMapPanel = document.getElementById("action-map-panel");
  const addBtn = document.getElementById("rules-add");
  const countEl = document.getElementById("rules-count");
  const grid = document.getElementById("action-map-grid");

  const searchBox = document.getElementById("rules-search");
  const labelEl = document.getElementById("rules-section-label");

  if (tableEl) tableEl.classList.add("hidden");
  if (actionMapPanel) actionMapPanel.classList.remove("hidden");
  if (addBtn) addBtn.classList.add("hidden");
  if (countEl) countEl.textContent = "";
  if (searchBox) searchBox.classList.add("hidden");
  if (labelEl) { labelEl.textContent = "动作映射"; labelEl.title = "action_map"; }

  try {
    const data = await fetchJson("/__ui__/api/rules_action_map");
    const actionMap = data.action_map || {};
    actionMapState = JSON.parse(JSON.stringify(actionMap));
    if (!grid) return;
    grid.innerHTML = "";
    const VALID_ACTIONS = ["block", "review", "sanitize", "pass"];
    Object.entries(actionMap).forEach(([category, threats]) => {
      const header = document.createElement("div");
      header.className = "field-card wide";
      header.innerHTML = `<div class="meta"><strong style="color:var(--accent);">${escapeHtml(category)}</strong></div>`;
      grid.appendChild(header);
      if (typeof threats === "object" && threats !== null) {
        Object.entries(threats).forEach(([threat, action]) => {
          const card = document.createElement("div");
          card.className = "field-card";
          const sel = document.createElement("select");
          sel.className = "action-map-select";
          VALID_ACTIONS.forEach((a) => {
            const opt = document.createElement("option");
            opt.value = a; opt.textContent = a;
            if (a === action) opt.selected = true;
            sel.appendChild(opt);
          });
          sel.addEventListener("change", () => {
            if (!actionMapState[category]) actionMapState[category] = {};
            actionMapState[category][threat] = sel.value;
          });
          card.innerHTML = `<div class="meta"><strong>${escapeHtml(threat)}</strong><span class="default">${escapeHtml(category)}</span></div>`;
          card.appendChild(sel);
          grid.appendChild(card);
        });
      }
    });
  } catch (err) {
    if (grid) grid.innerHTML = `<p style="color:var(--error)">加载失败: ${escapeHtml(err.message)}</p>`;
  }
}

function openRuleModal(section, item) {
  const modal = document.getElementById("rule-modal");
  if (!modal) return;
  document.getElementById("rule-modal-section").value = section;
  document.getElementById("rule-modal-edit-id").value = item ? (item.id || "") : "";
  document.getElementById("rule-modal-title").textContent = item ? "编辑规则" : "添加规则";
  document.getElementById("rule-modal-id").value = item ? (item.id || "") : "";
  document.getElementById("rule-modal-id").disabled = !!item;
  document.getElementById("rule-modal-regex").value = item ? (item.regex || "") : "";
  document.getElementById("rule-modal-kind").value = item ? (item.kind || item.category || "") : "";
  document.getElementById("rule-modal-error").textContent = "";
  document.getElementById("rule-modal-submit").textContent = item ? "保存" : "添加";

  // `kind` only exists on the anomaly/command groups; `category` on the request
  // sanitizer intent group. Show the field when the group actually uses one.
  const usesKind = section.endsWith("command_patterns");
  const usesCategory = section === "request_sanitizer.strong_intent_patterns";
  const kindField = document.getElementById("rule-modal-kind-field");
  if (kindField) {
    kindField.style.display = usesKind || usesCategory ? "" : "none";
    const label = kindField.querySelector("label");
    if (label) label.textContent = usesCategory ? "类别（category，可选）" : "类型（kind，可选）";
    kindField.dataset.fieldName = usesCategory ? "category" : "kind";
  }

  resetRegexLab();
  openModal(modal, document.getElementById("rule-modal-id"));
}

function closeRuleModal() {
  closeModal(document.getElementById("rule-modal"));
}

// ── Regex lab ────────────────────────────────
// Wraps every hit span in <mark> so the author can see exactly what the pattern
// eats, which is the part a plain "compiles ok" check never told them.
function renderProbeSample(sample, spans) {
  if (!spans.length) return `<span class="probe-miss">${escapeHtml(sample)}</span>`;
  let cursor = 0;
  let out = "";
  spans.forEach(([start, end]) => {
    if (start > cursor) out += escapeHtml(sample.slice(cursor, start));
    out += `<mark>${escapeHtml(sample.slice(start, end))}</mark>`;
    cursor = end;
  });
  out += escapeHtml(sample.slice(cursor));
  return out;
}

function resetRegexLab() {
  const result = document.getElementById("rule-modal-test-result");
  if (result) {
    result.innerHTML = "";
    result.classList.add("hidden");
  }
  setStatus("rule-modal-test-status", "");
}

async function runRegexLab() {
  const regex = document.getElementById("rule-modal-regex").value;
  const raw = document.getElementById("rule-modal-sample").value;
  const result = document.getElementById("rule-modal-test-result");
  const samples = raw.split("\n").filter((line) => line.length > 0).slice(0, 5);
  if (!regex.trim()) { setStatus("rule-modal-test-status", "请先填写正则表达式", true); return; }
  if (!samples.length) { setStatus("rule-modal-test-status", "请先填写测试文本", true); return; }

  setStatus("rule-modal-test-status", "测试中…");
  try {
    const data = await fetchJson("/__ui__/api/rules_test", {
      method: "POST",
      headers: {"Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken},
      body: JSON.stringify({regex, samples}),
    });
    result.classList.remove("hidden");
    if (data.timed_out) {
      result.innerHTML = `<p class="probe-danger">${escapeHtml(data.detail)}</p>`;
      setStatus("rule-modal-test-status", "超时", true);
      return;
    }
    const hits = data.results.filter((r) => r.matched).length;
    result.innerHTML = data.results
      .map((r) => {
        const sample = samples[r.index] ?? "";
        const head = r.matched
          ? `<span class="probe-hit-count">命中 ${r.match_count}${r.truncated ? "+" : ""} 处</span>`
          : '<span class="probe-miss-tag">未命中</span>';
        return `<div class="probe-row">${head}<pre class="probe-sample">${renderProbeSample(sample, r.spans)}</pre></div>`;
      })
      .join("");
    setStatus("rule-modal-test-status", `${hits} / ${samples.length} 条样本命中`);
  } catch (err) {
    setStatus("rule-modal-test-status", err.message, true);
  }
}

async function submitRuleModal() {
  const section = document.getElementById("rule-modal-section").value;
  const editId = document.getElementById("rule-modal-edit-id").value.trim();
  const isEdit = !!editId;
  const ruleId = document.getElementById("rule-modal-id").value.trim();
  const regex = document.getElementById("rule-modal-regex").value.trim();
  const kindField = document.getElementById("rule-modal-kind-field");
  const extraName = (kindField && kindField.dataset.fieldName) || "kind";
  const extraValue = kindField && kindField.style.display !== "none"
    ? document.getElementById("rule-modal-kind").value.trim()
    : "";
  const errEl = document.getElementById("rule-modal-error");
  errEl.textContent = "";
  if (!ruleId) { errEl.textContent = "请填写规则 ID"; return; }
  if (!regex) { errEl.textContent = "请填写正则表达式"; return; }
  const body = {id: ruleId, regex};
  if (extraValue) body[extraName] = extraValue;
  const submitBtn = document.getElementById("rule-modal-submit");
  submitBtn.disabled = true;
  submitBtn.textContent = "保存中…";
  try {
    if (isEdit) {
      const patch = {regex};
      if (extraValue) patch[extraName] = extraValue;
      await fetchJson(`/__ui__/api/rules/${encodeURIComponent(section)}/${encodeURIComponent(editId)}`, {
        method: "PATCH",
        headers: {"Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken},
        body: JSON.stringify(patch),
      });
    } else {
      await fetchJson(`/__ui__/api/rules/${encodeURIComponent(section)}`, {
        method: "POST",
        headers: {"Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken},
        body: JSON.stringify(body),
      });
    }
    closeRuleModal();
    await refreshRulesAfterWrite(section);
  } catch (err) {
    errEl.textContent = err.message;
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = isEdit ? "保存" : "添加";
  }
}

function bindRulesUI() {
  const sectionSearch = document.getElementById("rules-section-search");
  if (sectionSearch) {
    sectionSearch.addEventListener("input", (event) =>
      renderRuleSectionList(rulesSectionIndex, event.target.value));
  }
  const ruleSearch = document.getElementById("rules-search");
  if (ruleSearch) {
    ruleSearch.addEventListener("input", (event) => filterRulesTable(event.target.value));
  }
  const testBtn = document.getElementById("rule-modal-test");
  if (testBtn) testBtn.addEventListener("click", runRegexLab);

  const addBtn = document.getElementById("rules-add");
  if (addBtn) addBtn.addEventListener("click", () => openRuleModal(currentRulesSection, null));

  const closeBtn = document.getElementById("rule-modal-close");
  const cancelBtn = document.getElementById("rule-modal-cancel");
  const submitBtn = document.getElementById("rule-modal-submit");
  if (closeBtn) closeBtn.addEventListener("click", closeRuleModal);
  if (cancelBtn) cancelBtn.addEventListener("click", closeRuleModal);
  if (submitBtn) submitBtn.addEventListener("click", submitRuleModal);

  const saveActionMap = document.getElementById("save-action-map");
  if (saveActionMap) saveActionMap.addEventListener("click", async () => {
    setStatus("action-map-status", "保存中…");
    try {
      await fetchJson("/__ui__/api/rules_action_map", {
        method: "PATCH",
        headers: {"Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken},
        body: JSON.stringify(actionMapState),
      });
      setStatus("action-map-status", "已保存");
    } catch (err) {
      setStatus("action-map-status", `失败: ${err.message}`, true);
    }
  });

  const ruleModal = document.getElementById("rule-modal");
  if (ruleModal) {
    ruleModal.addEventListener("click", (e) => { if (e.target === ruleModal) closeRuleModal(); });
    ruleModal.addEventListener("keydown", (e) => {
      trapModalFocus(ruleModal, e);
      if (e.key === "Escape") {
        e.preventDefault();
        closeRuleModal();
      }
      if (e.key === "Enter" && !e.shiftKey && e.target.tagName !== "TEXTAREA") {
        const btn = document.getElementById("rule-modal-submit");
        if (btn && !btn.disabled) {
          e.preventDefault();
          submitRuleModal();
        }
      }
    });
  }
  loadRuleSections();
}

// ─── Key Management ───────────────────────────

async function loadKeys() {
  try {
    const data = await fetchJson("/__ui__/api/keys");
    const items = Array.isArray(data.items) ? data.items : [];
    items.forEach((item) => {
      const statusEl = document.getElementById(`key-status-${item.type}`);
      if (statusEl) {
        statusEl.textContent = item.exists ? "✓ 已生成" : "✗ 未找到";
        statusEl.style.color = item.exists ? "var(--success)" : "var(--error)";
      }
    });
  } catch (_err) {}
}

function keyLabel(keyType, rotated = false) {
  const labels = {
    gateway: "网关密钥",
    proxy_token: "代理令牌",
    fernet: "Fernet 加密密钥",
  };
  const base = labels[keyType] || keyType;
  return rotated ? `${base}（已轮换）` : base;
}

function formatKeySummary(data, {rotated = false} = {}) {
  const lines = [];
  if (rotated) {
    lines.push("已完成轮换。UI 不回显明文密钥，请使用下面的掩码和指纹核对服务器上的新值。");
  }
  if (data && data.masked_value) {
    lines.push(`掩码: ${data.masked_value}`);
  }
  if (data && data.key_fingerprint) {
    lines.push(`指纹: ${data.key_fingerprint}`);
  }
  if (!lines.length) {
    lines.push("无可显示的密钥摘要。");
  }
  return lines.join("\n");
}

function showKeyModal(keyType, data, {rotated = false} = {}) {
  const modal = document.getElementById("key-modal");
  const titleEl = document.getElementById("key-modal-title");
  const valueEl = document.getElementById("key-modal-value");
  if (!modal) return;
  if (titleEl) titleEl.textContent = keyLabel(keyType, rotated);
  if (valueEl) valueEl.textContent = formatKeySummary(data, {rotated});
  openModal(modal, document.getElementById("key-modal-copy"));
}

async function viewKey(keyType) {
  try {
    const data = await fetchJson(`/__ui__/api/keys/${encodeURIComponent(keyType)}`);
    showKeyModal(keyType, data);
  } catch (err) {
    alert(`查看失败: ${err.message}`);
  }
}

async function rotateKey(keyType) {
  const warnings = {
    fernet: "⚠️ 更换 Fernet 密钥后，历史脱敏映射将永久无法解密（可能影响上下文还原）。\n\n确认更换？",
    gateway: "更换网关密钥后，已注册的 Token 路由仍有效，但旧的 AEGIS_GATEWAY_KEY 将失效，需更新客户端配置。\n\n确认更换？",
    proxy_token: "更换代理令牌后 Caddy ↔ AegisGate 自动配对将失效，需重启服务重新配对。\n\n确认更换？",
  };
  if (!confirm(warnings[keyType] || "确认更换密钥？")) return;
  try {
    const data = await fetchJson(`/__ui__/api/keys/${encodeURIComponent(keyType)}/rotate`, {
      method: "POST",
      headers: {"x-aegis-ui-csrf": uiCsrfToken},
    });
    // Gateway key rotation invalidates the old session; server re-issues a new
    // session cookie and returns a fresh CSRF token — update it immediately so
    // subsequent requests (including loadKeys on modal close) don't get 401.
    if (data.csrf_token) uiCsrfToken = data.csrf_token;
    const detail = await fetchJson(`/__ui__/api/keys/${encodeURIComponent(keyType)}`);
    showKeyModal(keyType, detail, {rotated: true});
  } catch (err) {
    alert(`更换失败: ${err.message}`);
  }
}

function bindKeysUI() {
  document.querySelectorAll("[data-key-view]").forEach((btn) => {
    btn.addEventListener("click", () => viewKey(btn.dataset.keyView));
  });
  document.querySelectorAll("[data-key-rotate]").forEach((btn) => {
    btn.addEventListener("click", () => rotateKey(btn.dataset.keyRotate));
  });
  const closeBtn = document.getElementById("key-modal-close");
  const cancelBtn = document.getElementById("key-modal-cancel");
  const copyBtn = document.getElementById("key-modal-copy");
  const modal = document.getElementById("key-modal");
  function closeKeyModal() { if (modal) { closeModal(modal); loadKeys(); } }
  if (closeBtn) closeBtn.addEventListener("click", closeKeyModal);
  if (cancelBtn) cancelBtn.addEventListener("click", closeKeyModal);
  if (copyBtn) copyBtn.addEventListener("click", () => {
    const val = document.getElementById("key-modal-value").textContent;
    navigator.clipboard.writeText(val).then(() => {
      copyBtn.textContent = "已复制!";
      setTimeout(() => { copyBtn.textContent = "复制"; }, 1500);
    }).catch(() => {});
  });
  if (modal) {
    modal.addEventListener("click", (e) => { if (e.target === modal) closeKeyModal(); });
    modal.addEventListener("keydown", (e) => {
      trapModalFocus(modal, e);
      if (e.key === "Escape") {
        e.preventDefault();
        closeKeyModal();
      }
    });
  }
  loadKeys();
}

// ─── Stats Dashboard ─────────────────────

var currentStatsView = "hourly";

async function loadStats() {
  var tbody = document.getElementById("stats-tbody");
  var sinceEl = document.getElementById("stats-since");
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" class="token-table-empty">加载中...</td></tr>';
  try {
    var data = await fetchJson("/__ui__/api/stats");
    var t = data.totals || {};
    document.getElementById("stats-total-requests").textContent = (t.requests || 0).toLocaleString();
    document.getElementById("stats-total-redactions").textContent = (t.redactions || 0).toLocaleString();
    document.getElementById("stats-total-dangerous").textContent = (t.dangerous_replaced || 0).toLocaleString();
    document.getElementById("stats-total-blocked").textContent = (t.blocked || 0).toLocaleString();
    document.getElementById("stats-total-passthrough").textContent = (t.passthrough || 0).toLocaleString();
    if (sinceEl && data.since) sinceEl.textContent = "统计起始: " + data.since.replace("T", " ").replace(/\+.*/, "");

    var rows = currentStatsView === "hourly" ? data.hourly : data.daily;
    var timeKey = currentStatsView === "hourly" ? "hour" : "date";
    var thead = document.getElementById("stats-thead");
    if (thead) thead.innerHTML = '<tr><th scope="col">' + (currentStatsView === "hourly" ? "小时" : "日期") + '</th><th scope="col">请求</th><th scope="col">脱敏</th><th scope="col">危险替换</th><th scope="col">拦截</th><th scope="col">直通</th></tr>';

    if (!rows || !rows.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="token-table-empty">暂无数据</td></tr>';
      return;
    }
    tbody.innerHTML = "";
    rows.slice().reverse().forEach(function(row) {
      var tr = document.createElement("tr");
      var label = row[timeKey] || "";
      if (currentStatsView === "hourly" && label.length >= 13) label = label.slice(5) + ":00";
      tr.innerHTML =
        "<td>" + escapeHtml(label) + "</td>" +
        "<td>" + (row.requests || 0).toLocaleString() + "</td>" +
        "<td>" + (row.redactions || 0).toLocaleString() + "</td>" +
        "<td>" + (row.dangerous_replaced || 0).toLocaleString() + "</td>" +
        "<td>" + (row.blocked || 0).toLocaleString() + "</td>" +
        "<td>" + (row.passthrough || 0).toLocaleString() + "</td>";
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="6" class="token-table-empty" style="color:var(--error)">加载失败: ' + escapeHtml(err.message) + '</td></tr>';
  }
}

function bindStatsUI() {
  document.querySelectorAll("[data-stats-view]").forEach(function(tab) {
    tab.addEventListener("click", function() {
      document.querySelectorAll("[data-stats-view]").forEach(function(t) {
        t.classList.remove("active");
        t.setAttribute("aria-selected", "false");
      });
      tab.setAttribute("aria-selected", "true");
      tab.classList.add("active");
      currentStatsView = tab.dataset.statsView;
      loadStats();
    });
  });
  var refreshBtn = document.getElementById("stats-refresh");
  if (refreshBtn) refreshBtn.addEventListener("click", loadStats);
  var clearBtn = document.getElementById("stats-clear");
  if (clearBtn) clearBtn.addEventListener("click", async function() {
    if (!confirm("确认清除所有统计数据？此操作不可撤销。")) return;
    try {
      await fetchJson("/__ui__/api/stats", {
        method: "DELETE",
        headers: { "x-aegis-ui-csrf": uiCsrfToken },
      });
      loadStats();
    } catch (err) {
      alert("清除失败: " + err.message);
    }
  });
  loadStats();
}

// ─── Docker Compose Editor ────────────────────

var currentComposeFile = "";

async function loadComposeList() {
  var selector = document.getElementById("compose-selector");
  if (!selector) return;
  selector.innerHTML = "";
  try {
    var data = await fetchJson("/__ui__/api/compose");
    var items = Array.isArray(data.items) ? data.items : [];
    if (!items.length) {
      selector.innerHTML = '<span style="font-size:0.83rem;color:var(--muted);">未找到 Compose 文件</span>';
      return;
    }
    items.forEach(function(item) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "compose-file-btn" + (item.filename === currentComposeFile ? " active" : "");
      btn.textContent = item.filename + (item.exists ? "" : " (不存在)");
      btn.addEventListener("click", function() {
        currentComposeFile = item.filename;
        selector.querySelectorAll(".compose-file-btn").forEach(function(b) { b.classList.remove("active"); });
        btn.classList.add("active");
        loadComposeContent(item.filename);
      });
      selector.appendChild(btn);
    });
    if (!currentComposeFile && items.length) {
      currentComposeFile = items[0].filename;
      selector.querySelector(".compose-file-btn").classList.add("active");
      loadComposeContent(items[0].filename);
    } else if (currentComposeFile) {
      loadComposeContent(currentComposeFile);
    }
  } catch (err) {
    selector.innerHTML = '<span style="color:var(--error);font-size:0.83rem;">加载失败: ' + escapeHtml(err.message) + '</span>';
  }
}

async function loadComposeContent(filename) {
  var editor = document.getElementById("compose-editor");
  if (!editor) return;
  editor.value = "加载中…";
  try {
    var data = await fetchJson("/__ui__/api/compose/" + encodeURIComponent(filename));
    editor.value = data.content || "";
  } catch (err) {
    editor.value = "加载失败: " + err.message;
  }
}

function bindComposeUI() {
  var saveBtn = document.getElementById("save-compose");
  if (saveBtn) saveBtn.addEventListener("click", async function() {
    if (!currentComposeFile) return;
    var editor = document.getElementById("compose-editor");
    setStatus("compose-save-status", "保存中…");
    try {
      await fetchJson("/__ui__/api/compose/" + encodeURIComponent(currentComposeFile), {
        method: "PUT",
        headers: { "Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken },
        body: JSON.stringify({ content: editor.value }),
      });
      setStatus("compose-save-status", "已保存");
    } catch (err) {
      setStatus("compose-save-status", "保存失败: " + err.message, true);
    }
  });
  loadComposeList();
}

// ─── Restart ──────────────────────────────────

function bindRestartButton() {
  var btn = document.getElementById("restart-button");
  if (!btn) return;
  btn.addEventListener("click", async function() {
    if (!confirm("确认重启网关？服务将短暂中断约 1.5 秒。")) return;
    btn.disabled = true;
    btn.querySelector("svg + span, svg ~ *") || (btn.textContent = "重启中…");
    try {
      await fetchJson("/__ui__/api/restart", {
        method: "POST",
        headers: { "x-aegis-ui-csrf": uiCsrfToken },
      });
      updateHeaderStatus("restarting");
      setTimeout(function() { window.location.reload(); }, 3000);
    } catch (err) {
      alert("重启失败: " + err.message);
      btn.disabled = false;
    }
  });
}

// ─── Init new UI modules ─────────────────────

bindRulesUI();
bindKeysUI();
bindStatsUI();
bindComposeUI();
bindRestartButton();

(function initThemeToggle() {
  const btn = document.getElementById('theme-toggle');
  if (!btn) return;
  const sun = btn.querySelector('.icon-sun');
  const moon = btn.querySelector('.icon-moon');
  function updateIcon() {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    if (isDark) {
      sun.style.display = 'block';
      moon.style.display = 'none';
    } else {
      sun.style.display = 'none';
      moon.style.display = 'block';
    }
  }
  btn.addEventListener('click', () => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const newTheme = isDark ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('aegisgate_theme', newTheme);
    updateIcon();
  });
  updateIcon();
})();
