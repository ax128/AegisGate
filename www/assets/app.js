function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Link targets this viewer will turn into anchors. Anything else — most of all a
// `javascript:` URL — is left as the literal text the author wrote.
const DOC_LINK_ALLOWED = /^(?:https?:\/\/[^\s<>"']+|#[\w-]*|[\w./-]+\.md(?:#[\w-]*)?)$/i;

function renderDocLink(whole, label, href) {
  // escapeHtml already ran over the raw line, so & is &amp; here.
  const target = href.replace(/&amp;/g, "&");
  if (!DOC_LINK_ALLOWED.test(target)) return whole;
  if (/^https?:\/\//i.test(target)) {
    return `<a href="${escapeHtml(target)}" target="_blank" rel="noopener noreferrer">${label}</a>`;
  }
  const docId = target.split("#")[0];
  // A bare #anchor has no counterpart in this single-pane viewer.
  if (!docId) return label;
  return `<button type="button" class="doc-inline-link" data-doc-link="${escapeHtml(docId)}">${label}</button>`;
}

function renderInline(text) {
  return escapeHtml(text)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\[([^\]\n]+)\]\(([^)\s]+)\)/g, renderDocLink);
}

function isTableSeparatorRow(line) {
  return /^\s*\|?(?:\s*:?-{3,}:?\s*\|)+\s*:?-{3,}:?\s*\|?\s*$/.test(line)
    || /^\s*\|\s*:?-{3,}:?\s*\|\s*$/.test(line);
}

function splitTableRow(line) {
  return line
    .replace(/^\s*\|/, "")
    .replace(/\|\s*$/, "")
    .split("|")
    .map((cell) => cell.trim());
}

function renderMarkdown(markdown) {
  const lines = String(markdown || "").replace(/\r\n/g, "\n").split("\n");
  const chunks = [];
  let inCode = false;
  let codeLines = [];
  let listType = null;
  let paragraph = [];
  let tableLines = [];

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

  // README.md and README_zh.md are mostly tables. Without this they came out as
  // one run-on paragraph of pipes, which is what the docs panel showed by
  // default. A run of pipe lines is only a table when a separator row follows
  // the header; anything else falls back to paragraphs.
  function flushTable() {
    if (!tableLines.length) return;
    const rows = tableLines;
    tableLines = [];
    if (rows.length < 2 || !isTableSeparatorRow(rows[1])) {
      rows.forEach((line) => chunks.push(`<p>${renderInline(line)}</p>`));
      return;
    }
    const header = splitTableRow(rows[0]);
    const body = rows.slice(2).filter((line) => !isTableSeparatorRow(line)).map(splitTableRow);
    chunks.push(
      '<div class="markdown-table-wrap"><table class="markdown-table"><thead><tr>' +
        header.map((cell) => `<th scope="col">${renderInline(cell)}</th>`).join("") +
        "</tr></thead><tbody>" +
        body
          .map((cells) => `<tr>${cells.map((cell) => `<td>${renderInline(cell)}</td>`).join("")}</tr>`)
          .join("") +
        "</tbody></table></div>"
    );
  }

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (line.startsWith("```")) {
      flushParagraph();
      flushList();
      flushTable();
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
      flushTable();
      continue;
    }
    if (line.trimStart().startsWith("|")) {
      flushParagraph();
      flushList();
      tableLines.push(line);
      continue;
    }
    flushTable();
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
  flushTable();
  flushCode();
  return chunks.join("\n") || '<p class="empty-note">暂无内容。</p>';
}

let uiCsrfToken = "";
let configState = [];

// `resource` names the logical thing being read or written ("rules", "config"…).
// Reads remember its ETag; writes send it back as If-Match so a save from a
// stale tab is rejected instead of silently overwriting someone else's edit.
async function fetchJson(url, options = {}) {
  const { resource, ...init } = options;
  const method = (init.method || "GET").toUpperCase();
  const isWrite = method !== "GET" && method !== "HEAD";
  if (resource && isWrite) {
    const known = AegisUI.etags.get(resource);
    if (known) init.headers = { ...(init.headers || {}), "If-Match": known };
  }

  const response = await fetch(url, {
    cache: "no-store",
    credentials: "same-origin",
    ...init,
  });
  if (response.status === 401) {
    window.location.href = "/__ui__/login";
    throw new Error("unauthorized");
  }
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    let conflict = false;
    try {
      const data = await response.json();
      conflict = response.status === 409 && data.error === "etag_mismatch";
      if (data.detail) message = data.detail;
      else if (data.error) message = data.error;
    } catch (_error) {
      // noop
    }
    const error = new Error(message);
    error.status = response.status;
    error.conflict = conflict;
    throw error;
  }
  if (resource) {
    const tag = response.headers.get("ETag");
    // Only a 2xx reaches here — a rejected write already threw above, so it can
    // never refresh the validator and sneak through on retry. A *successful*
    // write must refresh it: the response carries the post-write ETag, and
    // without adopting it the next save from this same view would send the
    // pre-write validator and be rejected as a phantom conflict.
    if (tag) AegisUI.etags.set(resource, tag);
  }
  return response.json();
}

// One place decides what a failed write says. The raw server message is fine for
// a validation error the user can act on, but the transport-level ones used to
// surface as "HTTP 403" or the English "missing or invalid csrf token", neither
// of which tells anyone what to do next.
function describeWriteError(error, prefix) {
  if (error.conflict) {
    return `${prefix}：该内容已被其他会话修改，已为你重新加载最新版本，请确认后重新提交`;
  }
  if (error.status === 403) {
    return `${prefix}：登录会话已失效，请刷新页面后重试`;
  }
  if (error.status === 429) {
    return `${prefix}：操作过于频繁，请稍后再试`;
  }
  if (error.status >= 500) {
    return `${prefix}：服务端写入失败（${error.message}），请检查 config/ 目录权限与磁盘空间`;
  }
  return `${prefix}：${error.message}`;
}

// A conflict is not a failure the user caused; tell them what happened and
// reload the affected view so their next attempt starts from current state.
function handleWriteError(error, reload, prefix) {
  const level = error.conflict ? "warn" : "err";
  AegisUI.toast(describeWriteError(error, prefix), level, error.conflict ? { timeout: 8000 } : undefined);
  if (error.conflict && typeof reload === "function") reload();
}

// ─── Loading and empty states ──────────────────
// Tables used to show a single "加载中…" line and empty tables a dead sentence.
// Skeleton rows keep the layout from jumping, and an empty state that carries
// its own action removes the "so where is that button" step.

function skeletonRows(columns, rows = 3) {
  const cells = `<td><span class="skeleton-bar"></span></td>`.repeat(columns);
  return `<tr class="skeleton-row" aria-hidden="true">${cells}</tr>`.repeat(rows);
}

function showSkeleton(tbody, columns, rows = 3) {
  if (!tbody) return;
  tbody.innerHTML = skeletonRows(columns, rows);
}

function emptyStateRow(columns, message, action) {
  const button = action
    ? `<button type="button" class="btn-sm" data-empty-action="${escapeHtml(action.id)}">${escapeHtml(action.label)}</button>`
    : "";
  return (
    `<tr><td colspan="${columns}" class="token-table-empty">` +
    `<span class="empty-state"><span>${escapeHtml(message)}</span>${button}</span>` +
    `</td></tr>`
  );
}

function errorStateRow(columns, error, prefix) {
  return (
    `<tr><td colspan="${columns}" class="token-table-empty error-state">` +
    escapeHtml(describeWriteError(error, prefix)) +
    `</td></tr>`
  );
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
// Declared here rather than with the rules module: the unload guard below
// reads both dirty sets.
const actionMapDirty = new Set();

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
  if (item) {
    applyDependencies(item.section);
    updateDirtyIndicators();
  }
}

// The dirty set used to be write-only: the single blue border was the entire
// signal, and a reload dropped a dozen edits without a word. Now it drives the
// save button's count and the leave guard.
function updateDirtyIndicators() {
  configSections.forEach((section) => {
    const counter = document.getElementById(`dirty-${section.id}`);
    if (!counter) return;
    const pending = configState.filter(
      (item) => item.section === section.id && dirtyFields.has(item.field)
    ).length;
    counter.textContent = pending ? `（${pending} 项待保存）` : "";
  });
}

window.addEventListener("beforeunload", (event) => {
  if (!dirtyFields.size && !actionMapDirty.size) return;
  event.preventDefault();
  // Chrome ignores custom text but still needs returnValue set to prompt.
  event.returnValue = "";
});

function isChangedFromDefault(item) {
  // Secrets are never echoed to the browser, so there is nothing to compare.
  if (item.sensitive) return false;
  return String(item.value) !== String(item.default);
}

function resetFieldToDefault(fieldName) {
  const item = findField(fieldName);
  if (!item || item.sensitive) return;
  item.value = item.default;
  dirtyFields.add(fieldName);
  const card = document.getElementById(`card-${fieldName}`);
  const replacement = buildFieldCard(item);
  if (card) {
    if (card.classList.contains("search-hidden")) replacement.classList.add("search-hidden");
    card.replaceWith(replacement);
  }
  applyDependencies(item.section);
  updateDirtyIndicators();
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
  // Numbers stay strings here; the server coerces and range-checks them.
  const read = () => input.value;
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
  const changed = isChangedFromDefault(item);
  const badges = [];
  if (changed) {
    badges.push('<span class="field-badge changed" title="当前值与默认值不同">已改</span>');
  }
  if (item.requires_restart) {
    badges.push('<span class="field-badge restart" title="该字段被 hot_reload 固定，保存后需重启网关才生效">需重启</span>');
  }
  if (item.pending_value !== undefined) {
    badges.push('<span class="field-badge pending" title="已写入 config/.env，但当前进程仍在使用旧值">待生效</span>');
  }
  // The reset only rewrites the form; the value still goes through the same
  // save, coercion and range check as anything typed by hand.
  const defaultText = item.sensitive
    ? ""
    : `<span class="default">默认: ${escapeHtml(String(item.default))}` +
      (changed
        ? `<button type="button" class="field-reset" data-reset-field="${escapeHtml(item.field)}">恢复默认</button>`
        : "") +
      `</span>`;
  meta.innerHTML =
    `<strong>${escapeHtml(item.label)}${badges.join("")}</strong>` +
    `<span class="field-env">${escapeHtml(item.env)}</span>` +
    (item.help ? `<span class="field-help">${escapeHtml(item.help)}</span>` : "") +
    defaultText;
  card.appendChild(meta);
  card.appendChild(item.type === "bool" ? createBoolButton(item, card) : createInputField(item, card));
  if (dirtyFields.has(item.field)) card.classList.add("dirty");
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
    // The badges used to explain themselves only through a title attribute,
    // which touch and screen-reader users never see.
    `<p class="config-legend">` +
      `<span class="field-badge changed">已改</span>当前值与默认值不同` +
      `<span class="field-badge restart">需重启</span>保存后需重启网关才生效` +
      `<span class="field-badge pending">待生效</span>已写入 <code>config/.env</code>，当前进程仍用旧值` +
    `</p>` +
    `<div class="restart-banner hidden" id="restart-banner-${section.id}" role="status"></div>` +
    `<div class="config-groups" id="groups-${section.id}"></div>` +
    `<div class="panel-actions">` +
      `<button id="save-${section.id}" class="btn-save" type="button">` +
        `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">` +
        `<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>` +
        `<polyline points="17,21 17,13 7,13 7,21"/><polyline points="7,3 7,8 15,8"/></svg>` +
        `保存${escapeHtml(section.label)}<span class="save-count" id="dirty-${section.id}"></span>` +
      `</button>` +
      `<span id="${section.id}-save-status" class="status-note" aria-live="polite"></span>` +
    `</div>`;
  return panel;
}

function filterSection(sectionId, query) {
  const needle = String(query || "").trim().toLowerCase();
  const groups = document.getElementById(`groups-${sectionId}`);
  if (!groups) return 0;
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
  return visible;
}

// 100 fields across 8 panels, and the only search was per-panel: knowing the
// field but not which section owns it meant searching eight times. This drives
// every panel at once and folds away the ones with no hit, panel and nav entry
// together.
function filterAllSections(query) {
  const needle = String(query || "").trim().toLowerCase();
  let matchedFields = 0;
  let matchedSections = 0;
  configSections.forEach((section) => {
    const panel = document.getElementById(section.id);
    const nav = document.querySelector(`#config-nav a[href="#${section.id}"]`);
    const box = document.getElementById(`search-${section.id}`);
    if (box) box.value = needle;
    const visible = filterSection(section.id, needle);
    const hidden = Boolean(needle) && visible === 0;
    if (panel) panel.classList.toggle("search-hidden", hidden);
    if (nav) nav.classList.toggle("search-hidden", hidden);
    if (needle && visible) {
      matchedSections += 1;
      matchedFields += visible;
    }
  });
  const hits = document.getElementById("config-global-hits");
  if (!hits) return;
  if (!needle) hits.textContent = "";
  else if (matchedFields) hits.textContent = `${matchedSections} 个分区 · ${matchedFields} 项`;
  else hits.textContent = "无匹配";
}

// The overview's 安全级别 / 默认上游 cards name a config field, so send the
// reader to that field rather than to the top of a panel holding 15 of them.
function revealConfigField(fieldName) {
  const card = document.getElementById(`card-${fieldName}`);
  if (!card) return false;
  card.scrollIntoView({ block: "center" });
  card.classList.add("field-card-flash");
  setTimeout(() => card.classList.remove("field-card-flash"), 1600);
  const control = document.getElementById(`cfg-${fieldName}`);
  if (control && typeof control.focus === "function") control.focus({ preventScroll: true });
  return true;
}

function bindOverviewLinks() {
  document.querySelectorAll("[data-config-field]").forEach((link) => {
    link.addEventListener("click", (event) => {
      // Fall through to the plain anchor when the panels have not rendered yet.
      if (revealConfigField(link.dataset.configField)) event.preventDefault();
    });
  });
}

function bindConfigSearch() {
  const global = document.getElementById("config-global-search");
  if (global) {
    global.addEventListener("input", (event) => filterAllSections(event.target.value));
    global.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        global.value = "";
        filterAllSections("");
      }
    });
  }
  // The per-panel boxes and the global one must never disagree about what is
  // filtered, so typing in a panel drops the global query.
  document.getElementById("config-panels").addEventListener("input", (event) => {
    if (!event.target.classList.contains("config-search")) return;
    if (global && global.value) {
      global.value = "";
      const hits = document.getElementById("config-global-hits");
      if (hits) hits.textContent = "";
      configSections.forEach((section) => {
        const panel = document.getElementById(section.id);
        const nav = document.querySelector(`#config-nav a[href="#${section.id}"]`);
        if (panel) panel.classList.remove("search-hidden");
        if (nav) nav.classList.remove("search-hidden");
      });
    }
  });
  document.getElementById("config-panels").addEventListener("click", (event) => {
    const reset = event.target.closest("[data-reset-field]");
    if (reset) resetFieldToDefault(reset.dataset.resetField);
  });
}

function renderConfig(payload) {
  const items = Array.isArray(payload) ? payload : payload.items || [];
  const sections = (Array.isArray(payload) ? configSections : payload.sections) || configSections;
  configSections = sections;
  cloneState(items);

  const navHost = document.getElementById("config-nav");
  const panelHost = document.getElementById("config-panels");
  if (!panelHost) return;
  // Every save rebuilt all eight panels, which silently threw away whatever the
  // user had typed into the search boxes and jumped the page back up.
  const typedQueries = new Map();
  panelHost.querySelectorAll(".config-search").forEach((box) => typedQueries.set(box.id, box.value));
  const scrollTop = window.scrollY;
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

  typedQueries.forEach((value, id) => {
    const box = document.getElementById(id);
    if (box) box.value = value;
  });
  const globalQuery = document.getElementById("config-global-search");
  if (globalQuery && globalQuery.value.trim()) {
    filterAllSections(globalQuery.value);
  } else {
    sections.forEach((section) => {
      const box = document.getElementById(`search-${section.id}`);
      if (box && box.value) filterSection(section.id, box.value);
    });
  }
  updateDirtyIndicators();
  initScrollSpy();
  window.scrollTo({ top: scrollTop });
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
      resource: "config",
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
      AegisUI.toast(`已写入 config/.env，其中 ${restartRequired.length} 项需重启网关后生效`, "warn", { timeout: 8000 });
    } else {
      setStatus(statusId, "已保存，配置已热重载。");
      AegisUI.toast("配置已保存并热重载", "ok");
    }
    // Only the header/overview needs refreshing here. Going through
    // loadBootstrap re-fetched and re-rendered the whole config a second time
    // and reset the docs panel to its first document mid-read.
    await refreshOverview();
  } catch (error) {
    if (error.conflict) {
      setStatus(statusId, "配置已被其他会话修改，已重新加载", true);
      AegisUI.toast(describeWriteError(error, "保存失败"), "warn", { timeout: 8000 });
      const fresh = await fetchJson("/__ui__/api/config", { resource: "config" });
      renderConfig(fresh);
      await refreshOverview();
      return;
    }
    setStatus(statusId, describeWriteError(error, "保存失败"), true);
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

// The catalogue leads with the English README, which is the last thing a
// first-time reader of this console needs; the Web UI quickstart is.
const PREFERRED_FIRST_DOC = "WEBUI-QUICKSTART.md";

async function loadDocs() {
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
  const first = items.find((item) => item.id === PREFERRED_FIRST_DOC) || items[0];
  await loadDoc(first.id);
}

// Relative links inside a rendered document switch the viewer instead of
// navigating away from the console.
function bindDocLinks() {
  const viewer = document.getElementById("doc-content");
  if (!viewer) return;
  viewer.addEventListener("click", (event) => {
    const link = event.target.closest("[data-doc-link]");
    if (!link) return;
    event.preventDefault();
    loadDoc(link.dataset.docLink).catch(showDocError);
    document.getElementById("docs").scrollIntoView({ block: "start" });
  });
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

let docsLoaded = false;

// Status, listen address and the CSRF token only — cheap enough to run after
// every write without disturbing whatever else the user has open.
async function refreshOverview() {
  const output = document.getElementById("bootstrap-output");
  const data = await fetchJson("/__ui__/api/bootstrap");

  updateHeaderStatus(data.status);
  updateStatusBadge(data.status);

  document.getElementById("server-text").textContent = `${data.server.host}:${data.server.port}`;
  const security = document.getElementById("security-text");
  security.textContent = data.security.level || "-";
  const upstream = document.getElementById("upstream-text");
  upstream.textContent = data.upstream_base_url || "(未配置)";
  upstream.classList.toggle("is-unset", !data.upstream_base_url);

  uiCsrfToken = data.ui && data.ui.csrf_token ? data.ui.csrf_token : "";
  if (output) output.textContent = JSON.stringify(data, null, 2);
  bootstrapState = data;
  renderOnboarding();
  return data;
}

async function loadBootstrap() {
  await refreshOverview();

  const configData = await fetchJson("/__ui__/api/config", { resource: "config" });
  renderConfig(configData);

  // The catalogue does not change while the console is open, and reloading it
  // on every refresh threw away the document the user was reading.
  if (!docsLoaded) {
    await loadDocs();
    docsLoaded = true;
  }
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

// ─── Onboarding ──────────────────────────────
// "Logged in" to "first forwarded request" used to be an undocumented path
// through the sidebar, and the one value it ends in — the client base_url —
// appeared exactly once, in the dialog shown right after registration.

let bootstrapState = null;
let tokenItems = [];

// Mirrors gateway_auth._gateway_token_base_url. Deriving it from the browser's
// own origin is what the user should paste: it is the address they reached the
// console on, tunnel or reverse proxy included.
function clientBaseUrl(token) {
  return `${window.location.origin}/v1/__gw__/t/${token}`;
}

function copyButton(value, label = "复制") {
  return `<button type="button" class="btn-sm-ghost copy-btn" data-copy="${escapeHtml(value)}">${escapeHtml(label)}</button>`;
}

function bindCopyButtons(root) {
  if (!root) return;
  root.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-copy]");
    if (!button) return;
    const value = button.getAttribute("data-copy") || "";
    const original = button.dataset.copyLabel || button.textContent;
    button.dataset.copyLabel = original;
    try {
      await navigator.clipboard.writeText(value);
      button.textContent = "已复制";
      button.classList.add("copied");
      setTimeout(() => {
        button.textContent = original;
        button.classList.remove("copied");
      }, 1600);
    } catch (_error) {
      AegisUI.toast("浏览器拒绝了剪贴板访问，请手动复制", "warn");
    }
  });
}

function onboardStep(index, state, title, bodyHtml) {
  const marks = { done: "✓", now: String(index), todo: String(index) };
  return (
    `<li class="onboard-step onboard-${state}">` +
    `<span class="onboard-mark" aria-hidden="true">${marks[state]}</span>` +
    `<div class="onboard-body"><strong>${escapeHtml(title)}</strong>${bodyHtml}</div>` +
    `</li>`
  );
}

function renderOnboarding() {
  const host = document.getElementById("onboard");
  const list = document.getElementById("onboard-steps");
  if (!host || !list || !bootstrapState) return;

  const first = tokenItems[0];
  const defaultUpstream = String(bootstrapState.upstream_base_url || "").trim();
  const baseUrl = first
    ? clientBaseUrl(first.token)
    : defaultUpstream
      ? `${window.location.origin}/v1`
      : "";
  const routed = Boolean(first) || Boolean(defaultUpstream);

  const steps = [
    onboardStep(1, "done", "登录控制台", '<p>你已经在这里了。登录密码就是 <code>config/aegis_gateway.key</code> 的内容。</p>'),
    routed
      ? onboardStep(
          2,
          "done",
          "上游已就绪",
          first
            ? `<p>已注册 ${tokenItems.length} 个上游 Token，第一个指向 <code>${escapeHtml(first.upstream_base)}</code>。</p>`
            : `<p>已设置直连上游 <code>${escapeHtml(defaultUpstream)}</code>，<code>/v1/...</code> 可以不带 Token 直接调用。</p>`
        )
      : onboardStep(
          2,
          "now",
          "注册上游 Token",
          '<p>把你的模型服务地址（例如 <code>https://api.openai.com/v1</code>）注册进来，网关会生成一个路由 Token。</p>' +
            '<p class="onboard-actions"><button type="button" class="btn-sm" data-onboard-action="register">注册 Token</button></p>'
        ),
    baseUrl
      ? onboardStep(
          3,
          routed ? "now" : "todo",
          "把 Base URL 填进客户端",
          '<p>作为 OpenAI 兼容 API 的 <code>base_url</code> 使用，密钥仍然填上游自己的 key。</p>' +
            `<div class="onboard-copy">${copyButton(baseUrl, "复制 Base URL")}<code>${escapeHtml(baseUrl)}</code></div>` +
            `<div class="onboard-copy">${copyButton(`export OPENAI_BASE_URL="${baseUrl}"`, "复制环境变量")}<code>export OPENAI_BASE_URL="${escapeHtml(baseUrl)}"</code></div>`
        )
      : onboardStep(3, "todo", "把 Base URL 填进客户端", '<p>完成上一步后，这里会给出可直接复制的地址。</p>'),
  ];

  list.innerHTML = steps.join("");
  host.hidden = false;
  host.classList.toggle("onboard-complete", routed);

  const title = document.getElementById("onboard-title");
  if (title) title.textContent = routed ? "网关已就绪" : "先把第一个请求跑通";

  // Once a route exists this is reference material, not a task list — collapse
  // it by default, but remember whatever the user last chose.
  const stored = localStorage.getItem("aegisgate_onboard_open");
  const open = stored === null ? !routed : stored === "1";
  setOnboardOpen(open);
}

function setOnboardOpen(open) {
  const host = document.getElementById("onboard");
  const toggle = document.getElementById("onboard-toggle");
  if (!host || !toggle) return;
  host.classList.toggle("collapsed", !open);
  toggle.setAttribute("aria-expanded", open ? "true" : "false");
  toggle.textContent = open ? "收起" : "展开";
}

function bindOnboarding() {
  const host = document.getElementById("onboard");
  const toggle = document.getElementById("onboard-toggle");
  if (!host || !toggle) return;
  bindCopyButtons(host);
  toggle.addEventListener("click", () => {
    const open = toggle.getAttribute("aria-expanded") !== "true";
    localStorage.setItem("aegisgate_onboard_open", open ? "1" : "0");
    setOnboardOpen(open);
  });
  host.addEventListener("click", (event) => {
    if (event.target.closest('[data-onboard-action="register"]')) openTokenModal();
  });
}

// ─── Token Management ────────────────────────

async function loadTokens() {
  const tbody = document.getElementById("token-tbody");
  const countEl = document.getElementById("token-count");
  if (!tbody) return;
  showSkeleton(tbody, 5);
  try {
    const data = await fetchJson("/__ui__/api/tokens");
    const items = Array.isArray(data.items) ? data.items : [];
    tokenItems = items;
    renderOnboarding();
    if (countEl) countEl.textContent = `共 ${items.length} 个 Token`;
    if (!items.length) {
      tbody.innerHTML = emptyStateRow(5, "还没有注册任何上游 Token。", {
        id: "token-add",
        label: "注册 Token",
      });
      return;
    }
    tbody.innerHTML = "";
    items.forEach((item) => {
      const tr = document.createElement("tr");
      const wlCount = Array.isArray(item.whitelist_keys) ? item.whitelist_keys.length : 0;
      const wlTitle = wlCount
        ? `脱敏豁免字段: ${item.whitelist_keys.join(", ")}`
        : "未设置豁免，所有字段均参与脱敏";
      const baseUrl = clientBaseUrl(item.token);
      tr.innerHTML = `
        <td>
          <button class="token-code" title="点击复制完整 Token" data-copy="${escapeHtml(item.token)}">
            ${escapeHtml(item.token)}
          </button>
        </td>
        <td>
          <div class="token-baseurl">
            <code title="${escapeHtml(baseUrl)}">${escapeHtml(baseUrl)}</code>
            ${copyButton(baseUrl, "复制")}
          </div>
        </td>
        <td><div class="token-upstream" title="${escapeHtml(item.upstream_base)}">${escapeHtml(item.upstream_base)}</div></td>
        <td><span class="token-wl-count" title="${escapeHtml(wlTitle)}">${wlCount}</span></td>
        <td class="u-nowrap">
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
      // Token and base_url both copy through the shared delegated handler.
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
        const ok = await AegisUI.confirm({
          title: "删除 Token",
          message: "删除后使用该 Token 的客户端会立即失去访问，且无法恢复。",
          detail: t,
          confirmLabel: "删除",
          danger: true,
        });
        if (!ok) return;
        try {
          await fetchJson(`/__ui__/api/tokens/${encodeURIComponent(t)}`, {
            method: "DELETE",
            headers: { "x-aegis-ui-csrf": uiCsrfToken },
          });
          loadTokens();
        } catch (err) {
          handleWriteError(err, loadTokens, "删除失败");
        }
      });
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = errorStateRow(5, err, "Token 列表加载失败");
    if (countEl) countEl.textContent = "加载失败";
  }
}

// ── Upstream address feedback ────────────────
// The gateway refuses a malformed upstream when it forwards, not when it is
// registered, so a typo used to surface as a broken client hours later. These
// checks mirror gateway_keys.upstream_base_error; the server still has the
// final say, this just says it while the field is in front of the user.
const UPSTREAM_ENDPOINT_SUFFIXES = [
  "/chat/completions",
  "/completions",
  "/messages",
  "/embeddings",
  "/responses",
];

function upstreamFeedback(raw) {
  const value = String(raw || "").trim().replace(/\/+$/, "");
  if (!value) return { level: "", text: "" };
  let parsed;
  try {
    parsed = new URL(value);
  } catch (_error) {
    return { level: "err", text: "上游地址必须以 http:// 或 https:// 开头" };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { level: "err", text: "上游地址必须以 http:// 或 https:// 开头" };
  }
  if (!parsed.hostname) return { level: "err", text: "上游地址缺少主机名" };
  if (parsed.username || parsed.password) {
    return { level: "err", text: "上游地址不能包含用户名或密码，请改用请求头传递凭据" };
  }
  if (parsed.search || parsed.hash) {
    return { level: "err", text: "上游地址不能带查询参数或 # 片段" };
  }
  const path = parsed.pathname.replace(/\/+$/, "");
  const endpoint = UPSTREAM_ENDPOINT_SUFFIXES.find((suffix) => path.endsWith(suffix));
  if (endpoint) {
    return {
      level: "warn",
      text: `这里要填 base URL，不是具体端点：去掉结尾的 ${endpoint} 试试`,
    };
  }
  return { level: "ok", text: `将转发到 ${parsed.origin}${path || ""}` };
}

function renderUpstreamFeedback() {
  const note = document.getElementById("modal-upstream-note");
  const probe = document.getElementById("modal-probe");
  if (!note) return { level: "", text: "" };
  const feedback = upstreamFeedback(document.getElementById("modal-upstream").value);
  note.textContent = feedback.text;
  note.className = `field-note ${feedback.level}`;
  if (probe) probe.disabled = feedback.level === "err" || feedback.level === "";
  return feedback;
}

function resetTokenModalFeedback() {
  setStatus("modal-probe-status", "");
  renderUpstreamFeedback();
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
  resetTokenModalFeedback();
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
  resetTokenModalFeedback();
  openModal(modal, document.getElementById("modal-upstream"));
}

async function probeUpstream() {
  const feedback = renderUpstreamFeedback();
  if (feedback.level === "err" || !feedback.level) {
    setStatus("modal-probe-status", "请先填写有效的上游地址", true);
    return;
  }
  const button = document.getElementById("modal-probe");
  const upstream = document.getElementById("modal-upstream").value.trim();
  button.disabled = true;
  setStatus("modal-probe-status", "测试中…");
  try {
    const data = await fetchJson("/__ui__/api/tokens/probe", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken },
      body: JSON.stringify({ upstream_base: upstream }),
    });
    if (!data.reachable) {
      setStatus("modal-probe-status", `不可达：${data.detail}`, true);
      return;
    }
    // 401/403 from an upstream is the healthy answer here: the address resolved
    // and answered, it just wants the API key the client will send.
    const auth = data.status_code === 401 || data.status_code === 403;
    setStatus(
      "modal-probe-status",
      `已连通，返回 HTTP ${data.status_code}（${data.elapsed_ms} ms）` +
        (auth ? " — 需要鉴权，属正常" : ""),
      auth ? "warn" : "ok"
    );
  } catch (err) {
    setStatus("modal-probe-status", describeWriteError(err, "测试失败"), true);
  } finally {
    button.disabled = false;
  }
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
  const feedback = upstreamFeedback(upstream);
  if (feedback.level === "err") { errorEl.textContent = feedback.text; return; }

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
        AegisUI.toast("Token 已更新", "ok");
        await AegisUI.alert({
          title: "Token 已更新",
          message: "客户端的 base_url 需要同步更新为下面的地址。",
          html: AegisUI.copyRow("Base URL", data.base_url),
        });
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
        await AegisUI.alert({
          title: "Token 已存在，复用现有映射",
          html: AegisUI.copyRow("Token", data.token) + AegisUI.copyRow("Base URL", data.base_url),
        });
      } else {
        await AegisUI.alert({
          title: "注册成功",
          message: "Base URL 可直接作为 OpenAI 兼容 API 的 base_url 使用，请妥善保存。",
          html: AegisUI.copyRow("Token", data.token) + AegisUI.copyRow("Base URL", data.base_url),
        });
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
  const upstream   = document.getElementById("modal-upstream");
  const probeBtn   = document.getElementById("modal-probe");
  const tokensPanel = document.getElementById("tokens");

  if (addBtn)     addBtn.addEventListener("click", openTokenModal);
  if (refreshBtn) refreshBtn.addEventListener("click", loadTokens);
  if (closeBtn)   closeBtn.addEventListener("click", closeTokenModal);
  if (cancelBtn)  cancelBtn.addEventListener("click", closeTokenModal);
  if (submitBtn)  submitBtn.addEventListener("click", submitTokenModal);
  if (probeBtn)   probeBtn.addEventListener("click", probeUpstream);
  if (upstream) {
    upstream.addEventListener("input", () => {
      renderUpstreamFeedback();
      // A probe result belongs to the address that produced it.
      setStatus("modal-probe-status", "");
    });
  }
  bindCopyButtons(tokensPanel);
  if (tokensPanel) {
    tokensPanel.addEventListener("click", (event) => {
      if (event.target.closest('[data-empty-action="token-add"]')) openTokenModal();
    });
  }

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
    // The getting-started card is derived from the token list too, so a manual
    // refresh has to pick that up or it reports stale progress.
    loadTokens();
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
    const ok = await AegisUI.confirm({ title: "退出登录", message: "需要重新输入网关密钥才能再次进入控制台。", confirmLabel: "退出" });
    if (!ok) return;
    await fetchJson("/__ui__/api/logout", {
      method: "POST",
      headers: { "x-aegis-ui-csrf": uiCsrfToken },
    });
    window.location.href = "/__ui__/login";
  });
}

// ─── Keyboard ────────────────────────────────
// The sidebar is 15+ links deep, so reaching a search box by Tab is a chore.
// "/" jumps to the search box of whichever panel is on screen.

function visibleSearchBox() {
  const boxes = Array.from(document.querySelectorAll(".config-search, #rules-search, #audit-q"));
  const onScreen = boxes.find((box) => {
    if (box.classList.contains("hidden") || box.closest(".search-hidden")) return false;
    const rect = box.getBoundingClientRect();
    return rect.height > 0 && rect.top >= 0 && rect.top < window.innerHeight;
  });
  return onScreen || document.getElementById("config-global-search");
}

// A hash in the URL is resolved by the browser while the page is still mostly
// empty: the config panels, the rules workbench and the redaction list all load
// afterwards and all sit above #tokens and #docs, so the anchor ends up
// thousands of pixels short. Re-apply it while the page settles, and stop the
// moment the reader takes over.
function honourInitialHash() {
  const target = window.location.hash && document.querySelector(window.location.hash);
  if (!target) return;
  let cancelled = false;
  const cancel = () => { cancelled = true; };
  ["wheel", "touchstart", "keydown", "mousedown"].forEach((event) =>
    window.addEventListener(event, cancel, { once: true, passive: true })
  );
  let previousTop = null;
  let stableTicks = 0;
  const stop = setInterval(() => {
    if (cancelled) {
      clearInterval(stop);
      return;
    }
    const top = Math.round(target.getBoundingClientRect().top + window.scrollY);
    stableTicks = top === previousTop ? stableTicks + 1 : 0;
    previousTop = top;
    target.scrollIntoView();
    // Two quiet ticks means the loaders above it are done moving things.
    if (stableTicks >= 2) clearInterval(stop);
  }, 200);
  setTimeout(() => clearInterval(stop), 4000);
}

function bindKeyboardShortcuts() {
  document.addEventListener("keydown", (event) => {
    if (event.key !== "/" || event.ctrlKey || event.metaKey || event.altKey) return;
    const active = document.activeElement;
    const typing = active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA" || active.isContentEditable);
    if (typing) return;
    // A dialog owns the keyboard while it is open.
    if (document.querySelector(".dialog-overlay, .modal-overlay:not(.hidden)")) return;
    const box = visibleSearchBox();
    if (!box) return;
    event.preventDefault();
    box.focus();
    box.select();
  });
}

bindActions();
bindTokenModal();
bindOnboarding();
bindConfigSearch();
bindOverviewLinks();
bindDocLinks();
bindKeyboardShortcuts();
honourInitialHash();
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
  showSkeleton(tbody, 4);
  try {
    const data = await fetchJson("/__ui__/api/redact_values", { resource: "redact_values" });
    const items = Array.isArray(data.items) ? data.items : [];
    // An unreadable file arrives as an empty list too. Showing it as "nothing
    // configured yet" — with an add button — is what invited the overwrite: the
    // save behind that button replaces the values still sitting on disk.
    if (data.degraded) {
      if (countEl) countEl.textContent = "不可用";
      tbody.innerHTML =
        `<tr><td colspan="4" class="token-table-empty error-state">` +
        `${escapeHtml(data.degraded_detail || "精确值文件当前无法读取，已停止生效。")}` +
        `</td></tr>`;
      return;
    }
    if (countEl) countEl.textContent = `共 ${items.length} 条`;
    if (!items.length) {
      tbody.innerHTML = emptyStateRow(4, "还没有配置精确值脱敏。", {
        id: "redact-add",
        label: "添加值",
      });
      return;
    }
    tbody.innerHTML = "";
    items.forEach((item, idx) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${idx}</td>
        <td><code class="u-code-md">${escapeHtml(item.masked)}</code></td>
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
        const ok = await AegisUI.confirm({
          title: "删除精确值脱敏",
          message: `确认删除第 ${idx} 条？该值将不再从请求与响应中被替换。`,
          confirmLabel: "删除",
          danger: true,
        });
        if (!ok) return;
        try {
          await fetchJson(`/__ui__/api/redact_values/${idx}`, {
            method: "DELETE",
            resource: "redact_values",
            headers: { "x-aegis-ui-csrf": uiCsrfToken },
          });
          loadRedactValues();
        } catch (err) {
          handleWriteError(err, loadRedactValues, "删除失败");
        }
      });
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = errorStateRow(4, err, "精确值列表加载失败");
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
      resource: "redact_values",
      headers: { "Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken },
      body: JSON.stringify({ value }),
    });
    closeRedactModal();
    AegisUI.toast("已添加，该值将从请求与响应中被替换", "ok");
    loadRedactValues();
  } catch (err) {
    if (err.conflict) {
      closeRedactModal();
      handleWriteError(err, loadRedactValues, "添加失败");
      return;
    }
    errEl.textContent = err.message;
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "添加";
  }
}

function bindRedactUI() {
  const addBtn = document.getElementById("redact-add");
  const refreshBtn = document.getElementById("redact-refresh");
  const panel = document.getElementById("redact-values");
  if (addBtn) addBtn.addEventListener("click", openRedactModal);
  if (refreshBtn) refreshBtn.addEventListener("click", loadRedactValues);
  if (panel) {
    panel.addEventListener("click", (event) => {
      if (event.target.closest('[data-empty-action="redact-add"]')) openRedactModal();
    });
  }

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
    // A group the request-redaction panel owns is edited there, not here.
    if (section.hidden) return;
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

  // The action map below is appended unconditionally, so this has to be decided
  // before it lands — otherwise the sidebar is never empty and a search that
  // matches nothing looks like a group list that failed to load.
  if (!byFilter.size) {
    const note = document.createElement("p");
    note.className = "empty-note";
    note.textContent = "没有匹配的规则组";
    host.appendChild(note);
  }

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
}

async function selectRulesSection(sectionId) {
  if (sectionId !== currentRulesSection && actionMapDirty.size) {
    const ok = await AegisUI.confirm({
      title: "放弃未保存的动作映射改动？",
      message: `有 ${actionMapDirty.size} 项处置动作改了还没保存，切走后会丢失。`,
      confirmLabel: "放弃改动",
      danger: true,
    });
    if (!ok) return;
    actionMapDirty.clear();
    updateActionMapDirty();
  }
  currentRulesSection = sectionId;
  document.querySelectorAll("[data-rules-section]").forEach((node) => {
    const active = node.dataset.rulesSection === sectionId;
    node.classList.toggle("active", active);
    node.setAttribute("aria-selected", active ? "true" : "false");
  });
  const search = document.getElementById("rules-search");
  if (search) {
    search.value = "";
    search.placeholder = "按 ID 或正则搜索…";
  }
  loadRules(sectionId);
}

async function loadRuleSections(preferredSection) {
  try {
    const data = await fetchJson("/__ui__/api/rules");
    rulesSectionIndex = Array.isArray(data.sections) ? data.sections : [];
    const selectable = rulesSectionIndex.filter((s) => !s.hidden);
    const fallback = selectable.length ? selectable[0].id : ACTION_MAP_SECTION;
    const target = preferredSection
      || (selectable.some((s) => s.id === currentRulesSection) ? currentRulesSection : null)
      || fallback;
    currentRulesSection = selectable.some((s) => s.id === target) ? target : fallback;
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
  showSkeleton(tbody, 4);
  if (tableEl) tableEl.classList.remove("hidden");
  if (actionMapPanel) actionMapPanel.classList.add("hidden");
  if (searchBox) searchBox.classList.remove("hidden");

  try {
    const data = await fetchJson(`/__ui__/api/rules/${encodeURIComponent(section)}`, { resource: "rules" });
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
      tbody.innerHTML = currentRulesReadonly
        ? emptyStateRow(colCount, "该规则组暂无规则。")
        : emptyStateRow(colCount, "该规则组暂无规则。", { id: "rules-add", label: "添加规则" });
      if (countEl) countEl.textContent = "共 0 条规则";
      return;
    }

    tbody.innerHTML = "";
    items.forEach((item) => {
      const tr = document.createElement("tr");
      tr.dataset.search = `${item.id || ""} ${item.regex || ""}`.toLowerCase();
      const idCell = `<td><code class="u-code-sm">${escapeHtml(item.id || "")}</code></td>`;
      const regexCell = `<td class="rule-regex-cell" title="${escapeHtml(item.regex || "")}"><code>${escapeHtml(item.regex || "")}</code></td>`;
      const extraCells = extraKeys
        .map((key) => `<td><span class="rule-extra">${escapeHtml(String(item[key] ?? ""))}</span></td>`)
        .join("");
      const actionCell = currentRulesReadonly ? "" : `<td class="u-nowrap">
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
          const ok = await AegisUI.confirm({
            title: "删除安全规则",
            message: "规则删除后立即热重载生效，对应的检测能力会随之关闭。",
            detail: ruleId,
            confirmLabel: "删除",
            danger: true,
          });
          if (!ok) return;
          try {
            await fetchJson(`/__ui__/api/rules/${encodeURIComponent(section)}/${encodeURIComponent(ruleId)}`, {
              method: "DELETE",
              resource: "rules",
              headers: {"x-aegis-ui-csrf": uiCsrfToken},
            });
            await refreshRulesAfterWrite(section);
          } catch (err) {
            handleWriteError(err, () => refreshRulesAfterWrite(section), "删除失败");
          }
        });
      }
      tbody.appendChild(tr);
    });
    filterRulesTable(searchBox ? searchBox.value : "");
  } catch (err) {
    if (tbody) tbody.innerHTML = errorStateRow(4, err, "规则加载失败");
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
  // The action map is a long list of categories too, so it keeps the search box
  // rather than hiding it and leaving people to scroll.
  if (searchBox) {
    searchBox.classList.remove("hidden");
    searchBox.placeholder = "按类别或威胁名搜索…";
  }
  if (labelEl) { labelEl.textContent = "动作映射"; labelEl.title = "action_map"; }

  try {
    const data = await fetchJson("/__ui__/api/rules_action_map", { resource: "rules" });
    const actionMap = data.action_map || {};
    actionMapState = JSON.parse(JSON.stringify(actionMap));
    actionMapDirty.clear();
    updateActionMapDirty();
    if (!grid) return;
    grid.innerHTML = "";
    const VALID_ACTIONS = ["block", "review", "sanitize", "pass"];
    Object.entries(actionMap).forEach(([category, threats]) => {
      const header = document.createElement("div");
      header.className = "field-card wide action-map-header";
      header.dataset.search = String(category).toLowerCase();
      header.innerHTML = `<div class="meta"><strong class="u-accent">${escapeHtml(category)}</strong></div>`;
      grid.appendChild(header);
      if (typeof threats === "object" && threats !== null) {
        Object.entries(threats).forEach(([threat, action]) => {
          const card = document.createElement("div");
          card.className = "field-card";
          card.dataset.search = `${category} ${threat}`.toLowerCase();
          const sel = document.createElement("select");
          sel.className = "action-map-select";
          sel.setAttribute("aria-label", `${category} / ${threat} 的处置动作`);
          VALID_ACTIONS.forEach((a) => {
            const opt = document.createElement("option");
            opt.value = a; opt.textContent = a;
            if (a === action) opt.selected = true;
            sel.appendChild(opt);
          });
          sel.addEventListener("change", () => {
            if (!actionMapState[category]) actionMapState[category] = {};
            actionMapState[category][threat] = sel.value;
            // Changing a select and then switching groups used to drop the edit
            // without a word; now it is marked and the leave prompt covers it.
            const key = `${category}.${threat}`;
            if (sel.value === action) actionMapDirty.delete(key);
            else actionMapDirty.add(key);
            card.classList.toggle("dirty", sel.value !== action);
            updateActionMapDirty();
          });
          card.innerHTML = `<div class="meta"><strong>${escapeHtml(threat)}</strong><span class="default">${escapeHtml(category)}</span></div>`;
          card.appendChild(sel);
          grid.appendChild(card);
        });
      }
    });
    filterActionMap(searchBox ? searchBox.value : "");
  } catch (err) {
    if (grid) grid.innerHTML = `<p class="error-note">${escapeHtml(describeWriteError(err, "动作映射加载失败"))}</p>`;
  }
}

function updateActionMapDirty() {
  const counter = document.getElementById("action-map-dirty");
  if (counter) counter.textContent = actionMapDirty.size ? `（${actionMapDirty.size} 项待保存）` : "";
}

function filterActionMap(query) {
  const needle = String(query || "").trim().toLowerCase();
  const grid = document.getElementById("action-map-grid");
  if (!grid) return;
  grid.querySelectorAll(".field-card").forEach((card) => {
    const hit = !needle || (card.dataset.search || "").includes(needle);
    card.classList.toggle("search-hidden", !hit);
  });
}

let ruleModalOnSaved = null;

function openRuleModal(section, item, onSaved) {
  // The request-redaction panel reuses this modal (it carries the regex lab), so
  // a save has to refresh whichever view opened it.
  ruleModalOnSaved = typeof onSaved === "function" ? onSaved : null;
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
        resource: "rules",
        headers: {"Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken},
        body: JSON.stringify(patch),
      });
    } else {
      await fetchJson(`/__ui__/api/rules/${encodeURIComponent(section)}`, {
        method: "POST",
        resource: "rules",
        headers: {"Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken},
        body: JSON.stringify(body),
      });
    }
    const onSaved = ruleModalOnSaved;
    closeRuleModal();
    AegisUI.toast(isEdit ? "规则已更新，已热重载生效" : "规则已添加，已热重载生效", "ok");
    if (onSaved) await onSaved();
    else await refreshRulesAfterWrite(section);
  } catch (err) {
    if (err.conflict) {
      const onSaved = ruleModalOnSaved;
      closeRuleModal();
      handleWriteError(err, onSaved || (() => loadRules(section)), "保存失败");
      return;
    }
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
    ruleSearch.addEventListener("input", (event) => {
      if (currentRulesSection === ACTION_MAP_SECTION) filterActionMap(event.target.value);
      else filterRulesTable(event.target.value);
    });
  }
  const testBtn = document.getElementById("rule-modal-test");
  if (testBtn) testBtn.addEventListener("click", runRegexLab);

  const addBtn = document.getElementById("rules-add");
  if (addBtn) addBtn.addEventListener("click", () => openRuleModal(currentRulesSection, null));
  const rulesPanel = document.getElementById("rules");
  if (rulesPanel) {
    rulesPanel.addEventListener("click", (event) => {
      if (event.target.closest('[data-empty-action="rules-add"]')) {
        openRuleModal(currentRulesSection, null);
      }
    });
  }

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
        resource: "rules",
        headers: {"Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken},
        body: JSON.stringify(actionMapState),
      });
      setStatus("action-map-status", "已保存");
      AegisUI.toast("动作映射已保存", "ok");
      actionMapDirty.clear();
      updateActionMapDirty();
      document.querySelectorAll("#action-map-grid .field-card.dirty")
        .forEach((card) => card.classList.remove("dirty"));
    } catch (err) {
      setStatus("action-map-status", describeWriteError(err, "保存失败"), true);
      handleWriteError(err, loadActionMap, "保存失败");
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
    AegisUI.toast(describeWriteError(err, "查看失败"), "err");
  }
}

async function rotateKey(keyType) {
  const warnings = {
    fernet: "⚠️ 更换 Fernet 密钥后，历史脱敏映射将永久无法解密（可能影响上下文还原）。\n\n确认更换？",
    gateway: "更换网关密钥后，已注册的 Token 路由仍有效，但旧的 AEGIS_GATEWAY_KEY 将失效，需更新客户端配置。\n\n确认更换？",
    proxy_token: "更换代理令牌后 Caddy ↔ AegisGate 自动配对将失效，需重启服务重新配对。\n\n确认更换？",
  };
  const ok = await AegisUI.confirm({
    title: "更换密钥",
    message: warnings[keyType] || "确认更换密钥？",
    confirmLabel: "更换密钥",
    danger: true,
    requireText: keyType,
  });
  if (!ok) return;
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
    AegisUI.toast(describeWriteError(err, "更换失败"), "err");
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
  showSkeleton(tbody, 6);
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
    tbody.innerHTML = errorStateRow(6, err, "统计加载失败");
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
    const ok = await AegisUI.confirm({
      title: "清除请求统计",
      message: "所有历史统计将被清空，此操作不可撤销。",
      confirmLabel: "清除",
      danger: true,
    });
    if (!ok) return;
    try {
      await fetchJson("/__ui__/api/stats", {
        method: "DELETE",
        headers: { "x-aegis-ui-csrf": uiCsrfToken },
      });
      loadStats();
    } catch (err) {
      AegisUI.toast(describeWriteError(err, "清除失败"), "err");
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
      selector.innerHTML = '<span class="compose-empty">未找到 Compose 文件</span>';
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
        loadComposeContent(item.filename, item.exists);
      });
      selector.appendChild(btn);
    });
    // The list already knows which files are missing; fetching one of those
    // anyway just turned a known-absent file into a 404 and an error message.
    var current = items.find(function(item) { return item.filename === currentComposeFile; });
    if (!current && items.length) {
      current = items[0];
      currentComposeFile = current.filename;
      selector.querySelector(".compose-file-btn").classList.add("active");
    }
    if (current) loadComposeContent(current.filename, current.exists);
  } catch (err) {
    selector.innerHTML = '<span class="compose-error">' + escapeHtml(describeWriteError(err, "Compose 列表加载失败")) + '</span>';
  }
}

async function loadComposeContent(filename, exists) {
  var editor = document.getElementById("compose-editor");
  if (!editor) return;
  if (exists === false) {
    editor.value = "";
    editor.placeholder = filename + " 还不存在。在这里写入内容并保存即可创建它。";
    setStatus("compose-save-status", filename + " 尚未创建", "warn");
    return;
  }
  editor.value = "加载中…";
  try {
    var data = await fetchJson("/__ui__/api/compose/" + encodeURIComponent(filename), { resource: "compose" });
    editor.value = data.content || "";
    setStatus("compose-save-status", "");
  } catch (err) {
    editor.value = "";
    setStatus("compose-save-status", describeWriteError(err, "加载失败"), true);
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
        resource: "compose",
        headers: { "Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken },
        body: JSON.stringify({ content: editor.value }),
      });
      setStatus("compose-save-status", "已保存");
      AegisUI.toast("Compose 文件已保存", "ok");
    } catch (err) {
      setStatus("compose-save-status", describeWriteError(err, "保存失败"), true);
      handleWriteError(err, function () { loadComposeContent(currentComposeFile, true); }, "保存失败");
    }
  });
  loadComposeList();
}

// ─── Restart ──────────────────────────────────

function bindRestartButton() {
  var btn = document.getElementById("restart-button");
  if (!btn) return;
  btn.addEventListener("click", async function() {
    const ok = await AegisUI.confirm({
      title: "重启网关",
      message: "网关将在约 1.5 秒后收到 SIGTERM，期间正在处理的请求会中断。",
      confirmLabel: "重启",
      danger: true,
    });
    if (!ok) return;
    // Writing to btn.textContent used to wipe the icon along with the label and
    // never put either back, so a failed restart left the header stuck on
    // "重启中…" until a reload.
    var label = document.getElementById("restart-label");
    btn.disabled = true;
    if (label) label.textContent = "重启中…";
    try {
      await fetchJson("/__ui__/api/restart", {
        method: "POST",
        headers: { "x-aegis-ui-csrf": uiCsrfToken },
      });
      updateHeaderStatus("restarting");
      setTimeout(function() { window.location.reload(); }, 3000);
    } catch (err) {
      AegisUI.toast(describeWriteError(err, "重启失败"), "err");
      if (label) label.textContent = "重启";
      btn.disabled = false;
    }
  });
}


// ─── Request-side redaction (read-only) ───────
// Every fact this panel shows is computed server-side and rendered verbatim.
// Whether a rule is live on a given surface depends on the relaxed set, a route
// split, a message-role check and a separate hard-coded V2 set; re-deriving any
// of that here would be a second implementation free to drift from the one the
// request path actually runs. So: no derivation below, only rendering.

let requestRedactionState = null;

function rrSurfaceBadge(surface, effective, overlay) {
  const gated = overlay && overlay.active === false;
  const on = Boolean(effective);
  // A surface its master switch has turned off is *not* running, so it reads as
  // muted like any other inactive one — struck through to say why. Warning
  // colour here made a switched-off surface louder than a live one.
  const cls = !on || gated ? "badge-muted" : "badge-success";
  const title = [
    `${surface.code} ${surface.label}`,
    surface.detail ? `范围：${surface.detail}` : "",
    `使用集合：${rrPatternSetLabel(surface.pattern_set)}`,
    surface.note || "",
    on ? "该规则在此执行面生效" : "该规则在此执行面不生效",
    gated ? `已被总控 ${overlay.switch} 关闭` : "",
  ].filter(Boolean).join("\n");
  return (
    `<span class="badge ${cls} rr-surface-badge${gated ? " rr-surface-gated" : ""}" ` +
    `title="${escapeHtml(title)}">${escapeHtml(surface.code)}</span>`
  );
}

function rrPatternSetLabel(kind) {
  if (kind === "relaxed") return "relaxed 集";
  if (kind === "full") return "全量集";
  return "V2 固定 15 项集合";
}

function rrBoolBadge(value, onLabel, offLabel) {
  return value
    ? `<span class="badge badge-success">${escapeHtml(onLabel)}</span>`
    : `<span class="badge badge-muted">${escapeHtml(offLabel)}</span>`;
}

function rrTruncate(text, limit) {
  const value = String(text || "");
  return value.length > limit ? value.slice(0, limit) + "…" : value;
}

function rrAlerts(data) {
  const alerts = [];
  if (!data.rules_file_resolver_consistent) {
    alerts.push({
      level: "warn",
      title: "规则文件路径自检不一致",
      body:
        `控制台与运行时现在都使用 ${data.rules_file_path}；` +
        `按旧的「相对启动目录」规则会解析到 ${data.legacy_cwd_path}。` +
        (data.shadow_rules_files.length
          ? `磁盘上仍存在这些疑似影子文件，请人工核对后清理：${data.shadow_rules_files.join("、")}`
          : "该路径下当前没有残留文件。"),
    });
  }
  if (data.write_blocked) {
    alerts.push({
      level: "err",
      title: "存在归一化 ID 冲突，相关写入已阻断",
      body: data.normalized_collisions
        .map((item) => `${item.source} 中 ${item.raw.join("、")} 归一化后都是 ${item.normalized}`)
        .join("；") + "。请先在「安全规则」中消除冲突，工具不会代为选择保留哪一条。",
    });
  }
  if (data.malformed_pii_entries.length) {
    alerts.push({
      level: "err",
      title: "pii_patterns 中存在非映射条目",
      body:
        "V1 管道层对每一项直接取字段，这类条目会让请求管道抛错：" +
        data.malformed_pii_entries.map((item) => `第 ${item.index} 项（${rrTruncate(item.value, 40)}）`).join("、"),
    });
  }
  if (data.pending_enabled_false_ids.length) {
    alerts.push({
      level: "warn",
      title: "检测到待启用语义的配置，当前版本尚未执行",
      body:
        `以下规则在 YAML 中写了 enabled: false，但当前代码不读取该字段，它们仍在运行：` +
        `${data.pending_enabled_false_ids.join("、")}。下方的生效面按「运行中」计算。` +
        "后续版本启用该语义后，这些规则将开始真正停用，请提前确认。",
    });
  }
  if (data.unresolved_ids.length) {
    alerts.push({
      level: "warn",
      title: "relaxed 集中有悬空 ID",
      body:
        `${data.unresolved_ids.join("、")} 在当前配置里找不到对应规则。` +
        "这不改变任何行为（集合过滤只会跳过它们），但通常说明规则被删过。",
    });
  }
  const node = document.getElementById("rr-alerts");
  if (!node) return;
  node.innerHTML = alerts
    .map(
      (alert) =>
        `<div class="rr-alert rr-alert-${alert.level}">` +
        `<strong>${escapeHtml(alert.title)}</strong>` +
        `<span>${escapeHtml(alert.body)}</span></div>`
    )
    .join("");
}

function rrMasterSection(data) {
  const switches = Object.entries(data.master_switches)
    .map(([name, value]) => {
      const scope = data.master_switch_scopes[name] || "";
      const rendered = renderInline(scope);
      return (
        `<div class="rr-card">` +
        `<div class="rr-card-head"><code>${escapeHtml(name)}</code>` +
        rrBoolBadge(value, "已开启", "已关闭") +
        `</div><p class="u-note">${rendered}</p></div>`
      );
    })
    .join("");

  const mandatory =
    `<div class="rr-card rr-card-locked">` +
    `<div class="rr-card-head"><strong>V1 转发期脱敏</strong>` +
    `<span class="badge badge-success">强制安全基线</span></div>` +
    `<p class="u-note">保护结构化内容、工具定义、通用 JSON 与 multipart 表单字段，` +
    `<strong>没有关闭开关</strong>，本期也不新增。<code>enable_redaction</code> 关闭后它依旧运行。</p></div>`;

  const normalization =
    `<div class="rr-card">` +
    `<div class="rr-card-head"><strong>输入归一化</strong></div>` +
    `<ul class="rr-kv">` +
    `<li><code>normalize_nfkc</code>` +
    rrToggle({
      on: data.normalize_nfkc,
      onLabel: "true",
      offLabel: "false",
      action: "toggle-value",
      id: "normalize_nfkc",
    }) +
    `</li>` +
    `<li><code>strip_invisible_chars</code>` +
    rrToggle({
      on: data.strip_invisible_chars,
      onLabel: "true",
      offLabel: "false",
      action: "toggle-value",
      id: "strip_invisible_chars",
    }) +
    `</li>` +
    `<li><code>request_prefix_max_len</code>` +
    `<input class="rr-number" type="number" min="1" max="64" step="1" ` +
    `aria-label="request_prefix_max_len" data-rr-action="set-prefix-len" ` +
    `value="${escapeHtml(String(data.request_prefix_max_len))}"></li>` +
    `</ul>` +
    `<p class="u-note">1–64。负数会让占位符前缀被静默截空，因此有下界。</p></div>`;

  return (
    `<h3 class="rr-heading">总控与状态</h3>` +
    `<p class="u-note u-note-block">四个总控各自控制哪一层，是这个面板存在的第一个理由——` +
    `它们的名字看起来都像「关掉脱敏」，实际控制的层并不相同。</p>` +
    `<div class="rr-cards">${switches}${mandatory}${normalization}</div>`
  );
}

function rrSurfaceLegend(data) {
  return (
    `<div class="token-table-wrap"><table class="token-table"><thead><tr>` +
    `<th scope="col">执行面</th><th scope="col">范围</th>` +
    `<th scope="col">使用的 PII 集合</th><th scope="col">总控</th><th scope="col">说明</th>` +
    `</tr></thead><tbody>` +
    data.surfaces
      .map((surface) => {
        const overlay = data.master_switch_overlay[surface.id] || {};
        const gated = overlay.active === false;
        return (
          `<tr><td><strong>${escapeHtml(surface.code)}</strong> ${escapeHtml(surface.label)}</td>` +
          `<td class="u-note">${escapeHtml(surface.detail || "—")}</td>` +
          `<td>${escapeHtml(rrPatternSetLabel(surface.pattern_set))}</td>` +
          `<td>${
            overlay.switch
              ? `<code>${escapeHtml(overlay.switch)}</code>${
                  gated ? ' <span class="badge badge-warning">已关闭</span>' : ""
                }`
              : '<span class="badge badge-muted">无总控</span>'
          }</td>` +
          `<td class="u-note">${escapeHtml(surface.note || "")}</td></tr>`
        );
      })
      .join("") +
    `</tbody></table></div>`
  );
}

function rrStatusSection(data) {
  const reload = data.last_applied_write;
  const reloadCell = reload
    ? `最近一次已确认应用：${escapeHtml(reload.at)}（${escapeHtml(reload.event)}）` +
      `，热重载 ${reload.reload && reload.reload.ok ? "全部层成功" : "存在失败层"}` +
      (reload.backup ? `，备份 <code>${escapeHtml(reload.backup)}</code>` : "")
    : "本进程启动后尚未通过控制台写入过规则文件。";

  const relaxedLabels = { default: "使用代码默认值", all: "全部（[\"*\"]）", custom: "自定义列表", invalid: "配置类型非法，已回落到代码默认值" };

  return (
    `<h3 class="rr-heading">六个执行面</h3>` +
    `<p class="u-note u-note-block">请求侧脱敏不是「V1 / V2」两桶，而是六个执行面，其中 ` +
    `<strong>E1、E3、E4 三个受 relaxed 集支配</strong>；E2、E5 恒用全量集，E6 用自己的固定集合。</p>` +
    rrSurfaceLegend(data) +
    `<div class="rr-cards rr-cards-wide">` +
    `<div class="rr-card"><div class="rr-card-head"><strong>relaxed 集</strong>` +
    `<span class="badge badge-muted">${escapeHtml(relaxedLabels[data.relaxed_mode] || data.relaxed_mode)}</span></div>` +
    `<div class="rr-modes" role="group" aria-label="relaxed 集模式">` +
    rrModeButton(data, "default", "代码默认") +
    rrModeButton(data, "all", "全部") +
    rrModeButton(data, "custom", "自定义") +
    `</div>` +
    `<p class="u-note">支配 E1、E3、E4。当前解析结果：` +
    (data.relaxed_ids_resolved === null
      ? "所有已配置规则"
      : `${data.relaxed_ids_resolved.length} 项 — ${escapeHtml(data.relaxed_ids_resolved.join("、"))}`) +
    `</p>` +
    (data.unresolved_ids.length
      ? `<p class="u-note">悬空成员：` +
        data.unresolved_ids
          .map(
            (id) =>
              `<code>${escapeHtml(id)}</code> ` +
              `<button class="btn-danger-sm" type="button" data-rr-action="remove-unresolved" ` +
              `data-rr-id="${escapeHtml(id)}">清理</button>`
          )
          .join("　") +
        `</p>`
      : "") +
    `</div>` +
    `<div class="rr-card"><div class="rr-card-head"><strong>V2 固定集合（E6）</strong>` +
    `<span class="badge badge-muted">${data.v2_effective_ids.length} 项</span></div>` +
    `<p class="u-note">硬编码，与 <code>relaxed_pii_ids</code> 完全解耦；其中 ` +
    `${escapeHtml(data.v2_field_ids_in_set.join("、"))} 是 field 规则 ID，不是 PII 规则。</p></div>` +
    `<div class="rr-card"><div class="rr-card-head"><strong>规则文件</strong>` +
    (data.rules_file_resolver_consistent
      ? '<span class="badge badge-success">三处解析一致</span>'
      : '<span class="badge badge-warning">解析不一致</span>') +
    `</div><p class="u-note"><code>${escapeHtml(data.rules_file_path)}</code></p>` +
    `<p class="u-note">${reloadCell}</p></div>` +
    `<div class="rr-card"><div class="rr-card-head"><strong>管道层替换统计</strong>` +
    `<span class="badge badge-muted" id="rr-stat-value">—</span></div>` +
    `<p class="u-note">管道层去重后的敏感值替换数（含 PII 与 field 规则，统计期内）。` +
    `同一原文复用同一占位符，所以这是<strong>唯一敏感值个数</strong>而非命中次数。` +
    `不含 V1 转发层替换、V2 替换与精确值替换。</p></div>` +
    `</div>`
  );
}

function rrPiiSection(data) {
  const surfaces = data.surfaces;
  const header =
    `<tr><th scope="col">启用</th><th scope="col">relaxed</th><th scope="col">ID</th>` +
    `<th scope="col">类别</th><th scope="col">生效面</th><th scope="col">正则</th><th scope="col">操作</th></tr>`;

  const blocked = data.write_blocked;
  const rows = data.pii_rules
    .map((rule) => {
      const enabledCell = rrToggle({
        on: rule.enabled,
        onLabel: "启用",
        offLabel: "已停用",
        disabled: blocked,
        action: "toggle-enabled",
        id: rule.id,
        title: rule.enabled
          ? "停用后该规则不再被任何执行面编译"
          : "启用后该规则重新参与编译",
      });
      const relaxedCell = rrToggle({
        on: rule.relaxed_member,
        onLabel: "在集内",
        offLabel: "不在集内",
        disabled: blocked || !rule.relaxed_editable,
        action: "toggle-relaxed",
        id: rule.id,
        title: rule.relaxed_editable
          ? "支配 E1 / E3 / E4"
          : 'relaxed 集为 ["*"]，逐条成员不可编辑',
      });
      const badges = surfaces
        .map((surface) =>
          rrSurfaceBadge(
            surface,
            rule.effective_surfaces[surface.id],
            data.master_switch_overlay[surface.id]
          )
        )
        .join("");
      const regexClass = rule.regex_status === "ok" ? "" : " rr-regex-bad";
      return (
        `<tr><td>${enabledCell}</td><td>${relaxedCell}</td>` +
        `<td><code>${escapeHtml(rule.id)}</code></td>` +
        `<td class="u-note">${escapeHtml(rule.category || "未分类")}</td>` +
        `<td class="rr-surface-cell">${badges}</td>` +
        `<td><code class="rr-regex${regexClass}" title="${escapeHtml(rule.regex)}">${escapeHtml(
          rrTruncate(rule.regex, 46)
        )}</code>${
          rule.regex_status === "invalid"
            ? ' <span class="badge badge-error">无法编译</span>'
            : ""
        }</td>` +
        `<td class="u-nowrap">` +
        `<button class="btn-edit-sm" type="button" data-rr-action="edit" data-rr-id="${escapeHtml(
          rule.id
        )}">测试 / 编辑</button>` +
        `<button class="btn-danger-sm" type="button" data-rr-action="delete" data-rr-id="${escapeHtml(
          rule.id
        )}">删除</button></td></tr>`
      );
    })
    .join("");

  return (
    `<h3 class="rr-heading">PII 规则<span class="rr-heading-note">${data.pii_rules.length} 条</span>` +
    `<button class="btn-sm" type="button" data-rr-action="add">添加规则</button></h3>` +
    `<p class="u-note u-note-block">「relaxed」一列写的是该 ID 是否属于 <code>relaxed_pii_ids</code>，` +
    `<strong>支配 V1 对话路由（管道 + 转发）与 V1 multipart 转发</strong>——不是「在 V1 对话路由启用」，` +
    `也不是「全部路由」。两个控件各写一个维度：停用不会删除 relaxed 归属，重新启用后的范围没有隐藏状态。` +
    `生效面徽章由服务端计算后下发，面板不做任何推导。</p>` +
    (blocked
      ? `<p class="u-note u-note-block">存在归一化 ID 冲突，逐条修改与同 ID 的增删改已阻断。</p>`
      : "") +
    `<div class="token-table-wrap"><table class="token-table"><thead>${header}</thead>` +
    `<tbody>${
      rows ||
      emptyStateRow(7, "当前配置没有 PII 规则", { id: "rr-add", label: "添加规则" })
    }</tbody></table></div>`
  );
}

function rrToggle(options) {
  const cls = options.on ? "on" : "off";
  const label = options.on ? options.onLabel : options.offLabel;
  return (
    `<button type="button" role="switch" aria-checked="${options.on ? "true" : "false"}" ` +
    `aria-label="${escapeHtml(options.id)} ${escapeHtml(label)}" ` +
    `class="rr-toggle ${cls}"${options.disabled ? " disabled" : ""} ` +
    `data-rr-action="${options.action}" data-rr-id="${escapeHtml(options.id)}" ` +
    `data-rr-next="${options.on ? "false" : "true"}" ` +
    `title="${escapeHtml(options.title || "")}">${escapeHtml(label)}</button>`
  );
}

function rrFieldSection(data) {
  const field = data.field;
  const layers = field.layers
    .map(
      (layer) =>
        `<tr><td><strong>${escapeHtml(layer.label)}</strong></td>` +
        `<td>max(${layer.floor}, 配置值) = <strong>${escapeHtml(String(layer.effective_min_len))}</strong></td>` +
        `<td><code>${escapeHtml(layer.fallback_ids.join("、"))}</code></td>` +
        `<td><code>${escapeHtml(layer.explicit_default_id)}</code>` +
        (layer.legacy_string_id && layer.legacy_string_id !== layer.explicit_default_id
          ? `<br><span class="u-note">legacy 字符串条目：<code>${escapeHtml(layer.legacy_string_id)}</code></span>`
          : "") +
        `</td>` +
        `<td>${layer.relaxed_filtered ? "是" : "否"}</td>` +
        `<td class="u-note">${escapeHtml(layer.note)}</td></tr>`
    )
    .join("");

  const explicit = field.explicit_rules.length
    ? `<div class="token-table-wrap"><table class="token-table"><thead><tr>` +
      `<th scope="col">#</th><th scope="col">ID</th><th scope="col">正则</th><th scope="col">形态</th>` +
      `</tr></thead><tbody>` +
      field.explicit_rules
        .map(
          (rule) =>
            `<tr><td>${rule.index}</td><td><code>${escapeHtml(rule.id)}</code></td>` +
            `<td><code class="rr-regex" title="${escapeHtml(rule.regex)}">${escapeHtml(
              rrTruncate(rule.regex, 60)
            )}</code></td>` +
            `<td>${
              rule.legacy_string
                ? '<span class="badge badge-warning">legacy 字符串条目</span>'
                : '<span class="badge badge-muted">映射条目</span>'
            }</td></tr>`
        )
        .join("") +
      `</tbody></table></div>`
    : `<p class="u-note">当前未配置 <code>field_value_patterns</code>，三层各自使用自己的代码 fallback。</p>`;

  return (
    `<h3 class="rr-heading">Field 规则<span class="rr-heading-note">${
      field.mode === "explicit_yaml" ? "YAML 显式列表" : "代码默认"
    }</span></h3>` +
    `<p class="u-note u-note-block">Field 规则不能套用 PII 的 relaxed 算法：管道层无视路由恒跑，` +
    `转发层与 PII 合并后整体被 relaxed 过滤（默认 12 项不含这两个 ID），V2 的固定集合又恰好含它们。` +
    `本版只读——提供逐条启停会造出「YAML 已停用但 V2 fallback 仍在跑」的假控制。</p>` +
    `<div class="token-table-wrap"><table class="token-table"><thead><tr>` +
    `<th scope="col">层</th><th scope="col">最小长度下限</th><th scope="col">代码 fallback ID</th>` +
    `<th scope="col">显式条目缺省 ID</th><th scope="col">受 relaxed 过滤</th><th scope="col">说明</th>` +
    `</tr></thead><tbody>${layers}</tbody></table></div>` +
    `<p class="u-note u-note-block"><code>field_value_min_len</code> 当前配置值 ` +
    `<strong>${escapeHtml(String(field.field_value_min_len_configured))}</strong>，本版只读。` +
    (field.explicit_disables_min_len
      ? "注意：已配置显式 field 列表，该参数<strong>完全失效</strong>（只用于 fallback 正则）。"
      : "") +
    `</p>` +
    explicit +
    // The workbench only lists groups the YAML actually contains, so this link
    // has somewhere to land only when the file spells the list out.
    (field.mode === "explicit_yaml"
      ? `<p class="u-note"><a class="rr-jump" href="#rules" data-rr-jump="redaction.field_value_patterns">查看安全规则原始配置</a></p>`
      : `<p class="u-note">这两条 fallback 写在代码里，<code>security_filters.yaml</code> 中没有对应条目，因此规则工作台里也看不到它们。</p>`)
  );
}

function rrCoverageSection(data) {
  const rows = data.coverage_matrix
    .map((row) => {
      const restorable =
        row.restorable === true
          ? '<span class="badge badge-success">可还原</span>'
          : row.restorable === false
          ? '<span class="badge badge-warning">不可还原</span>'
          : '<span class="badge badge-muted">不适用</span>';
      return (
        `<tr${row.emphasis ? ' class="rr-row-emphasis"' : ""}>` +
        `<td><strong>${escapeHtml(row.surface)}</strong>${
          row.note ? `<br><span class="u-note">${escapeHtml(row.note)}</span>` : ""
        }</td>` +
        `<td>${escapeHtml(row.exact_value)}</td>` +
        `<td><code>${escapeHtml(row.pii_form)}</code></td>` +
        `<td>${restorable}</td></tr>`
      );
    })
    .join("");
  return (
    `<h3 class="rr-heading">精确值与替换形态覆盖面</h3>` +
    `<p class="u-note u-note-block">不承诺所有请求侧脱敏都可还原，也不承诺 multipart 上传的<strong>文件内容</strong>被扫描。</p>` +
    `<div class="token-table-wrap"><table class="token-table"><thead><tr>` +
    `<th scope="col">执行面</th><th scope="col">请求侧精确值脱敏</th>` +
    `<th scope="col">PII 替换形态</th><th scope="col">可还原</th>` +
    `</tr></thead><tbody>${rows}</tbody></table></div>`
  );
}

function rrExemptionsSection(data) {
  const ex = data.exemptions;
  const whitelistRows = ex.field_whitelist.tokens
    .flatMap((token) =>
      token.keys.map(
        (key) =>
          `<tr><td class="u-note">${escapeHtml(token.upstream_base || "—")}<br>` +
          `<code>${escapeHtml(token.token_masked)}</code></td>` +
          `<td><code>${escapeHtml(key.key)}</code></td>` +
          `<td>${
            key.v1_effective
              ? '<span class="badge badge-success">生效</span>'
              : '<span class="badge badge-error">被 denylist 忽略</span>'
          }</td>` +
          `<td><span class="badge badge-success">生效</span></td>` +
          `<td class="u-note">${
            key.denylist_hits.length
              ? `命中 denylist 子串：${escapeHtml(key.denylist_hits.join("、"))}`
              : "—"
          }</td></tr>`
      )
    )
    .join("");

  const matrix = ex.surface_matrix
    .map(
      (row) =>
        `<tr><td><strong>${escapeHtml(row.surface)}</strong></td>` +
        `<td class="u-note">${escapeHtml(row.field_whitelist)}</td>` +
        `<td class="u-note">${escapeHtml(row.passthrough)}</td>` +
        `<td class="u-note">${escapeHtml(row.upstream_whitelist)}</td></tr>`
    )
    .join("");

  const upstream = ex.upstream_whitelist;
  return (
    `<h3 class="rr-heading">豁免与绕过</h3>` +
    `<p class="u-note u-note-block">字段级白名单<strong>只保护指定 key/span</strong>，不是整请求绕过；` +
    `passthrough 与上游白名单才是整请求绕过，且各自只在部分路由可用。</p>` +
    `<div class="token-table-wrap"><table class="token-table"><thead><tr>` +
    `<th scope="col">执行面</th><th scope="col">字段级 whitelist_key</th>` +
    `<th scope="col">passthrough</th><th scope="col">上游白名单</th>` +
    `</tr></thead><tbody>${matrix}</tbody></table></div>` +
    `<h4 class="rr-subheading">Token 字段白名单</h4>` +
    `<p class="u-note u-note-block">V1 会把 token 注入的 key 再过一遍 denylist，V2 直接读 token scope 且<strong>没有 denylist</strong>。` +
    `所以同一个 key 可能「V1 忽略 / V2 生效」。客户端自带的 <code>x-aegis-redaction-whitelist</code> 头在两处都会被剥离，` +
    `不是独立来源。</p>` +
    `<div class="token-table-wrap"><table class="token-table"><thead><tr>` +
    `<th scope="col">Token</th><th scope="col">whitelist_key</th>` +
    `<th scope="col">V1</th><th scope="col">V2</th><th scope="col">原因</th>` +
    `</tr></thead><tbody>${
      whitelistRows || emptyStateRow(5, "没有 token 配置了字段级白名单")
    }</tbody></table></div>` +
    `<p class="u-note">denylist 子串：<code>${escapeHtml(ex.field_whitelist.denylist.join(", "))}</code></p>` +
    `<h4 class="rr-subheading">上游白名单</h4>` +
    `<div class="rr-cards">` +
    `<div class="rr-card"><div class="rr-card-head"><code>allow_public_upstream_whitelist</code>` +
    rrBoolBadge(upstream.allow_public_upstream_whitelist, "已开启", "已关闭") +
    `</div><p class="u-note">关闭时，只有 <code>client_is_internal</code> 不为 False 的客户端才能拿到这个绕过。</p></div>` +
    `<div class="rr-card"><div class="rr-card-head"><strong>client_is_internal</strong>` +
    (upstream.requires_internal_client
      ? '<span class="badge badge-warning">必须为内网客户端</span>'
      : '<span class="badge badge-muted">不作要求</span>') +
    `</div><p class="u-note">按请求判定，面板显示的是当前前置条件而非某次请求的结果。</p></div>` +
    `<div class="rr-card"><div class="rr-card-head"><strong>白名单上游</strong>` +
    `<span class="badge badge-muted">${upstream.configured_bases.length} 个</span></div>` +
    `<p class="u-note">${
      upstream.configured_bases.length
        ? escapeHtml(upstream.configured_bases.join("、"))
        : "未配置，当前没有任何上游可绕过过滤。"
    }</p></div></div>`
  );
}

function rrModeButton(data, mode, label) {
  const active = data.relaxed_mode === mode;
  return (
    `<button type="button" role="tab" aria-selected="${active ? "true" : "false"}" ` +
    `class="rr-mode${active ? " active" : ""}" data-rr-action="set-mode" data-rr-mode="${mode}"` +
    `${active ? " disabled" : ""}>${escapeHtml(label)}</button>`
  );
}

// Every write from this panel goes through here: one place decides how a 409
// that asks for confirmation is turned into a question, and a refused
// confirmation leaves the file untouched.
async function rrPatch(body, prefix) {
  try {
    const data = await fetchJson("/__ui__/api/request_redaction/settings", {
      method: "PATCH",
      resource: "rules",
      headers: { "Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken },
      body: JSON.stringify(body),
    });
    requestRedactionState = data;
    rrRender(data);
    AegisUI.toast("已保存，已热重载生效", "ok");
    return true;
  } catch (err) {
    handleWriteError(err, loadRequestRedaction, prefix);
    return false;
  }
}

async function rrConfirmedPatch(body, prefix, confirmation) {
  const ok = await AegisUI.confirm(confirmation);
  if (!ok) return false;
  return rrPatch(body, prefix);
}

async function rrSetMode(mode, data) {
  if (mode === "custom") {
    return rrConfirmedPatch(
      { relaxed: { operation: "materialize_custom", source: "current", confirm: true } },
      "切换 relaxed 模式失败",
      {
        title: "展开为自定义列表",
        message:
          data.relaxed_mode === "all"
            ? "将按当前完整的已配置 ID 集合生成一次快照。两处已知的、无害的不等价：" +
              "正则编译失败的条目也会被收进来（成为无害悬空项）；" +
              "legacy 字符串 field 条目按 FIELD_SECRET_{idx} 展开，与真正受 relaxed 过滤的 E3/E4 一致。"
            : "将把当前代码默认集合固化进 YAML。此后它不再跟随代码默认值变化。",
        detail:
          data.relaxed_mode === "all"
            ? "来源：当前完整 configured ID 集"
            : `来源：代码默认 ${data.default_relaxed_ids.length} 项`,
        confirmLabel: "展开",
      }
    );
  }
  const isAll = mode === "all";
  return rrConfirmedPatch(
    { relaxed: { operation: "set_mode", mode } },
    "切换 relaxed 模式失败",
    {
      title: isAll ? "relaxed 集设为「全部」" : "恢复代码默认值",
      message: isAll
        ? "所有已启用的 PII 规则都会在 E1 / E3 / E4 上运行——更严格，代价是更多误报。"
        : "将从 YAML 中删除 relaxed_pii_ids 这个 key，而不是写入当前默认集合，" +
          "这样它继续跟随代码默认值。当前的自定义列表会丢失。",
      confirmLabel: isAll ? "设为全部" : "恢复默认",
      danger: !isAll,
    }
  );
}

async function rrSetMembership(ruleId, enabled, data) {
  const body = { relaxed: { operation: "set_membership", id: ruleId, enabled } };
  if (data.relaxed_mode === "default") {
    const ok = await AegisUI.confirm({
      title: "转换为自定义 relaxed 列表",
      message:
        "当前使用代码默认 relaxed 集（未写入文件）。逐条修改会以当前默认集合为基线固化成自定义列表，" +
        "此后不再跟随代码默认值。",
      detail: `基线：${data.default_relaxed_ids.length} 项`,
      confirmLabel: "转换并修改",
    });
    if (!ok) return false;
    body.relaxed.confirm_materialize = true;
  }
  if (!enabled) {
    const rule = data.pii_rules.find((item) => item.id === ruleId);
    if (rule && rule.relaxed_removal_empties_list) {
      const ok = await AegisUI.confirm({
        title: "清空 relaxed 集",
        message:
          "移除后 relaxed 集为空：V1 对话路由（管道 + 转发）与 multipart 转发上将不再有任何 PII 规则生效。",
        detail: ruleId,
        confirmLabel: "确认清空",
        danger: true,
      });
      if (!ok) return false;
      body.relaxed.confirm_empty = true;
    }
  }
  return rrPatch(body, "修改 relaxed 归属失败");
}

async function rrSetEnabled(ruleId, enabled) {
  if (!enabled) {
    const ok = await AegisUI.confirm({
      title: "停用 PII 规则",
      message: "停用后该规则不再被 E1–E6 任何执行面编译，立即热重载生效。relaxed 归属会保留。",
      detail: ruleId,
      confirmLabel: "停用",
      danger: true,
    });
    if (!ok) return;
  }
  try {
    await fetchJson(
      `/__ui__/api/rules/redaction.pii_patterns/${encodeURIComponent(ruleId)}`,
      {
        method: "PATCH",
        resource: "rules",
        headers: { "Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken },
        body: JSON.stringify({ enabled }),
      }
    );
    AegisUI.toast(enabled ? "规则已启用" : "规则已停用", "ok");
    await loadRequestRedaction();
  } catch (err) {
    handleWriteError(err, loadRequestRedaction, enabled ? "启用失败" : "停用失败");
  }
}

async function rrDeleteRule(ruleId, data) {
  // The server already decided what this delete means for relaxed_pii_ids.
  const rule = data.pii_rules.find((item) => item.id === ruleId) || {};
  const inCustomList = rule.relaxed_reference === "custom_list";
  const inCodeDefault = rule.relaxed_reference === "code_default";

  const ok = await AegisUI.confirm({
    title: "删除 PII 规则",
    message:
      "删除后立即热重载生效，该规则在 E1–E6 上的脱敏一并消失。" +
      (inCustomList
        ? "它同时会从自定义 relaxed 列表中移除——同一次写入内完成。"
        : inCodeDefault
        ? "代码默认 relaxed 集仍会引用这个 ID，删除后是无害悬空引用：集合过滤只会跳过它。"
        : ""),
    detail: ruleId,
    confirmLabel: "删除",
    danger: true,
  });
  if (!ok) return;

  const params = new URLSearchParams();
  if (rule.relaxed_removal_empties_list) {
    // The server refuses this without confirm_empty, and answering that on the
    // caller's behalf would turn its question into a formality. Emptying the
    // list is its own decision, so it gets its own dialog.
    const confirmedEmpty = await AegisUI.confirm({
      title: "这会清空 relaxed 集",
      message:
        "它是自定义列表里的最后一个成员。移除后 relaxed 集为空，V1 对话路由（管道 + 转发）与 " +
        "multipart 转发上将没有任何 PII 规则生效——其余执行面不受影响。" +
        "若要保留一个悬空引用而不清空列表，请改从 relaxed 开关移除它，或先添加别的成员。",
      detail: ruleId,
      confirmLabel: "确认清空并删除",
      danger: true,
    });
    if (!confirmedEmpty) return;
    params.set("confirm_empty", "true");
  }
  const query = params.toString();
  try {
    const result = await fetchJson(
      `/__ui__/api/rules/redaction.pii_patterns/${encodeURIComponent(ruleId)}` +
        (query ? `?${query}` : ""),
      {
        method: "DELETE",
        resource: "rules",
        headers: { "x-aegis-ui-csrf": uiCsrfToken },
      }
    );
    AegisUI.toast(result.note || "规则已删除，已热重载生效", "ok", result.note ? { timeout: 8000 } : undefined);
    await loadRequestRedaction();
  } catch (err) {
    handleWriteError(err, loadRequestRedaction, "删除失败");
  }
}

function rrRender(data) {
  rrAlerts(data);
  document.getElementById("rr-master").innerHTML = rrMasterSection(data);
  document.getElementById("rr-status").innerHTML = rrStatusSection(data);
  document.getElementById("rr-pii").innerHTML = rrPiiSection(data);
  document.getElementById("rr-field").innerHTML = rrFieldSection(data);
  document.getElementById("rr-coverage").innerHTML = rrCoverageSection(data);
  document.getElementById("rr-exemptions").innerHTML = rrExemptionsSection(data);
  const summary = document.getElementById("rr-summary");
  if (summary) {
    summary.textContent =
      `${data.pii_rules.length} 条 PII 规则 · relaxed 集 ` +
      (data.relaxed_ids_resolved === null ? "全部" : `${data.relaxed_ids_resolved.length} 项`) +
      ` · Field ${data.field.mode === "explicit_yaml" ? "显式列表" : "代码默认"}`;
  }
}

async function loadRequestRedaction() {
  const summary = document.getElementById("rr-summary");
  if (summary) summary.textContent = "加载中…";
  try {
    const data = await fetchJson("/__ui__/api/request_redaction/settings", { resource: "rules" });
    requestRedactionState = data;
    rrRender(data);
    loadRequestRedactionStat();
  } catch (err) {
    if (summary) summary.textContent = describeWriteError(err, "加载失败");
  }
}

async function loadRequestRedactionStat() {
  const node = document.getElementById("rr-stat-value");
  if (!node) return;
  try {
    const stats = await fetchJson("/__ui__/api/stats");
    const total = (stats.totals && stats.totals.redactions) || 0;
    node.textContent = String(total);
  } catch (_err) {
    node.textContent = "不可用";
  }
}

function bindRequestRedactionUI() {
  const refresh = document.getElementById("rr-refresh");
  if (refresh) refresh.addEventListener("click", loadRequestRedaction);
  const panel = document.getElementById("request-redaction");
  if (!panel) return;

  panel.addEventListener("click", async (event) => {
    const jump = event.target.closest("[data-rr-jump]");
    if (jump) {
      loadRuleSections(jump.getAttribute("data-rr-jump"));
      return;
    }
    if (event.target.closest('[data-empty-action="rr-add"]')) {
      openRuleModal("redaction.pii_patterns", null, loadRequestRedaction);
      return;
    }
    const trigger = event.target.closest("[data-rr-action]");
    if (!trigger || trigger.disabled) return;
    const data = requestRedactionState;
    if (!data) return;
    const action = trigger.getAttribute("data-rr-action");
    const ruleId = trigger.getAttribute("data-rr-id");

    if (action === "set-mode") {
      await rrSetMode(trigger.getAttribute("data-rr-mode"), data);
    } else if (action === "toggle-relaxed") {
      await rrSetMembership(ruleId, trigger.getAttribute("data-rr-next") === "true", data);
    } else if (action === "toggle-enabled") {
      await rrSetEnabled(ruleId, trigger.getAttribute("data-rr-next") === "true");
    } else if (action === "toggle-value") {
      await rrPatch(
        { values: { [ruleId]: trigger.getAttribute("data-rr-next") === "true" } },
        "保存失败"
      );
    } else if (action === "remove-unresolved") {
      await rrConfirmedPatch(
        { relaxed: { operation: "remove_unresolved", id: ruleId, confirm: true } },
        "清理失败",
        {
          title: "清理悬空 relaxed 成员",
          message:
            "该 ID 在当前配置里没有对应规则。移除它不改变任何行为，只是让列表与配置一致。",
          detail: ruleId,
          confirmLabel: "清理",
        }
      );
    } else if (action === "add") {
      openRuleModal("redaction.pii_patterns", null, loadRequestRedaction);
    } else if (action === "edit") {
      const rule = data.pii_rules.find((item) => item.id === ruleId);
      openRuleModal(
        "redaction.pii_patterns",
        { id: ruleId, regex: rule ? rule.regex : "", category: rule ? rule.category : "" },
        loadRequestRedaction
      );
    } else if (action === "delete") {
      await rrDeleteRule(ruleId, data);
    }
  });

  panel.addEventListener("change", async (event) => {
    const input = event.target.closest('[data-rr-action="set-prefix-len"]');
    if (!input) return;
    const value = Number(input.value);
    if (!Number.isInteger(value)) {
      AegisUI.toast("request_prefix_max_len 必须是整数", "err");
      loadRequestRedaction();
      return;
    }
    await rrPatch({ values: { request_prefix_max_len: value } }, "保存失败");
  });

  loadRequestRedaction();
}

// ─── Init new UI modules ─────────────────────

bindRulesUI();
bindRequestRedactionUI();
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
