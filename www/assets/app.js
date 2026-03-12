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

function setStatus(id, message, isError = false) {
  const node = document.getElementById(id);
  if (!node) return;
  node.textContent = message;
  node.className = "status-note " + (isError ? "err" : message ? "ok" : "");
  // Auto-clear success messages after 4 seconds
  if (!isError && message) {
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

function fieldId(field) {
  return `cfg-${field.field}`;
}

function cloneState(items) {
  configState = items.map((item) => ({ ...item }));
}

function updateFieldValue(fieldName, value) {
  const item = configState.find((entry) => entry.field === fieldName);
  if (item) item.value = value;
}

function createBoolButton(item) {
  const button = document.createElement("button");
  button.type = "button";
  button.id = fieldId(item);
  button.className = `bool-button ${item.value ? "on" : "off"}`;
  button.textContent = item.value ? "已开启" : "已关闭";
  button.addEventListener("click", () => {
    const next = !item.value;
    item.value = next;
    button.className = `bool-button ${next ? "on" : "off"}`;
    button.textContent = next ? "已开启" : "已关闭";
  });
  return button;
}

function createInputField(item) {
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
    input.type = item.type === "int" ? "number" : "text";
    input.value = item.value ?? "";
  }
  input.id = fieldId(item);
  input.addEventListener("input", () => {
    updateFieldValue(item.field, item.type === "int" ? input.value : input.value);
  });
  input.addEventListener("change", () => {
    updateFieldValue(item.field, item.type === "int" ? input.value : input.value);
  });
  return input;
}

function renderConfig(items) {
  cloneState(items);
  const sections = {
    general: document.getElementById("general-config"),
    security: document.getElementById("security-config"),
    v2: document.getElementById("v2-config"),
  };
  Object.values(sections).forEach((node) => {
    if (node) node.innerHTML = "";
  });

  items.forEach((item) => {
    const card = document.createElement("div");
    card.className = `field-card ${item.type === "string" ? "wide" : ""}`;
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.innerHTML = `<strong>${escapeHtml(item.label)}</strong><span class="default">默认: ${escapeHtml(String(item.default))}</span>`;
    card.appendChild(meta);
    card.appendChild(item.type === "bool" ? createBoolButton(item) : createInputField(item));
    const section = sections[item.section];
    if (section) section.appendChild(card);
  });
}

function collectSectionValues(section) {
  const values = {};
  configState.filter((item) => item.section === section).forEach((item) => {
    values[item.field] = item.type === "int" ? String(item.value).trim() : item.value;
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
    renderConfig(data.config.items);
    setStatus(statusId, "已保存，配置已热重载。");
    await loadBootstrap();
  } catch (error) {
    setStatus(statusId, `保存失败: ${error.message}`, true);
  }
}

function setActiveNav(hash) {
  document.querySelectorAll(".nav-item").forEach((link) => {
    link.classList.toggle("active", link.getAttribute("href") === hash);
  });
}

function initScrollSpy() {
  const sections = document.querySelectorAll("main section[id]");
  if (!sections.length) return;

  function onScroll() {
    const offset = 80;
    let current = sections[0].id;
    sections.forEach((section) => {
      if (section.getBoundingClientRect().top <= offset) {
        current = section.id;
      }
    });
    setActiveNav(`#${current}`);
  }

  window.addEventListener("scroll", onScroll, { passive: true });
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
  renderConfig(configData.items);

  const preferredDocId = Array.isArray(data.docs) && data.docs.length ? data.docs[0].id : null;
  await loadDocs(preferredDocId);
}

// ─── Token Management ────────────────────────

function tokenDisplay(token) {
  return token;
}

async function loadTokens() {
  const tbody = document.getElementById("token-tbody");
  const countEl = document.getElementById("token-count");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="5" class="token-table-empty">加载中…</td></tr>`;
  try {
    const data = await fetchJson("/__ui__/api/tokens");
    const items = Array.isArray(data.items) ? data.items : [];
    if (countEl) countEl.textContent = `共 ${items.length} 个 Token`;
    if (!items.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="token-table-empty">暂无已注册的 Token，点击右上角「注册 Token」添加。</td></tr>`;
      return;
    }
    tbody.innerHTML = "";
    items.forEach((item) => {
      const tr = document.createElement("tr");
      const wlCount = Array.isArray(item.whitelist_keys) ? item.whitelist_keys.length : 0;
      const wlTitle = wlCount ? item.whitelist_keys.join(", ") : "无限制";
      tr.innerHTML = `
        <td>
          <button class="token-code" title="点击复制完整 Token" data-token="${escapeHtml(item.token)}">
            ${escapeHtml(tokenDisplay(item.token))}
          </button>
        </td>
        <td><div class="token-upstream" title="${escapeHtml(item.upstream_base)}">${escapeHtml(item.upstream_base)}</div></td>
        <td><span class="token-key-hint">${escapeHtml(item.gateway_key_hint || "—")}</span></td>
        <td><span class="token-wl-count" title="${escapeHtml(wlTitle)}">${wlCount || "∞"}</span></td>
        <td>
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
          setTimeout(() => { e.currentTarget.textContent = tokenDisplay(t); }, 1500);
        }).catch(() => {});
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
    tbody.innerHTML = `<tr><td colspan="5" class="token-table-empty" style="color:var(--error)">加载失败: ${escapeHtml(err.message)}</td></tr>`;
    if (countEl) countEl.textContent = "加载失败";
  }
}

function openTokenModal() {
  const modal = document.getElementById("token-modal");
  if (!modal) return;
  document.getElementById("modal-upstream").value = "";
  document.getElementById("modal-whitelist").value = "";
  document.getElementById("modal-error").textContent = "";
  modal.classList.remove("hidden");
  document.getElementById("modal-upstream").focus();
}

function closeTokenModal() {
  const modal = document.getElementById("token-modal");
  if (modal) modal.classList.add("hidden");
}

async function submitTokenModal() {
  const errorEl = document.getElementById("modal-error");
  const upstream = document.getElementById("modal-upstream").value.trim();
  const whitelist = document.getElementById("modal-whitelist").value.trim();
  errorEl.textContent = "";
  if (!upstream) { errorEl.textContent = "请填写上游地址"; return; }

  const body = { upstream_base: upstream };
  if (whitelist) {
    body.whitelist_key = whitelist.split(",").map((s) => s.trim()).filter(Boolean);
  }
  const submitBtn = document.getElementById("modal-submit");
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
  }
  // Close on Escape (only when modal is visible)
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && overlay && !overlay.classList.contains("hidden")) closeTokenModal();
  });
  // Submit on Enter inside modal inputs (guard against double-submit)
  if (overlay) {
    overlay.addEventListener("keydown", (e) => {
      const btn = overlay.querySelector("[data-action='submit-token']");
      if (e.key === "Enter" && !e.shiftKey && btn && !btn.disabled) submitTokenModal();
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
    await fetchJson("/__ui__/api/logout", {
      method: "POST",
      headers: { "x-aegis-ui-csrf": uiCsrfToken },
    });
    window.location.href = "/__ui__/login";
  });
  document.getElementById("save-general").addEventListener("click", () => saveSection("general", "general-save-status"));
  document.getElementById("save-security").addEventListener("click", () => saveSection("security", "security-save-status"));
  document.getElementById("save-v2").addEventListener("click", () => saveSection("v2", "v2-save-status"));
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
