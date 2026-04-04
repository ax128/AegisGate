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
    updateFieldValue(item.field, next);  // update configState clone, not original item
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
    updateFieldValue(item.field, item.type === "int" ? Number(input.value) : input.value);
  });
  input.addEventListener("change", () => {
    updateFieldValue(item.field, item.type === "int" ? Number(input.value) : input.value);
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

let currentRulesSection = "pii_patterns";
let actionMapState = {};

async function loadRules(section) {
  if (section === "action_map") {
    await loadActionMap();
    return;
  }
  const tbody = document.getElementById("rules-tbody");
  const countEl = document.getElementById("rules-count");
  const thead = document.getElementById("rules-thead");
  const tableEl = document.getElementById("rules-table");
  const actionMapPanel = document.getElementById("action-map-panel");
  const addBtn = document.getElementById("rules-add");
  if (tbody) tbody.innerHTML = `<tr><td colspan="4" class="token-table-empty">加载中…</td></tr>`;
  if (tableEl) tableEl.classList.remove("hidden");
  if (actionMapPanel) actionMapPanel.classList.add("hidden");
  if (addBtn) addBtn.classList.remove("hidden");

  const showKind = section === "command_patterns";
  if (thead) {
    thead.innerHTML = showKind
      ? `<tr><th>ID</th><th>Regex</th><th>类型</th><th>操作</th></tr>`
      : `<tr><th>ID</th><th>Regex</th><th>操作</th></tr>`;
  }
  try {
    const data = await fetchJson(`/__ui__/api/rules/${encodeURIComponent(section)}`);
    const items = Array.isArray(data.items) ? data.items : [];
    if (countEl) countEl.textContent = `共 ${items.length} 条规则`;
    if (!items.length) {
      tbody.innerHTML = `<tr><td colspan="${showKind ? 4 : 3}" class="token-table-empty">暂无规则，点击「添加规则」新增。</td></tr>`;
      return;
    }
    tbody.innerHTML = "";
    items.forEach((item) => {
      const tr = document.createElement("tr");
      const idCell = `<td><code style="font-size:0.82rem;">${escapeHtml(item.id || "")}</code></td>`;
      const regexCell = `<td style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(item.regex || "")}"><code style="font-size:0.79rem;">${escapeHtml(item.regex || "")}</code></td>`;
      const kindCell = showKind ? `<td><span style="font-size:0.8rem;color:var(--muted);">${escapeHtml(item.kind || "")}</span></td>` : "";
      const actionCell = `<td style="white-space:nowrap;">
        <button class="btn-edit-sm" data-rule-id="${escapeHtml(item.id)}" data-rule-regex="${escapeHtml(item.regex || "")}" data-rule-kind="${escapeHtml(item.kind || "")}">编辑</button>
        <button class="btn-danger-sm" data-del-rule-id="${escapeHtml(item.id)}">删除</button>
      </td>`;
      tr.innerHTML = idCell + regexCell + kindCell + actionCell;
      tr.querySelector(".btn-edit-sm").addEventListener("click", (e) => {
        const btn = e.currentTarget;
        openRuleModal(section, {id: btn.dataset.ruleId, regex: btn.dataset.ruleRegex, kind: btn.dataset.ruleKind});
      });
      tr.querySelector(".btn-danger-sm").addEventListener("click", async (e) => {
        const ruleId = e.currentTarget.dataset.delRuleId;
        if (!confirm(`确认删除规则 "${ruleId}"？`)) return;
        try {
          await fetchJson(`/__ui__/api/rules/${encodeURIComponent(section)}/${encodeURIComponent(ruleId)}`, {
            method: "DELETE",
            headers: {"x-aegis-ui-csrf": uiCsrfToken},
          });
          loadRules(section);
        } catch (err) {
          alert(`删除失败: ${err.message}`);
        }
      });
      tbody.appendChild(tr);
    });
  } catch (err) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="4" class="token-table-empty" style="color:var(--error)">加载失败: ${escapeHtml(err.message)}</td></tr>`;
    if (countEl) countEl.textContent = "加载失败";
  }
}

async function loadActionMap() {
  const tableEl = document.getElementById("rules-table");
  const actionMapPanel = document.getElementById("action-map-panel");
  const addBtn = document.getElementById("rules-add");
  const countEl = document.getElementById("rules-count");
  const grid = document.getElementById("action-map-grid");

  if (tableEl) tableEl.classList.add("hidden");
  if (actionMapPanel) actionMapPanel.classList.remove("hidden");
  if (addBtn) addBtn.classList.add("hidden");
  if (countEl) countEl.textContent = "";

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
  document.getElementById("rule-modal-kind").value = item ? (item.kind || "") : "";
  document.getElementById("rule-modal-error").textContent = "";
  document.getElementById("rule-modal-submit").textContent = item ? "保存" : "添加";
  const showKind = section === "command_patterns";
  const kindField = document.getElementById("rule-modal-kind-field");
  if (kindField) kindField.style.display = showKind ? "" : "none";
  openModal(modal, document.getElementById("rule-modal-id"));
}

function closeRuleModal() {
  closeModal(document.getElementById("rule-modal"));
}

async function submitRuleModal() {
  const section = document.getElementById("rule-modal-section").value;
  const editId = document.getElementById("rule-modal-edit-id").value.trim();
  const isEdit = !!editId;
  const ruleId = document.getElementById("rule-modal-id").value.trim();
  const regex = document.getElementById("rule-modal-regex").value.trim();
  const kind = document.getElementById("rule-modal-kind").value.trim();
  const errEl = document.getElementById("rule-modal-error");
  errEl.textContent = "";
  if (!ruleId) { errEl.textContent = "请填写规则 ID"; return; }
  if (!regex) { errEl.textContent = "请填写正则表达式"; return; }
  const body = {id: ruleId, regex};
  if (kind) body.kind = kind;
  const submitBtn = document.getElementById("rule-modal-submit");
  submitBtn.disabled = true;
  submitBtn.textContent = "保存中…";
  try {
    if (isEdit) {
      await fetchJson(`/__ui__/api/rules/${encodeURIComponent(section)}/${encodeURIComponent(editId)}`, {
        method: "PATCH",
        headers: {"Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken},
        body: JSON.stringify({regex, kind: kind || undefined}),
      });
    } else {
      await fetchJson(`/__ui__/api/rules/${encodeURIComponent(section)}`, {
        method: "POST",
        headers: {"Content-Type": "application/json", "x-aegis-ui-csrf": uiCsrfToken},
        body: JSON.stringify(body),
      });
    }
    closeRuleModal();
    loadRules(section);
  } catch (err) {
    errEl.textContent = err.message;
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = isEdit ? "保存" : "添加";
  }
}

function bindRulesUI() {
  document.querySelectorAll("[data-rules-section]").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll("[data-rules-section]").forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      currentRulesSection = tab.dataset.rulesSection;
      loadRules(currentRulesSection);
    });
  });
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
      if (e.key === "Enter" && !e.shiftKey) {
        const btn = document.getElementById("rule-modal-submit");
        if (btn && !btn.disabled) {
          e.preventDefault();
          submitRuleModal();
        }
      }
    });
  }
  // Load default section
  loadRules("pii_patterns");
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
    if (thead) thead.innerHTML = "<tr><th>" + (currentStatsView === "hourly" ? "小时" : "日期") + "</th><th>请求</th><th>脱敏</th><th>危险替换</th><th>拦截</th><th>直通</th></tr>";

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
      document.querySelectorAll("[data-stats-view]").forEach(function(t) { t.classList.remove("active"); });
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
