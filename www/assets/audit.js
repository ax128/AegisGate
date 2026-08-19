// Audit explorer.
//
// Kept in its own file rather than bolted onto app.js: it is self-contained, and
// app.js is already 1300 lines. Loaded after app.js, so escapeHtml / fetchJson /
// setStatus / uiCsrfToken are available as globals.

(function initAuditExplorer() {
  const panel = document.getElementById("audit");
  if (!panel) return;

  let cursor = null;
  let loading = false;
  let rowSeq = 0;

  const FILTER_INPUTS = {
    since: "audit-since",
    until: "audit-until",
    route: "audit-route",
    disposition: "audit-disposition",
    min_risk: "audit-min-risk",
    tag: "audit-tag",
    q: "audit-q",
  };

  function readFilters() {
    const params = new URLSearchParams();
    Object.entries(FILTER_INPUTS).forEach(([key, id]) => {
      const node = document.getElementById(id);
      const value = node ? String(node.value || "").trim() : "";
      if (!value) return;
      // datetime-local yields "2026-08-19T10:00" with no zone; the server reads
      // a bare timestamp as UTC, which matches how the log is written.
      params.set(key, value);
    });
    return params;
  }

  function riskClass(score) {
    const value = Number(score);
    if (!Number.isFinite(value)) return "risk-none";
    if (value >= 0.7) return "risk-high";
    if (value >= 0.3) return "risk-mid";
    return "risk-low";
  }

  function dispositionClass(value) {
    if (value === "block") return "badge-error";
    if (value === "sanitize" || value === "review") return "badge-warning";
    if (value === "allow" || value === "pass") return "badge-success";
    return "badge-muted";
  }

  function formatTs(value) {
    const raw = String(value || "");
    if (!raw) return "—";
    // Trim to "MM-DD HH:MM:SS" — the table is dense and the year never varies
    // within a page.
    const match = raw.match(/^\d{4}-(\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/);
    return match ? `${match[1]} ${match[2]}` : raw.slice(0, 19);
  }

  function formatBytes(bytes) {
    const value = Number(bytes) || 0;
    if (value < 1024) return `${value} B`;
    if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
    return `${(value / 1024 / 1024).toFixed(1)} MB`;
  }

  function renderTags(tags) {
    if (!Array.isArray(tags) || !tags.length) return '<span class="audit-dim">—</span>';
    return tags
      .map((tag) => `<span class="audit-tag">${escapeHtml(String(tag))}</span>`)
      .join("");
  }

  function buildRow(item) {
    const rowId = `audit-detail-${rowSeq++}`;
    const tr = document.createElement("tr");
    tr.className = "audit-row";
    tr.tabIndex = 0;
    tr.setAttribute("role", "button");
    tr.setAttribute("aria-expanded", "false");
    tr.setAttribute("aria-controls", rowId);

    const risk = item.risk_score;
    const riskText = Number.isFinite(Number(risk)) ? Number(risk).toFixed(2) : "—";
    tr.innerHTML =
      `<td class="audit-ts">${escapeHtml(formatTs(item.ts))}</td>` +
      `<td class="audit-route"><code>${escapeHtml(String(item.route || item.event || "—"))}</code></td>` +
      `<td><span class="audit-risk ${riskClass(risk)}">${riskText}</span></td>` +
      `<td><span class="badge ${dispositionClass(item.request_disposition)}">${escapeHtml(String(item.request_disposition || "—"))}</span></td>` +
      `<td><span class="badge ${dispositionClass(item.response_disposition)}">${escapeHtml(String(item.response_disposition || "—"))}</span></td>` +
      `<td>${renderTags(item.security_tags)}</td>`;

    const detail = document.createElement("tr");
    detail.className = "audit-detail hidden";
    detail.id = rowId;
    const payload = { ...item };
    delete payload._offset;
    detail.innerHTML =
      `<td colspan="6"><pre class="audit-json">${escapeHtml(JSON.stringify(payload, null, 2))}</pre></td>`;

    function toggle() {
      const open = detail.classList.toggle("hidden");
      tr.setAttribute("aria-expanded", open ? "false" : "true");
      tr.classList.toggle("open", !open);
    }
    tr.addEventListener("click", toggle);
    tr.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        toggle();
      }
    });
    return [tr, detail];
  }

  function setScanNote(data) {
    const note = document.getElementById("audit-scan-note");
    if (!note) return;
    const parts = [];
    if (data.file_size !== undefined) parts.push(`日志 ${formatBytes(data.file_size)}`);
    if (data.scanned_bytes) parts.push(`本次扫描 ${formatBytes(data.scanned_bytes)}`);
    if (data.budget_exhausted) parts.push("已达单次扫描上限，可继续加载更早记录");
    if (data.reached_start) parts.push("已到文件开头");
    if (data.malformed_lines) parts.push(`跳过 ${data.malformed_lines} 行无法解析的记录`);
    note.textContent = parts.join(" · ");
  }

  async function loadAudit(append) {
    if (loading) return;
    loading = true;
    const tbody = document.getElementById("audit-tbody");
    const countEl = document.getElementById("audit-count");
    const moreBtn = document.getElementById("audit-more");
    if (!append) {
      cursor = null;
      rowSeq = 0;
      tbody.innerHTML = '<tr><td colspan="6" class="token-table-empty">加载中…</td></tr>';
    }
    try {
      const params = readFilters();
      params.set("limit", "50");
      if (append && cursor !== null) params.set("cursor", String(cursor));
      const data = await fetchJson(`/__ui__/api/audit?${params.toString()}`);

      if (!append) tbody.innerHTML = "";
      const existing = tbody.querySelectorAll("tr.audit-row").length;
      if (!data.items.length && !existing) {
        tbody.innerHTML = '<tr><td colspan="6" class="token-table-empty">没有符合条件的记录</td></tr>';
      } else {
        data.items.forEach((item) => {
          const [row, detail] = buildRow(item);
          tbody.appendChild(row);
          tbody.appendChild(detail);
        });
      }
      cursor = data.next_cursor;
      if (moreBtn) moreBtn.classList.toggle("hidden", cursor === null);
      const total = tbody.querySelectorAll("tr.audit-row").length;
      if (countEl) countEl.textContent = `已加载 ${total} 条`;
      setScanNote(data);
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="6" class="token-table-empty" style="color:var(--error)">加载失败: ${escapeHtml(err.message)}</td></tr>`;
      if (countEl) countEl.textContent = "";
    } finally {
      loading = false;
    }
  }

  async function loadSummary() {
    const host = document.getElementById("audit-summary");
    if (!host) return;
    try {
      const data = await fetchJson(`/__ui__/api/audit/summary?${readFilters().toString()}`);
      if (!data.available || !data.records) {
        host.innerHTML = '<p class="audit-dim">暂无审计记录。</p>';
        return;
      }
      const buckets = data.risk_buckets || {};
      const blocked = Object.entries(data.dispositions || {})
        .filter(([key]) => key.endsWith(":block"))
        .reduce((sum, [, count]) => sum + count, 0);
      const topRoute = (data.routes || [])[0];
      const topTag = (data.tags || [])[0];
      host.innerHTML =
        tile("样本记录数", data.records, data.complete ? "覆盖全部日志" : "仅统计日志尾部") +
        tile("拦截", blocked, "request/response 处置为 block") +
        tile("高风险 (≥0.7)", buckets["0.7-1.0"] || 0, `中 ${buckets["0.3-0.7"] || 0} · 低 ${buckets["0.0-0.3"] || 0}`) +
        tile("最活跃路由", topRoute ? topRoute.count : 0, topRoute ? topRoute.key : "—") +
        tile("最多安全标签", topTag ? topTag.count : 0, topTag ? topTag.key : "—");
    } catch (err) {
      host.innerHTML = `<p class="error-note">概览加载失败: ${escapeHtml(err.message)}</p>`;
    }
  }

  function tile(label, value, hint) {
    return (
      `<div class="stat-card">` +
      `<div class="stat-card-label">${escapeHtml(label)}</div>` +
      `<div class="stat-card-value">${escapeHtml(String(value))}</div>` +
      `<div class="audit-tile-hint">${escapeHtml(String(hint))}</div>` +
      `</div>`
    );
  }

  function exportAudit(format) {
    const params = readFilters();
    params.set("format", format);
    // A plain navigation keeps the session cookie and lets the browser handle
    // the download; no blob juggling needed.
    window.location.href = `/__ui__/api/audit/export?${params.toString()}`;
  }

  async function loadSampleDates() {
    const select = document.getElementById("sample-date");
    const note = document.getElementById("sample-note");
    if (!select) return;
    try {
      const data = await fetchJson("/__ui__/api/dangerous_samples/dates");
      select.innerHTML = "";
      if (!data.items.length) {
        select.innerHTML = '<option value="">无样本文件</option>';
        if (note) {
          note.textContent = data.enabled
            ? "尚未产生危险响应样本"
            : "未开启：AEGIS_ENABLE_DANGEROUS_RESPONSE_LOG=false";
        }
        return;
      }
      data.items.forEach((item) => {
        const option = document.createElement("option");
        option.value = item.date;
        option.textContent = `${item.date} (${formatBytes(item.size)})`;
        select.appendChild(option);
      });
      if (note) note.textContent = `共 ${data.items.length} 个日期`;
    } catch (err) {
      if (note) note.textContent = `加载失败: ${err.message}`;
    }
  }

  async function loadSamples() {
    const select = document.getElementById("sample-date");
    const host = document.getElementById("sample-list");
    if (!select || !host || !select.value) return;
    host.innerHTML = '<p class="audit-dim">加载中…</p>';
    try {
      const data = await fetchJson(
        `/__ui__/api/dangerous_samples?date=${encodeURIComponent(select.value)}&limit=50`
      );
      if (!data.items.length) {
        host.innerHTML = '<p class="audit-dim">该日期没有样本记录。</p>';
        return;
      }
      host.innerHTML = data.items
        .map((item) => {
          const payload = { ...item };
          delete payload._offset;
          return (
            `<details class="audit-sample">` +
            `<summary><span class="audit-ts">${escapeHtml(formatTs(item.ts))}</span>` +
            `<code>${escapeHtml(String(item.route || item.event || "—"))}</code>` +
            `${renderTags(item.security_tags)}</summary>` +
            `<pre class="audit-json">${escapeHtml(JSON.stringify(payload, null, 2))}</pre>` +
            `</details>`
          );
        })
        .join("");
    } catch (err) {
      host.innerHTML = `<p class="error-note">加载失败: ${escapeHtml(err.message)}</p>`;
    }
  }

  function bind(id, event, handler) {
    const node = document.getElementById(id);
    if (node) node.addEventListener(event, handler);
  }

  bind("audit-apply", "click", () => {
    loadAudit(false);
    loadSummary();
  });
  bind("audit-reset", "click", () => {
    Object.values(FILTER_INPUTS).forEach((id) => {
      const node = document.getElementById(id);
      if (node) node.value = "";
    });
    loadAudit(false);
    loadSummary();
  });
  bind("audit-more", "click", () => loadAudit(true));
  bind("audit-export-jsonl", "click", () => exportAudit("jsonl"));
  bind("audit-export-csv", "click", () => exportAudit("csv"));
  bind("sample-load", "click", loadSamples);
  bind("audit-q", "keydown", (event) => {
    if (event.key === "Enter") {
      loadAudit(false);
      loadSummary();
    }
  });

  loadSummary();
  loadAudit(false);
  loadSampleDates();
})();
