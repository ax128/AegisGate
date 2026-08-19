// Console UI primitives: toasts, dialogs, and the ETag store.
//
// Loaded before app.js so `AegisUI` exists by the time app.js runs its init.
// Deliberately self-contained — it builds its own overlay and focus trap rather
// than reaching into app.js — so load order can never produce a half-wired
// dialog.
//
// Why it exists: the console drove every confirmation through window.confirm and
// every result through window.alert. Native dialogs block the event loop, cannot
// be styled, cannot carry a copy button next to a freshly issued base_url, and
// give a destructive action exactly the same weight as an informational one.

(function buildAegisUI(global) {
  "use strict";

  const TOAST_TIMEOUT = { ok: 3200, warn: 5200, err: 6200 };
  const FOCUSABLE =
    'button:not([disabled]), [href], input:not([disabled]):not([type="hidden"]),' +
    ' select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

  function escapeHtml(text) {
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // ── ETag store ──────────────────────────────────────────────
  // Keyed by logical resource ("rules", "config", …) rather than URL: one file
  // backs several endpoints, and they must all share a validator.
  const etags = new Map();

  // ── Toasts ──────────────────────────────────────────────────
  let toastHost = null;

  function ensureToastHost() {
    if (toastHost && document.body.contains(toastHost)) return toastHost;
    toastHost = document.createElement("div");
    toastHost.className = "toast-host";
    toastHost.setAttribute("role", "status");
    toastHost.setAttribute("aria-live", "polite");
    document.body.appendChild(toastHost);
    return toastHost;
  }

  const TOAST_ICONS = {
    ok: '<polyline points="20,6 9,17 4,12"/>',
    warn: '<path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>',
    err: '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>',
  };

  function toast(message, kind, options) {
    const level = TOAST_ICONS[kind] ? kind : "ok";
    const settings = options || {};
    const node = document.createElement("div");
    node.className = `toast toast-${level}`;
    node.innerHTML =
      `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"` +
      ` stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${TOAST_ICONS[level]}</svg>` +
      `<span class="toast-text">${escapeHtml(message)}</span>` +
      `<button class="toast-close" type="button" aria-label="关闭提示">&times;</button>`;

    const host = ensureToastHost();
    host.appendChild(node);
    requestAnimationFrame(() => node.classList.add("visible"));

    let timer = null;
    function dismiss() {
      if (timer) clearTimeout(timer);
      node.classList.remove("visible");
      setTimeout(() => node.remove(), 220);
    }
    node.querySelector(".toast-close").addEventListener("click", dismiss);
    const timeout = settings.timeout === undefined ? TOAST_TIMEOUT[level] : settings.timeout;
    if (timeout > 0) timer = setTimeout(dismiss, timeout);
    return dismiss;
  }

  // ── Dialogs ─────────────────────────────────────────────────
  let openDialog = null;

  function closeDialog(result) {
    if (!openDialog) return;
    const { overlay, resolve, previousFocus, onKeydown } = openDialog;
    openDialog = null;
    document.removeEventListener("keydown", onKeydown, true);
    overlay.classList.remove("visible");
    setTimeout(() => overlay.remove(), 180);
    if (previousFocus && typeof previousFocus.focus === "function") previousFocus.focus();
    resolve(result);
  }

  function trapFocus(overlay, event) {
    if (event.key !== "Tab") return;
    const nodes = Array.from(overlay.querySelectorAll(FOCUSABLE)).filter(
      (node) => node.offsetParent !== null
    );
    if (!nodes.length) return;
    const first = nodes[0];
    const last = nodes[nodes.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function showDialog(config) {
    // One dialog at a time: a second request resolves the first as cancelled
    // rather than stacking overlays.
    if (openDialog) closeDialog(false);

    const options = config || {};
    const danger = Boolean(options.danger);
    const confirmWord = String(options.requireText || "");

    return new Promise((resolve) => {
      const overlay = document.createElement("div");
      overlay.className = "dialog-overlay";
      overlay.setAttribute("role", "dialog");
      overlay.setAttribute("aria-modal", "true");
      overlay.setAttribute("aria-label", options.title || "确认");

      const bodyHtml = options.html
        ? options.html
        : `<p class="dialog-message">${escapeHtml(options.message || "")}</p>`;
      const detailHtml = options.detail
        ? `<pre class="dialog-detail">${escapeHtml(options.detail)}</pre>`
        : "";
      const requireHtml = confirmWord
        ? `<label class="dialog-require">请输入 <code>${escapeHtml(confirmWord)}</code> 以确认` +
          `<input type="text" class="dialog-require-input" autocomplete="off" spellcheck="false"></label>`
        : "";
      const cancelHtml = options.mode === "alert"
        ? ""
        : `<button class="btn-sm-ghost dialog-cancel" type="button">${escapeHtml(options.cancelLabel || "取消")}</button>`;

      overlay.innerHTML =
        `<div class="dialog-card${danger ? " dialog-danger" : ""}">` +
        `<h3 class="dialog-title">${escapeHtml(options.title || "确认操作")}</h3>` +
        `<div class="dialog-body">${bodyHtml}${detailHtml}${requireHtml}</div>` +
        `<div class="dialog-foot">${cancelHtml}` +
        `<button class="btn-sm dialog-confirm${danger ? " dialog-confirm-danger" : ""}" type="button">` +
        `${escapeHtml(options.confirmLabel || "确定")}</button></div>` +
        `</div>`;

      document.body.appendChild(overlay);
      requestAnimationFrame(() => overlay.classList.add("visible"));

      const confirmBtn = overlay.querySelector(".dialog-confirm");
      const cancelBtn = overlay.querySelector(".dialog-cancel");
      const requireInput = overlay.querySelector(".dialog-require-input");

      if (requireInput) {
        confirmBtn.disabled = true;
        requireInput.addEventListener("input", () => {
          confirmBtn.disabled = requireInput.value.trim() !== confirmWord;
        });
      }

      function onKeydown(event) {
        if (!openDialog || openDialog.overlay !== overlay) return;
        trapFocus(overlay, event);
        if (event.key === "Escape") {
          event.preventDefault();
          closeDialog(false);
        }
        if (event.key === "Enter" && event.target.tagName !== "TEXTAREA" && !confirmBtn.disabled) {
          event.preventDefault();
          closeDialog(true);
        }
      }

      openDialog = { overlay, resolve, previousFocus: document.activeElement, onKeydown };
      document.addEventListener("keydown", onKeydown, true);

      confirmBtn.addEventListener("click", () => closeDialog(true));
      if (cancelBtn) cancelBtn.addEventListener("click", () => closeDialog(false));
      overlay.addEventListener("click", (event) => {
        if (event.target === overlay) closeDialog(false);
      });

      // A destructive dialog opens focused on Cancel, so Enter never destroys
      // anything by reflex.
      const initial = requireInput || (danger && cancelBtn ? cancelBtn : confirmBtn);
      setTimeout(() => initial.focus(), 40);

      overlay.querySelectorAll("[data-copy]").forEach((button) => {
        button.addEventListener("click", async () => {
          const value = button.getAttribute("data-copy") || "";
          try {
            await navigator.clipboard.writeText(value);
            button.textContent = "已复制";
            setTimeout(() => { button.textContent = "复制"; }, 1600);
          } catch (_error) {
            toast("浏览器拒绝了剪贴板访问，请手动复制", "warn");
          }
        });
      });
    });
  }

  function confirmDialog(options) {
    return showDialog({ ...options, mode: "confirm" });
  }

  function alertDialog(options) {
    return showDialog({ ...options, mode: "alert", confirmLabel: options.confirmLabel || "知道了" });
  }

  // Copy-to-clipboard row for values the user must carry elsewhere (base_url,
  // freshly issued tokens): the old flow printed these into window.alert and
  // left people re-typing them.
  function copyRow(label, value) {
    return (
      `<div class="dialog-copy-row">` +
      `<span class="dialog-copy-label">${escapeHtml(label)}</span>` +
      `<code class="dialog-copy-value">${escapeHtml(value)}</code>` +
      `<button class="btn-sm-ghost dialog-copy-btn" type="button" data-copy="${escapeHtml(value)}">复制</button>` +
      `</div>`
    );
  }

  global.AegisUI = {
    toast,
    confirm: confirmDialog,
    alert: alertDialog,
    copyRow,
    escapeHtml,
    etags,
  };
})(window);
