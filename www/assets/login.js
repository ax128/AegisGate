// Status codes carry the actionable part of a failed login; the server's own
// `detail` is English and, for the rate limiter, says nothing a user can act on.
const LOGIN_ERRORS = {
  403: "网关密钥不正确，请核对 config/aegis_gateway.key 的完整内容",
  429: "登录尝试过于频繁，请稍后再试",
};

async function login(password) {
  const response = await fetch("/__ui__/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ password }),
  });
  if (response.ok) return;
  let message = LOGIN_ERRORS[response.status] || `登录失败 (HTTP ${response.status})`;
  if (!LOGIN_ERRORS[response.status]) {
    try {
      const data = await response.json();
      if (data.detail) message = data.detail;
      else if (data.error) message = data.error;
    } catch (_error) {
      // noop
    }
  }
  throw new Error(message);
}

// Logging in sets a session cookie that is Secure by default. Over plain HTTP
// to anything but localhost the browser drops it, so the redirect to /__ui__
// bounced straight back here with nothing on screen to explain why. Confirm the
// session actually took before navigating, and name the setting if it did not.
async function sessionIsUsable() {
  try {
    const response = await fetch("/__ui__/api/bootstrap", {
      credentials: "same-origin",
      cache: "no-store",
    });
    return response.ok;
  } catch (_error) {
    return true; // a network blip here should not block the redirect
  }
}

const COOKIE_HELP =
  "密钥正确，但浏览器没有保存会话 Cookie：当前是 HTTP 访问，而 " +
  "AEGIS_LOCAL_UI_SECURE_COOKIE=true 只允许 HTTPS 保存。请改用 HTTPS 访问，" +
  "或把该项设为 false 后重启网关。";

document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorEl = document.getElementById("login-error");
  const submitBtn = event.currentTarget.querySelector(".btn-login");
  errorEl.textContent = "";
  errorEl.classList.remove("login-error-wide");
  const password = document.getElementById("password-input").value;
  submitBtn.disabled = true;
  submitBtn.textContent = "登录中…";
  try {
    await login(password);
    if (await sessionIsUsable()) {
      window.location.href = "/__ui__";
      return;
    }
    errorEl.textContent = COOKIE_HELP;
    errorEl.classList.add("login-error-wide");
  } catch (error) {
    errorEl.textContent = error.message;
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "登 录";
  }
});

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  try {
    await navigator.clipboard.writeText(button.getAttribute("data-copy") || "");
    const original = button.textContent;
    button.textContent = "已复制";
    setTimeout(() => { button.textContent = original; }, 1600);
  } catch (_error) {
    // Clipboard is blocked in some contexts; the command stays selectable.
  }
});

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
