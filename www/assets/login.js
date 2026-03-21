async function login(password) {
  const response = await fetch("/__ui__/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ password }),
  });
  if (response.ok) {
    window.location.href = "/__ui__";
    return;
  }
  let message = `登录失败 (HTTP ${response.status})`;
  try {
    const data = await response.json();
    if (data.detail) {
      message = data.detail;
    } else if (data.error) {
      message = data.error;
    }
  } catch (_error) {
    // noop
  }
  throw new Error(message);
}

document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const errorEl = document.getElementById("login-error");
  errorEl.textContent = "";
  const password = document.getElementById("password-input").value;
  try {
    await login(password);
  } catch (error) {
    errorEl.textContent = error.message;
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
