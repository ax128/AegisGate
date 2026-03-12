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
