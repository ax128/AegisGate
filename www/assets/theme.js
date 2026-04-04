(function initStoredTheme() {
  try {
    var savedTheme = localStorage.getItem("aegisgate_theme");
    var prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    var isDark = savedTheme === "dark" || (!savedTheme && prefersDark);
    document.documentElement.setAttribute("data-theme", isDark ? "dark" : "light");
  } catch (_error) {
    document.documentElement.setAttribute("data-theme", "light");
  }
})();
