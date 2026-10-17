// Applies the saved (or system) colour theme before the page paints, so there is no flash.
(function () {
  var theme = null;
  try { theme = localStorage.getItem("vault.theme"); } catch (e) { /* storage blocked */ }
  if (theme !== "dark" && theme !== "light") {
    theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.documentElement.setAttribute("data-theme", theme);
})();
