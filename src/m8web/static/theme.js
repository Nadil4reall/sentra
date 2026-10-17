"use strict";

(() => {
  const key = "sentra.appearance";
  const systemDark = window.matchMedia("(prefers-color-scheme: dark)");
  let preference = "system";
  try {
    const stored = window.localStorage.getItem(key);
    if (["system", "light", "dark"].includes(stored)) preference = stored;
  } catch (_) {
    // Storage may be disabled; System remains the non-persistent default.
  }

  const apply = () => {
    document.documentElement.dataset.appearance = preference;
    document.documentElement.dataset.theme = preference === "system"
      ? (systemDark.matches ? "dark" : "light") : preference;
  };
  apply();
  systemDark.addEventListener("change", () => {
    if (preference === "system") apply();
  });

  document.addEventListener("DOMContentLoaded", () => {
    const control = document.getElementById("appearance");
    if (!control) return;
    control.value = preference;
    control.addEventListener("change", () => {
      if (!["system", "light", "dark"].includes(control.value)) return;
      preference = control.value;
      try { window.localStorage.setItem(key, preference); } catch (_) { /* UI still changes. */ }
      apply();
    });
  });
})();
