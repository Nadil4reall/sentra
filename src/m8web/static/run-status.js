"use strict";

// Presentation only: no POST, form submission, or workflow transition.
const rail = document.querySelector("[data-run-status-url]");
if (rail) {
  const stages = [...rail.querySelectorAll("[data-run-stage]")];
  const updated = document.querySelector("[data-run-updated]");
  const relative = document.querySelector("[data-run-relative]");
  let stopped = false;
  let errors = 0;

  const renderRelative = () => {
    if (!updated || !relative) return;
    const recorded = Date.parse(updated.dateTime || updated.textContent);
    if (!Number.isFinite(recorded)) {
      relative.textContent = "recently";
      return;
    }
    const seconds = Math.max(0, Math.floor((Date.now() - recorded) / 1000));
    relative.textContent = seconds < 5 ? "just now" : seconds < 60 ? `${seconds} seconds ago` :
      seconds < 3600 ? `${Math.floor(seconds / 60)} minutes ago` : "over an hour ago";
  };
  renderRelative();
  window.setInterval(renderRelative, 1000);

  const poll = async () => {
    if (stopped) return;
    if (document.hidden) {
      window.setTimeout(poll, 10000);
      return;
    }
    try {
      const response = await fetch(rail.dataset.runStatusUrl, {
        credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" }
      });
      if (response.status === 401 || response.redirected || response.status === 403) {
        stopped = true;
        return;
      }
      if (!response.ok) throw new Error("status unavailable");
      const status = await response.json();
      errors = 0;
      let transition = false;
      for (const item of status.stages) {
        const element = stages.find(stage => stage.dataset.runStage === item.key);
        if (!element) continue;
        if (element.dataset.runState !== item.state || element.dataset.runLabel !== item.label) {
          transition = true;
          element.dataset.runState = item.state;
          element.dataset.runLabel = item.label;
          element.querySelector(".run-rail-state").textContent = item.label;
          element.className = `run-rail-step state-${item.state}${item.current ? " is-current" : ""}`;
          element.querySelector(".run-rail-mark").textContent = item.state === "complete" ? "✓" : item.current ? "◉" : "○";
        }
        const elapsed = document.querySelector(`[data-run-elapsed="${item.key}"]`);
        if (elapsed && item.elapsed) elapsed.textContent = item.elapsed;
      }
      if (updated) {
        updated.dateTime = status.read_at;
        updated.textContent = status.read_at;
        renderRelative();
      }
      // Reload only the GET page on a real state change to reveal the next
      // explicit action; never perform a mutation or submit a form here.
      if (transition) {
        window.location.reload();
        return;
      }
    } catch (_) {
      errors = Math.min(errors + 1, 4);
    }
    window.setTimeout(poll, errors ? Math.min(30000, 2500 * (2 ** errors)) : 2500);
  };

  window.setTimeout(poll, 2500);
}

document.querySelectorAll("form[data-submit-once]").forEach(form => {
  form.addEventListener("submit", () => {
    const button = form.querySelector('button[type="submit"]');
    // Delay disabling until the browser has serialized the successful form.
    if (button) window.setTimeout(() => { button.disabled = true; }, 0);
  }, { once: true });
});
