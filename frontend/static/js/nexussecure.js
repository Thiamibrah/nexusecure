/* =============================================
   NexusSecure — Frontend utilities
   ============================================= */

// ---- Auth helpers ----
function getToken() { return localStorage.getItem("token"); }

function authHeaders() {
  return { Authorization: `Bearer ${getToken()}` };
}

function parseJwt(token) {
  try {
    return JSON.parse(atob(token.split(".")[1]));
  } catch { return {}; }
}

// Redirect to login if no token (except on login page)
(function guardAuth() {
  if (window.location.pathname === "/") return;
  const token = getToken();
  if (!token) { window.location.href = "/"; return; }
  const payload = parseJwt(token);
  if (payload.exp && Date.now() / 1000 > payload.exp) {
    localStorage.removeItem("token");
    window.location.href = "/";
  }
})();

// ---- Theme toggle (dark/light) ----
// The actual dark<->light class is applied pre-paint by an inline script in
// base.html's <head> (reads the same "nexus-theme" key) — this just wires the button
// and keeps its icon in sync. Reloading on toggle (instead of live-patching every
// component) keeps chart colors, Bootstrap-utility overrides, etc. from getting out
// of sync with the CSS.
function chartThemeColors() {
  const light = document.documentElement.getAttribute("data-theme") === "light";
  return light
    ? { tick: "#5c6773", grid: "rgba(20,24,31,.08)" }
    : { tick: "#8b949e", grid: "rgba(255,255,255,.05)" };
}

// ---- Theme-aware semantic colors ----
// The dark-tuned severity/status palette (bright neon green, cyan, amber especially)
// is chosen to pop on navy — several of these fail WCAG contrast used as *text* on a
// white page (checked: safe green #00e676 is ~1.7:1 on white, need ≥4.5:1). Light mode
// gets its own deepened set instead of reusing the same hex values everywhere a score
// or status is rendered as colored text (KPI numbers, gauge labels, chart lines/icons).
const SEMANTIC_COLOR = {
  dark:  { critical: "#dc3545", high: "#fd7e14", medium: "#ffc107", low: "#0dcaf0", safe: "#00e676", info: "#6c757d" },
  light: { critical: "#dc3545", high: "#b8530a", medium: "#8a6d00", low: "#0e7c93", safe: "#087a41", info: "#6c757d" },
};
function semanticColor(key) {
  const theme = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
  return SEMANTIC_COLOR[theme][key] || SEMANTIC_COLOR[theme].info;
}

(function initThemeToggle() {
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;
  const icon = btn.querySelector("i");
  const isLight = document.documentElement.getAttribute("data-theme") === "light";
  icon.className = isLight ? "bi bi-moon-stars" : "bi bi-sun";
  btn.addEventListener("click", () => {
    const nowLight = document.documentElement.getAttribute("data-theme") !== "light";
    localStorage.setItem("nexus-theme", nowLight ? "light" : "dark");
    window.location.reload();
  });
})();

// ---- Fill sidebar user info & show role-based menu ----
(function fillSidebarUser() {
  const p = parseJwt(getToken());
  if (!p.sub) return;
  const role = p.role || "client";

  const roleLabels = { admin: "Administrateur", analyst: "Analyste", client: "Client" };
  const roleColors = { admin: "#dc3545", analyst: "#1a73e8", client: "#6c757d" };

  const roleLabelEl = document.getElementById("sidebar-role-label");
  const topbarRole  = document.getElementById("topbar-role");

  if (roleLabelEl) { roleLabelEl.textContent = roleLabels[role] || role; roleLabelEl.style.color = roleColors[role]; }
  if (topbarRole) {
    topbarRole.textContent = (roleLabels[role] || role).toUpperCase();
    topbarRole.style.background = roleColors[role];
    topbarRole.style.color = "#fff";
  }

  // Load username async
  fetch("/api/users/me", { headers: authHeaders() })
    .then(r => r.json())
    .then(u => {
      const el = document.getElementById("sidebar-username");
      if (el) el.textContent = u.username;
      // Backend blocks every route except /api/users/me(/password) and /api/auth/logout
      // while must_change_password is set — send the user where they can actually act
      // on it instead of leaving them on a page full of silently-failing API calls.
      if (u.must_change_password && window.location.pathname !== "/profile") {
        window.location.href = "/profile";
      }
    }).catch(() => {});

  // Show correct sidebar
  const sidebarEl = document.querySelector(`.sidebar-${role}`);
  if (sidebarEl) sidebarEl.classList.remove("d-none");

  // Highlight active link
  document.querySelectorAll(".nav-link.sidebar-link").forEach(a => {
    if (a.getAttribute("href") === window.location.pathname) a.classList.add("active");
  });
})();

// ---- Global notification bell (topbar) ----
// Reuses /api/dashboard/alerts (same endpoint as the dashboard's own alert panel) and
// the same localStorage dismissal key, so dismissing an alert anywhere hides it
// everywhere — this is a lightweight always-visible view, not a replacement for the
// more detailed panel on the dashboard.
(function initNotifBell() {
  const bell = document.getElementById("notif-bell");
  if (!bell) return;
  const badge = document.getElementById("notif-badge");
  const list = document.getElementById("notif-list");
  const iconMap  = { scan_failed: "bi-x-circle-fill", critical_vuln: "bi-exclamation-triangle-fill", new_report: "bi-file-earmark-check-fill" };
  const colorMap = { danger: semanticColor("critical"), success: semanticColor("safe") };

  async function loadNotifs() {
    try {
      const res = await fetch("/api/dashboard/alerts", { headers: authHeaders() });
      if (!res.ok) return;
      const alerts = await res.json();
      const dismissed = JSON.parse(localStorage.getItem("nexus_dismissed_alerts") || "[]");
      const visible = alerts.filter(a => !dismissed.includes(a.type + "_" + a.date.slice(0, 13)));
      badge.textContent = visible.length;
      badge.classList.toggle("d-none", visible.length === 0);
      list.innerHTML = visible.length
        ? visible.map(a => `
            <div class="d-flex align-items-start gap-2 p-2" style="border-bottom:1px solid var(--border)">
              <i class="bi ${iconMap[a.type] || "bi-info-circle"}" style="color:${colorMap[a.level] || "#ffc107"};margin-top:2px;flex-shrink:0"></i>
              <div class="text-fg" style="font-size:.83rem">${a.message}</div>
            </div>`).join("")
        : `<div class="text-center text-fg-muted py-3" style="font-size:.85rem">Aucune alerte</div>`;
    } catch {}
  }

  loadNotifs();
  setInterval(loadNotifs, 30000);
})();

// ---- "New reports" badge on the sidebar link ----
(function initReportsBadge() {
  const links = document.querySelectorAll("a.reports-nav-link");
  if (!links.length) return;
  fetch("/api/reports/new-count", { headers: authHeaders() })
    .then(r => r.json())
    .then(({ count }) => {
      if (!count) return;
      links.forEach(a => a.insertAdjacentHTML("beforeend",
        ` <span class="badge bg-danger ms-1" style="font-size:.65rem">${count}</span>`));
    }).catch(() => {});
})();

// ---- Logout ----
const btnLogout = document.getElementById("btn-logout");
if (btnLogout) {
  btnLogout.addEventListener("click", async (e) => {
    e.preventDefault();
    try { await fetch("/api/auth/logout", { method: "POST", headers: authHeaders() }); } catch {}
    localStorage.removeItem("token");
    window.location.href = "/";
  });
}

// ---- Sidebar toggle ----
const toggleBtn = document.getElementById("toggle-sidebar");
const sidebar = document.getElementById("sidebar");

// Add overlay element for mobile
const overlay = document.createElement("div");
overlay.id = "sidebar-overlay";
document.body.appendChild(overlay);

if (toggleBtn && sidebar) {
  const isMobile = () => window.innerWidth <= 768;

  // Restore saved state on desktop only
  if (!isMobile() && localStorage.getItem("sidebar-collapsed") === "1") {
    sidebar.classList.add("collapsed");
  }
  // On mobile: start hidden
  if (isMobile()) sidebar.classList.add("collapsed");

  toggleBtn.addEventListener("click", () => {
    sidebar.classList.toggle("collapsed");
    if (isMobile()) {
      overlay.classList.toggle("visible", !sidebar.classList.contains("collapsed"));
    } else {
      localStorage.setItem("sidebar-collapsed", sidebar.classList.contains("collapsed") ? "1" : "0");
    }
  });

  overlay.addEventListener("click", () => {
    sidebar.classList.add("collapsed");
    overlay.classList.remove("visible");
  });

  // Handle resize
  window.addEventListener("resize", () => {
    if (!isMobile()) {
      overlay.classList.remove("visible");
      if (localStorage.getItem("sidebar-collapsed") !== "1") {
        sidebar.classList.remove("collapsed");
      }
    } else {
      sidebar.classList.add("collapsed");
    }
  });
}

// ---- API helpers ----
// Add trailing slash only on collection URLs (no trailing segment that looks like an ID)
function normalizeUrl(url) {
  const [path, qs] = url.split("?");
  // Don't add slash if last segment is a number (resource ID) or "download"
  const lastSegment = path.split("/").filter(Boolean).pop() || "";
  const normalized = (!lastSegment || /^\d+$/.test(lastSegment) || lastSegment === "download" || lastSegment === "stats" || lastSegment === "me")
    ? path
    : path.endsWith("/") ? path : path + "/";
  return qs ? normalized + "?" + qs : normalized;
}

async function apiGet(url) {
  const res = await fetch(normalizeUrl(url), { headers: authHeaders() });
  if (res.status === 401) { window.location.href = "/"; return; }
  if (!res.ok) throw new Error((await res.json()).detail || `Error ${res.status}`);
  return res.json();
}

async function apiPost(url, body) {
  const res = await fetch(normalizeUrl(url), {
    method: "POST",
    headers: { ...authHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (res.status === 401) { window.location.href = "/"; return; }
  if (!res.ok) throw new Error((await res.json()).detail || `Error ${res.status}`);
  return res.status === 204 ? null : res.json();
}

// ---- Badge helpers ----
function statusBadge(status) {
  const map = {
    pending: "secondary", running: "info text-dark",
    completed: "success", failed: "danger",
  };
  return `<span class="badge bg-${map[status] || "secondary"}">${status}</span>`;
}

function severityBadge(sev) {
  return `<span class="badge badge-${sev}">${sev.toUpperCase()}</span>`;
}

// ---- Toasts (replaces alert() for action results) ----
const TOAST_ICON  = { success: "bi-check-circle-fill", danger: "bi-x-circle-fill", warning: "bi-exclamation-triangle-fill", info: "bi-info-circle-fill" };
function _toastColor(type) {
  // Recomputed per-toast (not a module-level const) so it's always correct even
  // though in practice the theme only changes via a full page reload.
  return { success: semanticColor("safe"), danger: semanticColor("critical"),
           warning: semanticColor("high"), info: "#1a73e8" }[type] || "#1a73e8";
}

function _toastContainer() {
  let c = document.getElementById("toast-container");
  if (!c) {
    c = document.createElement("div");
    c.id = "toast-container";
    c.className = "toast-container position-fixed top-0 end-0 p-3";
    c.style.zIndex = 1080;
    document.body.appendChild(c);
  }
  return c;
}

function showToast(message, type = "success") {
  const color = _toastColor(type);
  const el = document.createElement("div");
  el.className = "toast align-items-center border-0";
  el.setAttribute("role", "alert");
  el.style.cssText = `background:var(--bg-card);border:1px solid ${color}55;border-radius:8px`;
  el.innerHTML = `
    <div class="d-flex">
      <div class="toast-body d-flex align-items-center gap-2" style="color:var(--text-primary)">
        <i class="bi ${TOAST_ICON[type] || TOAST_ICON.info}" style="color:${color}"></i>
        <span>${message}</span>
      </div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Fermer"></button>
    </div>`;
  _toastContainer().appendChild(el);
  const t = new bootstrap.Toast(el, { delay: 4500 });
  el.addEventListener("hidden.bs.toast", () => el.remove());
  t.show();
}

// ---- Confirmation modal (replaces confirm()) — returns a Promise<boolean> ----
let _confirmModalEl = null;
function confirmModal(message) {
  if (!_confirmModalEl) {
    _confirmModalEl = document.createElement("div");
    _confirmModalEl.className = "modal fade";
    _confirmModalEl.tabIndex = -1;
    _confirmModalEl.innerHTML = `
      <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content bg-dark text-white border-secondary">
          <div class="modal-header border-secondary">
            <h5 class="modal-title"><i class="bi bi-exclamation-triangle-fill text-warning me-2"></i>Confirmation</h5>
            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Fermer"></button>
          </div>
          <div class="modal-body" id="confirm-modal-body"></div>
          <div class="modal-footer border-secondary">
            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Annuler</button>
            <button type="button" class="btn btn-danger" id="confirm-modal-ok">Confirmer</button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(_confirmModalEl);
  }
  const el = _confirmModalEl;
  el.querySelector("#confirm-modal-body").textContent = message;
  const modal = bootstrap.Modal.getOrCreateInstance(el);
  const okBtn = el.querySelector("#confirm-modal-ok");
  return new Promise(resolve => {
    let decided = false;
    const onOk = () => { decided = true; modal.hide(); resolve(true); };
    const onHidden = () => { el.removeEventListener("hidden.bs.modal", onHidden); if (!decided) resolve(false); };
    okBtn.addEventListener("click", onOk, { once: true });
    el.addEventListener("hidden.bs.modal", onHidden);
    modal.show();
  });
}

// ---- Prompt modal (replaces prompt()) — returns a Promise<string|null> ----
function promptModal(title, { inputType = "text", placeholder = "", hint = "" } = {}) {
  const el = document.createElement("div");
  el.className = "modal fade";
  el.tabIndex = -1;
  el.innerHTML = `
    <div class="modal-dialog modal-dialog-centered">
      <div class="modal-content bg-dark text-white border-secondary">
        <div class="modal-header border-secondary">
          <h5 class="modal-title"><i class="bi bi-key-fill text-accent me-2"></i>${title}</h5>
          <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Fermer"></button>
        </div>
        <div class="modal-body">
          <input type="${inputType}" class="form-control bg-dark border-secondary text-white"
                 id="prompt-modal-input" placeholder="${placeholder}">
          ${hint ? `<div class="form-text text-fg-muted" style="font-size:.72rem">${hint}</div>` : ""}
        </div>
        <div class="modal-footer border-secondary">
          <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Annuler</button>
          <button type="button" class="btn btn-accent" id="prompt-modal-ok">Valider</button>
        </div>
      </div>
    </div>`;
  document.body.appendChild(el);
  const modal = new bootstrap.Modal(el);
  const input = el.querySelector("#prompt-modal-input");
  const okBtn = el.querySelector("#prompt-modal-ok");
  return new Promise(resolve => {
    let decided = false;
    const submit = () => { decided = true; modal.hide(); resolve(input.value); };
    okBtn.addEventListener("click", submit);
    input.addEventListener("keydown", e => { if (e.key === "Enter") submit(); });
    el.addEventListener("hidden.bs.modal", () => { if (!decided) resolve(null); el.remove(); });
    modal.show();
    setTimeout(() => input.focus(), 300);
  });
}

// ---- Table skeleton / empty state ----
function tableSkeleton(tbody, cols, rows = 4) {
  tbody.innerHTML = Array.from({ length: rows }).map(() =>
    `<tr class="skeleton-row">${Array.from({ length: cols }).map(() =>
      `<td><span class="skeleton-bar" style="width:${40 + Math.round(Math.random() * 45)}%"></span></td>`
    ).join("")}</tr>`
  ).join("");
}

function tableEmpty(tbody, cols, message, icon = "bi-inbox") {
  tbody.innerHTML = `<tr><td colspan="${cols}">
    <div class="empty-state"><i class="bi ${icon}"></i>${message}</div>
  </td></tr>`;
}

// ---- Client-side table controller: search + sort + pagination ----
// Data is already fully loaded (small volumes) — filtering/sorting/paging happens
// in memory and re-renders via the caller's onRender callback.
function createTableController({ pageSize = 10, searchFields = [], onRender }) {
  const state = { data: [], query: "", sortKey: null, sortDir: 1, page: 1 };

  function filteredSorted() {
    let rows = state.data;
    if (state.query) {
      const q = state.query.toLowerCase();
      rows = rows.filter(r => searchFields.some(f => String(r[f] ?? "").toLowerCase().includes(q)));
    }
    if (state.sortKey) {
      rows = [...rows].sort((a, b) => {
        const av = a[state.sortKey], bv = b[state.sortKey];
        if (av == null && bv == null) return 0;
        if (av == null) return 1;
        if (bv == null) return -1;
        if (av > bv) return state.sortDir;
        if (av < bv) return -state.sortDir;
        return 0;
      });
    }
    return rows;
  }

  function render() {
    const rows = filteredSorted();
    const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
    if (state.page > totalPages) state.page = totalPages;
    const start = (state.page - 1) * pageSize;
    onRender(rows.slice(start, start + pageSize), { total: rows.length, page: state.page, totalPages });
  }

  return {
    // resetPage: false lets background polling refresh data without kicking the user
    // off the page they're currently viewing.
    setData(data, resetPage = true) { state.data = data; if (resetPage) state.page = 1; render(); },
    setQuery(q) { state.query = q; state.page = 1; render(); },
    toggleSort(key) {
      if (state.sortKey === key) state.sortDir *= -1;
      else { state.sortKey = key; state.sortDir = 1; }
      render();
    },
    setPage(p) { state.page = p; render(); },
    getSort() { return { key: state.sortKey, dir: state.sortDir }; },
    getFiltered() { return filteredSorted(); }, // for CSV export of the current filter/sort, unpaginated
  };
}

function renderPaginationControls(container, { page, totalPages }, onPageChange) {
  if (totalPages <= 1) { container.innerHTML = ""; return; }
  container.innerHTML = `
    <div class="d-flex align-items-center justify-content-between mt-2 px-1">
      <small class="text-fg-muted">Page ${page} / ${totalPages}</small>
      <div class="btn-group btn-group-sm">
        <button class="btn btn-outline-secondary" ${page <= 1 ? "disabled" : ""} data-page="${page - 1}">
          <i class="bi bi-chevron-left"></i>
        </button>
        <button class="btn btn-outline-secondary" ${page >= totalPages ? "disabled" : ""} data-page="${page + 1}">
          <i class="bi bi-chevron-right"></i>
        </button>
      </div>
    </div>`;
  container.querySelectorAll("button[data-page]").forEach(btn => {
    btn.addEventListener("click", () => onPageChange(parseInt(btn.dataset.page, 10)));
  });
}

function wireSortableHeaders(theadEl, onSort) {
  theadEl.querySelectorAll("th[data-sort]").forEach(th => {
    th.style.cursor = "pointer";
    th.classList.add("user-select-none");
    th.addEventListener("click", () => onSort(th.dataset.sort));
  });
}

function updateSortIndicator(theadEl, key, dir) {
  theadEl.querySelectorAll("th[data-sort]").forEach(th => {
    th.querySelector(".sort-icon")?.remove();
    if (th.dataset.sort === key) {
      th.insertAdjacentHTML("beforeend",
        ` <i class="bi bi-caret-${dir === 1 ? "up" : "down"}-fill sort-icon" style="font-size:.6rem"></i>`);
    }
  });
}

// ---- CSV export ----
function toCSV(rows, columns) {
  const esc = v => {
    const s = String(v ?? "");
    return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const header = columns.map(c => esc(c.label)).join(",");
  const lines = rows.map(r =>
    columns.map(c => esc(typeof c.value === "function" ? c.value(r) : r[c.value])).join(","));
  return [header, ...lines].join("\r\n");
}

function downloadCSV(filename, rows, columns) {
  const csv = toCSV(rows, columns);
  const blob = new Blob(["﻿" + csv], { type: "text/csv;charset=utf-8;" }); // BOM for Excel accents
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
