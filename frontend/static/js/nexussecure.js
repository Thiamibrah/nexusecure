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
    }).catch(() => {});

  // Show correct sidebar
  const sidebarEl = document.querySelector(`.sidebar-${role}`);
  if (sidebarEl) sidebarEl.classList.remove("d-none");

  // Highlight active link
  document.querySelectorAll(".nav-link.sidebar-link").forEach(a => {
    if (a.getAttribute("href") === window.location.pathname) a.classList.add("active");
  });
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
