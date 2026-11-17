// Authentication, Route Guards & Shared Navigation Helper
function getCurrentUser() {
  const userStr = sessionStorage.getItem("emailshield_user");
  if (!userStr) return null;
  try {
    return JSON.parse(userStr);
  } catch {
    sessionStorage.removeItem("emailshield_user");
    return null;
  }
}

function redirectByRole(roleName) {
  const r = (roleName || "").toLowerCase();
  if (r.includes("admin")) {
    window.location.replace("/admin/");
  } else if (r.includes("analyst")) {
    window.location.replace("/analyst/");
  } else {
    window.location.replace("/viewer/");
  }
}

function enforceDirectoryProtection() {
  // Wipe any residual localStorage to eliminate multi-tab/cross-tab session leakage
  try {
    localStorage.removeItem("emailshield_user");
  } catch {}

  const path = window.location.pathname.toLowerCase();
  // Allow root login page and root index
  if (path === "/" || path === "/index.html" || path === "") return;

  const user = getCurrentUser();
  if (!user) {
    // Block Direct URL Access / Forced Browsing: redirect back to login immediately
    window.location.replace("/");
    return false;
  }

  const role = (user.roleName || "").toLowerCase();
  if (path.startsWith("/admin/") && !role.includes("admin")) {
    redirectByRole(user.roleName);
    return false;
  }
  if (path.startsWith("/analyst/") && !role.includes("analyst")) {
    redirectByRole(user.roleName);
    return false;
  }
  if (path.startsWith("/viewer/") && !role.includes("viewer") && !role.includes("user")) {
    redirectByRole(user.roleName);
    return false;
  }
  return true;
}

// Enforce immediate directory and forced browsing guard on load
enforceDirectoryProtection();

function requireAuth(allowedRole) {
  const user = getCurrentUser();
  if (!user) {
    window.location.replace("/");
    return null;
  }

  if (allowedRole) {
    const roleLower = (user.roleName || "").toLowerCase();
    const allowed = Array.isArray(allowedRole)
      ? allowedRole.some(r => roleLower.includes(r.toLowerCase()))
      : roleLower.includes(allowedRole.toLowerCase());

    if (!allowed) {
      redirectByRole(user.roleName);
      return null;
    }
  }

  initUserHeader(user);
  return user;
}

function initUserHeader(user) {
  if (!user) return;

  const sideName = document.getElementById("sidebarUserName");
  const sideEmail = document.getElementById("sidebarUserEmail");
  const sideRole = document.getElementById("sidebarUserRole");

  if (sideName) sideName.textContent = user.fullName;
  if (sideEmail) sideEmail.textContent = user.email;
  if (sideRole) {
    sideRole.textContent = user.roleName;
    sideRole.className = `role-tag ${getRoleClass(user.roleName)}`;
  }

  const navName = document.getElementById("navUserName");
  const navRole = document.getElementById("navUserRole");
  if (navName) navName.textContent = user.fullName;
  if (navRole) {
    navRole.textContent = user.roleName;
    navRole.className = `role-tag ${getRoleClass(user.roleName)}`;
  }
}

async function logout() {
  sessionStorage.removeItem("emailshield_user");
  sessionStorage.clear();
  try {
    localStorage.removeItem("emailshield_user");
    localStorage.clear();
  } catch {}
  try {
    await fetch("/api/auth/logout", { method: "POST" });
  } catch {}
  window.location.replace("/");
}

function confirmSignOut() {
  let modal = document.getElementById("signOutModal");
  if (!modal) {
    createSignOutModal();
    modal = document.getElementById("signOutModal");
  }
  modal.style.display = "flex";
}

function closeSignOutModal() {
  const modal = document.getElementById("signOutModal");
  if (modal) modal.style.display = "none";
}

function createSignOutModal() {
  const html = `
    <div id="signOutModal" class="modal-overlay" style="display: none;" onclick="if(event.target===this) closeSignOutModal()">
      <div class="modal-box">
        <div class="modal-icon">🚪</div>
        <h3 class="modal-title">Sign Out Confirmation</h3>
        <p class="modal-desc">Are you sure you want to sign out of EmailShield? You will need to sign in again to access your dashboard.</p>
        <div class="modal-actions">
          <button class="btn btn-secondary" onclick="closeSignOutModal()">Cancel</button>
          <button class="btn btn-danger" onclick="logout()">Yes, Sign Out</button>
        </div>
      </div>
    </div>
  `;
  document.body.insertAdjacentHTML("beforeend", html);
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeSignOutModal();
});

function getRoleClass(roleName) {
  const r = (roleName || "").toLowerCase();
  if (r.includes("admin")) return "role-admin";
  if (r.includes("analyst")) return "role-analyst";
  return "role-viewer";
}

function showAlert(message, type = "info") {
  const alertEl = document.getElementById("globalAlert");
  if (!alertEl) return;
  alertEl.className = `alert alert-${type}`;
  alertEl.textContent = message;
  alertEl.style.display = "block";
  setTimeout(() => {
    alertEl.style.display = "none";
  }, 5000);
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

