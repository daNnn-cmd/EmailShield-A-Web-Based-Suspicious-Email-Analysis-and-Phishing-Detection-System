// Administrator Shared Functionality
async function loadAdminSummary() {
  try {
    const res = await fetch("/api/dashboard/summary");
    if (!res.ok) return;
    const data = await res.json();

    const t = document.getElementById("admStatTotalAnalyzed");
    const h = document.getElementById("admStatHighRisk");
    const u = document.getElementById("admStatUsers");
    const a = document.getElementById("admStatAudits");

    if (t) t.textContent = data.totalAnalyzed;
    if (h) h.textContent = data.highRiskCount;
    if (u) u.textContent = data.totalUsers;
    if (a) a.textContent = data.totalAudits;
  } catch {}
}

// User Pagination State
let cachedAdminUsers = [];
let allAdminUsers = [];
let usersCurrentPage = 1;
let usersPageSize = 10;

async function loadAdminUsers() {
  const tbody = document.getElementById("tableUsersBody");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="6" style="text-align: center;">Loading users...</td></tr>`;

  try {
    const res = await fetch("/api/auth/users");
    if (!res.ok) throw new Error();
    const users = await res.json();
    cachedAdminUsers = users;
    allAdminUsers = users;
    usersCurrentPage = 1;
    renderAdminUsers();
  } catch {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--danger);">Failed to load users.</td></tr>`;
  }
}

function renderAdminUsers() {
  const tbody = document.getElementById("tableUsersBody");
  if (!tbody) return;

  if (allAdminUsers.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center;">No users registered.</td></tr>`;
    updateUsersPagination(0, 0, 0, 1);
    return;
  }

  const currentUser = getCurrentUser();
  const isUsersPage = window.location.pathname.includes("users.html");
  const isPaginated = !!document.getElementById("usersPagination");
  let displayUsers = allAdminUsers;

  if (isPaginated) {
    const totalPages = Math.ceil(allAdminUsers.length / usersPageSize) || 1;
    if (usersCurrentPage > totalPages) usersCurrentPage = totalPages;
    if (usersCurrentPage < 1) usersCurrentPage = 1;

    const start = (usersCurrentPage - 1) * usersPageSize;
    const end = Math.min(start + usersPageSize, allAdminUsers.length);
    displayUsers = allAdminUsers.slice(start, end);

    updateUsersPagination(start + 1, end, allAdminUsers.length, totalPages);
  } else {
    // Quick preview (e.g. on admin overview)
    displayUsers = allAdminUsers.slice(0, 5);
  }

  tbody.innerHTML = displayUsers.map(u => {
    const isSelf = currentUser && currentUser.userId === u.userId;
    
    const actionButtons = isUsersPage ? `
      <div style="display: flex; gap: 6px; flex-wrap: wrap;">
        <button class="btn btn-secondary btn-sm" onclick="openEditUserModal(${u.userId})" title="Edit user details">
          ✏️ Edit
        </button>
        <button class="btn btn-secondary btn-sm" onclick="toggleUserStatus(${u.userId})" ${isSelf ? "disabled title='Cannot change your own account status'" : ""}>
          ${u.isActive ? "Deactivate" : "Activate"}
        </button>
      </div>
    ` : `
      <button class="btn btn-secondary btn-sm" onclick="toggleUserStatus(${u.userId})" ${isSelf ? "disabled title='Cannot change your own account status'" : ""}>
        ${u.isActive ? "Deactivate" : "Activate"}
      </button>
    `;

    return `
      <tr>
        <td><strong>${escapeHtml(u.fullName)}</strong></td>
        <td>${escapeHtml(u.email)}</td>
        <td>${escapeHtml(u.roleName)}</td>
        <td>${u.isActive ? "Active" : "Inactive"}</td>
        <td>${new Date(u.createdAt).toLocaleDateString()}</td>
        <td>${actionButtons}</td>
      </tr>
    `;
  }).join("");
}

function updateUsersPagination(start, end, total, totalPages) {
  const infoEl = document.getElementById("usersPaginationInfo");
  const numEl = document.getElementById("usersPageNumber");
  const btnPrev = document.getElementById("btnUsersPrev");
  const btnNext = document.getElementById("btnUsersNext");

  if (infoEl) {
    infoEl.textContent = total > 0 
      ? `Showing ${start} to ${end} of ${total} users` 
      : "Showing 0 to 0 of 0 users";
  }

  if (numEl) {
    numEl.textContent = `Page ${usersCurrentPage} of ${totalPages}`;
  }

  if (btnPrev) btnPrev.disabled = usersCurrentPage <= 1;
  if (btnNext) btnNext.disabled = usersCurrentPage >= totalPages;
}

function prevUsersPage() {
  if (usersCurrentPage > 1) {
    usersCurrentPage--;
    renderAdminUsers();
  }
}

function nextUsersPage() {
  const totalPages = Math.ceil(allAdminUsers.length / usersPageSize);
  if (usersCurrentPage < totalPages) {
    usersCurrentPage++;
    renderAdminUsers();
  }
}

function changeUsersPageSize(newSize) {
  usersPageSize = parseInt(newSize, 10) || 10;
  usersCurrentPage = 1;
  renderAdminUsers();
}

async function toggleUserStatus(id) {
  try {
    const res = await fetch(`/api/auth/users/${id}/toggle-status`, { method: "PUT" });
    if (res.ok) {
      showAlert("User status updated successfully.", "success");
      loadAdminUsers();
      if (typeof loadAdminSummary === "function") loadAdminSummary();
    } else {
      const data = await res.json();
      showAlert(data.message || "Failed to update user status.", "danger");
    }
  } catch {
    showAlert("Failed to update user status.", "danger");
  }
}

// User CRUD: Add Modal & Operations
function openAddUserModal() {
  const modal = document.getElementById("modalAddUser");
  if (!modal) return;
  document.getElementById("formAddUser")?.reset();
  modal.style.display = "flex";
}

function closeAddUserModal() {
  const modal = document.getElementById("modalAddUser");
  if (modal) modal.style.display = "none";
}

async function submitAddUser(e) {
  e.preventDefault();
  const fullName = document.getElementById("addFullName")?.value.trim();
  const email = document.getElementById("addEmail")?.value.trim();
  const password = document.getElementById("addPassword")?.value;
  const roleId = parseInt(document.getElementById("addRoleId")?.value || "3");
  const currentUser = getCurrentUser();

  const submitBtn = document.getElementById("btnAddUserSubmit");
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = "Creating...";
  }

  try {
    const res = await fetch("/api/auth/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fullName,
        email,
        password,
        roleId,
        adminUserId: currentUser?.userId || null
      })
    });

    const data = await res.json();
    if (!res.ok) {
      showAlert(data.message || "Failed to create user account.", "danger");
      return;
    }

    closeAddUserModal();
    showAlert(`User account for ${data.fullName} created successfully.`, "success");
    loadAdminUsers();
    if (typeof loadAdminSummary === "function") loadAdminSummary();
  } catch {
    showAlert("Network error while creating user account.", "danger");
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = "Create Account";
    }
  }
}

// User CRUD: Edit Modal & Operations
function openEditUserModal(userId) {
  const user = cachedAdminUsers.find(u => u.userId === userId);
  if (!user) return;

  const modal = document.getElementById("modalEditUser");
  if (!modal) return;

  document.getElementById("editUserId").value = user.userId;
  document.getElementById("editFullName").value = user.fullName;
  document.getElementById("editEmail").value = user.email;
  document.getElementById("editRoleId").value = user.roleId;
  document.getElementById("editIsActive").value = user.isActive ? "true" : "false";
  document.getElementById("editPassword").value = "";

  modal.style.display = "flex";
}

function closeEditUserModal() {
  const modal = document.getElementById("modalEditUser");
  if (modal) modal.style.display = "none";
}

async function submitEditUser(e) {
  e.preventDefault();
  const userId = parseInt(document.getElementById("editUserId")?.value);
  const fullName = document.getElementById("editFullName")?.value.trim();
  const email = document.getElementById("editEmail")?.value.trim();
  const roleId = parseInt(document.getElementById("editRoleId")?.value);
  const isActive = document.getElementById("editIsActive")?.value === "true";
  const password = document.getElementById("editPassword")?.value || null;
  const currentUser = getCurrentUser();

  const submitBtn = document.getElementById("btnEditUserSubmit");
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = "Saving...";
  }

  try {
    const res = await fetch(`/api/auth/users/${userId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fullName,
        email,
        roleId,
        isActive,
        password,
        adminUserId: currentUser?.userId || null
      })
    });

    const data = await res.json();
    if (!res.ok) {
      showAlert(data.message || "Failed to update user account.", "danger");
      return;
    }

    closeEditUserModal();
    showAlert(`User account for ${data.fullName} updated successfully.`, "success");
    loadAdminUsers();
    if (typeof loadAdminSummary === "function") loadAdminSummary();
  } catch {
    showAlert("Network error while updating user account.", "danger");
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = "Save Changes";
    }
  }
}

// User CRUD: Delete Modal & Operations
function openDeleteUserModal(userId, name, email) {
  const modal = document.getElementById("modalDeleteUser");
  if (!modal) return;

  document.getElementById("deleteTargetUserId").value = userId;
  const msg = document.getElementById("deleteUserMsg");
  if (msg) {
    msg.innerHTML = `Are you sure you want to permanently delete user account <strong>${escapeHtml(name)}</strong> (${escapeHtml(email)})? This action cannot be undone.`;
  }

  modal.style.display = "flex";
}

function closeDeleteUserModal() {
  const modal = document.getElementById("modalDeleteUser");
  if (modal) modal.style.display = "none";
}

async function executeDeleteUser() {
  const targetId = document.getElementById("deleteTargetUserId")?.value;
  if (!targetId) return;

  const currentUser = getCurrentUser();
  const adminParam = currentUser?.userId ? `?adminUserId=${currentUser.userId}` : "";

  const confirmBtn = document.getElementById("btnConfirmDelete");
  if (confirmBtn) {
    confirmBtn.disabled = true;
    confirmBtn.textContent = "Deleting...";
  }

  try {
    const res = await fetch(`/api/auth/users/${targetId}${adminParam}`, {
      method: "DELETE"
    });

    const data = await res.json();
    if (!res.ok) {
      showAlert(data.message || "Failed to delete user account.", "danger");
      return;
    }

    closeDeleteUserModal();
    showAlert(data.message || "User account deleted successfully.", "success");
    loadAdminUsers();
    if (typeof loadAdminSummary === "function") loadAdminSummary();
  } catch {
    showAlert("Network error while deleting user account.", "danger");
  } finally {
    if (confirmBtn) {
      confirmBtn.disabled = false;
      confirmBtn.textContent = "Delete Account";
    }
  }
}

// Audit Log Pagination State
let allAuditLogs = [];
let auditCurrentPage = 1;
let auditPageSize = 10;

function formatPhilippineTime(dateStr) {
  if (!dateStr) return "-";
  try {
    // Treat timestamp as UTC if no offset specified, and convert to Asia/Manila (PST, UTC+8)
    const isoStr = (dateStr.endsWith("Z") || dateStr.includes("+")) ? dateStr : dateStr + "Z";
    const date = new Date(isoStr);
    return date.toLocaleString("en-PH", {
      timeZone: "Asia/Manila",
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: true
    });
  } catch {
    return new Date(dateStr).toLocaleString();
  }
}

async function loadAuditLogs() {
  const tbody = document.getElementById("tableAuditsBody");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="4" style="text-align: center;">Loading audit logs...</td></tr>`;

  try {
    const res = await fetch("/api/audit?limit=500");
    if (!res.ok) throw new Error();
    allAuditLogs = await res.json();
    auditCurrentPage = 1;
    renderAuditLogs();
  } catch {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--danger);">Failed to load audit logs.</td></tr>`;
  }
}

function renderAuditLogs() {
  const tbody = document.getElementById("tableAuditsBody");
  if (!tbody) return;

  if (allAuditLogs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align: center;">No audit logs recorded yet.</td></tr>`;
    updateAuditPagination(0, 0, 0, 1);
    return;
  }

  const isPaginated = !!document.getElementById("auditPagination");
  let displayLogs = allAuditLogs;

  if (isPaginated) {
    const totalPages = Math.ceil(allAuditLogs.length / auditPageSize) || 1;
    if (auditCurrentPage > totalPages) auditCurrentPage = totalPages;
    if (auditCurrentPage < 1) auditCurrentPage = 1;

    const start = (auditCurrentPage - 1) * auditPageSize;
    const end = Math.min(start + auditPageSize, allAuditLogs.length);
    displayLogs = allAuditLogs.slice(start, end);

    updateAuditPagination(start + 1, end, allAuditLogs.length, totalPages);
  } else {
    // Quick preview (e.g. on admin overview)
    displayLogs = allAuditLogs.slice(0, 5);
  }

  tbody.innerHTML = displayLogs.map(l => `
    <tr>
      <td><strong>${escapeHtml(l.userName)}</strong></td>
      <td>${escapeHtml(l.action)}</td>
      <td>${escapeHtml(l.description || "-")}</td>
      <td><code style="color: var(--accent);">${formatPhilippineTime(l.createdAt)}</code></td>
    </tr>
  `).join("");
}

function updateAuditPagination(start, end, total, totalPages) {
  const infoEl = document.getElementById("auditPaginationInfo");
  const numEl = document.getElementById("auditPageNumber");
  const btnPrev = document.getElementById("btnAuditPrev");
  const btnNext = document.getElementById("btnAuditNext");

  if (infoEl) {
    infoEl.textContent = total > 0 
      ? `Showing ${start} to ${end} of ${total} logs` 
      : "Showing 0 to 0 of 0 logs";
  }

  if (numEl) {
    numEl.textContent = `Page ${auditCurrentPage} of ${totalPages}`;
  }

  if (btnPrev) btnPrev.disabled = auditCurrentPage <= 1;
  if (btnNext) btnNext.disabled = auditCurrentPage >= totalPages;
}

function prevAuditPage() {
  if (auditCurrentPage > 1) {
    auditCurrentPage--;
    renderAuditLogs();
  }
}

function nextAuditPage() {
  const totalPages = Math.ceil(allAuditLogs.length / auditPageSize);
  if (auditCurrentPage < totalPages) {
    auditCurrentPage++;
    renderAuditLogs();
  }
}

function changeAuditPageSize(newSize) {
  auditPageSize = parseInt(newSize, 10) || 10;
  auditCurrentPage = 1;
  renderAuditLogs();
}

// Global Scans Pagination State
let allAdminScans = [];
let scansCurrentPage = 1;
let scansPageSize = 10;

async function loadAdminScans() {
  const tbody = document.getElementById("tableAdminScansBody");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="7" style="text-align: center;">Loading analysis records...</td></tr>`;

  try {
    const res = await fetch("/api/analysis/history");
    if (!res.ok) throw new Error();
    allAdminScans = await res.json();
    scansCurrentPage = 1;
    renderAdminScans();
  } catch {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--danger);">Failed to load history.</td></tr>`;
  }
}

function renderAdminScans() {
  const tbody = document.getElementById("tableAdminScansBody");
  if (!tbody) return;

  if (allAdminScans.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center;">No previous scans recorded.</td></tr>`;
    updateScansPagination(0, 0, 0, 1);
    return;
  }

  const isPaginated = !!document.getElementById("scansPagination");
  let displayScans = allAdminScans;

  if (isPaginated) {
    const totalPages = Math.ceil(allAdminScans.length / scansPageSize) || 1;
    if (scansCurrentPage > totalPages) scansCurrentPage = totalPages;
    if (scansCurrentPage < 1) scansCurrentPage = 1;

    const start = (scansCurrentPage - 1) * scansPageSize;
    const end = Math.min(start + scansPageSize, allAdminScans.length);
    displayScans = allAdminScans.slice(start, end);

    updateScansPagination(start + 1, end, allAdminScans.length, totalPages);
  } else {
    displayScans = allAdminScans.slice(0, 5);
  }

  tbody.innerHTML = displayScans.map(item => `
    <tr>
      <td><strong>${escapeHtml(item.subject || "(No Subject)")}</strong></td>
      <td>${escapeHtml(item.senderEmail || "-")}</td>
      <td>${escapeHtml(item.submittedBy || "-")}</td>
      <td><strong>${item.riskScore}/100</strong></td>
      <td><span class="badge badge-${(item.riskClassification || "low").toLowerCase()}">${item.riskClassification}</span></td>
      <td>${item.analyzedAt ? new Date(item.analyzedAt).toLocaleDateString() : "-"}</td>
      <td>
        <a class="btn btn-secondary btn-sm" href="/admin/report.html?id=${item.analysisId}">
          Inspect Report
        </a>
      </td>
    </tr>
  `).join("");
}

function updateScansPagination(start, end, total, totalPages) {
  const infoEl = document.getElementById("scansPaginationInfo");
  const numEl = document.getElementById("scansPageNumber");
  const btnPrev = document.getElementById("btnScansPrev");
  const btnNext = document.getElementById("btnScansNext");

  if (infoEl) {
    infoEl.textContent = total > 0 
      ? `Showing ${start} to ${end} of ${total} records` 
      : "Showing 0 to 0 of 0 records";
  }

  if (numEl) {
    numEl.textContent = `Page ${scansCurrentPage} of ${totalPages}`;
  }

  if (btnPrev) btnPrev.disabled = scansCurrentPage <= 1;
  if (btnNext) btnNext.disabled = scansCurrentPage >= totalPages;
}

function prevScansPage() {
  if (scansCurrentPage > 1) {
    scansCurrentPage--;
    renderAdminScans();
  }
}

function nextScansPage() {
  const totalPages = Math.ceil(allAdminScans.length / scansPageSize);
  if (scansCurrentPage < totalPages) {
    scansCurrentPage++;
    renderAdminScans();
  }
}

function changeScansPageSize(newSize) {
  scansPageSize = parseInt(newSize, 10) || 10;
  scansCurrentPage = 1;
  renderAdminScans();
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    closeAddUserModal();
    closeEditUserModal();
    closeDeleteUserModal();
  }
});


