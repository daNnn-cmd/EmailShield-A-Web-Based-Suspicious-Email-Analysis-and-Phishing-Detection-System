// Viewer / User Functionality
let selectedViewerFile = null;

function switchViewerInputTab(tab) {
  const isText = tab === "text";
  document.getElementById("viewerTabBtnText")?.classList.toggle("active", isText);
  document.getElementById("viewerTabBtnFile")?.classList.toggle("active", !isText);
  document.getElementById("viewerInputTextSection").style.display = isText ? "block" : "none";
  document.getElementById("viewerInputFileSection").style.display = !isText ? "block" : "none";
}

function onViewerFileSelected(input) {
  if (input.files && input.files[0]) {
    selectedViewerFile = input.files[0];
  }
}

async function submitViewerText() {
  const content = document.getElementById("viewerEmailContent").value.trim();
  if (!content) {
    showAlert("Please paste email text to check.", "warning");
    return;
  }

  showAlert("Scanning email text with threat engine...", "info");
  const user = getCurrentUser();

  try {
    const res = await fetch("/api/analysis/submit-text", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        userId: user ? user.userId : 1,
        rawContent: content
      })
    });

    if (!res.ok) throw new Error();
    const data = await res.json();
    renderViewerResultCard(data);
    loadViewerHistory();
    showAlert("Scan complete! Forensic evaluation ready.", "success");
  } catch {
    showAlert("Error scanning email text.", "danger");
  }
}

async function submitViewerEmlFile() {
  if (!selectedViewerFile) {
    showAlert("Please select a .eml file to upload.", "warning");
    return;
  }

  showAlert("Uploading and inspecting .eml file...", "info");
  const user = getCurrentUser();
  const formData = new FormData();
  formData.append("file", selectedViewerFile);
  formData.append("userId", user ? user.userId : 1);

  try {
    const res = await fetch("/api/analysis/upload-eml", {
      method: "POST",
      body: formData
    });

    if (!res.ok) {
      const err = await res.json();
      showAlert(err.message || "Failed to process .eml file.", "danger");
      return;
    }

    const data = await res.json();
    renderViewerResultCard(data);
    loadViewerHistory();
    showAlert(".EML File inspected successfully!", "success");
  } catch {
    showAlert("Error processing .eml upload.", "danger");
  }
}

function renderViewerResultCard(data) {
  const card = document.getElementById("viewerResultCard");
  if (!card) return;

  const isHigh = data.riskClassification === "High";
  const isMed = data.riskClassification === "Medium";

  card.style.borderColor = isHigh ? "var(--danger)" : (isMed ? "var(--warning)" : "var(--success)");
  const user = getCurrentUser();

  card.innerHTML = `
    <div style="font-size: 50px; margin-bottom: 8px;">${isHigh ? "🚨" : (isMed ? "⚠️" : "✅")}</div>
    <h3 style="color: ${isHigh ? "#fca5a5" : (isMed ? "#fcd34d" : "#86efac")}; font-size: 1.4rem;">
      ${data.riskClassification.toUpperCase()} RISK (Score: ${data.riskScore}/100)
    </h3>
    <p style="margin: 8px 0; font-size: 0.95rem; line-height: 1.4;">${escapeHtml(data.analysisSummary)}</p>
    
    <div class="alert alert-info" style="text-align: left; margin: 12px 0 0;">
      <strong>Security Advice:</strong>
      <div style="white-space: pre-line; margin-top: 4px;">${escapeHtml(data.recommendation)}</div>
    </div>

    <div style="display: flex; gap: 8px; justify-content: center; margin-top: 14px; flex-wrap: wrap;">
      <button class="btn btn-secondary btn-sm" onclick="window.open('/api/reports/export-pdf/${data.analysisId}?userId=${user ? user.userId : 1}', '_blank')">
        📄 Download PDF Report
      </button>
      <button class="btn btn-secondary btn-sm" onclick="window.open('/api/reports/export-csv/${data.analysisId}?userId=${user ? user.userId : 1}', '_blank')">
        📥 Download CSV
      </button>
    </div>
  `;
}

// Viewer History Pagination State
let allViewerHistory = [];
let viewerCurrentPage = 1;
let viewerPageSize = 10;

async function loadViewerHistory() {
  const tbody = document.getElementById("tableViewerHistoryBody");
  if (!tbody) return;
  const user = getCurrentUser();
  if (!user) return;

  tbody.innerHTML = `<tr><td colspan="5" style="text-align: center;">Loading past submissions...</td></tr>`;

  try {
    const res = await fetch(`/api/analysis/history?userId=${user.userId}`);
    if (!res.ok) throw new Error();
    allViewerHistory = await res.json();
    viewerCurrentPage = 1;
    renderViewerHistory();
  } catch {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--danger);">Failed to load history.</td></tr>`;
  }
}

function renderViewerHistory() {
  const tbody = document.getElementById("tableViewerHistoryBody");
  if (!tbody) return;

  if (allViewerHistory.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center;">No emails submitted yet.</td></tr>`;
    updateViewerPagination(0, 0, 0, 1);
    return;
  }

  const user = getCurrentUser();
  const isPaginated = !!document.getElementById("viewerPagination");
  let displayList = allViewerHistory;

  if (isPaginated) {
    const totalPages = Math.ceil(allViewerHistory.length / viewerPageSize) || 1;
    if (viewerCurrentPage > totalPages) viewerCurrentPage = totalPages;
    if (viewerCurrentPage < 1) viewerCurrentPage = 1;

    const start = (viewerCurrentPage - 1) * viewerPageSize;
    const end = Math.min(start + viewerPageSize, allViewerHistory.length);
    displayList = allViewerHistory.slice(start, end);

    updateViewerPagination(start + 1, end, allViewerHistory.length, totalPages);
  } else {
    displayList = allViewerHistory.slice(0, 5);
  }

  tbody.innerHTML = displayList.map(item => `
    <tr>
      <td><strong>${escapeHtml(item.subject || "(No Subject)")}</strong></td>
      <td>${escapeHtml(item.senderEmail || "-")}</td>
      <td><span class="badge badge-${(item.riskClassification || "low").toLowerCase()}">${item.riskClassification}</span></td>
      <td>${item.analyzedAt ? new Date(item.analyzedAt).toLocaleDateString() : "-"}</td>
      <td>
        <div style="display: flex; gap: 4px;">
          <a class="btn btn-secondary btn-sm" href="/viewer/report.html?id=${item.analysisId}" title="View Findings">
            Inspect
          </a>
          <button class="btn btn-secondary btn-sm" onclick="window.open('/api/reports/export-pdf/${item.analysisId}?userId=${user ? user.userId : 1}', '_blank')" title="Download PDF">
            📄 PDF
          </button>
        </div>
      </td>
    </tr>
  `).join("");
}

function updateViewerPagination(start, end, total, totalPages) {
  const infoEl = document.getElementById("viewerPaginationInfo");
  const numEl = document.getElementById("viewerPageNumber");
  const btnPrev = document.getElementById("btnViewerPrev");
  const btnNext = document.getElementById("btnViewerNext");

  if (infoEl) {
    infoEl.textContent = total > 0 
      ? `Showing ${start} to ${end} of ${total} submissions` 
      : "Showing 0 to 0 of 0 submissions";
  }

  if (numEl) {
    numEl.textContent = `Page ${viewerCurrentPage} of ${totalPages}`;
  }

  if (btnPrev) btnPrev.disabled = viewerCurrentPage <= 1;
  if (btnNext) btnNext.disabled = viewerCurrentPage >= totalPages;
}

function prevViewerPage() {
  if (viewerCurrentPage > 1) {
    viewerCurrentPage--;
    renderViewerHistory();
  }
}

function nextViewerPage() {
  const totalPages = Math.ceil(allViewerHistory.length / viewerPageSize);
  if (viewerCurrentPage < totalPages) {
    viewerCurrentPage++;
    renderViewerHistory();
  }
}

function changeViewerPageSize(newSize) {
  viewerPageSize = parseInt(newSize, 10) || 10;
  viewerCurrentPage = 1;
  renderViewerHistory();
}

