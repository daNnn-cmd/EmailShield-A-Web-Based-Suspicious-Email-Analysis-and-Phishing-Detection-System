// Security Analyst Functionality
let currentSelectedFile = null;

function setupDropzone() {
  const dropzone = document.getElementById("dropzoneEml");
  if (!dropzone) return;

  ["dragenter", "dragover"].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFile(files[0]);
    }
  });
}

function handleFileSelected(event) {
  const files = event.target.files;
  if (files.length > 0) {
    handleFile(files[0]);
  }
}

function handleFile(file) {
  if (!file.name.toLowerCase().endsWith(".eml")) {
    showAlert("Please select a valid .eml file.", "danger");
    return;
  }
  currentSelectedFile = file;
  const nameEl = document.getElementById("fileSelectedName");
  nameEl.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
  nameEl.style.display = "block";
  document.getElementById("btnSubmitEml").disabled = false;
}

function switchSubmissionMode(mode) {
  document.getElementById("analystTabBtnUpload").classList.toggle("active", mode === "upload");
  document.getElementById("analystTabBtnPaste").classList.toggle("active", mode === "paste");
  document.getElementById("subModeUpload").style.display = mode === "upload" ? "block" : "none";
  document.getElementById("subModePaste").style.display = mode === "paste" ? "block" : "none";
}

function loadSamplePhishingEmail() {
  switchSubmissionMode("paste");
  const sample = 
`From: "CEO Tim Cook" <tcook@apple-corp-update.xyz>
Reply-To: security-recovery@wire-payments.top
To: accounting@school.edu
Subject: URGENT: Wire Transfer Update & Immediate Account Verification
Date: Fri, 14 Nov 2026 08:15:00 +0000
Authentication-Results: mx.school.edu; spf=fail smtp.mailfrom=apple-corp-update.xyz; dkim=fail; dmarc=fail

Dear Finance Team,

Please review the attached invoice immediately. Our previous banking details are currently undergoing a security audit.
You are required to process the pending vendor wire transfer ($48,500) to our new account within 24 hours to avoid service termination.

Verify your payment authorization credentials here:
http://192.168.1.105/login-verification?ref=update-account

Strictly confidential. Do not discuss this request by phone.

Regards,
Tim Cook
CEO`;

  document.getElementById("textEmailContent").value = sample;
  showAlert("Sample BEC & Phishing email loaded into editor!", "info");
}

async function submitRawText() {
  const content = document.getElementById("textEmailContent").value.trim();
  if (!content) {
    showAlert("Please enter or paste email content to analyze.", "warning");
    return;
  }

  showAlert("Analyzing email sample against threat heuristics...", "info");
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

    if (!res.ok) {
      const err = await res.json();
      showAlert(err.message || "Analysis failed.", "danger");
      return;
    }

    const data = await res.json();
    sessionStorage.setItem("active_analysis", JSON.stringify(data));
    window.location.href = `/analyst/report.html?id=${data.analysisId}`;
  } catch {
    showAlert("Failed to contact analysis engine.", "danger");
  }
}

async function submitEmlFile() {
  if (!currentSelectedFile) {
    showAlert("Please select a .eml file first.", "warning");
    return;
  }

  showAlert("Uploading and parsing .eml file...", "info");
  const user = getCurrentUser();
  const formData = new FormData();
  formData.append("file", currentSelectedFile);
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
    sessionStorage.setItem("active_analysis", JSON.stringify(data));
    window.location.href = `/analyst/report.html?id=${data.analysisId}`;
  } catch {
    showAlert("Failed to upload .eml file.", "danger");
  }
}

// Analyst History Pagination State
let allAnalystHistory = [];
let analystCurrentPage = 1;
let analystPageSize = 10;

async function loadAnalystHistory() {
  const tbody = document.getElementById("tableAnalystHistoryBody");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="7" style="text-align: center;">Loading history...</td></tr>`;

  try {
    const res = await fetch("/api/analysis/history");
    if (!res.ok) throw new Error();
    allAnalystHistory = await res.json();
    analystCurrentPage = 1;
    renderAnalystHistory();
  } catch {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--danger);">Failed to load history.</td></tr>`;
  }
}

function renderAnalystHistory() {
  const tbody = document.getElementById("tableAnalystHistoryBody");
  if (!tbody) return;

  if (allAnalystHistory.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center;">No previous scans recorded.</td></tr>`;
    updateAnalystPagination(0, 0, 0, 1);
    return;
  }

  const isPaginated = !!document.getElementById("analystPagination");
  let displayList = allAnalystHistory;

  if (isPaginated) {
    const totalPages = Math.ceil(allAnalystHistory.length / analystPageSize) || 1;
    if (analystCurrentPage > totalPages) analystCurrentPage = totalPages;
    if (analystCurrentPage < 1) analystCurrentPage = 1;

    const start = (analystCurrentPage - 1) * analystPageSize;
    const end = Math.min(start + analystPageSize, allAnalystHistory.length);
    displayList = allAnalystHistory.slice(start, end);

    updateAnalystPagination(start + 1, end, allAnalystHistory.length, totalPages);
  } else {
    displayList = allAnalystHistory.slice(0, 5);
  }

  tbody.innerHTML = displayList.map(item => `
    <tr>
      <td><strong>${escapeHtml(item.subject || "(No Subject)")}</strong></td>
      <td>${escapeHtml(item.senderEmail || "-")}</td>
      <td>${escapeHtml(item.submittedBy || "-")}</td>
      <td><strong>${item.riskScore}/100</strong></td>
      <td><span class="badge badge-${(item.riskClassification || "low").toLowerCase()}">${item.riskClassification}</span></td>
      <td>${item.analyzedAt ? new Date(item.analyzedAt).toLocaleDateString() : "-"}</td>
      <td>
        <a class="btn btn-secondary btn-sm" href="/analyst/report.html?id=${item.analysisId}">
          Inspect
        </a>
      </td>
    </tr>
  `).join("");
}

function updateAnalystPagination(start, end, total, totalPages) {
  const infoEl = document.getElementById("analystPaginationInfo");
  const numEl = document.getElementById("analystPageNumber");
  const btnPrev = document.getElementById("btnAnalystPrev");
  const btnNext = document.getElementById("btnAnalystNext");

  if (infoEl) {
    infoEl.textContent = total > 0 
      ? `Showing ${start} to ${end} of ${total} records` 
      : "Showing 0 to 0 of 0 records";
  }

  if (numEl) {
    numEl.textContent = `Page ${analystCurrentPage} of ${totalPages}`;
  }

  if (btnPrev) btnPrev.disabled = analystCurrentPage <= 1;
  if (btnNext) btnNext.disabled = analystCurrentPage >= totalPages;
}

function prevAnalystPage() {
  if (analystCurrentPage > 1) {
    analystCurrentPage--;
    renderAnalystHistory();
  }
}

function nextAnalystPage() {
  const totalPages = Math.ceil(allAnalystHistory.length / analystPageSize);
  if (analystCurrentPage < totalPages) {
    analystCurrentPage++;
    renderAnalystHistory();
  }
}

function changeAnalystPageSize(newSize) {
  analystPageSize = parseInt(newSize, 10) || 10;
  analystCurrentPage = 1;
  renderAnalystHistory();
}

