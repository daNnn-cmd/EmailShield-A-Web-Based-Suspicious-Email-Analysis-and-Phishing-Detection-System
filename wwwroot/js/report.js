// Shared Forensic Analysis Report Logic
var currentAnalysisId = null;

async function initReportPage() {
  const urlParams = new URLSearchParams(window.location.search);
  const analysisId = urlParams.get("id");

  if (analysisId) {
    try {
      const res = await fetch(`/api/analysis/${analysisId}`);
      if (res.ok) {
        const data = await res.json();
        displayAnalysisResult(data);
        return;
      }
    } catch {}
  }

  // Check sessionStorage
  const cached = sessionStorage.getItem("active_analysis");
  if (cached) {
    try {
      const data = JSON.parse(cached);
      displayAnalysisResult(data);
      return;
    } catch {}
  }

  // If no ID or cached item, load the most recent analysis
  try {
    const histRes = await fetch("/api/analysis/history");
    if (histRes.ok) {
      const list = await histRes.json();
      if (list.length > 0) {
        const firstId = list[0].analysisId;
        const detRes = await fetch(`/api/analysis/${firstId}`);
        if (detRes.ok) {
          const data = await detRes.json();
          displayAnalysisResult(data);
          return;
        }
      } else {
        const classEl = document.getElementById("resultClassification");
        const summaryEl = document.getElementById("resultSummary");
        if (classEl) classEl.textContent = "NO SCANS YET";
        if (summaryEl) summaryEl.textContent = "No email analyses have been recorded yet. Submit an email to generate a forensic findings report.";
      }
    }
  } catch {}
}

function displayAnalysisResult(data) {
  if (!data) return;
  currentAnalysisId = data.analysisId;
  const section = document.getElementById("analystResultSection");
  if (section) section.style.display = "block";

  // Score Box
  const scoreBox = document.getElementById("resultScoreBox");
  const scoreCircle = document.getElementById("resultScoreCircle");
  const classEl = document.getElementById("resultClassification");
  const summaryEl = document.getElementById("resultSummary");

  if (scoreCircle) scoreCircle.textContent = data.riskScore;
  if (classEl) classEl.textContent = `${(data.riskClassification || "LOW").toUpperCase()} RISK`;
  if (summaryEl) summaryEl.textContent = data.analysisSummary || "Analysis completed.";

  if (scoreBox) scoreBox.className = `score-box score-${(data.riskClassification || "low").toLowerCase()}`;

  // Meta
  const subEl = document.getElementById("resSubject");
  if (subEl) subEl.textContent = data.subject || "(No Subject)";
  const fromEl = document.getElementById("resFrom");
  if (fromEl) fromEl.textContent = data.senderEmail || "(Unknown)";
  const toEl = document.getElementById("resTo");
  if (toEl) toEl.textContent = data.recipientEmail || "(Unknown)";
  const typeEl = document.getElementById("resType");
  if (typeEl) typeEl.textContent = data.submissionType || "Text";
  const userEl = document.getElementById("resUser");
  if (userEl) userEl.textContent = data.submittedBy || "System User";
  const dateEl = document.getElementById("resDate");
  if (dateEl) dateEl.textContent = data.analyzedAt ? new Date(data.analyzedAt).toLocaleString() : "-";
  const recEl = document.getElementById("resRecommendations");
  if (recEl) recEl.textContent = data.recommendation || "No mitigation steps necessary.";

  // Counts
  const cT = document.getElementById("countThreats");
  if (cT) cT.textContent = data.threatIndicators ? data.threatIndicators.length : 0;
  const cU = document.getElementById("countUrls");
  if (cU) cU.textContent = data.urls ? data.urls.length : 0;
  const cA = document.getElementById("countAttachments");
  if (cA) cA.textContent = data.attachments ? data.attachments.length : 0;

  // Threats Table
  const tbodyThreats = document.getElementById("tableThreatsBody");
  if (tbodyThreats) {
    if (!data.threatIndicators || data.threatIndicators.length === 0) {
      tbodyThreats.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--success);">No threat indicators detected.</td></tr>`;
    } else {
      tbodyThreats.innerHTML = data.threatIndicators.map(t => `
        <tr>
          <td><span class="badge badge-${(t.severity || "low").toLowerCase()}">${escapeHtml(t.severity)}</span></td>
          <td><strong>${escapeHtml(t.threatType)}</strong></td>
          <td>+${t.points} pts</td>
          <td>${escapeHtml(t.threatDescription)}</td>
        </tr>
      `).join("");
    }
  }

  // Auth Tab
  const auth = data.authentication || {};
  const spfEl = document.getElementById("resSpf");
  if (spfEl) spfEl.textContent = auth.spfResult || "None";
  const dkimEl = document.getElementById("resDkim");
  if (dkimEl) dkimEl.textContent = auth.dkimResult || "None";
  const dmarcEl = document.getElementById("resDmarc");
  if (dmarcEl) dmarcEl.textContent = auth.dmarcResult || "None";
  const authHeaderEl = document.getElementById("resAuthHeader");
  if (authHeaderEl) authHeaderEl.textContent = auth.authenticationHeader || "No Authentication-Results header provided.";

  setBadgeColor("resSpf", auth.spfResult);
  setBadgeColor("resDkim", auth.dkimResult);
  setBadgeColor("resDmarc", auth.dmarcResult);

  // URLs Table
  const tbodyUrls = document.getElementById("tableUrlsBody");
  if (tbodyUrls) {
    if (!data.urls || data.urls.length === 0) {
      tbodyUrls.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No links embedded in email.</td></tr>`;
    } else {
      tbodyUrls.innerHTML = data.urls.map(u => `
        <tr>
          <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            <a href="#" style="color: var(--accent);">${escapeHtml(u.originalUrl)}</a>
          </td>
          <td>${escapeHtml(u.domain || "-")}</td>
          <td><span class="badge ${u.reputationStatus === "Malicious" ? "badge-high" : (u.reputationStatus === "Suspicious" ? "badge-medium" : "badge-low")}">${escapeHtml(u.reputationStatus || "Clean")}</span></td>
          <td>${u.isSuspicious ? "⚠️ Yes" : "No"}</td>
          <td>${escapeHtml(u.detectionReason || "-")}</td>
        </tr>
      `).join("");
    }
  }

  // Attachments Table
  const tbodyAtt = document.getElementById("tableAttachmentsBody");
  if (tbodyAtt) {
    if (!data.attachments || data.attachments.length === 0) {
      tbodyAtt.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No attachments detected.</td></tr>`;
    } else {
      tbodyAtt.innerHTML = data.attachments.map(a => `
        <tr>
          <td><strong>${escapeHtml(a.fileName)}</strong></td>
          <td><code>${escapeHtml(a.fileExtension || "-")}</code></td>
          <td>${escapeHtml(a.mimeType || "-")}</td>
          <td>${a.fileSize ? (a.fileSize / 1024).toFixed(1) + " KB" : "-"}</td>
          <td>${a.isSuspicious ? "🚨 Suspicious" : "Clean"}</td>
          <td>${escapeHtml(a.detectionReason || "-")}</td>
        </tr>
      `).join("");
    }
  }
}

function setBadgeColor(elementId, value) {
  const el = document.getElementById(elementId);
  if (!value || !el) return;
  const v = value.toLowerCase();
  if (v === "pass") el.style.color = "var(--success)";
  else if (v === "fail") el.style.color = "var(--danger)";
  else if (v === "softfail" || v === "neutral") el.style.color = "var(--warning)";
  else el.style.color = "var(--text-muted)";
}

function switchResultTab(tab) {
  const tabs = ["threats", "auth", "urls", "attachments"];
  tabs.forEach(t => {
    const el = document.getElementById(`resTab${t.charAt(0).toUpperCase() + t.slice(1)}`);
    if (el) el.style.display = t === tab ? "block" : "none";
  });
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach(b => {
    b.classList.remove("active");
    if (b.getAttribute("onclick") && b.getAttribute("onclick").includes(`'${tab}'`)) {
      b.classList.add("active");
    }
  });
}

function exportCurrentReportCsv() {
  if (!currentAnalysisId) {
    showAlert("Please select an analysis first.", "warning");
    return;
  }
  const user = getCurrentUser();
  const uid = user ? user.userId : 1;
  window.open(`/api/reports/export-csv/${currentAnalysisId}?userId=${uid}`, "_blank");
}

function exportCurrentReportPdf() {
  if (!currentAnalysisId) {
    showAlert("Please select an analysis first.", "warning");
    return;
  }
  const user = getCurrentUser();
  const uid = user ? user.userId : 1;
  window.open(`/api/reports/export-pdf/${currentAnalysisId}?userId=${uid}`, "_blank");
}

function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

