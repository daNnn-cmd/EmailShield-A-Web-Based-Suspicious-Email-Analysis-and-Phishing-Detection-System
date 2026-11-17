using System.Text;
using EmailShield.Data;
using EmailShield.DTOs;
using EmailShield.Models;
using EmailShield.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EmailShield.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ReportsController : ControllerBase
{
    private readonly EmailShieldDbContext _context;

    public ReportsController(EmailShieldDbContext context)
    {
        _context = context;
    }

    [HttpGet("export-pdf/{analysisId}")]
    public async Task<IActionResult> ExportPdf(int analysisId, [FromQuery] int userId = 1)
    {
        var analysis = await _context.AnalysisResults
            .Include(a => a.Email)
            .ThenInclude(e => e.User)
            .FirstOrDefaultAsync(a => a.AnalysisId == analysisId);

        if (analysis == null) return NotFound(new { message = "Analysis record not found." });

        int emailId = analysis.EmailId;

        var headers = await _context.EmailHeaders
            .Where(h => h.EmailId == emailId)
            .Select(h => new HeaderDto { HeaderName = h.HeaderName, HeaderValue = h.HeaderValue })
            .ToListAsync();

        var auth = await _context.AuthenticationResults
            .Where(a => a.EmailId == emailId)
            .Select(a => new AuthenticationResultDto
            {
                SpfResult = a.Spfresult,
                DkimResult = a.Dkimresult,
                DmarcResult = a.Dmarcresult,
                VerificationMethod = a.VerificationMethod,
                AuthenticationHeader = a.AuthenticationHeader
            })
            .FirstOrDefaultAsync();

        var threats = await _context.ThreatIndicators
            .Where(t => t.EmailId == emailId)
            .Select(t => new ThreatIndicatorDto
            {
                ThreatType = t.ThreatType,
                Severity = t.Severity,
                ThreatDescription = t.ThreatDescription,
                Points = t.Points
            })
            .ToListAsync();

        var urls = await _context.UrlAnalyses
            .Where(u => u.EmailId == emailId)
            .Select(u => new UrlAnalysisDto
            {
                OriginalUrl = u.OriginalUrl,
                Domain = u.Domain,
                IsValid = u.IsValid,
                IsSuspicious = u.IsSuspicious,
                ReputationStatus = u.ReputationStatus,
                DetectionReason = u.DetectionReason
            })
            .ToListAsync();

        var attachments = await _context.AttachmentMetadata
            .Where(a => a.EmailId == emailId)
            .Select(a => new AttachmentDto
            {
                FileName = a.FileName,
                FileExtension = a.FileExtension,
                MimeType = a.MimeType,
                FileSize = a.FileSize,
                IsSuspicious = a.IsSuspicious,
                DetectionReason = a.DetectionReason
            })
            .ToListAsync();

        var detail = new AnalysisDetailResponse
        {
            AnalysisId = analysis.AnalysisId,
            EmailId = analysis.EmailId,
            Subject = analysis.Email.Subject,
            SenderEmail = analysis.Email.SenderEmail,
            RecipientEmail = analysis.Email.RecipientEmail,
            EmailBody = analysis.Email.EmailBody,
            UploadedFileName = analysis.Email.UploadedFileName,
            SubmissionType = analysis.Email.SubmissionType,
            SubmittedAt = analysis.Email.SubmittedAt,
            SubmittedBy = analysis.Email.User?.FullName ?? "Unknown",
            RiskScore = analysis.RiskScore,
            RiskClassification = analysis.RiskClassification,
            AnalysisSummary = analysis.AnalysisSummary,
            Recommendation = analysis.Recommendation,
            AnalyzedAt = analysis.AnalyzedAt,
            Authentication = auth,
            Headers = headers,
            ThreatIndicators = threats,
            Urls = urls,
            Attachments = attachments
        };

        byte[] pdfBytes = PdfReportGenerator.GenerateAnalysisPdf(detail);
        string fileName = $"EmailShield_Report_Analysis_{analysis.AnalysisId}_{DateTime.UtcNow:yyyyMMddHHmmss}.pdf";

        // Save into GeneratedReports table
        _context.GeneratedReports.Add(new GeneratedReport
        {
            AnalysisId = analysis.AnalysisId,
            GeneratedBy = userId > 0 ? userId : 1,
            ReportType = "PDF",
            FileName = fileName,
            GeneratedAt = DateTime.UtcNow
        });

        _context.AuditLogs.Add(new AuditLog
        {
            UserId = userId > 0 ? userId : null,
            Action = "REPORT_EXPORTED",
            Description = $"Exported PDF Forensic Report for Analysis #{analysis.AnalysisId} ({analysis.Email.Subject}).",
            Ipaddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1",
            CreatedAt = DateTime.UtcNow
        });

        await _context.SaveChangesAsync();

        return File(pdfBytes, "application/pdf", fileName);
    }

    [HttpGet("export-csv/{analysisId}")]
    public async Task<IActionResult> ExportCsv(int analysisId, [FromQuery] int userId = 1)
    {
        var analysis = await _context.AnalysisResults
            .Include(a => a.Email)
            .FirstOrDefaultAsync(a => a.AnalysisId == analysisId);

        if (analysis == null) return NotFound(new { message = "Analysis record not found." });

        int emailId = analysis.EmailId;
        var threats = await _context.ThreatIndicators.Where(t => t.EmailId == emailId).ToListAsync();
        var urls = await _context.UrlAnalyses.Where(u => u.EmailId == emailId).ToListAsync();
        var attachments = await _context.AttachmentMetadata.Where(a => a.EmailId == emailId).ToListAsync();
        var auth = await _context.AuthenticationResults.FirstOrDefaultAsync(a => a.EmailId == emailId);

        var sb = new StringBuilder();
        sb.AppendLine("EmailShield Security Analysis Report");
        sb.AppendLine($"Analysis ID,{analysis.AnalysisId}");
        sb.AppendLine($"Email Subject,\"{EscapeCsv(analysis.Email.Subject)}\"");
        sb.AppendLine($"Sender,\"{EscapeCsv(analysis.Email.SenderEmail)}\"");
        sb.AppendLine($"Recipient,\"{EscapeCsv(analysis.Email.RecipientEmail)}\"");
        sb.AppendLine($"Risk Classification,{analysis.RiskClassification}");
        sb.AppendLine($"Risk Score,{analysis.RiskScore}/100");
        sb.AppendLine($"Analyzed Date,{analysis.AnalyzedAt:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine();

        sb.AppendLine("Authentication Verification");
        sb.AppendLine($"SPF Result,{auth?.Spfresult ?? "None"}");
        sb.AppendLine($"DKIM Result,{auth?.Dkimresult ?? "None"}");
        sb.AppendLine($"DMARC Result,{auth?.Dmarcresult ?? "None"}");
        sb.AppendLine();

        sb.AppendLine("Identified Threat Indicators");
        sb.AppendLine("Severity,Type,Points,Description");
        foreach (var t in threats)
        {
            sb.AppendLine($"{t.Severity},\"{EscapeCsv(t.ThreatType)}\",{t.Points},\"{EscapeCsv(t.ThreatDescription)}\"");
        }
        sb.AppendLine();

        sb.AppendLine("URL Analysis");
        sb.AppendLine("URL,Domain,Suspicious,Reputation,Reason");
        foreach (var u in urls)
        {
            sb.AppendLine($"\"{EscapeCsv(u.OriginalUrl)}\",\"{EscapeCsv(u.Domain)}\",{u.IsSuspicious},{u.ReputationStatus},\"{EscapeCsv(u.DetectionReason)}\"");
        }
        sb.AppendLine();

        sb.AppendLine("Attachment Metadata");
        sb.AppendLine("Filename,Extension,Size(bytes),Suspicious,Reason");
        foreach (var att in attachments)
        {
            sb.AppendLine($"\"{EscapeCsv(att.FileName)}\",\"{EscapeCsv(att.FileExtension)}\",{att.FileSize},{att.IsSuspicious},\"{EscapeCsv(att.DetectionReason)}\"");
        }
        sb.AppendLine();

        sb.AppendLine("Summary and Recommendations");
        sb.AppendLine($"Summary,\"{EscapeCsv(analysis.AnalysisSummary)}\"");
        sb.AppendLine($"Recommendations,\"{EscapeCsv(analysis.Recommendation)}\"");

        string fileName = $"EmailShield_Report_Analysis_{analysis.AnalysisId}_{DateTime.UtcNow:yyyyMMddHHmmss}.csv";

        // Save into GeneratedReports table
        _context.GeneratedReports.Add(new GeneratedReport
        {
            AnalysisId = analysis.AnalysisId,
            GeneratedBy = userId > 0 ? userId : 1,
            ReportType = "CSV",
            FileName = fileName,
            GeneratedAt = DateTime.UtcNow
        });
        await _context.SaveChangesAsync();

        byte[] bytes = Encoding.UTF8.GetBytes(sb.ToString());
        return File(bytes, "text/csv", fileName);
    }

    private static string EscapeCsv(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        return value.Replace("\"", "\"\"");
    }
}
