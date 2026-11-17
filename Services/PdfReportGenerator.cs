using System.Text;
using EmailShield.DTOs;

namespace EmailShield.Services;

public static class PdfReportGenerator
{
    public static byte[] GenerateAnalysisPdf(AnalysisDetailResponse analysis)
    {
        var objects = new List<string>();

        // Content stream
        var content = new StringBuilder();

        void DrawRect(float x, float y, float w, float h, float r, float g, float b, bool fill = true)
        {
            content.AppendLine($"{r:F2} {g:F2} {b:F2} {(fill ? "rg" : "RG")}");
            content.AppendLine($"{x:F1} {y:F1} {w:F1} {h:F1} re {(fill ? "f" : "s")}");
        }

        void DrawText(float x, float y, string text, string font = "/F1", float size = 10, float r = 0, float g = 0, float b = 0)
        {
            string sanitized = EscapePdf(text);
            content.AppendLine("BT");
            content.AppendLine($"{font} {size:F1} Tf");
            content.AppendLine($"{r:F2} {g:F2} {b:F2} rg");
            content.AppendLine($"{x:F1} {y:F1} Td");
            content.AppendLine($"({sanitized}) Tj");
            content.AppendLine("ET");
        }

        void DrawLine(float x1, float y1, float x2, float y2, float r = 0.8f, float g = 0.8f, float b = 0.8f)
        {
            content.AppendLine($"{r:F2} {g:F2} {b:F2} RG");
            content.AppendLine("1 w");
            content.AppendLine($"{x1:F1} {y1:F1} m {x2:F1} {y2:F1} l S");
        }

        float yPos = 750;

        // Header Background
        DrawRect(40, 720, 515, 60, 0.05f, 0.08f, 0.15f);
        DrawText(55, 755, "EmailShield Phishing & Email Threat Report", "/F2", 15, 0.97f, 0.98f, 1.0f);
        DrawText(55, 735, "Suspicious Email Analysis & Forensic Findings", "/F1", 9, 0.22f, 0.74f, 0.97f);
        DrawText(420, 745, $"ID: #{analysis.AnalysisId}", "/F2", 10, 0.9f, 0.9f, 0.9f);
        DrawText(420, 730, $"{analysis.AnalyzedAt:yyyy-MM-dd HH:mm} UTC", "/F1", 8, 0.7f, 0.7f, 0.7f);

        yPos = 700;

        // Risk Banner
        float boxR = 0.1f, boxG = 0.7f, boxB = 0.5f; // Low
        if (analysis.RiskClassification.Equals("High", StringComparison.OrdinalIgnoreCase))
        {
            boxR = 0.9f; boxG = 0.25f; boxB = 0.25f;
        }
        else if (analysis.RiskClassification.Equals("Medium", StringComparison.OrdinalIgnoreCase))
        {
            boxR = 0.95f; boxG = 0.6f; boxB = 0.05f;
        }

        DrawRect(40, yPos - 35, 515, 40, boxR, boxG, boxB);
        DrawText(55, yPos - 15, $"RISK LEVEL: {analysis.RiskClassification.ToUpper()}", "/F2", 13, 1f, 1f, 1f);
        DrawText(55, yPos - 28, $"Overall Threat Assessment Score: {analysis.RiskScore} / 100", "/F1", 9, 1f, 1f, 1f);
        DrawText(430, yPos - 22, $"{analysis.RiskScore}/100", "/F2", 16, 1f, 1f, 1f);

        yPos -= 55;

        // Email Details Section
        DrawText(40, yPos, "1. EMAIL SAMPLE METADATA", "/F2", 11, 0.1f, 0.2f, 0.35f);
        DrawLine(40, yPos - 4, 555, yPos - 4, 0.2f, 0.5f, 0.8f);
        yPos -= 18;

        DrawText(45, yPos, "Subject:", "/F2", 9, 0.3f, 0.3f, 0.3f);
        DrawText(110, yPos, Truncate(analysis.Subject, 75), "/F1", 9, 0.1f, 0.1f, 0.1f);
        yPos -= 14;

        DrawText(45, yPos, "From:", "/F2", 9, 0.3f, 0.3f, 0.3f);
        DrawText(110, yPos, Truncate(analysis.SenderEmail, 75), "/F1", 9, 0.1f, 0.1f, 0.1f);
        yPos -= 14;

        DrawText(45, yPos, "To:", "/F2", 9, 0.3f, 0.3f, 0.3f);
        DrawText(110, yPos, Truncate(analysis.RecipientEmail, 75), "/F1", 9, 0.1f, 0.1f, 0.1f);
        yPos -= 14;

        DrawText(45, yPos, "Submitted By:", "/F2", 9, 0.3f, 0.3f, 0.3f);
        DrawText(110, yPos, $"{analysis.SubmittedBy} ({analysis.SubmissionType})", "/F1", 9, 0.1f, 0.1f, 0.1f);
        yPos -= 22;

        // Authentication Verification Section
        DrawText(40, yPos, "2. EMAIL AUTHENTICATION VERIFICATION", "/F2", 11, 0.1f, 0.2f, 0.35f);
        DrawLine(40, yPos - 4, 555, yPos - 4, 0.2f, 0.5f, 0.8f);
        yPos -= 18;

        DrawText(45, yPos, $"SPF Result: {analysis.Authentication?.SpfResult ?? "None"}", "/F2", 9, 0.1f, 0.1f, 0.1f);
        DrawText(210, yPos, $"DKIM Result: {analysis.Authentication?.DkimResult ?? "None"}", "/F2", 9, 0.1f, 0.1f, 0.1f);
        DrawText(380, yPos, $"DMARC Result: {analysis.Authentication?.DmarcResult ?? "None"}", "/F2", 9, 0.1f, 0.1f, 0.1f);
        yPos -= 22;

        // Threat Indicators Section
        DrawText(40, yPos, $"3. IDENTIFIED THREAT INDICATORS ({analysis.ThreatIndicators.Count})", "/F2", 11, 0.1f, 0.2f, 0.35f);
        DrawLine(40, yPos - 4, 555, yPos - 4, 0.2f, 0.5f, 0.8f);
        yPos -= 16;

        if (analysis.ThreatIndicators.Count == 0)
        {
            DrawText(45, yPos, "No suspicious threat indicators flagged.", "/F1", 9, 0.4f, 0.4f, 0.4f);
            yPos -= 16;
        }
        else
        {
            foreach (var t in analysis.ThreatIndicators.Take(4))
            {
                DrawText(45, yPos, $"• [{t.Severity.ToUpper()}] {t.ThreatType} (+{t.Points} pts)", "/F2", 9, 0.8f, 0.2f, 0.2f);
                yPos -= 12;
                DrawText(55, yPos, Truncate(t.ThreatDescription, 95), "/F1", 8, 0.3f, 0.3f, 0.3f);
                yPos -= 14;
            }
        }

        yPos -= 6;

        // URLs and Attachments Summary
        DrawText(40, yPos, "4. EMBEDDED URLS & ATTACHMENTS ANALYSIS", "/F2", 11, 0.1f, 0.2f, 0.35f);
        DrawLine(40, yPos - 4, 555, yPos - 4, 0.2f, 0.5f, 0.8f);
        yPos -= 16;

        string urlSummary = analysis.Urls.Count == 0 
            ? "No hyperlinks detected in email content."
            : $"Extracted {analysis.Urls.Count} URL(s) - {analysis.Urls.Count(u => u.IsSuspicious)} flagged as suspicious/malicious.";
        DrawText(45, yPos, $"URLs: {urlSummary}", "/F1", 9, 0.2f, 0.2f, 0.2f);
        yPos -= 14;

        if (analysis.Urls.Any(u => u.IsSuspicious))
        {
            var firstBad = analysis.Urls.First(u => u.IsSuspicious);
            DrawText(55, yPos, $"Sample Flagged: {Truncate(firstBad.OriginalUrl, 60)} ({firstBad.ReputationStatus})", "/F1", 8, 0.8f, 0.2f, 0.2f);
            yPos -= 14;
        }

        string attSummary = analysis.Attachments.Count == 0
            ? "No file attachments included."
            : $"{analysis.Attachments.Count} attachment(s) inspected - {analysis.Attachments.Count(a => a.IsSuspicious)} flagged high risk.";
        DrawText(45, yPos, $"Attachments: {attSummary}", "/F1", 9, 0.2f, 0.2f, 0.2f);
        yPos -= 22;

        // Executive Summary & Recommendations
        DrawText(40, yPos, "5. FORENSIC CONCLUSION & MITIGATION ADVICE", "/F2", 11, 0.1f, 0.2f, 0.35f);
        DrawLine(40, yPos - 4, 555, yPos - 4, 0.2f, 0.5f, 0.8f);
        yPos -= 16;

        DrawText(45, yPos, "Summary:", "/F2", 9, 0.2f, 0.2f, 0.2f);
        DrawText(95, yPos, Truncate(analysis.AnalysisSummary, 85), "/F1", 8, 0.3f, 0.3f, 0.3f);
        yPos -= 16;

        DrawText(45, yPos, "Recommended Actions:", "/F2", 9, 0.2f, 0.2f, 0.2f);
        yPos -= 12;
        var recLines = (analysis.Recommendation ?? "").Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var r in recLines.Take(3))
        {
            DrawText(55, yPos, Truncate(r.Trim(), 90), "/F1", 8, 0.25f, 0.25f, 0.25f);
            yPos -= 12;
        }

        // Footer
        DrawLine(40, 50, 555, 50, 0.85f, 0.85f, 0.85f);
        DrawText(40, 38, "Generated by EmailShield • Suspicious Email Analysis and Phishing Detection System", "/F1", 8, 0.5f, 0.5f, 0.5f);
        DrawText(480, 38, "Page 1 of 1", "/F1", 8, 0.5f, 0.5f, 0.5f);

        // Build PDF document
        var pdf = new StringBuilder();
        pdf.AppendLine("%PDF-1.4");

        var streamBytes = Encoding.Latin1.GetBytes(content.ToString());

        // Obj 1: Catalog
        objects.Add("<< /Type /Catalog /Pages 2 0 R >>");
        // Obj 2: Pages
        objects.Add("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        // Obj 3: Page
        objects.Add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595.28 841.89] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>");
        // Obj 4: Content Stream
        objects.Add($"<< /Length {streamBytes.Length} >>\nstream\n{content}\nendstream");
        // Obj 5: Font F1 (Helvetica)
        objects.Add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");
        // Obj 6: Font F2 (Helvetica-Bold)
        objects.Add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>");

        var offsets = new List<long>();
        long currentOffset = 9; // "%PDF-1.4\n"

        for (int i = 0; i < objects.Count; i++)
        {
            offsets.Add(currentOffset);
            string objStr = $"{i + 1} 0 obj\n{objects[i]}\nendobj\n";
            pdf.Append(objStr);
            currentOffset += Encoding.Latin1.GetByteCount(objStr);
        }

        long xrefOffset = currentOffset;
        pdf.AppendLine("xref");
        pdf.AppendLine($"0 {objects.Count + 1}");
        pdf.AppendLine("0000000000 65535 f ");
        for (int i = 0; i < objects.Count; i++)
        {
            pdf.AppendLine($"{offsets[i]:D10} 00000 n ");
        }

        pdf.AppendLine("trailer");
        pdf.AppendLine($"<< /Size {objects.Count + 1} /Root 1 0 R >>");
        pdf.AppendLine("startxref");
        pdf.AppendLine(xrefOffset.ToString());
        pdf.AppendLine("%%EOF");

        return Encoding.Latin1.GetBytes(pdf.ToString());
    }

    private static string EscapePdf(string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        var sb = new StringBuilder();
        foreach (char c in text)
        {
            if (c == '(' || c == ')' || c == '\\') sb.Append('\\').Append(c);
            else if (c >= 32 && c <= 126) sb.Append(c);
            else sb.Append(' ');
        }
        return sb.ToString();
    }

    private static string Truncate(string? str, int maxLength)
    {
        if (string.IsNullOrEmpty(str)) return string.Empty;
        return str.Length <= maxLength ? str : str.Substring(0, maxLength - 3) + "...";
    }
}
