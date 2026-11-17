namespace EmailShield.DTOs;

public class SubmitEmailTextRequest
{
    public int UserId { get; set; }
    public string RawContent { get; set; } = string.Empty;
}

public class AnalysisDetailResponse
{
    public int AnalysisId { get; set; }
    public int EmailId { get; set; }
    public string? Subject { get; set; }
    public string? SenderEmail { get; set; }
    public string? RecipientEmail { get; set; }
    public string? EmailBody { get; set; }
    public string? UploadedFileName { get; set; }
    public string SubmissionType { get; set; } = string.Empty;
    public DateTime SubmittedAt { get; set; }
    public string? SubmittedBy { get; set; }

    // Risk
    public int RiskScore { get; set; }
    public string RiskClassification { get; set; } = "Low";
    public string? AnalysisSummary { get; set; }
    public string? Recommendation { get; set; }
    public DateTime AnalyzedAt { get; set; }

    // Child records
    public AuthenticationResultDto? Authentication { get; set; }
    public List<HeaderDto> Headers { get; set; } = new();
    public List<ThreatIndicatorDto> ThreatIndicators { get; set; } = new();
    public List<UrlAnalysisDto> Urls { get; set; } = new();
    public List<AttachmentDto> Attachments { get; set; } = new();
}

public class HeaderDto
{
    public string HeaderName { get; set; } = string.Empty;
    public string? HeaderValue { get; set; }
}

public class AuthenticationResultDto
{
    public string? SpfResult { get; set; }
    public string? DkimResult { get; set; }
    public string? DmarcResult { get; set; }
    public string? VerificationMethod { get; set; }
    public string? AuthenticationHeader { get; set; }
}

public class ThreatIndicatorDto
{
    public string ThreatType { get; set; } = string.Empty;
    public string Severity { get; set; } = "Low";
    public string? ThreatDescription { get; set; }
    public int Points { get; set; }
}

public class UrlAnalysisDto
{
    public string OriginalUrl { get; set; } = string.Empty;
    public string? Domain { get; set; }
    public bool? IsValid { get; set; }
    public bool IsSuspicious { get; set; }
    public string? ReputationStatus { get; set; }
    public string? DetectionReason { get; set; }
}

public class AttachmentDto
{
    public string FileName { get; set; } = string.Empty;
    public string? FileExtension { get; set; }
    public string? MimeType { get; set; }
    public long? FileSize { get; set; }
    public bool IsSuspicious { get; set; }
    public string? DetectionReason { get; set; }
}

public class DashboardSummaryDto
{
    public int TotalAnalyzed { get; set; }
    public int HighRiskCount { get; set; }
    public int MediumRiskCount { get; set; }
    public int LowRiskCount { get; set; }
}

public class AnalysisHistoryItemDto
{
    public int AnalysisId { get; set; }
    public int EmailId { get; set; }
    public string? Subject { get; set; }
    public string? SenderEmail { get; set; }
    public string? SubmittedBy { get; set; }
    public int RiskScore { get; set; }
    public string RiskClassification { get; set; } = "Low";
    public DateTime? AnalyzedAt { get; set; }
}

