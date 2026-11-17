using System;
using System.Collections.Generic;

namespace EmailShield.Models;

public partial class EmailSample
{
    public int EmailId { get; set; }

    public int UserId { get; set; }

    public string? Subject { get; set; }

    public string? SenderEmail { get; set; }

    public string? RecipientEmail { get; set; }

    public string? EmailBody { get; set; }

    public string? OriginalEmailContent { get; set; }

    public string? UploadedFileName { get; set; }

    public string SubmissionType { get; set; } = null!;

    public DateTime SubmittedAt { get; set; }

    public virtual AnalysisResult? AnalysisResult { get; set; }

    public virtual ICollection<AttachmentMetadatum> AttachmentMetadata { get; set; } = new List<AttachmentMetadatum>();

    public virtual ICollection<AuthenticationResult> AuthenticationResults { get; set; } = new List<AuthenticationResult>();

    public virtual ICollection<EmailHeader> EmailHeaders { get; set; } = new List<EmailHeader>();

    public virtual ICollection<ThreatIndicator> ThreatIndicators { get; set; } = new List<ThreatIndicator>();

    public virtual ICollection<UrlAnalysis> UrlAnalyses { get; set; } = new List<UrlAnalysis>();

    public virtual User User { get; set; } = null!;
}
