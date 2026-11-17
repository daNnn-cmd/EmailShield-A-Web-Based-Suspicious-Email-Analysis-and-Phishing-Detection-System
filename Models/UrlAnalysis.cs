using System;
using System.Collections.Generic;

namespace EmailShield.Models;

public partial class UrlAnalysis
{
    public int UrlId { get; set; }

    public int EmailId { get; set; }

    public string OriginalUrl { get; set; } = null!;

    public string? Domain { get; set; }

    public bool? IsValid { get; set; }

    public bool IsSuspicious { get; set; }

    public string? ReputationStatus { get; set; }

    public string? DetectionReason { get; set; }

    public DateTime AnalyzedAt { get; set; }

    public virtual EmailSample Email { get; set; } = null!;
}
