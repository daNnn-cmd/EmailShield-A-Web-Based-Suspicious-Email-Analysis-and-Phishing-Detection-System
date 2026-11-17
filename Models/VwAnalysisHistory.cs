using System;
using System.Collections.Generic;

namespace EmailShield.Models;

public partial class VwAnalysisHistory
{
    public int AnalysisId { get; set; }

    public int EmailId { get; set; }

    public string? Subject { get; set; }

    public string? SenderEmail { get; set; }

    public string SubmittedBy { get; set; } = null!;

    public int RiskScore { get; set; }

    public string RiskClassification { get; set; } = null!;

    public DateTime AnalyzedAt { get; set; }
}
