using System;
using System.Collections.Generic;

namespace EmailShield.Models;

public partial class AnalysisResult
{
    public int AnalysisId { get; set; }

    public int EmailId { get; set; }

    public int RiskScore { get; set; }

    public string RiskClassification { get; set; } = null!;

    public string? AnalysisSummary { get; set; }

    public string? Recommendation { get; set; }

    public DateTime AnalyzedAt { get; set; }

    public virtual EmailSample Email { get; set; } = null!;

    public virtual ICollection<GeneratedReport> GeneratedReports { get; set; } = new List<GeneratedReport>();
}
