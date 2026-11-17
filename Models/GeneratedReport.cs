using System;
using System.Collections.Generic;

namespace EmailShield.Models;

public partial class GeneratedReport
{
    public int ReportId { get; set; }

    public int AnalysisId { get; set; }

    public int GeneratedBy { get; set; }

    public string ReportType { get; set; } = null!;

    public string? FileName { get; set; }

    public DateTime GeneratedAt { get; set; }

    public virtual AnalysisResult Analysis { get; set; } = null!;

    public virtual User GeneratedByNavigation { get; set; } = null!;
}
