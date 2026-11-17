using System;
using System.Collections.Generic;

namespace EmailShield.Models;

public partial class VwDashboardSummary
{
    public int? TotalAnalyzed { get; set; }

    public int? HighRiskCount { get; set; }

    public int? MediumRiskCount { get; set; }

    public int? LowRiskCount { get; set; }
}
