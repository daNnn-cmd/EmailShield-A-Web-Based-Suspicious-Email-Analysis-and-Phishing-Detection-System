using System;
using System.Collections.Generic;

namespace EmailShield.Models;

public partial class ThreatIndicator
{
    public int ThreatId { get; set; }

    public int EmailId { get; set; }

    public string ThreatType { get; set; } = null!;

    public string? ThreatDescription { get; set; }

    public string Severity { get; set; } = null!;

    public int Points { get; set; }

    public DateTime DetectedAt { get; set; }

    public virtual EmailSample Email { get; set; } = null!;
}
