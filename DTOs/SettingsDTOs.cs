namespace EmailShield.DTOs;

public class SystemSettingsDto
{
    public RiskThresholdSettings RiskThresholds { get; set; } = new();
    public RuleToggleSettings RuleToggles { get; set; } = new();
    public RuleWeightingSettings RuleWeightings { get; set; } = new();
    public ThreatIntelSettings ThreatIntel { get; set; } = new();
}

public class RiskThresholdSettings
{
    public int HighRiskThreshold { get; set; } = 70;
    public int MediumRiskThreshold { get; set; } = 40;
}

public class RuleToggleSettings
{
    public bool EnableSpoofingDetection { get; set; } = true;
    public bool EnableUrlAnalysis { get; set; } = true;
    public bool EnableAttachmentInspection { get; set; } = true;
    public bool EnableAuthVerification { get; set; } = true;
    public bool EnableBecDetection { get; set; } = true;
}

public class RuleWeightingSettings
{
    public int SpfFailPoints { get; set; } = 25;
    public int DkimFailPoints { get; set; } = 20;
    public int DmarcFailPoints { get; set; } = 25;
    public int ReplyToMismatchPoints { get; set; } = 25;
    public int DisplayNameImpersonationPoints { get; set; } = 30;
    public int DangerousAttachmentPoints { get; set; } = 30;
    public int DoubleExtensionPoints { get; set; } = 35;
    public int MacroDocumentPoints { get; set; } = 20;
    public int BecWireFraudPoints { get; set; } = 30;
    public int UrgencyLanguagePoints { get; set; } = 15;
}

public class ThreatIntelSettings
{
    public bool EnableOpenPhish { get; set; } = true;
    public bool EnableVirusTotal { get; set; } = true;
    public bool EnableAbuseIpdb { get; set; } = true;
    public bool EnableUrlHaus { get; set; } = true;
    public bool EnableSpamhaus { get; set; } = true;
    public string MonitoredTlds { get; set; } = ".xyz, .top, .work, .click, .buzz, .country, .tk, .ml, .ga, .cf, .gq, .site, .online";
    public bool AutoQuarantineHighRisk { get; set; } = true;
    public bool AlertSecurityAnalystOnBec { get; set; } = true;
}

