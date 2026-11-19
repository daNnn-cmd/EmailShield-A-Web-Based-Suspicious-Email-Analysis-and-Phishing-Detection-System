namespace EmailShield.DTOs;

public class DatabaseSyncResultDto
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string Direction { get; set; } = "Bidirectional";
    public int UsersSynced { get; set; }
    public int EmailSamplesSynced { get; set; }
    public int AuditLogsSynced { get; set; }
    public long DurationMs { get; set; }
    public DateTime SyncedAt { get; set; } = DateTime.UtcNow;
    public List<string> Logs { get; set; } = new();
    public DatabaseConnectionStatusDto? LocalStatus { get; set; }
    public DatabaseConnectionStatusDto? OnlineStatus { get; set; }
}

public class DatabaseConnectionStatusDto
{
    public string Name { get; set; } = string.Empty;
    public string Server { get; set; } = string.Empty;
    public string Database { get; set; } = string.Empty;
    public bool IsConnected { get; set; }
    public long LatencyMs { get; set; }
    public string? ErrorMessage { get; set; }
    public int UsersCount { get; set; }
    public int EmailSamplesCount { get; set; }
    public int AuditLogsCount { get; set; }
}

public class DatabaseSyncStatusSummaryDto
{
    public string ActiveTarget { get; set; } = "Online";
    public DatabaseConnectionStatusDto Local { get; set; } = new();
    public DatabaseConnectionStatusDto Online { get; set; } = new();
    public DateTime? LastSyncTime { get; set; }
    public string? LastSyncMessage { get; set; }
    public bool IsAutoSyncEnabled { get; set; } = true;
    public int SyncIntervalMinutes { get; set; } = 5;
}

public class SetActiveTargetRequest
{
    public string Target { get; set; } = "Online"; // "Online" or "Local"
}
