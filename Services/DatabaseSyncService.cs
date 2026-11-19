using System.Data;
using System.Diagnostics;
using EmailShield.DTOs;
using Microsoft.Data.SqlClient;

namespace EmailShield.Services;

public class DatabaseSyncService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<DatabaseSyncService> _logger;

    private static DateTime? _lastSyncTime;
    private static string? _lastSyncMessage;
    private static readonly object _syncLock = new();

    public DatabaseSyncService(IConfiguration configuration, ILogger<DatabaseSyncService> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public string GetLocalConnectionString()
    {
        return _configuration.GetConnectionString("LocalConnection") 
            ?? "Data Source=LAPTOP-1ERS664U\\SQLEXPRESS;Initial Catalog=EmailShieldDB;Integrated Security=True;Trust Server Certificate=True;";
    }

    public string GetOnlineConnectionString()
    {
        return _configuration.GetConnectionString("OnlineConnection") 
            ?? _configuration.GetConnectionString("DefaultConnection") 
            ?? "Server=db81100.public.databaseasp.net; Database=db81100; User Id=db81100; Password=6Be_?g8NA@s9; Encrypt=True; TrustServerCertificate=True; MultipleActiveResultSets=True;";
    }

    public string GetActiveTarget()
    {
        return _configuration["DatabaseSettings:ActiveTarget"] ?? "Online";
    }

    public async Task<DatabaseSyncStatusSummaryDto> GetStatusAsync()
    {
        var localStatus = await TestConnectionAsync("Local (SQLEXPRESS)", GetLocalConnectionString());
        var onlineStatus = await TestConnectionAsync("Online (databaseasp.net)", GetOnlineConnectionString());

        return new DatabaseSyncStatusSummaryDto
        {
            ActiveTarget = GetActiveTarget(),
            Local = localStatus,
            Online = onlineStatus,
            LastSyncTime = _lastSyncTime,
            LastSyncMessage = _lastSyncMessage,
            IsAutoSyncEnabled = _configuration.GetValue<bool>("DatabaseSettings:EnableAutoSync", true),
            SyncIntervalMinutes = _configuration.GetValue<int>("DatabaseSettings:SyncIntervalMinutes", 5)
        };
    }

    private async Task<DatabaseConnectionStatusDto> TestConnectionAsync(string displayName, string connStr)
    {
        var status = new DatabaseConnectionStatusDto
        {
            Name = displayName
        };

        var builder = new SqlConnectionStringBuilder(connStr);
        status.Server = builder.DataSource;
        status.Database = builder.InitialCatalog;

        var sw = Stopwatch.StartNew();
        try
        {
            builder.ConnectTimeout = 8;
            using var conn = new SqlConnection(builder.ConnectionString);
            await conn.OpenAsync();
            sw.Stop();

            status.IsConnected = true;
            status.LatencyMs = sw.ElapsedMilliseconds;

            const string countSql = @"
                SELECT 
                    (SELECT COUNT(*) FROM Users) AS UsersCount,
                    (SELECT COUNT(*) FROM EmailSamples) AS SamplesCount,
                    (SELECT COUNT(*) FROM AuditLogs) AS AuditsCount;";

            using var cmd = new SqlCommand(countSql, conn);
            using var reader = await cmd.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                status.UsersCount = reader.GetInt32(0);
                status.EmailSamplesCount = reader.GetInt32(1);
                status.AuditLogsCount = reader.GetInt32(2);
            }
        }
        catch (Exception ex)
        {
            sw.Stop();
            status.IsConnected = false;
            status.LatencyMs = sw.ElapsedMilliseconds;
            status.ErrorMessage = ex.Message;
        }

        return status;
    }

    public async Task<DatabaseSyncResultDto> SyncDatabasesAsync(string direction = "Bidirectional")
    {
        var result = new DatabaseSyncResultDto
        {
            Direction = direction,
            SyncedAt = DateTime.UtcNow
        };

        var sw = Stopwatch.StartNew();

        // Ensure single execution at a time
        if (!Monitor.TryEnter(_syncLock, TimeSpan.FromSeconds(5)))
        {
            result.Success = false;
            result.Message = "A database synchronization task is already in progress.";
            return result;
        }

        try
        {
            string localConnStr = GetLocalConnectionString();
            string onlineConnStr = GetOnlineConnectionString();

            result.LocalStatus = await TestConnectionAsync("Local (SQLEXPRESS)", localConnStr);
            result.OnlineStatus = await TestConnectionAsync("Online (databaseasp.net)", onlineConnStr);

            if (!result.LocalStatus.IsConnected || !result.OnlineStatus.IsConnected)
            {
                result.Success = false;
                result.Message = $"Synchronization aborted: {(result.LocalStatus.IsConnected ? "Online" : "Local")} database is unreachable.";
                return result;
            }

            result.Logs.Add($"[Info] Verified connectivity: Local ({result.LocalStatus.LatencyMs}ms) <---> Online ({result.OnlineStatus.LatencyMs}ms).");

            using var localConn = new SqlConnection(localConnStr);
            using var onlineConn = new SqlConnection(onlineConnStr);
            await localConn.OpenAsync();
            await onlineConn.OpenAsync();

            int usersSynced = 0;
            int samplesSynced = 0;
            int auditsSynced = 0;

            // 1. Synchronize Users
            usersSynced += await SyncUsersAsync(localConn, onlineConn, direction, result.Logs);

            // 2. Synchronize EmailSamples and related forensic records
            samplesSynced += await SyncEmailSamplesAsync(localConn, onlineConn, direction, result.Logs);

            // 3. Synchronize AuditLogs
            auditsSynced += await SyncAuditLogsAsync(localConn, onlineConn, direction, result.Logs);

            sw.Stop();
            result.Success = true;
            result.UsersSynced = usersSynced;
            result.EmailSamplesSynced = samplesSynced;
            result.AuditLogsSynced = auditsSynced;
            result.DurationMs = sw.ElapsedMilliseconds;
            result.Message = $"Synchronization completed in {sw.ElapsedMilliseconds}ms. Synced {usersSynced} users, {samplesSynced} email scans, and {auditsSynced} audit records.";

            _lastSyncTime = DateTime.UtcNow;
            _lastSyncMessage = result.Message;

            // Re-fetch updated counts
            result.LocalStatus = await TestConnectionAsync("Local (SQLEXPRESS)", localConnStr);
            result.OnlineStatus = await TestConnectionAsync("Online (databaseasp.net)", onlineConnStr);

            _logger.LogInformation("[DatabaseSync] {Message}", result.Message);
        }
        catch (Exception ex)
        {
            sw.Stop();
            result.Success = false;
            result.DurationMs = sw.ElapsedMilliseconds;
            result.Message = $"Sync failed with error: {ex.Message}";
            result.Logs.Add($"[Error] {ex.ToString()}");
            _logger.LogError(ex, "[DatabaseSync] Synchronization failed.");
        }
        finally
        {
            Monitor.Exit(_syncLock);
        }

        return result;
    }

    private async Task<int> SyncUsersAsync(SqlConnection local, SqlConnection online, string direction, List<string> logs)
    {
        int count = 0;

        var localUsers = await FetchTableRowsAsync(local, "SELECT UserID, FullName, Email, PasswordHash, RoleID, IsActive, CreatedAt FROM Users");
        var onlineUsers = await FetchTableRowsAsync(online, "SELECT UserID, FullName, Email, PasswordHash, RoleID, IsActive, CreatedAt FROM Users");

        var localEmails = localUsers.Select(r => r["Email"]?.ToString()?.ToLowerInvariant()).Where(e => !string.IsNullOrEmpty(e)).ToHashSet();
        var onlineEmails = onlineUsers.Select(r => r["Email"]?.ToString()?.ToLowerInvariant()).Where(e => !string.IsNullOrEmpty(e)).ToHashSet();

        // Local -> Online
        if (direction == "Bidirectional" || direction == "LocalToOnline")
        {
            foreach (var u in localUsers)
            {
                string email = u["Email"]?.ToString()?.ToLowerInvariant() ?? "";
                if (!onlineEmails.Contains(email))
                {
                    await InsertUserRecordAsync(online, u);
                    logs.Add($"[User Sync] Local -> Online: Replicated user '{u["Email"]}' ({u["FullName"]}).");
                    count++;
                }
            }
        }

        // Online -> Local
        if (direction == "Bidirectional" || direction == "OnlineToLocal")
        {
            foreach (var u in onlineUsers)
            {
                string email = u["Email"]?.ToString()?.ToLowerInvariant() ?? "";
                if (!localEmails.Contains(email))
                {
                    await InsertUserRecordAsync(local, u);
                    logs.Add($"[User Sync] Online -> Local: Replicated user '{u["Email"]}' ({u["FullName"]}).");
                    count++;
                }
            }
        }

        return count;
    }

    private async Task InsertUserRecordAsync(SqlConnection targetConn, Dictionary<string, object?> row)
    {
        int targetUserId = Convert.ToInt32(row["UserID"]);
        bool idExists = await CheckIdExistsAsync(targetConn, "Users", "UserID", targetUserId);

        string insertSql;
        if (!idExists)
        {
            insertSql = @"
                SET IDENTITY_INSERT Users ON;
                INSERT INTO Users (UserID, FullName, Email, PasswordHash, RoleID, IsActive, CreatedAt)
                VALUES (@UserID, @FullName, @Email, @PasswordHash, @RoleID, @IsActive, @CreatedAt);
                SET IDENTITY_INSERT Users OFF;";
        }
        else
        {
            insertSql = @"
                INSERT INTO Users (FullName, Email, PasswordHash, RoleID, IsActive, CreatedAt)
                VALUES (@FullName, @Email, @PasswordHash, @RoleID, @IsActive, @CreatedAt);";
        }

        using var cmd = new SqlCommand(insertSql, targetConn);
        if (!idExists) cmd.Parameters.AddWithValue("@UserID", targetUserId);
        cmd.Parameters.AddWithValue("@FullName", row["FullName"] ?? "");
        cmd.Parameters.AddWithValue("@Email", row["Email"] ?? "");
        cmd.Parameters.AddWithValue("@PasswordHash", row["PasswordHash"] ?? "");
        cmd.Parameters.AddWithValue("@RoleID", row["RoleID"] ?? 1);
        cmd.Parameters.AddWithValue("@IsActive", row["IsActive"] ?? true);
        cmd.Parameters.AddWithValue("@CreatedAt", row["CreatedAt"] ?? DateTime.UtcNow);

        await cmd.ExecuteNonQueryAsync();
    }

    private async Task<int> SyncEmailSamplesAsync(SqlConnection local, SqlConnection online, string direction, List<string> logs)
    {
        int count = 0;

        var localSamples = await FetchTableRowsAsync(local, "SELECT EmailID, UserID, SubmissionType, UploadedFileName, SenderEmail, RecipientEmail, Subject, RawEmailContent, SubmittedAt FROM EmailSamples ORDER BY EmailID");
        var onlineSamples = await FetchTableRowsAsync(online, "SELECT EmailID, UserID, SubmissionType, UploadedFileName, SenderEmail, RecipientEmail, Subject, RawEmailContent, SubmittedAt FROM EmailSamples ORDER BY EmailID");

        string MakeKey(Dictionary<string, object?> r)
        {
            string sender = (r["SenderEmail"]?.ToString() ?? "").Trim().ToLowerInvariant();
            string subj = (r["Subject"]?.ToString() ?? "").Trim();
            string subTime = Convert.ToDateTime(r["SubmittedAt"]).ToString("yyyy-MM-dd HH:mm:ss");
            return $"{sender}|{subj}|{subTime}";
        }

        var localKeys = localSamples.ToDictionary(MakeKey, r => r);
        var onlineKeys = onlineSamples.ToDictionary(MakeKey, r => r);

        // Local -> Online
        if (direction == "Bidirectional" || direction == "LocalToOnline")
        {
            foreach (var kvp in localKeys)
            {
                if (!onlineKeys.ContainsKey(kvp.Key))
                {
                    await ReplicateEmailAndChildrenAsync(sourceConn: local, targetConn: online, sourceSample: kvp.Value);
                    logs.Add($"[Scan Sync] Local -> Online: Replicated scan EmailID={kvp.Value["EmailID"]} ('{kvp.Value["Subject"]}').");
                    count++;
                }
            }
        }

        // Online -> Local
        if (direction == "Bidirectional" || direction == "OnlineToLocal")
        {
            foreach (var kvp in onlineKeys)
            {
                if (!localKeys.ContainsKey(kvp.Key))
                {
                    await ReplicateEmailAndChildrenAsync(sourceConn: online, targetConn: local, sourceSample: kvp.Value);
                    logs.Add($"[Scan Sync] Online -> Local: Replicated scan EmailID={kvp.Value["EmailID"]} ('{kvp.Value["Subject"]}').");
                    count++;
                }
            }
        }

        return count;
    }

    private async Task ReplicateEmailAndChildrenAsync(SqlConnection sourceConn, SqlConnection targetConn, Dictionary<string, object?> sourceSample)
    {
        int sourceEmailId = Convert.ToInt32(sourceSample["EmailID"]);
        int sourceUserId = Convert.ToInt32(sourceSample["UserID"]);

        // Resolve or fallback UserID in target
        bool targetUserExists = await CheckIdExistsAsync(targetConn, "Users", "UserID", sourceUserId);
        int finalUserId = targetUserExists ? sourceUserId : 1;

        bool idFree = !await CheckIdExistsAsync(targetConn, "EmailSamples", "EmailID", sourceEmailId);
        int finalEmailId = sourceEmailId;

        if (idFree)
        {
            string insertEmailSql = @"
                SET IDENTITY_INSERT EmailSamples ON;
                INSERT INTO EmailSamples (EmailID, UserID, SubmissionType, UploadedFileName, SenderEmail, RecipientEmail, Subject, RawEmailContent, SubmittedAt)
                VALUES (@EmailID, @UserID, @SubmissionType, @UploadedFileName, @SenderEmail, @RecipientEmail, @Subject, @RawEmailContent, @SubmittedAt);
                SET IDENTITY_INSERT EmailSamples OFF;";

            using var cmd = new SqlCommand(insertEmailSql, targetConn);
            cmd.Parameters.AddWithValue("@EmailID", sourceEmailId);
            cmd.Parameters.AddWithValue("@UserID", finalUserId);
            cmd.Parameters.AddWithValue("@SubmissionType", sourceSample["SubmissionType"] ?? "Text");
            cmd.Parameters.AddWithValue("@UploadedFileName", (object?)sourceSample["UploadedFileName"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@SenderEmail", (object?)sourceSample["SenderEmail"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@RecipientEmail", (object?)sourceSample["RecipientEmail"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@Subject", (object?)sourceSample["Subject"] ?? "(No Subject)");
            cmd.Parameters.AddWithValue("@RawEmailContent", (object?)sourceSample["RawEmailContent"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@SubmittedAt", sourceSample["SubmittedAt"] ?? DateTime.UtcNow);

            await cmd.ExecuteNonQueryAsync();
        }
        else
        {
            string insertEmailSql = @"
                INSERT INTO EmailSamples (UserID, SubmissionType, UploadedFileName, SenderEmail, RecipientEmail, Subject, RawEmailContent, SubmittedAt)
                OUTPUT INSERTED.EmailID
                VALUES (@UserID, @SubmissionType, @UploadedFileName, @SenderEmail, @RecipientEmail, @Subject, @RawEmailContent, @SubmittedAt);";

            using var cmd = new SqlCommand(insertEmailSql, targetConn);
            cmd.Parameters.AddWithValue("@UserID", finalUserId);
            cmd.Parameters.AddWithValue("@SubmissionType", sourceSample["SubmissionType"] ?? "Text");
            cmd.Parameters.AddWithValue("@UploadedFileName", (object?)sourceSample["UploadedFileName"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@SenderEmail", (object?)sourceSample["SenderEmail"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@RecipientEmail", (object?)sourceSample["RecipientEmail"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@Subject", (object?)sourceSample["Subject"] ?? "(No Subject)");
            cmd.Parameters.AddWithValue("@RawEmailContent", (object?)sourceSample["RawEmailContent"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@SubmittedAt", sourceSample["SubmittedAt"] ?? DateTime.UtcNow);

            finalEmailId = Convert.ToInt32(await cmd.ExecuteScalarAsync());
        }

        // Child Records:
        // 1. EmailHeaders
        var headers = await FetchTableRowsAsync(sourceConn, $"SELECT HeaderName, HeaderValue FROM EmailHeaders WHERE EmailID = {sourceEmailId}");
        foreach (var h in headers)
        {
            using var cmd = new SqlCommand("INSERT INTO EmailHeaders (EmailID, HeaderName, HeaderValue) VALUES (@EmailID, @HeaderName, @HeaderValue)", targetConn);
            cmd.Parameters.AddWithValue("@EmailID", finalEmailId);
            cmd.Parameters.AddWithValue("@HeaderName", h["HeaderName"] ?? "");
            cmd.Parameters.AddWithValue("@HeaderValue", (object?)h["HeaderValue"] ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync();
        }

        // 2. AuthenticationResults
        var auths = await FetchTableRowsAsync(sourceConn, $"SELECT SPFResult, DKIMResult, DMARCResult, AuthenticationHeader, VerificationMethod, CheckedAt FROM AuthenticationResults WHERE EmailID = {sourceEmailId}");
        foreach (var a in auths)
        {
            using var cmd = new SqlCommand(@"INSERT INTO AuthenticationResults (EmailID, SPFResult, DKIMResult, DMARCResult, AuthenticationHeader, VerificationMethod, CheckedAt)
                VALUES (@EmailID, @SPFResult, @DKIMResult, @DMARCResult, @AuthenticationHeader, @VerificationMethod, @CheckedAt)", targetConn);
            cmd.Parameters.AddWithValue("@EmailID", finalEmailId);
            cmd.Parameters.AddWithValue("@SPFResult", (object?)a["SPFResult"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@DKIMResult", (object?)a["DKIMResult"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@DMARCResult", (object?)a["DMARCResult"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@AuthenticationHeader", (object?)a["AuthenticationHeader"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@VerificationMethod", (object?)a["VerificationMethod"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@CheckedAt", a["CheckedAt"] ?? DateTime.UtcNow);
            await cmd.ExecuteNonQueryAsync();
        }

        // 3. UrlAnalyses
        var urls = await FetchTableRowsAsync(sourceConn, $"SELECT OriginalURL, Domain, ReputationStatus, IsSuspicious, AnalyzedAt FROM UrlAnalyses WHERE EmailID = {sourceEmailId}");
        foreach (var u in urls)
        {
            using var cmd = new SqlCommand(@"INSERT INTO UrlAnalyses (EmailID, OriginalURL, Domain, ReputationStatus, IsSuspicious, AnalyzedAt)
                VALUES (@EmailID, @OriginalURL, @Domain, @ReputationStatus, @IsSuspicious, @AnalyzedAt)", targetConn);
            cmd.Parameters.AddWithValue("@EmailID", finalEmailId);
            cmd.Parameters.AddWithValue("@OriginalURL", u["OriginalURL"] ?? "");
            cmd.Parameters.AddWithValue("@Domain", (object?)u["Domain"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@ReputationStatus", (object?)u["ReputationStatus"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@IsSuspicious", u["IsSuspicious"] ?? false);
            cmd.Parameters.AddWithValue("@AnalyzedAt", u["AnalyzedAt"] ?? DateTime.UtcNow);
            await cmd.ExecuteNonQueryAsync();
        }

        // 4. AttachmentMetadata
        var atts = await FetchTableRowsAsync(sourceConn, $"SELECT FileName, FileExtension, MimeType, FileSize, IsSuspicious, InspectedAt FROM AttachmentMetadata WHERE EmailID = {sourceEmailId}");
        foreach (var at in atts)
        {
            using var cmd = new SqlCommand(@"INSERT INTO AttachmentMetadata (EmailID, FileName, FileExtension, MimeType, FileSize, IsSuspicious, InspectedAt)
                VALUES (@EmailID, @FileName, @FileExtension, @MimeType, @FileSize, @IsSuspicious, @InspectedAt)", targetConn);
            cmd.Parameters.AddWithValue("@EmailID", finalEmailId);
            cmd.Parameters.AddWithValue("@FileName", at["FileName"] ?? "");
            cmd.Parameters.AddWithValue("@FileExtension", (object?)at["FileExtension"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@MimeType", (object?)at["MimeType"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@FileSize", (object?)at["FileSize"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@IsSuspicious", at["IsSuspicious"] ?? false);
            cmd.Parameters.AddWithValue("@InspectedAt", at["InspectedAt"] ?? DateTime.UtcNow);
            await cmd.ExecuteNonQueryAsync();
        }

        // 5. ThreatIndicators
        var threats = await FetchTableRowsAsync(sourceConn, $"SELECT ThreatType, Severity, Points, ThreatDescription, DetectedAt FROM ThreatIndicators WHERE EmailID = {sourceEmailId}");
        foreach (var t in threats)
        {
            using var cmd = new SqlCommand(@"INSERT INTO ThreatIndicators (EmailID, ThreatType, Severity, Points, ThreatDescription, DetectedAt)
                VALUES (@EmailID, @ThreatType, @Severity, @Points, @ThreatDescription, @DetectedAt)", targetConn);
            cmd.Parameters.AddWithValue("@EmailID", finalEmailId);
            cmd.Parameters.AddWithValue("@ThreatType", t["ThreatType"] ?? "");
            cmd.Parameters.AddWithValue("@Severity", t["Severity"] ?? "Low");
            cmd.Parameters.AddWithValue("@Points", t["Points"] ?? 0);
            cmd.Parameters.AddWithValue("@ThreatDescription", (object?)t["ThreatDescription"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@DetectedAt", t["DetectedAt"] ?? DateTime.UtcNow);
            await cmd.ExecuteNonQueryAsync();
        }

        // 6. AnalysisResults
        var analysis = await FetchTableRowsAsync(sourceConn, $"SELECT RiskScore, RiskClassification, SummaryExplanation, AnalyzedAt FROM AnalysisResults WHERE EmailID = {sourceEmailId}");
        if (analysis.Count > 0)
        {
            var an = analysis[0];
            using var cmd = new SqlCommand(@"INSERT INTO AnalysisResults (EmailID, RiskScore, RiskClassification, SummaryExplanation, AnalyzedAt)
                VALUES (@EmailID, @RiskScore, @RiskClassification, @SummaryExplanation, @AnalyzedAt)", targetConn);
            cmd.Parameters.AddWithValue("@EmailID", finalEmailId);
            cmd.Parameters.AddWithValue("@RiskScore", an["RiskScore"] ?? 0);
            cmd.Parameters.AddWithValue("@RiskClassification", an["RiskClassification"] ?? "Low");
            cmd.Parameters.AddWithValue("@SummaryExplanation", (object?)an["SummaryExplanation"] ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@AnalyzedAt", an["AnalyzedAt"] ?? DateTime.UtcNow);
            await cmd.ExecuteNonQueryAsync();
        }

        // 7. GeneratedReports
        var reports = await FetchTableRowsAsync(sourceConn, $"SELECT GeneratedBy, ReportType, FileName, GeneratedAt FROM GeneratedReports WHERE AnalysisID IN (SELECT AnalysisID FROM AnalysisResults WHERE EmailID = {sourceEmailId})");
        if (reports.Count > 0)
        {
            // Find target AnalysisID
            object? targetAnalysisIdObj = await new SqlCommand($"SELECT AnalysisID FROM AnalysisResults WHERE EmailID = {finalEmailId}", targetConn).ExecuteScalarAsync();
            if (targetAnalysisIdObj != null && targetAnalysisIdObj != DBNull.Value)
            {
                int targetAnalysisId = Convert.ToInt32(targetAnalysisIdObj);
                foreach (var rep in reports)
                {
                    using var cmd = new SqlCommand(@"INSERT INTO GeneratedReports (AnalysisID, GeneratedBy, ReportType, FileName, GeneratedAt)
                        VALUES (@AnalysisID, @GeneratedBy, @ReportType, @FileName, @GeneratedAt)", targetConn);
                    cmd.Parameters.AddWithValue("@AnalysisID", targetAnalysisId);
                    cmd.Parameters.AddWithValue("@GeneratedBy", finalUserId);
                    cmd.Parameters.AddWithValue("@ReportType", rep["ReportType"] ?? "PDF");
                    cmd.Parameters.AddWithValue("@FileName", rep["FileName"] ?? "");
                    cmd.Parameters.AddWithValue("@GeneratedAt", rep["GeneratedAt"] ?? DateTime.UtcNow);
                    await cmd.ExecuteNonQueryAsync();
                }
            }
        }
    }

    private async Task<int> SyncAuditLogsAsync(SqlConnection local, SqlConnection online, string direction, List<string> logs)
    {
        int count = 0;

        var localAudits = await FetchTableRowsAsync(local, "SELECT AuditID, UserID, Action, Description, IPAddress, CreatedAt FROM AuditLogs");
        var onlineAudits = await FetchTableRowsAsync(online, "SELECT AuditID, UserID, Action, Description, IPAddress, CreatedAt FROM AuditLogs");

        string MakeKey(Dictionary<string, object?> r)
        {
            string action = (r["Action"]?.ToString() ?? "").Trim();
            string desc = (r["Description"]?.ToString() ?? "").Trim();
            string time = Convert.ToDateTime(r["CreatedAt"]).ToString("yyyy-MM-dd HH:mm:ss");
            return $"{action}|{desc}|{time}";
        }

        var localKeys = localAudits.ToDictionary(MakeKey, r => r);
        var onlineKeys = onlineAudits.ToDictionary(MakeKey, r => r);

        // Local -> Online
        if (direction == "Bidirectional" || direction == "LocalToOnline")
        {
            foreach (var kvp in localKeys)
            {
                if (!onlineKeys.ContainsKey(kvp.Key))
                {
                    await InsertAuditRecordAsync(online, kvp.Value);
                    count++;
                }
            }
        }

        // Online -> Local
        if (direction == "Bidirectional" || direction == "OnlineToLocal")
        {
            foreach (var kvp in onlineKeys)
            {
                if (!localKeys.ContainsKey(kvp.Key))
                {
                    await InsertAuditRecordAsync(local, kvp.Value);
                    count++;
                }
            }
        }

        if (count > 0)
        {
            logs.Add($"[Audit Sync] Replicated {count} missing audit trail records.");
        }

        return count;
    }

    private async Task InsertAuditRecordAsync(SqlConnection targetConn, Dictionary<string, object?> row)
    {
        object? userIdVal = row["UserID"];
        int? finalUserId = null;
        if (userIdVal != null && userIdVal != DBNull.Value)
        {
            int candidate = Convert.ToInt32(userIdVal);
            if (await CheckIdExistsAsync(targetConn, "Users", "UserID", candidate))
            {
                finalUserId = candidate;
            }
        }

        const string insertSql = @"
            INSERT INTO AuditLogs (UserID, Action, Description, IPAddress, CreatedAt)
            VALUES (@UserID, @Action, @Description, @IPAddress, @CreatedAt);";

        using var cmd = new SqlCommand(insertSql, targetConn);
        cmd.Parameters.AddWithValue("@UserID", (object?)finalUserId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@Action", row["Action"] ?? "UNKNOWN");
        cmd.Parameters.AddWithValue("@Description", (object?)row["Description"] ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@IPAddress", (object?)row["IPAddress"] ?? "127.0.0.1");
        cmd.Parameters.AddWithValue("@CreatedAt", row["CreatedAt"] ?? DateTime.UtcNow);

        await cmd.ExecuteNonQueryAsync();
    }

    private static async Task<bool> CheckIdExistsAsync(SqlConnection conn, string tableName, string colName, int id)
    {
        using var cmd = new SqlCommand($"SELECT COUNT(*) FROM {tableName} WHERE {colName} = {id}", conn);
        int exists = Convert.ToInt32(await cmd.ExecuteScalarAsync());
        return exists > 0;
    }

    private static async Task<List<Dictionary<string, object?>>> FetchTableRowsAsync(SqlConnection conn, string sql)
    {
        var list = new List<Dictionary<string, object?>>();
        using var cmd = new SqlCommand(sql, conn);
        using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var dict = new Dictionary<string, object?>();
            for (int i = 0; i < reader.FieldCount; i++)
            {
                dict[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            }
            list.Add(dict);
        }
        return list;
    }
}
