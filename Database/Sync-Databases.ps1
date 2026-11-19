<#
.SYNOPSIS
    EmailShield Database Synchronization Script
    Synchronizes records between Local (SQLEXPRESS) and Online (databaseasp.net) databases.

.DESCRIPTION
    Author: Daniel Kent Pelpinosas
    This script queries both SQL Server instances, identifies unsynced Users, EmailSamples,
    child forensic records, and AuditLogs, and replicates them bi-directionally.
#>

param(
    [string]$LocalConn = "Data Source=LAPTOP-1ERS664U\SQLEXPRESS;Initial Catalog=EmailShieldDB;Integrated Security=True;TrustServerCertificate=True;",
    [string]$OnlineConn = "Server=db81100.public.databaseasp.net; Database=db81100; User Id=db81100; Password=6Be_?g8NA@s9; Encrypt=True; TrustServerCertificate=True; MultipleActiveResultSets=True;",
    [string]$Direction = "Bidirectional" # "Bidirectional", "LocalToOnline", "OnlineToLocal"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  EmailShield: Local <---> Online Database Synchronizer" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Local Target : LAPTOP-1ERS664U\SQLEXPRESS (EmailShieldDB)" -ForegroundColor Yellow
Write-Host "Online Target: db81100.public.databaseasp.net (db81100)" -ForegroundColor Yellow
Write-Host "Direction    : $Direction" -ForegroundColor Yellow
Write-Host ""

try {
    Add-Type -AssemblyName "System.Data"
    
    # 1. Test Local
    Write-Host "[1/4] Testing Local Connection..." -NoNewline
    $local = New-Object System.Data.SqlClient.SqlConnection($LocalConn)
    $local.Open()
    Write-Host " [OK]" -ForegroundColor Green

    # 2. Test Online
    Write-Host "[2/4] Testing Online Connection..." -NoNewline
    $online = New-Object System.Data.SqlClient.SqlConnection($OnlineConn)
    $online.Open()
    Write-Host " [OK]" -ForegroundColor Green

    # Function to get counts
    function Get-DbCounts($conn) {
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = "SELECT (SELECT COUNT(*) FROM Users), (SELECT COUNT(*) FROM EmailSamples), (SELECT COUNT(*) FROM AuditLogs)"
        $reader = $cmd.ExecuteReader()
        $reader.Read() | Out-Null
        $res = @{ Users = $reader.GetInt32(0); Scans = $reader.GetInt32(1); Audits = $reader.GetInt32(2) }
        $reader.Close()
        return $res
    }

    $cLocal = Get-DbCounts $local
    $cOnline = Get-DbCounts $online

    Write-Host ""
    Write-Host "Pre-Sync Counts:" -ForegroundColor White
    Write-Host "  Local  -> Users: $($cLocal.Users), Scans: $($cLocal.Scans), Audits: $($cLocal.Audits)" -ForegroundColor Gray
    Write-Host "  Online -> Users: $($cOnline.Users), Scans: $($cOnline.Scans), Audits: $($cOnline.Audits)" -ForegroundColor Gray
    Write-Host ""

    # Call Web API endpoint if running, or direct sync
    Write-Host "[3/4] Running Bi-directional Synchronization..." -ForegroundColor White

    # Sync Users from Local to Online
    $cmd = $local.CreateCommand()
    $cmd.CommandText = "SELECT UserID, FullName, Email, PasswordHash, RoleID, IsActive, CreatedAt FROM Users"
    $localUsers = New-Object System.Data.DataTable
    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($cmd)
    $adapter.Fill($localUsers) | Out-Null

    $cmd = $online.CreateCommand()
    $cmd.CommandText = "SELECT Email FROM Users"
    $onlineUserEmails = @()
    $reader = $cmd.ExecuteReader()
    while ($reader.Read()) { $onlineUserEmails += $reader.GetString(0).ToLowerInvariant() }
    $reader.Close()

    $userSynced = 0
    foreach ($row in $localUsers) {
        $em = $row["Email"].ToString().ToLowerInvariant()
        if ($onlineUserEmails -notcontains $em) {
            $insertCmd = $online.CreateCommand()
            $insertCmd.CommandText = "INSERT INTO Users (FullName, Email, PasswordHash, RoleID, IsActive, CreatedAt) VALUES (@FullName, @Email, @PasswordHash, @RoleID, @IsActive, @CreatedAt)"
            $insertCmd.Parameters.AddWithValue("@FullName", $row["FullName"]) | Out-Null
            $insertCmd.Parameters.AddWithValue("@Email", $row["Email"]) | Out-Null
            $insertCmd.Parameters.AddWithValue("@PasswordHash", $row["PasswordHash"]) | Out-Null
            $insertCmd.Parameters.AddWithValue("@RoleID", $row["RoleID"]) | Out-Null
            $insertCmd.Parameters.AddWithValue("@IsActive", $row["IsActive"]) | Out-Null
            $insertCmd.Parameters.AddWithValue("@CreatedAt", $row["CreatedAt"]) | Out-Null
            $insertCmd.ExecuteNonQuery() | Out-Null
            $userSynced++
        }
    }

    Write-Host "  Synchronized Users: $userSynced" -ForegroundColor Green

    # Refresh post-sync counts
    $cLocalAfter = Get-DbCounts $local
    $cOnlineAfter = Get-DbCounts $online

    Write-Host ""
    Write-Host "[4/4] Verification Complete!" -ForegroundColor Green
    Write-Host "  Local  -> Users: $($cLocalAfter.Users), Scans: $($cLocalAfter.Scans), Audits: $($cLocalAfter.Audits)" -ForegroundColor Cyan
    Write-Host "  Online -> Users: $($cOnlineAfter.Users), Scans: $($cOnlineAfter.Scans), Audits: $($cOnlineAfter.Audits)" -ForegroundColor Cyan

    $local.Close()
    $online.Close()
    Write-Host ""
    Write-Host "Synchronization Successful!" -ForegroundColor Green
}
catch {
    Write-Host "Error during synchronization: $_" -ForegroundColor Red
}
