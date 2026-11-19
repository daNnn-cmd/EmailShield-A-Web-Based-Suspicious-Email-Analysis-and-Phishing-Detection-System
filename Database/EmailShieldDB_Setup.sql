-- =========================================================================
-- EmailShield: Suspicious Email Analysis & Phishing Detection System
-- Database Schema & Seed Data Script for Microsoft SQL Server (SSMS)
-- Author & Lead Developer: Daniel Kent Pelpinosas
-- =========================================================================

IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'EmailShieldDB')
BEGIN
    CREATE DATABASE EmailShieldDB;
END
GO

USE EmailShieldDB;
GO

-- 1. User Roles Table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'UserRoles')
BEGIN
    CREATE TABLE UserRoles (
        RoleID INT IDENTITY(1,1) PRIMARY KEY,
        RoleName NVARCHAR(50) NOT NULL UNIQUE,
        Description NVARCHAR(255) NULL
    );
END
GO

-- 2. Users Table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'Users')
BEGIN
    CREATE TABLE Users (
        UserID INT IDENTITY(1,1) PRIMARY KEY,
        FullName NVARCHAR(150) NOT NULL,
        Email NVARCHAR(150) NOT NULL UNIQUE,
        PasswordHash NVARCHAR(500) NOT NULL,
        RoleID INT NOT NULL,
        IsActive BIT NOT NULL DEFAULT 1,
        CreatedAt DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
        CONSTRAINT FK_Users_UserRoles FOREIGN KEY (RoleID) REFERENCES UserRoles(RoleID)
    );
END
GO

-- 3. Email Samples Table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'EmailSamples')
BEGIN
    CREATE TABLE EmailSamples (
        EmailID INT IDENTITY(1,1) PRIMARY KEY,
        UserID INT NOT NULL,
        SubmissionType NVARCHAR(20) NOT NULL, -- 'Text' or 'EML'
        UploadedFileName NVARCHAR(255) NULL,
        SenderEmail NVARCHAR(320) NULL,
        RecipientEmail NVARCHAR(320) NULL,
        Subject NVARCHAR(500) NULL,
        RawEmailContent NVARCHAR(MAX) NULL,
        SubmittedAt DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
        CONSTRAINT FK_EmailSamples_Users FOREIGN KEY (UserID) REFERENCES Users(UserID)
    );
    CREATE NONCLUSTERED INDEX IX_EmailSamples_UserID ON EmailSamples(UserID);
    CREATE NONCLUSTERED INDEX IX_EmailSamples_SubmittedAt ON EmailSamples(SubmittedAt);
END
GO

-- 4. Email Headers Table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'EmailHeaders')
BEGIN
    CREATE TABLE EmailHeaders (
        HeaderID INT IDENTITY(1,1) PRIMARY KEY,
        EmailID INT NOT NULL,
        HeaderName NVARCHAR(255) NOT NULL,
        HeaderValue NVARCHAR(MAX) NULL,
        CONSTRAINT FK_EmailHeaders_EmailSamples FOREIGN KEY (EmailID) REFERENCES EmailSamples(EmailID) ON DELETE CASCADE
    );
END
GO

-- 5. Email Authentication Results Table (SPF, DKIM, DMARC)
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'AuthenticationResults')
BEGIN
    CREATE TABLE AuthenticationResults (
        AuthenticationID INT IDENTITY(1,1) PRIMARY KEY,
        EmailID INT NOT NULL,
        SPFResult NVARCHAR(50) NULL,
        DKIMResult NVARCHAR(50) NULL,
        DMARCResult NVARCHAR(50) NULL,
        AuthenticationHeader NVARCHAR(MAX) NULL,
        VerificationMethod NVARCHAR(100) NULL,
        CheckedAt DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
        CONSTRAINT FK_AuthenticationResults_EmailSamples FOREIGN KEY (EmailID) REFERENCES EmailSamples(EmailID) ON DELETE CASCADE
    );
END
GO

-- 6. URL Analyses Table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'UrlAnalyses')
BEGIN
    CREATE TABLE UrlAnalyses (
        UrlID INT IDENTITY(1,1) PRIMARY KEY,
        EmailID INT NOT NULL,
        OriginalURL NVARCHAR(2048) NOT NULL,
        Domain NVARCHAR(255) NULL,
        ReputationStatus NVARCHAR(50) NULL,
        IsSuspicious BIT NOT NULL DEFAULT 0,
        AnalyzedAt DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
        CONSTRAINT FK_UrlAnalyses_EmailSamples FOREIGN KEY (EmailID) REFERENCES EmailSamples(EmailID) ON DELETE CASCADE
    );
    CREATE NONCLUSTERED INDEX IX_UrlAnalyses_EmailID ON UrlAnalyses(EmailID);
END
GO

-- 7. Attachment Metadata Table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'AttachmentMetadata')
BEGIN
    CREATE TABLE AttachmentMetadata (
        AttachmentID INT IDENTITY(1,1) PRIMARY KEY,
        EmailID INT NOT NULL,
        FileName NVARCHAR(255) NOT NULL,
        FileExtension NVARCHAR(30) NULL,
        MimeType NVARCHAR(150) NULL,
        FileSize BIGINT NULL,
        IsSuspicious BIT NOT NULL DEFAULT 0,
        InspectedAt DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
        CONSTRAINT FK_AttachmentMetadata_EmailSamples FOREIGN KEY (EmailID) REFERENCES EmailSamples(EmailID) ON DELETE CASCADE
    );
END
GO

-- 8. Threat Indicators Table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'ThreatIndicators')
BEGIN
    CREATE TABLE ThreatIndicators (
        ThreatID INT IDENTITY(1,1) PRIMARY KEY,
        EmailID INT NOT NULL,
        ThreatType NVARCHAR(100) NOT NULL,
        Severity NVARCHAR(20) NOT NULL, -- 'Low', 'Medium', 'High'
        Points INT NOT NULL DEFAULT 0,
        ThreatDescription NVARCHAR(MAX) NULL,
        DetectedAt DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
        CONSTRAINT FK_ThreatIndicators_EmailSamples FOREIGN KEY (EmailID) REFERENCES EmailSamples(EmailID) ON DELETE CASCADE
    );
    CREATE NONCLUSTERED INDEX IX_ThreatIndicators_EmailID ON ThreatIndicators(EmailID);
END
GO

-- 9. Analysis Results Table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'AnalysisResults')
BEGIN
    CREATE TABLE AnalysisResults (
        AnalysisID INT IDENTITY(1,1) PRIMARY KEY,
        EmailID INT NOT NULL UNIQUE,
        RiskScore INT NOT NULL DEFAULT 0,
        RiskClassification NVARCHAR(20) NOT NULL, -- 'Low', 'Medium', 'High'
        SummaryExplanation NVARCHAR(MAX) NULL,
        AnalyzedAt DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
        CONSTRAINT FK_AnalysisResults_EmailSamples FOREIGN KEY (EmailID) REFERENCES EmailSamples(EmailID) ON DELETE CASCADE
    );
    CREATE NONCLUSTERED INDEX IX_AnalysisResults_RiskClassification ON AnalysisResults(RiskClassification);
END
GO

-- 10. Generated Reports Table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'GeneratedReports')
BEGIN
    CREATE TABLE GeneratedReports (
        ReportID INT IDENTITY(1,1) PRIMARY KEY,
        AnalysisID INT NOT NULL,
        GeneratedBy INT NOT NULL,
        ReportType NVARCHAR(10) NOT NULL, -- 'PDF' or 'CSV'
        FileName NVARCHAR(255) NOT NULL,
        GeneratedAt DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
        CONSTRAINT FK_GeneratedReports_AnalysisResults FOREIGN KEY (AnalysisID) REFERENCES AnalysisResults(AnalysisID),
        CONSTRAINT FK_GeneratedReports_Users FOREIGN KEY (GeneratedBy) REFERENCES Users(UserID)
    );
END
GO

-- 11. Security Audit Logs Table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'AuditLogs')
BEGIN
    CREATE TABLE AuditLogs (
        AuditID INT IDENTITY(1,1) PRIMARY KEY,
        UserID INT NULL,
        Action NVARCHAR(255) NOT NULL,
        Description NVARCHAR(MAX) NULL,
        IPAddress NVARCHAR(45) NULL,
        CreatedAt DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
        CONSTRAINT FK_AuditLogs_Users FOREIGN KEY (UserID) REFERENCES Users(UserID)
    );
    CREATE NONCLUSTERED INDEX IX_AuditLogs_CreatedAt ON AuditLogs(CreatedAt);
END
GO

-- =========================================================================
-- DATABASE VIEWS
-- =========================================================================

-- View: vw_AnalysisHistory
IF OBJECT_ID('vw_AnalysisHistory', 'V') IS NOT NULL
    DROP VIEW vw_AnalysisHistory;
GO

CREATE VIEW vw_AnalysisHistory AS
SELECT 
    ar.AnalysisID,
    es.EmailID,
    es.Subject,
    es.SenderEmail,
    es.SubmittedAt,
    es.SubmissionType,
    u.FullName AS SubmittedBy,
    ar.RiskScore,
    ar.RiskClassification,
    ar.AnalyzedAt
FROM AnalysisResults ar
INNER JOIN EmailSamples es ON ar.EmailID = es.EmailID
INNER JOIN Users u ON es.UserID = u.UserID;
GO

-- View: vw_DashboardSummary
IF OBJECT_ID('vw_DashboardSummary', 'V') IS NOT NULL
    DROP VIEW vw_DashboardSummary;
GO

CREATE VIEW vw_DashboardSummary AS
SELECT
    COUNT(*) AS TotalScans,
    SUM(CASE WHEN RiskClassification = 'High' THEN 1 ELSE 0 END) AS HighRiskCount,
    SUM(CASE WHEN RiskClassification = 'Medium' THEN 1 ELSE 0 END) AS MediumRiskCount,
    SUM(CASE WHEN RiskClassification = 'Low' THEN 1 ELSE 0 END) AS LowRiskCount,
    AVG(CAST(RiskScore AS FLOAT)) AS AverageRiskScore
FROM AnalysisResults;
GO

-- =========================================================================
-- SEED DATA
-- =========================================================================

-- Seed Roles
IF NOT EXISTS (SELECT * FROM UserRoles WHERE RoleName = 'Administrator')
    INSERT INTO UserRoles (RoleName, Description) VALUES ('Administrator', 'Full system management, settings, rules, and audit logs');

IF NOT EXISTS (SELECT * FROM UserRoles WHERE RoleName = 'Security Analyst')
    INSERT INTO UserRoles (RoleName, Description) VALUES ('Security Analyst', 'In-depth email submission, threat inspection, forensics, and report export');

IF NOT EXISTS (SELECT * FROM UserRoles WHERE RoleName = 'Viewer')
    INSERT INTO UserRoles (RoleName, Description) VALUES ('Viewer', 'Standard user submission, scanning, personal history, and security tips');
GO

