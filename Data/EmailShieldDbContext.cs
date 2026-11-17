using System;
using System.Collections.Generic;
using EmailShield.Models;
using Microsoft.EntityFrameworkCore;

namespace EmailShield.Data;

public partial class EmailShieldDbContext : DbContext
{
    public EmailShieldDbContext(DbContextOptions<EmailShieldDbContext> options)
        : base(options)
    {
    }

    public virtual DbSet<AnalysisResult> AnalysisResults { get; set; }

    public virtual DbSet<AttachmentMetadatum> AttachmentMetadata { get; set; }

    public virtual DbSet<AuditLog> AuditLogs { get; set; }

    public virtual DbSet<AuthenticationResult> AuthenticationResults { get; set; }

    public virtual DbSet<EmailHeader> EmailHeaders { get; set; }

    public virtual DbSet<EmailSample> EmailSamples { get; set; }

    public virtual DbSet<GeneratedReport> GeneratedReports { get; set; }

    public virtual DbSet<ThreatIndicator> ThreatIndicators { get; set; }

    public virtual DbSet<UrlAnalysis> UrlAnalyses { get; set; }

    public virtual DbSet<User> Users { get; set; }

    public virtual DbSet<UserRole> UserRoles { get; set; }

    public virtual DbSet<VwAnalysisHistory> VwAnalysisHistories { get; set; }

    public virtual DbSet<VwDashboardSummary> VwDashboardSummaries { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AnalysisResult>(entity =>
        {
            entity.HasKey(e => e.AnalysisId).HasName("PK__Analysis__5B789DE8D9331CA4");

            entity.HasIndex(e => e.RiskClassification, "IX_AnalysisResults_RiskClassification");

            entity.HasIndex(e => e.EmailId, "UQ__Analysis__7ED91AEECBEE63DE").IsUnique();

            entity.Property(e => e.AnalysisId).HasColumnName("AnalysisID");
            entity.Property(e => e.AnalyzedAt).HasDefaultValueSql("(sysdatetime())");
            entity.Property(e => e.EmailId).HasColumnName("EmailID");
            entity.Property(e => e.RiskClassification).HasMaxLength(20);

            entity.HasOne(d => d.Email).WithOne(p => p.AnalysisResult)
                .HasForeignKey<AnalysisResult>(d => d.EmailId)
                .HasConstraintName("FK_AnalysisResults_EmailSamples");
        });

        modelBuilder.Entity<AttachmentMetadatum>(entity =>
        {
            entity.HasKey(e => e.AttachmentId).HasName("PK__Attachme__442C64DEDF62DABA");

            entity.Property(e => e.AttachmentId).HasColumnName("AttachmentID");
            entity.Property(e => e.EmailId).HasColumnName("EmailID");
            entity.Property(e => e.FileExtension).HasMaxLength(30);
            entity.Property(e => e.FileName).HasMaxLength(255);
            entity.Property(e => e.InspectedAt).HasDefaultValueSql("(sysdatetime())");
            entity.Property(e => e.MimeType).HasMaxLength(150);

            entity.HasOne(d => d.Email).WithMany(p => p.AttachmentMetadata)
                .HasForeignKey(d => d.EmailId)
                .HasConstraintName("FK_AttachmentMetadata_EmailSamples");
        });

        modelBuilder.Entity<AuditLog>(entity =>
        {
            entity.HasKey(e => e.AuditId).HasName("PK__AuditLog__A17F23B8EB329D52");

            entity.HasIndex(e => e.CreatedAt, "IX_AuditLogs_CreatedAt");

            entity.Property(e => e.AuditId).HasColumnName("AuditID");
            entity.Property(e => e.Action).HasMaxLength(255);
            entity.Property(e => e.CreatedAt).HasDefaultValueSql("(sysdatetime())");
            entity.Property(e => e.Ipaddress)
                .HasMaxLength(45)
                .HasColumnName("IPAddress");
            entity.Property(e => e.UserId).HasColumnName("UserID");

            entity.HasOne(d => d.User).WithMany(p => p.AuditLogs)
                .HasForeignKey(d => d.UserId)
                .HasConstraintName("FK_AuditLogs_Users");
        });

        modelBuilder.Entity<AuthenticationResult>(entity =>
        {
            entity.HasKey(e => e.AuthenticationId).HasName("PK__Authenti__81919C5B80586445");

            entity.Property(e => e.AuthenticationId).HasColumnName("AuthenticationID");
            entity.Property(e => e.CheckedAt).HasDefaultValueSql("(sysdatetime())");
            entity.Property(e => e.Dkimresult)
                .HasMaxLength(50)
                .HasColumnName("DKIMResult");
            entity.Property(e => e.Dmarcresult)
                .HasMaxLength(50)
                .HasColumnName("DMARCResult");
            entity.Property(e => e.EmailId).HasColumnName("EmailID");
            entity.Property(e => e.Spfresult)
                .HasMaxLength(50)
                .HasColumnName("SPFResult");
            entity.Property(e => e.VerificationMethod).HasMaxLength(100);

            entity.HasOne(d => d.Email).WithMany(p => p.AuthenticationResults)
                .HasForeignKey(d => d.EmailId)
                .HasConstraintName("FK_AuthenticationResults_EmailSamples");
        });

        modelBuilder.Entity<EmailHeader>(entity =>
        {
            entity.HasKey(e => e.HeaderId).HasName("PK__EmailHea__DC3E69C37518D359");

            entity.Property(e => e.HeaderId).HasColumnName("HeaderID");
            entity.Property(e => e.EmailId).HasColumnName("EmailID");
            entity.Property(e => e.HeaderName).HasMaxLength(255);

            entity.HasOne(d => d.Email).WithMany(p => p.EmailHeaders)
                .HasForeignKey(d => d.EmailId)
                .HasConstraintName("FK_EmailHeaders_EmailSamples");
        });

        modelBuilder.Entity<EmailSample>(entity =>
        {
            entity.HasKey(e => e.EmailId).HasName("PK__EmailSam__7ED91AEF0ACEEC2B");

            entity.HasIndex(e => e.SubmittedAt, "IX_EmailSamples_SubmittedAt");

            entity.HasIndex(e => e.UserId, "IX_EmailSamples_UserID");

            entity.Property(e => e.EmailId).HasColumnName("EmailID");
            entity.Property(e => e.RecipientEmail).HasMaxLength(320);
            entity.Property(e => e.SenderEmail).HasMaxLength(320);
            entity.Property(e => e.Subject).HasMaxLength(500);
            entity.Property(e => e.SubmissionType).HasMaxLength(20);
            entity.Property(e => e.SubmittedAt).HasDefaultValueSql("(sysdatetime())");
            entity.Property(e => e.UploadedFileName).HasMaxLength(255);
            entity.Property(e => e.UserId).HasColumnName("UserID");

            entity.HasOne(d => d.User).WithMany(p => p.EmailSamples)
                .HasForeignKey(d => d.UserId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_EmailSamples_Users");
        });

        modelBuilder.Entity<GeneratedReport>(entity =>
        {
            entity.HasKey(e => e.ReportId).HasName("PK__Generate__D5BD48E502D8A200");

            entity.Property(e => e.ReportId).HasColumnName("ReportID");
            entity.Property(e => e.AnalysisId).HasColumnName("AnalysisID");
            entity.Property(e => e.FileName).HasMaxLength(255);
            entity.Property(e => e.GeneratedAt).HasDefaultValueSql("(sysdatetime())");
            entity.Property(e => e.ReportType).HasMaxLength(10);

            entity.HasOne(d => d.Analysis).WithMany(p => p.GeneratedReports)
                .HasForeignKey(d => d.AnalysisId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_GeneratedReports_AnalysisResults");

            entity.HasOne(d => d.GeneratedByNavigation).WithMany(p => p.GeneratedReports)
                .HasForeignKey(d => d.GeneratedBy)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_GeneratedReports_Users");
        });

        modelBuilder.Entity<ThreatIndicator>(entity =>
        {
            entity.HasKey(e => e.ThreatId).HasName("PK__ThreatIn__7C58E6012A901BA9");

            entity.HasIndex(e => e.EmailId, "IX_ThreatIndicators_EmailID");

            entity.Property(e => e.ThreatId).HasColumnName("ThreatID");
            entity.Property(e => e.DetectedAt).HasDefaultValueSql("(sysdatetime())");
            entity.Property(e => e.EmailId).HasColumnName("EmailID");
            entity.Property(e => e.Severity).HasMaxLength(20);
            entity.Property(e => e.ThreatType).HasMaxLength(100);

            entity.HasOne(d => d.Email).WithMany(p => p.ThreatIndicators)
                .HasForeignKey(d => d.EmailId)
                .HasConstraintName("FK_ThreatIndicators_EmailSamples");
        });

        modelBuilder.Entity<UrlAnalysis>(entity =>
        {
            entity.HasKey(e => e.UrlId).HasName("PK__UrlAnaly__BDE12DD0AFD3D09B");

            entity.HasIndex(e => e.EmailId, "IX_UrlAnalyses_EmailID");

            entity.Property(e => e.UrlId).HasColumnName("UrlID");
            entity.Property(e => e.AnalyzedAt).HasDefaultValueSql("(sysdatetime())");
            entity.Property(e => e.Domain).HasMaxLength(255);
            entity.Property(e => e.EmailId).HasColumnName("EmailID");
            entity.Property(e => e.OriginalUrl)
                .HasMaxLength(2048)
                .HasColumnName("OriginalURL");
            entity.Property(e => e.ReputationStatus).HasMaxLength(50);

            entity.HasOne(d => d.Email).WithMany(p => p.UrlAnalyses)
                .HasForeignKey(d => d.EmailId)
                .HasConstraintName("FK_UrlAnalyses_EmailSamples");
        });

        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.UserId).HasName("PK__Users__1788CCACF0D338C5");

            entity.HasIndex(e => e.Email, "UQ__Users__A9D10534276EC68A").IsUnique();

            entity.Property(e => e.UserId).HasColumnName("UserID");
            entity.Property(e => e.CreatedAt).HasDefaultValueSql("(sysdatetime())");
            entity.Property(e => e.Email).HasMaxLength(150);
            entity.Property(e => e.FullName).HasMaxLength(150);
            entity.Property(e => e.IsActive).HasDefaultValue(true);
            entity.Property(e => e.PasswordHash).HasMaxLength(500);
            entity.Property(e => e.RoleId).HasColumnName("RoleID");

            entity.HasOne(d => d.Role).WithMany(p => p.Users)
                .HasForeignKey(d => d.RoleId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_Users_UserRoles");
        });

        modelBuilder.Entity<UserRole>(entity =>
        {
            entity.HasKey(e => e.RoleId).HasName("PK__UserRole__8AFACE3AD4356DBB");

            entity.HasIndex(e => e.RoleName, "UQ__UserRole__8A2B6160E65FC242").IsUnique();

            entity.Property(e => e.RoleId).HasColumnName("RoleID");
            entity.Property(e => e.Description).HasMaxLength(255);
            entity.Property(e => e.RoleName).HasMaxLength(50);
        });

        modelBuilder.Entity<VwAnalysisHistory>(entity =>
        {
            entity
                .HasNoKey()
                .ToView("vw_AnalysisHistory");

            entity.Property(e => e.AnalysisId).HasColumnName("AnalysisID");
            entity.Property(e => e.EmailId).HasColumnName("EmailID");
            entity.Property(e => e.RiskClassification).HasMaxLength(20);
            entity.Property(e => e.SenderEmail).HasMaxLength(320);
            entity.Property(e => e.Subject).HasMaxLength(500);
            entity.Property(e => e.SubmittedBy).HasMaxLength(150);
        });

        modelBuilder.Entity<VwDashboardSummary>(entity =>
        {
            entity
                .HasNoKey()
                .ToView("vw_DashboardSummary");
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
