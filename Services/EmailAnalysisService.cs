using System.Text.RegularExpressions;
using EmailShield.Data;
using EmailShield.DTOs;
using EmailShield.Models;
using Microsoft.EntityFrameworkCore;
using MimeKit;

namespace EmailShield.Services;

public class EmailAnalysisService
{
    private readonly EmailShieldDbContext _context;
    private readonly SystemSettingsService _settingsService;

    public EmailAnalysisService(EmailShieldDbContext context, SystemSettingsService settingsService)
    {
        _context = context;
        _settingsService = settingsService;
    }

    public async Task<AnalysisDetailResponse> AnalyzeAsync(
        string rawContent,
        string submissionType,
        string? uploadedFileName,
        int userId,
        Stream? fileStream = null)
    {
        var settings = _settingsService.GetSettings();
        MimeMessage? mimeMessage = null;
        string subject = string.Empty;
        string senderEmail = string.Empty;
        string recipientEmail = string.Empty;
        string emailBody = string.Empty;
        var headersList = new List<(string Name, string Value)>();
        var attachmentsList = new List<AttachmentDto>();

        string normalizedContent = rawContent?.Replace("\r\n", "\n").Replace("\r", "\n").Replace("\n", "\r\n") ?? string.Empty;

        if (fileStream != null && submissionType.Equals("EML", StringComparison.OrdinalIgnoreCase))
        {
            fileStream.Position = 0;
            mimeMessage = await MimeMessage.LoadAsync(fileStream);
        }
        else if (!string.IsNullOrWhiteSpace(normalizedContent))
        {
            using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(normalizedContent));
            try
            {
                mimeMessage = await MimeMessage.LoadAsync(stream);
            }
            catch
            {
                // Raw text fallback if not full RFC822 format
                mimeMessage = null;
            }
        }

        if (mimeMessage != null)
        {
            subject = mimeMessage.Subject ?? string.Empty;
            senderEmail = mimeMessage.From.Mailboxes.FirstOrDefault()?.Address ?? string.Empty;
            recipientEmail = mimeMessage.To.Mailboxes.FirstOrDefault()?.Address ?? string.Empty;
            emailBody = mimeMessage.TextBody ?? mimeMessage.HtmlBody ?? string.Empty;

            foreach (var h in mimeMessage.Headers)
            {
                headersList.Add((h.Field, h.Value));
            }

            foreach (var attachment in mimeMessage.Attachments)
            {
                string fileName = attachment.ContentDisposition?.FileName 
                    ?? attachment.ContentType.Name 
                    ?? "unnamed_attachment";
                string ext = Path.GetExtension(fileName).ToLowerInvariant();
                string mimeType = attachment.ContentType.MimeType;
                long? size = null;

                if (attachment is MimePart part && part.Content != null)
                {
                    using var ms = new MemoryStream();
                    part.Content.DecodeTo(ms);
                    size = ms.Length;
                }

                attachmentsList.Add(new AttachmentDto
                {
                    FileName = fileName,
                    FileExtension = ext,
                    MimeType = mimeType,
                    FileSize = size
                });
            }
        }

        // Comprehensive fallback: Ensure headers, sender, subject, and body are extracted even if RFC822 parser misses informal text
        if (!string.IsNullOrWhiteSpace(normalizedContent))
        {
            if (string.IsNullOrWhiteSpace(emailBody))
            {
                emailBody = normalizedContent;
            }

            if (string.IsNullOrWhiteSpace(senderEmail))
            {
                var fromMatch = Regex.Match(normalizedContent, @"(?:^|\n)From:\s*([^\r\n]+)", RegexOptions.IgnoreCase);
                if (fromMatch.Success) senderEmail = ExtractEmailAddress(fromMatch.Groups[1].Value);
            }

            if (string.IsNullOrWhiteSpace(recipientEmail))
            {
                var toMatch = Regex.Match(normalizedContent, @"(?:^|\n)To:\s*([^\r\n]+)", RegexOptions.IgnoreCase);
                if (toMatch.Success) recipientEmail = ExtractEmailAddress(toMatch.Groups[1].Value);
            }

            if (string.IsNullOrWhiteSpace(subject))
            {
                var subjMatch = Regex.Match(normalizedContent, @"(?:^|\n)Subject:\s*([^\r\n]+)", RegexOptions.IgnoreCase);
                if (subjMatch.Success) subject = subjMatch.Groups[1].Value.Trim();
            }

            // Extract additional headers like Authentication-Results, Reply-To, Received-SPF if missing from headersList
            var headerMatches = Regex.Matches(normalizedContent, @"(?:^|\n)([A-Za-z0-9\-]+):\s*([^\r\n]+(?:\r?\n[ \t]+[^\r\n]+)*)");
            foreach (Match m in headerMatches)
            {
                string hName = m.Groups[1].Value.Trim();
                string hVal = Regex.Replace(m.Groups[2].Value, @"\r?\n[ \t]+", " ").Trim();
                if (!headersList.Any(h => h.Name.Equals(hName, StringComparison.OrdinalIgnoreCase)))
                {
                    headersList.Add((hName, hVal));
                }
            }
        }

        if (string.IsNullOrWhiteSpace(subject)) subject = "(No Subject)";
        if (string.IsNullOrWhiteSpace(senderEmail)) senderEmail = "unknown@unknown.com";

        // Step 1: Initialize Threat Indicators & Scoring
        var threatIndicators = new List<ThreatIndicatorDto>();
        int totalScore = 0;

        // Step 2: Email Authentication Check (SPF, DKIM, DMARC)
        var authResult = EvaluateAuthentication(headersList);
        if (settings.RuleToggles.EnableAuthVerification)
        {
            if (authResult.SpfResult?.Equals("Fail", StringComparison.OrdinalIgnoreCase) == true)
            {
                threatIndicators.Add(new ThreatIndicatorDto
                {
                    ThreatType = "SPF Authentication Failure",
                    Severity = "High",
                    Points = settings.RuleWeightings.SpfFailPoints,
                    ThreatDescription = "The sender's IP address is not authorized to send emails on behalf of the domain."
                });
                totalScore += settings.RuleWeightings.SpfFailPoints;
            }
            else if (authResult.SpfResult?.Equals("SoftFail", StringComparison.OrdinalIgnoreCase) == true)
            {
                threatIndicators.Add(new ThreatIndicatorDto
                {
                    ThreatType = "SPF SoftFail Warning",
                    Severity = "Medium",
                    Points = 15,
                    ThreatDescription = "The sender domain designated the sending host as not allowed, but in a non-strict mode."
                });
                totalScore += 15;
            }

            if (authResult.DkimResult?.Equals("Fail", StringComparison.OrdinalIgnoreCase) == true)
            {
                threatIndicators.Add(new ThreatIndicatorDto
                {
                    ThreatType = "DKIM Signature Invalid",
                    Severity = "High",
                    Points = settings.RuleWeightings.DkimFailPoints,
                    ThreatDescription = "The cryptographic DKIM signature failed verification or email was altered in transit."
                });
                totalScore += settings.RuleWeightings.DkimFailPoints;
            }

            if (authResult.DmarcResult?.Equals("Fail", StringComparison.OrdinalIgnoreCase) == true)
            {
                threatIndicators.Add(new ThreatIndicatorDto
                {
                    ThreatType = "DMARC Policy Rejection",
                    Severity = "High",
                    Points = settings.RuleWeightings.DmarcFailPoints,
                    ThreatDescription = "DMARC alignment failed for both SPF and DKIM."
                });
                totalScore += settings.RuleWeightings.DmarcFailPoints;
            }
        }

        // Step 3: Sender & Domain Spoofing Analysis
        if (settings.RuleToggles.EnableSpoofingDetection)
        {
            EvaluateSpoofing(mimeMessage, headersList, senderEmail, threatIndicators, ref totalScore, settings);
        }

        // Step 4: URL Extraction & Analysis
        var extractedUrls = settings.RuleToggles.EnableUrlAnalysis
            ? ExtractAndAnalyzeUrls(emailBody, rawContent ?? string.Empty, threatIndicators, ref totalScore, settings)
            : new List<UrlAnalysisDto>();

        // Step 5: Attachment Metadata Inspection
        if (settings.RuleToggles.EnableAttachmentInspection)
        {
            EvaluateAttachments(attachmentsList, threatIndicators, ref totalScore, settings);
        }

        // Step 6: Phishing & Business Email Compromise (BEC) Heuristics
        if (settings.RuleToggles.EnableBecDetection)
        {
            EvaluateBECAndPhishingKeywords(emailBody, subject, threatIndicators, ref totalScore, settings);
        }

        // Calculate Final Risk Classification using Dynamic Thresholds
        int finalScore = Math.Clamp(totalScore, 0, 100);
        string riskClassification;
        if (finalScore >= settings.RiskThresholds.HighRiskThreshold)
            riskClassification = "High";
        else if (finalScore >= settings.RiskThresholds.MediumRiskThreshold)
            riskClassification = "Medium";
        else
            riskClassification = "Low";

        string summary = GenerateAnalysisSummary(riskClassification, finalScore, threatIndicators);
        string recommendation = GenerateRecommendations(riskClassification, threatIndicators);

        // Step 7: Persist everything to SQL Server Database
        var emailSample = new EmailSample
        {
            UserId = userId,
            Subject = subject.Length > 500 ? subject[..500] : subject,
            SenderEmail = senderEmail.Length > 320 ? senderEmail[..320] : senderEmail,
            RecipientEmail = recipientEmail.Length > 320 ? recipientEmail[..320] : recipientEmail,
            EmailBody = emailBody,
            OriginalEmailContent = rawContent,
            UploadedFileName = uploadedFileName,
            SubmissionType = submissionType,
            SubmittedAt = DateTime.UtcNow
        };
        _context.EmailSamples.Add(emailSample);
        await _context.SaveChangesAsync();

        // Save Headers
        foreach (var h in headersList.Take(50)) // preserve top 50 key headers
        {
            _context.EmailHeaders.Add(new EmailHeader
            {
                EmailId = emailSample.EmailId,
                HeaderName = h.Name.Length > 255 ? h.Name[..255] : h.Name,
                HeaderValue = h.Value
            });
        }

        // Save Authentication Results
        _context.AuthenticationResults.Add(new AuthenticationResult
        {
            EmailId = emailSample.EmailId,
            Spfresult = authResult.SpfResult,
            Dkimresult = authResult.DkimResult,
            Dmarcresult = authResult.DmarcResult,
            AuthenticationHeader = authResult.AuthenticationHeader,
            VerificationMethod = authResult.VerificationMethod,
            CheckedAt = DateTime.UtcNow
        });

        // Save URLs
        foreach (var u in extractedUrls)
        {
            _context.UrlAnalyses.Add(new UrlAnalysis
            {
                EmailId = emailSample.EmailId,
                OriginalUrl = u.OriginalUrl.Length > 2048 ? u.OriginalUrl[..2048] : u.OriginalUrl,
                Domain = u.Domain,
                IsValid = u.IsValid,
                IsSuspicious = u.IsSuspicious,
                ReputationStatus = u.ReputationStatus,
                DetectionReason = u.DetectionReason,
                AnalyzedAt = DateTime.UtcNow
            });
        }

        // Save Attachment Metadata
        foreach (var a in attachmentsList)
        {
            _context.AttachmentMetadata.Add(new AttachmentMetadatum
            {
                EmailId = emailSample.EmailId,
                FileName = a.FileName.Length > 255 ? a.FileName[..255] : a.FileName,
                FileExtension = a.FileExtension,
                MimeType = a.MimeType,
                FileSize = a.FileSize,
                IsSuspicious = a.IsSuspicious,
                DetectionReason = a.DetectionReason,
                InspectedAt = DateTime.UtcNow
            });
        }

        // Save Threat Indicators
        foreach (var ti in threatIndicators)
        {
            _context.ThreatIndicators.Add(new ThreatIndicator
            {
                EmailId = emailSample.EmailId,
                ThreatType = ti.ThreatType.Length > 100 ? ti.ThreatType[..100] : ti.ThreatType,
                ThreatDescription = ti.ThreatDescription,
                Severity = ti.Severity,
                Points = ti.Points,
                DetectedAt = DateTime.UtcNow
            });
        }

        // Save Analysis Result
        var analysisRecord = new AnalysisResult
        {
            EmailId = emailSample.EmailId,
            RiskScore = finalScore,
            RiskClassification = riskClassification,
            AnalysisSummary = summary,
            Recommendation = recommendation,
            AnalyzedAt = DateTime.UtcNow
        };
        _context.AnalysisResults.Add(analysisRecord);

        // Add Audit Log
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = userId,
            Action = "EMAIL_ANALYZED",
            Description = $"Analyzed email '{emailSample.Subject}' (Risk: {riskClassification}, Score: {finalScore}/100)",
            Ipaddress = "127.0.0.1",
            CreatedAt = DateTime.UtcNow
        });

        await _context.SaveChangesAsync();

        var submitterUser = await _context.Users.FirstOrDefaultAsync(u => u.UserId == userId);

        return new AnalysisDetailResponse
        {
            AnalysisId = analysisRecord.AnalysisId,
            EmailId = emailSample.EmailId,
            Subject = emailSample.Subject,
            SenderEmail = emailSample.SenderEmail,
            RecipientEmail = emailSample.RecipientEmail,
            EmailBody = emailSample.EmailBody,
            UploadedFileName = emailSample.UploadedFileName,
            SubmissionType = emailSample.SubmissionType,
            SubmittedAt = emailSample.SubmittedAt,
            SubmittedBy = submitterUser?.FullName ?? "Unknown User",
            RiskScore = finalScore,
            RiskClassification = riskClassification,
            AnalysisSummary = summary,
            Recommendation = recommendation,
            AnalyzedAt = analysisRecord.AnalyzedAt,
            Authentication = authResult,
            Headers = headersList.Select(h => new HeaderDto { HeaderName = h.Name, HeaderValue = h.Value }).ToList(),
            ThreatIndicators = threatIndicators,
            Urls = extractedUrls,
            Attachments = attachmentsList
        };
    }

    private static string ExtractEmailAddress(string raw)
    {
        var match = Regex.Match(raw, @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}");
        return match.Success ? match.Value : raw.Trim();
    }

    private static AuthenticationResultDto EvaluateAuthentication(List<(string Name, string Value)> headers)
    {
        var auth = new AuthenticationResultDto
        {
            SpfResult = "None",
            DkimResult = "None",
            DmarcResult = "None",
            VerificationMethod = "Standard Header Parsing"
        };

        var authHeader = headers.FirstOrDefault(h => h.Name.Equals("Authentication-Results", StringComparison.OrdinalIgnoreCase)).Value
            ?? headers.FirstOrDefault(h => h.Name.Equals("Received-SPF", StringComparison.OrdinalIgnoreCase)).Value;

        if (!string.IsNullOrEmpty(authHeader))
        {
            auth.AuthenticationHeader = authHeader;

            // SPF check
            if (Regex.IsMatch(authHeader, @"spf=pass", RegexOptions.IgnoreCase)) auth.SpfResult = "Pass";
            else if (Regex.IsMatch(authHeader, @"spf=fail", RegexOptions.IgnoreCase)) auth.SpfResult = "Fail";
            else if (Regex.IsMatch(authHeader, @"spf=softfail", RegexOptions.IgnoreCase)) auth.SpfResult = "SoftFail";
            else if (Regex.IsMatch(authHeader, @"spf=neutral", RegexOptions.IgnoreCase)) auth.SpfResult = "Neutral";

            // DKIM check
            if (Regex.IsMatch(authHeader, @"dkim=pass", RegexOptions.IgnoreCase)) auth.DkimResult = "Pass";
            else if (Regex.IsMatch(authHeader, @"dkim=fail", RegexOptions.IgnoreCase)) auth.DkimResult = "Fail";

            // DMARC check
            if (Regex.IsMatch(authHeader, @"dmarc=pass", RegexOptions.IgnoreCase)) auth.DmarcResult = "Pass";
            else if (Regex.IsMatch(authHeader, @"dmarc=fail", RegexOptions.IgnoreCase)) auth.DmarcResult = "Fail";
        }

        return auth;
    }

    private static void EvaluateSpoofing(
        MimeMessage? mime,
        List<(string Name, string Value)> headers,
        string senderEmail,
        List<ThreatIndicatorDto> indicators,
        ref int score,
        SystemSettingsDto settings)
    {
        // 1. Reply-To Mismatch
        string replyTo = string.Empty;
        if (mime != null && mime.ReplyTo.Count > 0)
        {
            replyTo = mime.ReplyTo.Mailboxes.FirstOrDefault()?.Address ?? string.Empty;
        }
        else
        {
            var rMatch = headers.FirstOrDefault(h => h.Name.Equals("Reply-To", StringComparison.OrdinalIgnoreCase)).Value;
            if (!string.IsNullOrEmpty(rMatch)) replyTo = ExtractEmailAddress(rMatch);
        }

        if (!string.IsNullOrEmpty(replyTo) && !string.IsNullOrEmpty(senderEmail) &&
            !replyTo.Equals(senderEmail, StringComparison.OrdinalIgnoreCase))
        {
            int pts = settings.RuleWeightings.ReplyToMismatchPoints;
            indicators.Add(new ThreatIndicatorDto
            {
                ThreatType = "Reply-To Address Mismatch",
                Severity = "High",
                Points = pts,
                ThreatDescription = $"Visible sender ({senderEmail}) differs from Reply-To destination ({replyTo}). Responses will be redirected to a different address."
            });
            score += pts;
        }

        // 2. Display Name Spoofing
        string displayName = string.Empty;
        string mailboxAddress = senderEmail;

        if (mime != null && mime.From.Count > 0)
        {
            var mailbox = mime.From.Mailboxes.FirstOrDefault();
            if (mailbox != null)
            {
                displayName = mailbox.Name ?? string.Empty;
                mailboxAddress = mailbox.Address ?? senderEmail;
            }
        }
        else
        {
            var fromHeader = headers.FirstOrDefault(h => h.Name.Equals("From", StringComparison.OrdinalIgnoreCase)).Value;
            if (!string.IsNullOrEmpty(fromHeader))
            {
                var dnMatch = Regex.Match(fromHeader, @"^""?([^""<]+)""?\s*<([^>]+)>");
                if (dnMatch.Success)
                {
                    displayName = dnMatch.Groups[1].Value.Trim();
                    mailboxAddress = dnMatch.Groups[2].Value.Trim();
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(displayName))
        {
            var embeddedEmail = ExtractEmailAddress(displayName);
            if (!string.IsNullOrEmpty(embeddedEmail) && !embeddedEmail.Equals(mailboxAddress, StringComparison.OrdinalIgnoreCase))
            {
                int pts = settings.RuleWeightings.DisplayNameImpersonationPoints;
                indicators.Add(new ThreatIndicatorDto
                {
                    ThreatType = "Display Name Impersonation",
                    Severity = "High",
                    Points = pts,
                    ThreatDescription = $"Display name contains an impersonated address '{embeddedEmail}', while actual sending address is '{mailboxAddress}'."
                });
                score += pts;
            }
        }
    }

    private static List<UrlAnalysisDto> ExtractAndAnalyzeUrls(
        string body,
        string raw,
        List<ThreatIndicatorDto> indicators,
        ref int score,
        SystemSettingsDto settings)
    {
        var urlList = new List<UrlAnalysisDto>();
        var urlMatches = Regex.Matches(body + " " + raw, @"https?://[^\s<>""']+");
        var distinctUrls = urlMatches.Select(m => m.Value.TrimEnd('.', ',', ';')).Distinct().Take(20).ToList();

        var suspiciousTlds = (settings.ThreatIntel.MonitoredTlds ?? ".xyz, .top, .work, .click")
            .Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(t => t.Trim().ToLowerInvariant())
            .ToArray();
            
        var phishingKeywords = new[] { "login", "signin", "verify", "update-account", "secure", "bank", "paypal", "microsoft-login", "wallet", "recover", "authenticate" };

        bool foundSuspiciousUrl = false;

        foreach (var u in distinctUrls)
        {
            bool isSuspicious = false;
            string reason = "Safe";
            string reputation = "Clean";
            string domain = string.Empty;
            bool isValid = Uri.TryCreate(u, UriKind.Absolute, out var uri);

            if (isValid && uri != null)
            {
                domain = uri.Host;

                // Check 1: IP Address in URL
                if (Regex.IsMatch(domain, @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"))
                {
                    isSuspicious = true;
                    reputation = "Malicious";
                    reason = "Raw IP address host detected instead of standard domain name.";
                    score += 25;
                }
                // Check 2: Embedded credentials / @ in URL
                else if (u.Contains('@'))
                {
                    isSuspicious = true;
                    reputation = "Malicious";
                    reason = "URL contains an '@' symbol used for userinfo deceptive redirection.";
                    score += 25;
                }
                // Check 3: Suspicious TLD
                else if (suspiciousTlds.Any(tld => domain.EndsWith(tld, StringComparison.OrdinalIgnoreCase)))
                {
                    isSuspicious = true;
                    reputation = "Suspicious";
                    reason = "Domain uses a monitored high-abuse top-level domain (TLD).";
                    score += 15;
                }
                // Check 4: Phishing keywords in domain or path
                else if (phishingKeywords.Any(kw => u.Contains(kw, StringComparison.OrdinalIgnoreCase)))
                {
                    isSuspicious = true;
                    reputation = "Suspicious";
                    reason = "URL contains credential-harvesting or account verification keywords.";
                    score += 15;
                }
            }
            else
            {
                isValid = false;
                reason = "Malformed URL";
            }

            if (isSuspicious) foundSuspiciousUrl = true;

            urlList.Add(new UrlAnalysisDto
            {
                OriginalUrl = u,
                Domain = domain,
                IsValid = isValid,
                IsSuspicious = isSuspicious,
                ReputationStatus = reputation,
                DetectionReason = reason
            });
        }

        if (foundSuspiciousUrl)
        {
            indicators.Add(new ThreatIndicatorDto
            {
                ThreatType = "Malicious or Suspicious Links Detected",
                Severity = "High",
                Points = 25,
                ThreatDescription = "Email contains links with phishing keywords, raw IP hosts, or abusive domain structures."
            });
        }

        return urlList;
    }

    private static void EvaluateAttachments(
        List<AttachmentDto> attachments,
        List<ThreatIndicatorDto> indicators,
        ref int score,
        SystemSettingsDto settings)
    {
        var dangerousExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".ps1",
            ".hta", ".cpl", ".msi", ".iso", ".img", ".vhd", ".dll", ".jar", ".com"
        };

        var macroExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".docm", ".xlsm", ".pptm", ".dotm", ".xltm"
        };

        foreach (var att in attachments)
        {
            string ext = att.FileExtension ?? string.Empty;
            string fn = att.FileName.ToLowerInvariant();

            // Double extension check (e.g. invoice.pdf.exe)
            if (Regex.IsMatch(fn, @"\.[a-z0-9]+\.(exe|scr|bat|vbs|js|msi|cmd|ps1)$"))
            {
                int pts = settings.RuleWeightings.DoubleExtensionPoints;
                att.IsSuspicious = true;
                att.DetectionReason = "Deceptive double extension designed to conceal executable file type.";
                indicators.Add(new ThreatIndicatorDto
                {
                    ThreatType = "Deceptive Attachment Extension",
                    Severity = "High",
                    Points = pts,
                    ThreatDescription = $"Attachment '{att.FileName}' uses a double extension masking an executable payload."
                });
                score += pts;
            }
            else if (dangerousExtensions.Contains(ext))
            {
                int pts = settings.RuleWeightings.DangerousAttachmentPoints;
                att.IsSuspicious = true;
                att.DetectionReason = $"Dangerous executable file type ({ext}).";
                indicators.Add(new ThreatIndicatorDto
                {
                    ThreatType = "High-Risk Executable Attachment",
                    Severity = "High",
                    Points = pts,
                    ThreatDescription = $"Attachment '{att.FileName}' is an executable or script with high malware potential."
                });
                score += pts;
            }
            else if (macroExtensions.Contains(ext))
            {
                int pts = settings.RuleWeightings.MacroDocumentPoints;
                att.IsSuspicious = true;
                att.DetectionReason = "Macro-enabled Office document capable of executing malicious embedded VBA scripts.";
                indicators.Add(new ThreatIndicatorDto
                {
                    ThreatType = "Macro-Enabled Office Document",
                    Severity = "Medium",
                    Points = pts,
                    ThreatDescription = $"Attachment '{att.FileName}' contains executable macro code."
                });
                score += pts;
            }
            else if (ext.Equals(".zip", StringComparison.OrdinalIgnoreCase) || ext.Equals(".rar", StringComparison.OrdinalIgnoreCase))
            {
                att.IsSuspicious = true;
                att.DetectionReason = "Archive container commonly used to evade email antivirus scanners.";
                indicators.Add(new ThreatIndicatorDto
                {
                    ThreatType = "Compressed Archive Attachment",
                    Severity = "Medium",
                    Points = 10,
                    ThreatDescription = $"Attachment '{att.FileName}' is an archive. Files inside must be quarantined."
                });
                score += 10;
            }
        }
    }

    private static void EvaluateBECAndPhishingKeywords(
        string body,
        string subject,
        List<ThreatIndicatorDto> indicators,
        ref int score,
        SystemSettingsDto settings)
    {
        string text = (subject + " " + body).ToLowerInvariant();

        // 1. Urgency & Threats
        var urgencyTerms = new[]
        {
            "immediate action required", "urgent response required", "account suspended within 24 hours",
            "terminate immediately", "act now", "critical security update", "unauthorized login detected",
            "respond immediately", "expires today", "final notice"
        };
        if (urgencyTerms.Any(t => text.Contains(t)))
        {
            int pts = settings.RuleWeightings.UrgencyLanguagePoints;
            indicators.Add(new ThreatIndicatorDto
            {
                ThreatType = "Urgent Coercive Language",
                Severity = "Medium",
                Points = pts,
                ThreatDescription = "Email pressures recipient with artificial urgency, threats of account termination, or immediate deadlines."
            });
            score += pts;
        }

        // 2. Financial & Business Email Compromise (BEC)
        var becTerms = new[]
        {
            "wire transfer", "bank account details", "change of payment instruction", "new bank details",
            "vendor invoice payment", "transfer funds", "gift card", "routing number", "swift code",
            "payment details updated", "strictly confidential payment"
        };
        if (becTerms.Any(t => text.Contains(t)))
        {
            int pts = settings.RuleWeightings.BecWireFraudPoints;
            indicators.Add(new ThreatIndicatorDto
            {
                ThreatType = "Business Email Compromise (BEC) / Wire Fraud Indicator",
                Severity = "High",
                Points = pts,
                ThreatDescription = "Email requests changes to financial payment instructions, wire transfers, or sensitive bank details."
            });
            score += pts;
        }

        // 3. Credential Harvesting Signals
        var credTerms = new[]
        {
            "verify your password", "reset your login", "confirm your credentials", "update your password",
            "validate your account details", "sign in to prevent interruption", "re-authenticate"
        };
        if (credTerms.Any(t => text.Contains(t)))
        {
            indicators.Add(new ThreatIndicatorDto
            {
                ThreatType = "Credential Harvesting Attempt",
                Severity = "High",
                Points = 25,
                ThreatDescription = "Email directs recipient to reveal or confirm login credentials, passwords, or personal identity information."
            });
            score += 25;
        }
    }

    private static string GenerateAnalysisSummary(string riskClassification, int score, List<ThreatIndicatorDto> indicators)
    {
        if (riskClassification == "High")
        {
            return $"CRITICAL: This email exhibits severe risk indicators (Risk Score: {score}/100) including {indicators.Count} suspicious threat patterns. High probability of phishing, credential harvesting, or BEC fraud.";
        }
        else if (riskClassification == "Medium")
        {
            return $"WARNING: This email contains suspicious indicators (Risk Score: {score}/100). Exercise caution before clicking links, opening attachments, or complying with requests.";
        }
        else
        {
            return $"LOW RISK: No critical phishing, BEC, or malicious attachment indicators were detected (Risk Score: {score}/100). Always maintain standard email safety practices.";
        }
    }

    private static string GenerateRecommendations(string riskClassification, List<ThreatIndicatorDto> indicators)
    {
        if (riskClassification == "High")
        {
            return "1. DO NOT click any links or download attachments.\n2. DO NOT reply or execute any financial/payment instructions.\n3. Report this email to your organization's IT Security Officer.\n4. Block the sender domain in your email gateway.";
        }
        else if (riskClassification == "Medium")
        {
            return "1. Independently verify the sender's identity using a separate channel (phone call or verified chat).\n2. Hover over links to verify destination domains before clicking.\n3. Inspect attachments in an isolated sandbox.";
        }
        else
        {
            return "1. Standard email hygiene is recommended.\n2. Verify unexpected requests even from known senders.";
        }
    }
}
