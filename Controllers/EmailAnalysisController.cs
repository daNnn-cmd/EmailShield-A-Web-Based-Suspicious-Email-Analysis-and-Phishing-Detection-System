using EmailShield.Data;
using EmailShield.DTOs;
using EmailShield.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EmailShield.Controllers;

[ApiController]
[Route("api/analysis")]
[Route("api/[controller]")]
public class EmailAnalysisController : ControllerBase
{
    private readonly EmailShieldDbContext _context;
    private readonly EmailAnalysisService _analysisService;

    public EmailAnalysisController(EmailShieldDbContext context, EmailAnalysisService analysisService)
    {
        _context = context;
        _analysisService = analysisService;
    }

    [HttpPost("submit-text")]
    public async Task<IActionResult> SubmitText([FromBody] SubmitEmailTextRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.RawContent))
            return BadRequest(new { message = "Email text or header content cannot be empty." });

        try
        {
            var result = await _analysisService.AnalyzeAsync(
                rawContent: request.RawContent,
                submissionType: "Text",
                uploadedFileName: null,
                userId: request.UserId > 0 ? request.UserId : 1);

            return Ok(result);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Analysis failed.", error = ex.Message });
        }
    }

    [HttpPost("upload-eml")]
    [Consumes("multipart/form-data")]
    public async Task<IActionResult> UploadEml([FromForm] IFormFile file, [FromForm] int userId)
    {
        if (file == null || file.Length == 0)
            return BadRequest(new { message = "Please select a valid .eml file." });

        if (!Path.GetExtension(file.FileName).Equals(".eml", StringComparison.OrdinalIgnoreCase))
            return BadRequest(new { message = "Only .eml files are supported for upload." });

        try
        {
            using var stream = file.OpenReadStream();
            using var reader = new StreamReader(stream);
            string rawContent = await reader.ReadToEndAsync();
            stream.Position = 0;

            var result = await _analysisService.AnalyzeAsync(
                rawContent: rawContent,
                submissionType: "EML",
                uploadedFileName: file.FileName,
                userId: userId > 0 ? userId : 1,
                fileStream: stream);

            return Ok(result);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Failed to process .eml file.", error = ex.Message });
        }
    }

    [HttpGet("history")]
    public async Task<IActionResult> GetHistory([FromQuery] int? userId = null)
    {
        // Query the view created in SSMS
        var query = _context.VwAnalysisHistories.AsQueryable();

        // If filtered by user
        if (userId.HasValue)
        {
            // Join with EmailSamples to match specific user
            var userEmailIds = await _context.EmailSamples
                .Where(e => e.UserId == userId.Value)
                .Select(e => e.EmailId)
                .ToListAsync();

            var filtered = await query
                .Where(h => userEmailIds.Contains(h.EmailId))
                .OrderByDescending(h => h.AnalyzedAt)
                .Select(h => new AnalysisHistoryItemDto
                {
                    AnalysisId = h.AnalysisId,
                    EmailId = h.EmailId,
                    Subject = h.Subject,
                    SenderEmail = h.SenderEmail,
                    SubmittedBy = h.SubmittedBy,
                    RiskScore = h.RiskScore,
                    RiskClassification = h.RiskClassification,
                    AnalyzedAt = h.AnalyzedAt
                })
                .ToListAsync();

            return Ok(filtered);
        }

        var list = await query
            .OrderByDescending(h => h.AnalyzedAt)
            .Select(h => new AnalysisHistoryItemDto
            {
                AnalysisId = h.AnalysisId,
                EmailId = h.EmailId,
                Subject = h.Subject,
                SenderEmail = h.SenderEmail,
                SubmittedBy = h.SubmittedBy,
                RiskScore = h.RiskScore,
                RiskClassification = h.RiskClassification,
                AnalyzedAt = h.AnalyzedAt
            })
            .ToListAsync();

        return Ok(list);
    }

    [HttpGet("{analysisId}")]
    public async Task<IActionResult> GetAnalysisDetail(int analysisId)
    {
        var analysis = await _context.AnalysisResults
            .Include(a => a.Email)
            .ThenInclude(e => e.User)
            .FirstOrDefaultAsync(a => a.AnalysisId == analysisId);

        if (analysis == null) return NotFound(new { message = "Analysis record not found." });

        int emailId = analysis.EmailId;

        var headers = await _context.EmailHeaders
            .Where(h => h.EmailId == emailId)
            .Select(h => new HeaderDto { HeaderName = h.HeaderName, HeaderValue = h.HeaderValue })
            .ToListAsync();

        var auth = await _context.AuthenticationResults
            .Where(a => a.EmailId == emailId)
            .Select(a => new AuthenticationResultDto
            {
                SpfResult = a.Spfresult,
                DkimResult = a.Dkimresult,
                DmarcResult = a.Dmarcresult,
                VerificationMethod = a.VerificationMethod,
                AuthenticationHeader = a.AuthenticationHeader
            })
            .FirstOrDefaultAsync();

        var threats = await _context.ThreatIndicators
            .Where(t => t.EmailId == emailId)
            .Select(t => new ThreatIndicatorDto
            {
                ThreatType = t.ThreatType,
                Severity = t.Severity,
                ThreatDescription = t.ThreatDescription,
                Points = t.Points
            })
            .ToListAsync();

        var urls = await _context.UrlAnalyses
            .Where(u => u.EmailId == emailId)
            .Select(u => new UrlAnalysisDto
            {
                OriginalUrl = u.OriginalUrl,
                Domain = u.Domain,
                IsValid = u.IsValid,
                IsSuspicious = u.IsSuspicious,
                ReputationStatus = u.ReputationStatus,
                DetectionReason = u.DetectionReason
            })
            .ToListAsync();

        var attachments = await _context.AttachmentMetadata
            .Where(a => a.EmailId == emailId)
            .Select(a => new AttachmentDto
            {
                FileName = a.FileName,
                FileExtension = a.FileExtension,
                MimeType = a.MimeType,
                FileSize = a.FileSize,
                IsSuspicious = a.IsSuspicious,
                DetectionReason = a.DetectionReason
            })
            .ToListAsync();

        var response = new AnalysisDetailResponse
        {
            AnalysisId = analysis.AnalysisId,
            EmailId = analysis.EmailId,
            Subject = analysis.Email.Subject,
            SenderEmail = analysis.Email.SenderEmail,
            RecipientEmail = analysis.Email.RecipientEmail,
            EmailBody = analysis.Email.EmailBody,
            UploadedFileName = analysis.Email.UploadedFileName,
            SubmissionType = analysis.Email.SubmissionType,
            SubmittedAt = analysis.Email.SubmittedAt,
            SubmittedBy = analysis.Email.User?.FullName ?? "Unknown",
            RiskScore = analysis.RiskScore,
            RiskClassification = analysis.RiskClassification,
            AnalysisSummary = analysis.AnalysisSummary,
            Recommendation = analysis.Recommendation,
            AnalyzedAt = analysis.AnalyzedAt,
            Authentication = auth,
            Headers = headers,
            ThreatIndicators = threats,
            Urls = urls,
            Attachments = attachments
        };

        return Ok(response);
    }
}
