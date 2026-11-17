using EmailShield.Data;
using EmailShield.DTOs;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EmailShield.Controllers;

[ApiController]
[Route("api/[controller]")]
public class DashboardController : ControllerBase
{
    private readonly EmailShieldDbContext _context;

    public DashboardController(EmailShieldDbContext context)
    {
        _context = context;
    }

    [HttpGet("summary")]
    public async Task<IActionResult> GetSummary()
    {
        // Query the view created in SSMS
        var summary = await _context.VwDashboardSummaries.FirstOrDefaultAsync();

        int totalAnalyzed = summary?.TotalAnalyzed ?? 0;
        int highRisk = summary?.HighRiskCount ?? 0;
        int mediumRisk = summary?.MediumRiskCount ?? 0;
        int lowRisk = summary?.LowRiskCount ?? 0;

        int totalUsers = await _context.Users.CountAsync();
        int totalAudits = await _context.AuditLogs.CountAsync();

        return Ok(new
        {
            totalAnalyzed,
            highRiskCount = highRisk,
            mediumRiskCount = mediumRisk,
            lowRiskCount = lowRisk,
            totalUsers,
            totalAudits
        });
    }
}

