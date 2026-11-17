using EmailShield.Data;
using EmailShield.DTOs;
using EmailShield.Models;
using EmailShield.Services;
using Microsoft.AspNetCore.Mvc;

namespace EmailShield.Controllers;

[ApiController]
[Route("api/[controller]")]
public class SettingsController : ControllerBase
{
    private readonly SystemSettingsService _settingsService;
    private readonly EmailShieldDbContext _context;

    public SettingsController(SystemSettingsService settingsService, EmailShieldDbContext context)
    {
        _settingsService = settingsService;
        _context = context;
    }

    [HttpGet]
    public IActionResult GetSettings()
    {
        var settings = _settingsService.GetSettings();
        return Ok(settings);
    }

    [HttpPut]
    public async Task<IActionResult> UpdateSettings([FromBody] SystemSettingsDto newSettings, [FromQuery] int adminUserId = 1)
    {
        if (newSettings == null)
            return BadRequest(new { message = "Invalid settings payload." });

        _settingsService.UpdateSettings(newSettings);

        _context.AuditLogs.Add(new AuditLog
        {
            UserId = adminUserId > 0 ? adminUserId : null,
            Action = "SYSTEM_CONFIG_UPDATED",
            Description = "Administrator updated analysis rules, risk thresholds, and threat intelligence settings.",
            Ipaddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1",
            CreatedAt = DateTime.UtcNow
        });
        await _context.SaveChangesAsync();

        return Ok(new { success = true, message = "System settings and analysis rules updated successfully." });
    }

    [HttpPost("reset")]
    public async Task<IActionResult> ResetSettings([FromQuery] int adminUserId = 1)
    {
        var defaults = _settingsService.ResetToDefaults();

        _context.AuditLogs.Add(new AuditLog
        {
            UserId = adminUserId > 0 ? adminUserId : null,
            Action = "SYSTEM_CONFIG_RESET",
            Description = "Administrator restored default analysis rules and threat intelligence configuration.",
            Ipaddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1",
            CreatedAt = DateTime.UtcNow
        });
        await _context.SaveChangesAsync();

        return Ok(new { success = true, message = "Settings reset to defaults successfully.", settings = defaults });
    }
}

