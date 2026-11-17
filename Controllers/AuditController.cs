using EmailShield.Data;
using EmailShield.DTOs;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EmailShield.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuditController : ControllerBase
{
    private readonly EmailShieldDbContext _context;

    public AuditController(EmailShieldDbContext context)
    {
        _context = context;
    }

    [HttpGet]
    public async Task<IActionResult> GetLogs([FromQuery] int limit = 500)
    {
        var logs = await _context.AuditLogs
            .Include(a => a.User)
            .OrderByDescending(a => a.CreatedAt)
            .Take(limit)
            .Select(a => new AuditLogDto
            {
                AuditId = a.AuditId,
                UserId = a.UserId,
                UserName = a.User != null ? a.User.FullName : "System",
                Action = a.Action,
                Description = a.Description,
                IpAddress = a.Ipaddress,
                CreatedAt = a.CreatedAt
            })
            .ToListAsync();

        return Ok(logs);
    }
}
