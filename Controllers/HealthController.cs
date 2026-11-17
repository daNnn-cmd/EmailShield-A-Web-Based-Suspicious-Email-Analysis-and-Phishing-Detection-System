using EmailShield.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EmailShield.Controllers;

[ApiController]
[Route("api/[controller]")]
public class HealthController : ControllerBase
{
    private readonly EmailShieldDbContext _context;

    public HealthController(EmailShieldDbContext context)
    {
        _context = context;
    }

    [HttpGet("db-check")]
    public async Task<IActionResult> CheckDatabase()
    {
        try
        {
            var canConnect = await _context.Database.CanConnectAsync();
            if (canConnect)
            {
                var userCount = await _context.Users.CountAsync();
                return Ok(new
                {
                    status = "Connected",
                    database = "EmailShieldDB",
                    canConnect = true,
                    totalUsers = userCount
                });
            }

            return StatusCode(500, new { status = "Failed", message = "Cannot connect to database" });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { status = "Error", error = ex.Message });
        }
    }
}

