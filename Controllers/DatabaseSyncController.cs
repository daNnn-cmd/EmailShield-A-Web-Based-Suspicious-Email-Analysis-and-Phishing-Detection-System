using EmailShield.DTOs;
using EmailShield.Services;
using Microsoft.AspNetCore.Mvc;

namespace EmailShield.Controllers;

[ApiController]
[Route("api/[controller]")]
[Route("api/database")]
public class DatabaseSyncController : ControllerBase
{
    private readonly DatabaseSyncService _syncService;
    private readonly ILogger<DatabaseSyncController> _logger;

    public DatabaseSyncController(DatabaseSyncService syncService, ILogger<DatabaseSyncController> logger)
    {
        _syncService = syncService;
        _logger = logger;
    }

    [HttpGet("status")]
    public async Task<IActionResult> GetStatus()
    {
        try
        {
            var summary = await _syncService.GetStatusAsync();
            return Ok(summary);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to retrieve database status.");
            return StatusCode(500, new { message = "Error checking database status.", error = ex.Message });
        }
    }

    [HttpPost("sync")]
    public async Task<IActionResult> RunSync([FromQuery] string direction = "Bidirectional")
    {
        try
        {
            var result = await _syncService.SyncDatabasesAsync(direction);
            if (!result.Success)
            {
                return BadRequest(result);
            }
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Database sync failed.");
            return StatusCode(500, new { message = "Database sync failed.", error = ex.Message });
        }
    }
}
