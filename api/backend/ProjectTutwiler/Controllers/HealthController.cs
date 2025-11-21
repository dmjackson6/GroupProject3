using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ProjectTutwiler.Data;

namespace ProjectTutwiler.Controllers;

[ApiController]
[Route("api/[controller]")]
public class HealthController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<HealthController> _logger;

    public HealthController(ApplicationDbContext context, ILogger<HealthController> logger)
    {
        _context = context;
        _logger = logger;
    }

    [HttpGet("db-test")]
    public async Task<IActionResult> TestDatabaseConnection()
    {
        try
        {
            // Attempt to open connection to database
            var canConnect = await _context.Database.CanConnectAsync();

            if (canConnect)
            {
                _logger.LogInformation("Database connection successful");
                return Ok(new
                {
                    status = "success",
                    message = "Database connection established successfully",
                    timestamp = DateTime.UtcNow
                });
            }
            else
            {
                _logger.LogWarning("Database connection failed - CanConnect returned false");
                return StatusCode(500, new
                {
                    status = "error",
                    message = "Unable to connect to the database",
                    timestamp = DateTime.UtcNow
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Database connection test failed with exception");
            return StatusCode(500, new
            {
                status = "error",
                message = "Database connection failed",
                error = ex.Message,
                timestamp = DateTime.UtcNow
            });
        }
    }
}

