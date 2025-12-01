using Microsoft.AspNetCore.Mvc;
using ProjectTutwiler.Services.Deduplication;

namespace ProjectTutwiler.Controllers;

[ApiController]
[Route("api/[controller]")]
public class DeduplicationController : ControllerBase
{
    private readonly VulnerabilityDeduplicationService _deduplicationService;
    private readonly ILogger<DeduplicationController> _logger;

    public DeduplicationController(
        VulnerabilityDeduplicationService deduplicationService,
        ILogger<DeduplicationController> logger)
    {
        _deduplicationService = deduplicationService;
        _logger = logger;
    }

    /// <summary>
    /// Deduplicate vulnerabilities by CVE ID, merging duplicates and keeping the most complete record
    /// </summary>
    [HttpPost("run")]
    public async Task<ActionResult<DeduplicationResult>> RunDeduplication()
    {
        try
        {
            _logger.LogInformation("Manual deduplication triggered");

            var result = await _deduplicationService.DeduplicateByCveIdAsync();

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during deduplication");
            return StatusCode(500, new
            {
                error = "Deduplication failed",
                message = ex.Message,
                timestamp = DateTime.UtcNow
            });
        }
    }
}

