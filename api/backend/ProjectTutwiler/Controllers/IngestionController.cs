using Microsoft.AspNetCore.Mvc;
using ProjectTutwiler.Data;
using ProjectTutwiler.Models.Enums;
using ProjectTutwiler.Services.DataIngestion;

namespace ProjectTutwiler.Controllers;

[ApiController]
[Route("api/[controller]")]
public class IngestionController : ControllerBase
{
    private readonly VulnerabilityIngestionService _ingestionService;
    private readonly IngestionOrchestrator _orchestrator;
    private readonly IVulnerabilityRepository _repository;
    private readonly ILogger<IngestionController> _logger;
    private static DateTime? _lastIngestionTimestamp = null;
    private static IngestionResult? _lastIngestionResult = null;

    public IngestionController(
        VulnerabilityIngestionService ingestionService,
        IngestionOrchestrator orchestrator,
        IVulnerabilityRepository repository,
        ILogger<IngestionController> logger)
    {
        _ingestionService = ingestionService;
        _orchestrator = orchestrator;
        _repository = repository;
        _logger = logger;
    }

    /// <summary>
    /// Manually trigger vulnerability ingestion from NVD
    /// </summary>
    /// <param name="daysBack">Number of days to fetch vulnerabilities (default: 7)</param>
    /// <returns>Ingestion result with statistics</returns>
    [HttpPost("nvd")]
    public async Task<ActionResult<IngestionResult>> IngestFromNvd([FromQuery] int daysBack = 7)
    {
        try
        {
            if (daysBack < 1 || daysBack > 120)
            {
                return BadRequest(new { error = "daysBack must be between 1 and 120" });
            }

            _logger.LogInformation("Manual ingestion triggered for last {DaysBack} days", daysBack);

            var result = await _ingestionService.IngestFromNvdAsync(daysBack);

            // Cache the last ingestion result
            _lastIngestionTimestamp = DateTime.UtcNow;
            _lastIngestionResult = result;

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during manual ingestion");
            return StatusCode(500, new
            {
                error = "Ingestion failed",
                message = ex.Message,
                timestamp = DateTime.UtcNow
            });
        }
    }

    /// <summary>
    /// Manually trigger CISA KEV ingestion only
    /// </summary>
    /// <returns>Ingestion result with statistics</returns>
    [HttpPost("cisa-kev")]
    public async Task<ActionResult<IngestionResult>> IngestFromCisaKev()
    {
        try
        {
            _logger.LogInformation("Manual CISA KEV ingestion triggered");

            var result = await _ingestionService.IngestFromCisaKevAsync();

            // Cache the last ingestion result
            _lastIngestionTimestamp = DateTime.UtcNow;
            _lastIngestionResult = result;

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during CISA KEV ingestion");
            return StatusCode(500, new
            {
                error = "CISA KEV ingestion failed",
                message = ex.Message,
                timestamp = DateTime.UtcNow
            });
        }
    }

    /// <summary>
    /// Run full ingestion from both NVD and CISA KEV
    /// </summary>
    /// <param name="daysBack">Number of days to fetch NVD vulnerabilities (default: 7)</param>
    /// <returns>Combined ingestion result with statistics</returns>
    [HttpPost("full")]
    public async Task<ActionResult<CombinedIngestionResult>> RunFullIngestion([FromQuery] int daysBack = 7)
    {
        try
        {
            if (daysBack < 1 || daysBack > 120)
            {
                return BadRequest(new { error = "daysBack must be between 1 and 120" });
            }

            _logger.LogInformation("Full ingestion triggered: NVD ({DaysBack} days) + CISA KEV", daysBack);

            var result = await _orchestrator.RunFullIngestionAsync(daysBack);

            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during full ingestion");
            return StatusCode(500, new
            {
                error = "Full ingestion failed",
                message = ex.Message,
                timestamp = DateTime.UtcNow
            });
        }
    }

    /// <summary>
    /// Get ingestion status and database statistics
    /// </summary>
    /// <returns>Status information including vulnerability count and last ingestion time</returns>
    [HttpGet("status")]
    public async Task<ActionResult<object>> GetStatus()
    {
        try
        {
            var allVulnerabilities = await _repository.GetAllAsync(skip: 0, take: 1);
            var totalCount = (await _repository.GetAllAsync(skip: 0, take: 10000)).Count;

            return Ok(new
            {
                databaseStatus = "connected",
                totalVulnerabilities = totalCount,
                lastIngestionTimestamp = _lastIngestionTimestamp,
                lastIngestionResult = _lastIngestionResult,
                timestamp = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving ingestion status");
            return StatusCode(500, new
            {
                error = "Failed to retrieve status",
                message = ex.Message,
                timestamp = DateTime.UtcNow
            });
        }
    }

    /// <summary>
    /// Get detailed statistics about vulnerabilities
    /// </summary>
    /// <returns>Statistics including counts by priority and known exploited</returns>
    [HttpGet("stats")]
    public async Task<ActionResult<object>> GetStats()
    {
        try
        {
            var allVulns = await _repository.GetAllAsync(skip: 0, take: 10000);
            var totalCount = allVulns.Count;
            var knownExploitedCount = await _repository.CountKnownExploitedAsync();

            // Count by priority level
            var criticalCount = (await _repository.GetByPriorityLevelAsync(PriorityLevel.CRITICAL)).Count;
            var highCount = (await _repository.GetByPriorityLevelAsync(PriorityLevel.HIGH)).Count;
            var mediumCount = (await _repository.GetByPriorityLevelAsync(PriorityLevel.MEDIUM)).Count;
            var lowCount = (await _repository.GetByPriorityLevelAsync(PriorityLevel.LOW)).Count;

            return Ok(new
            {
                totalVulnerabilities = totalCount,
                knownExploited = knownExploitedCount,
                byPriority = new
                {
                    critical = criticalCount,
                    high = highCount,
                    medium = mediumCount,
                    low = lowCount,
                    unscored = totalCount - criticalCount - highCount - mediumCount - lowCount
                },
                lastIngestionTimestamp = _lastIngestionTimestamp,
                timestamp = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving statistics");
            return StatusCode(500, new
            {
                error = "Failed to retrieve statistics",
                message = ex.Message,
                timestamp = DateTime.UtcNow
            });
        }
    }
}

