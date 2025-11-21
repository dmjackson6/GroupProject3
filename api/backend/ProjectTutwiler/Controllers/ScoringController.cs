using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ProjectTutwiler.Data;
using ProjectTutwiler.Models;

namespace ProjectTutwiler.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ScoringController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<ScoringController> _logger;

    public ScoringController(ApplicationDbContext context, ILogger<ScoringController> logger)
    {
        _context = context;
        _logger = logger;
    }

    /// <summary>
    /// Get BioImpactScore for a specific vulnerability
    /// </summary>
    [HttpGet("vulnerability/{id}")]
    public async Task<ActionResult<BioImpactScore>> GetVulnerabilityScore(int id)
    {
        try
        {
            var score = await _context.BioImpactScores
                .Include(b => b.Vulnerability)
                .FirstOrDefaultAsync(b => b.VulnerabilityId == id);

            if (score == null)
            {
                return NotFound(new { message = $"No bio-impact score found for vulnerability ID {id}" });
            }

            return Ok(score);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving score for vulnerability {Id}", id);
            return StatusCode(500, new { message = "Internal server error retrieving score" });
        }
    }

    /// <summary>
    /// Get distribution of vulnerabilities by priority level
    /// </summary>
    [HttpGet("distribution")]
    public async Task<ActionResult> GetDistribution()
    {
        try
        {
            var distribution = await _context.BioImpactScores
                .GroupBy(b => b.PriorityLevel)
                .Select(g => new
                {
                    PriorityLevel = g.Key,
                    Count = g.Count(),
                    AverageCompositeScore = Math.Round(g.Average(b => (double)b.CompositeScore), 2)
                })
                .OrderByDescending(x => x.PriorityLevel)
                .ToListAsync();

            var totalCount = await _context.BioImpactScores.CountAsync();

            return Ok(new
            {
                TotalScored = totalCount,
                Distribution = distribution
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving score distribution");
            return StatusCode(500, new { message = "Internal server error retrieving distribution" });
        }
    }

    /// <summary>
    /// Get top critical vulnerabilities by composite score
    /// </summary>
    [HttpGet("top-critical")]
    public async Task<ActionResult> GetTopCritical([FromQuery] int limit = 10)
    {
        try
        {
            if (limit < 1 || limit > 100)
            {
                return BadRequest(new { message = "Limit must be between 1 and 100" });
            }

            var topCritical = await _context.BioImpactScores
                .Include(b => b.Vulnerability)
                .OrderByDescending(b => b.CompositeScore)
                .ThenByDescending(b => b.HumanSafetyScore)
                .Take(limit)
                .Select(b => new
                {
                    b.Id,
                    b.VulnerabilityId,
                    CveId = b.Vulnerability.CveId,
                    Description = b.Vulnerability.Description.Length > 150 
                        ? b.Vulnerability.Description.Substring(0, 150) + "..." 
                        : b.Vulnerability.Description,
                    b.CompositeScore,
                    b.PriorityLevel,
                    b.HumanSafetyScore,
                    b.SupplyChainScore,
                    b.ExploitabilityScore,
                    b.PatchAvailabilityScore,
                    b.AffectedBioSectors,
                    KnownExploited = b.Vulnerability.KnownExploited,
                    CvssScore = b.Vulnerability.CvssScore,
                    PublishedDate = b.Vulnerability.PublishedDate,
                    b.CreatedAt
                })
                .ToListAsync();

            return Ok(new
            {
                Limit = limit,
                ResultCount = topCritical.Count,
                Vulnerabilities = topCritical
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving top critical vulnerabilities");
            return StatusCode(500, new { message = "Internal server error retrieving top critical" });
        }
    }

    /// <summary>
    /// Get summary statistics for all scored vulnerabilities
    /// </summary>
    [HttpGet("stats")]
    public async Task<ActionResult> GetStats()
    {
        try
        {
            var stats = await _context.BioImpactScores
                .GroupBy(b => 1)
                .Select(g => new
                {
                    TotalScored = g.Count(),
                    AverageCompositeScore = Math.Round(g.Average(b => (double)b.CompositeScore), 2),
                    AverageHumanSafetyScore = Math.Round(g.Average(b => b.HumanSafetyScore), 2),
                    AverageSupplyChainScore = Math.Round(g.Average(b => b.SupplyChainScore), 2),
                    AverageExploitabilityScore = Math.Round(g.Average(b => b.ExploitabilityScore), 2),
                    AveragePatchAvailabilityScore = Math.Round(g.Average(b => b.PatchAvailabilityScore), 2),
                    MaxCompositeScore = g.Max(b => b.CompositeScore),
                    MinCompositeScore = g.Min(b => b.CompositeScore)
                })
                .FirstOrDefaultAsync();

            if (stats == null)
            {
                return Ok(new { message = "No scored vulnerabilities found" });
            }

            return Ok(stats);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving scoring statistics");
            return StatusCode(500, new { message = "Internal server error retrieving stats" });
        }
    }
}

