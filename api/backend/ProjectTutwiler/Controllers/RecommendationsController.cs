using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ProjectTutwiler.Data;
using ProjectTutwiler.Services.Recommendations;

namespace ProjectTutwiler.Controllers;

[ApiController]
[Route("api/[controller]")]
public class RecommendationsController : ControllerBase
{
    private readonly RecommendationService _recommendationService;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<RecommendationsController> _logger;

    public RecommendationsController(
        RecommendationService recommendationService,
        ApplicationDbContext context,
        ILogger<RecommendationsController> logger)
    {
        _recommendationService = recommendationService;
        _context = context;
        _logger = logger;
    }

    /// <summary>
    /// Get all recommendations for a specific vulnerability
    /// </summary>
    [HttpGet("vulnerability/{id}")]
    public async Task<ActionResult> GetVulnerabilityRecommendations(int id)
    {
        try
        {
            var recommendations = await _context.ActionRecommendations
                .Where(r => r.VulnerabilityId == id)
                .OrderBy(r => r.RecommendationType)
                .Select(r => new
                {
                    r.Id,
                    r.VulnerabilityId,
                    r.RecommendationType,
                    r.ActionText,
                    r.SafeToImplement,
                    r.RequiresTier2,
                    r.CreatedAt
                })
                .ToListAsync();

            if (!recommendations.Any())
            {
                return NotFound(new { message = $"No recommendations found for vulnerability ID {id}" });
            }

            return Ok(new
            {
                VulnerabilityId = id,
                TotalRecommendations = recommendations.Count,
                Recommendations = recommendations
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving recommendations for vulnerability {Id}", id);
            return StatusCode(500, new { message = "Internal server error retrieving recommendations" });
        }
    }

    /// <summary>
    /// Generate and save new recommendations for a vulnerability
    /// </summary>
    [HttpPost("generate/{id}")]
    public async Task<ActionResult> GenerateRecommendations(int id)
    {
        try
        {
            var recommendations = await _recommendationService.GenerateRecommendationsAsync(id);

            return Ok(new
            {
                VulnerabilityId = id,
                TotalGenerated = recommendations.Count,
                Recommendations = recommendations.Select(r => new
                {
                    r.Id,
                    r.VulnerabilityId,
                    r.RecommendationType,
                    r.ActionText,
                    r.SafeToImplement,
                    r.RequiresTier2,
                    r.CreatedAt
                })
            });
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "Cannot generate recommendations for vulnerability {Id}", id);
            return BadRequest(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating recommendations for vulnerability {Id}", id);
            return StatusCode(500, new { message = "Internal server error generating recommendations" });
        }
    }

    /// <summary>
    /// Get formatted summary with vulnerability details, score, and grouped recommendations
    /// </summary>
    [HttpGet("summary/{id}")]
    public async Task<ActionResult> GetRecommendationSummary(int id)
    {
        try
        {
            var vulnerability = await _context.Vulnerabilities
                .Include(v => v.BioImpactScore)
                .Include(v => v.ActionRecommendations)
                .FirstOrDefaultAsync(v => v.Id == id);

            if (vulnerability == null)
            {
                return NotFound(new { message = $"Vulnerability ID {id} not found" });
            }

            if (vulnerability.BioImpactScore == null)
            {
                return BadRequest(new { message = $"Vulnerability {vulnerability.CveId} has not been analyzed yet" });
            }

            if (!vulnerability.ActionRecommendations.Any())
            {
                return NotFound(new { message = $"No recommendations found for {vulnerability.CveId}. Use POST /api/recommendations/generate/{id} to create them." });
            }

            // Group recommendations by type
            var groupedRecommendations = vulnerability.ActionRecommendations
                .GroupBy(r => r.RecommendationType)
                .OrderBy(g => g.Key)
                .Select(g => new
                {
                    Type = g.Key.ToString(),
                    Count = g.Count(),
                    Actions = g.Select(r => new
                    {
                        r.Id,
                        r.ActionText,
                        r.SafeToImplement,
                        r.RequiresTier2
                    }).ToList()
                })
                .ToList();

            return Ok(new
            {
                Vulnerability = new
                {
                    vulnerability.Id,
                    vulnerability.CveId,
                    vulnerability.Description,
                    vulnerability.CvssScore,
                    vulnerability.PublishedDate,
                    vulnerability.KnownExploited,
                    vulnerability.VendorName
                },
                BioImpactScore = new
                {
                    vulnerability.BioImpactScore.CompositeScore,
                    vulnerability.BioImpactScore.PriorityLevel,
                    vulnerability.BioImpactScore.HumanSafetyScore,
                    vulnerability.BioImpactScore.SupplyChainScore,
                    vulnerability.BioImpactScore.ExploitabilityScore,
                    vulnerability.BioImpactScore.PatchAvailabilityScore,
                    vulnerability.BioImpactScore.AffectedBioSectors,
                    vulnerability.BioImpactScore.BioRelevanceConfidence
                },
                RecommendationSummary = new
                {
                    TotalRecommendations = vulnerability.ActionRecommendations.Count,
                    RequiresTier2Escalation = vulnerability.ActionRecommendations.Any(r => r.RequiresTier2),
                    AllSafeToImplement = vulnerability.ActionRecommendations.All(r => r.SafeToImplement),
                    GroupedByType = groupedRecommendations
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving recommendation summary for vulnerability {Id}", id);
            return StatusCode(500, new { message = "Internal server error retrieving summary" });
        }
    }

    /// <summary>
    /// Get statistics about recommendations across all vulnerabilities
    /// </summary>
    [HttpGet("stats")]
    public async Task<ActionResult> GetRecommendationStats()
    {
        try
        {
            var totalRecommendations = await _context.ActionRecommendations.CountAsync();
            
            if (totalRecommendations == 0)
            {
                return Ok(new { message = "No recommendations generated yet" });
            }

            var stats = await _context.ActionRecommendations
                .GroupBy(r => 1)
                .Select(g => new
                {
                    TotalRecommendations = g.Count(),
                    VulnerabilitiesWithRecommendations = g.Select(r => r.VulnerabilityId).Distinct().Count(),
                    SafeToImplementCount = g.Count(r => r.SafeToImplement),
                    RequiresTier2Count = g.Count(r => r.RequiresTier2),
                    ByType = g.GroupBy(r => r.RecommendationType)
                        .Select(tg => new
                        {
                            Type = tg.Key.ToString(),
                            Count = tg.Count()
                        })
                        .ToList()
                })
                .FirstOrDefaultAsync();

            return Ok(stats);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving recommendation statistics");
            return StatusCode(500, new { message = "Internal server error retrieving stats" });
        }
    }
}

