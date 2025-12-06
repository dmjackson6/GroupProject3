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
    /// Generate recommendations for all analyzed vulnerabilities that don't have them yet
    /// </summary>
    [HttpPost("generate-all-missing")]
    public async Task<ActionResult> GenerateAllMissingRecommendations()
    {
        try
        {
            _logger.LogInformation("Starting batch generation of recommendations for analyzed vulnerabilities without recommendations");

            // Find all vulnerabilities that have BioImpactScore but no ActionRecommendations
            var vulnerabilitiesWithoutRecommendations = await _context.Vulnerabilities
                .Include(v => v.BioImpactScore)
                .Where(v => v.BioImpactScore != null)
                .Where(v => !v.ActionRecommendations.Any())
                .Select(v => new { v.Id, v.CveId })
                .ToListAsync();

            if (vulnerabilitiesWithoutRecommendations.Count == 0)
            {
                return Ok(new
                {
                    message = "All analyzed vulnerabilities already have recommendations",
                    totalProcessed = 0,
                    successCount = 0,
                    failureCount = 0,
                    results = new List<object>()
                });
            }

            _logger.LogInformation("Found {Count} analyzed vulnerabilities without recommendations", vulnerabilitiesWithoutRecommendations.Count);

            var results = new List<object>();
            int successCount = 0;
            int failureCount = 0;

            foreach (var vuln in vulnerabilitiesWithoutRecommendations)
            {
                try
                {
                    var recommendations = await _recommendationService.GenerateRecommendationsAsync(vuln.Id);
                    results.Add(new
                    {
                        vulnerabilityId = vuln.Id,
                        cveId = vuln.CveId,
                        status = "success",
                        recommendationsGenerated = recommendations.Count
                    });
                    successCount++;
                    _logger.LogDebug("Generated {Count} recommendations for {CveId}", recommendations.Count, vuln.CveId);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to generate recommendations for {CveId}", vuln.CveId);
                    results.Add(new
                    {
                        vulnerabilityId = vuln.Id,
                        cveId = vuln.CveId,
                        status = "failed",
                        error = ex.Message
                    });
                    failureCount++;
                }
            }

            _logger.LogInformation("Completed batch recommendation generation: {Success} succeeded, {Failure} failed out of {Total}",
                successCount, failureCount, vulnerabilitiesWithoutRecommendations.Count);

            return Ok(new
            {
                message = $"Generated recommendations for {successCount} vulnerabilities. {failureCount} failed.",
                totalFound = vulnerabilitiesWithoutRecommendations.Count,
                successCount,
                failureCount,
                results
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in batch recommendation generation");
            return StatusCode(500, new { message = "Internal server error during batch recommendation generation", error = ex.Message });
        }
    }

    /// <summary>
    /// Regenerate all recommendations for analyzed vulnerabilities with new personalized templates
    /// </summary>
    [HttpPost("regenerate-all")]
    public async Task<ActionResult> RegenerateAllRecommendations([FromQuery] int? limit = null)
    {
        try
        {
            _logger.LogInformation("Starting regeneration of all recommendations with personalized templates");

            // Find all vulnerabilities that have BioImpactScore (analyzed)
            var analyzedVulnerabilities = await _context.Vulnerabilities
                .Include(v => v.BioImpactScore)
                .Where(v => v.BioImpactScore != null)
                .Select(v => new { v.Id, v.CveId })
                .ToListAsync();

            if (analyzedVulnerabilities.Count == 0)
            {
                return Ok(new
                {
                    message = "No analyzed vulnerabilities found",
                    totalProcessed = 0,
                    successCount = 0,
                    failureCount = 0,
                    results = new List<object>()
                });
            }

            _logger.LogInformation("Found {Count} analyzed vulnerabilities to regenerate recommendations for", analyzedVulnerabilities.Count);

            // Apply limit if specified (for testing)
            if (limit.HasValue && limit.Value > 0)
            {
                analyzedVulnerabilities = analyzedVulnerabilities.Take(limit.Value).ToList();
                _logger.LogInformation("Limited to processing {Count} vulnerabilities for testing", analyzedVulnerabilities.Count);
            }

            var results = new List<object>();
            int successCount = 0;
            int failureCount = 0;
            int skippedCount = 0;

            foreach (var vuln in analyzedVulnerabilities)
            {
                try
                {
                    // Check if recommendations already exist and are personalized
                    var existingRecs = await _context.ActionRecommendations
                        .Where(r => r.VulnerabilityId == vuln.Id)
                        .ToListAsync();
                    
                    // Check if recommendations are already personalized
                    // New personalized recommendations have distinct markers that old ones don't:
                    // 1. CVE ID in parentheses format: (CVE-XXXX-XXXX)
                    // 2. CVSS score format: CVSS X.X
                    // 3. Exploit warning emoji: ⚠️
                    // Old recommendations don't have these patterns
                    bool isPersonalized = false;
                    if (existingRecs.Any())
                    {
                        var vulnerability = await _context.Vulnerabilities
                            .Include(v => v.BioImpactScore)
                            .FirstOrDefaultAsync(v => v.Id == vuln.Id);
                        
                        if (vulnerability != null)
                        {
                            // Check for new template markers (these are ONLY in personalized recommendations):
                            // 1. CVE ID in parentheses - new format: "(CVE-2025-XXXX)"
                            bool hasCveInParentheses = existingRecs.Any(r => 
                                r.ActionText.Contains($"({vulnerability.CveId})"));
                            
                            // 2. CVSS score format - new format: "CVSS X.X"
                            bool hasCvssFormat = existingRecs.Any(r => 
                                r.ActionText.Contains("CVSS") && r.ActionText.Contains("."));
                            
                            // 3. Exploit warning emoji - new format: "⚠️"
                            bool hasExploitEmoji = existingRecs.Any(r => 
                                r.ActionText.Contains("⚠️"));
                            
                            // If it has ANY of these new format markers, it's personalized
                            isPersonalized = hasCveInParentheses || hasCvssFormat || hasExploitEmoji;
                        }
                    }
                    
                    // Skip if already personalized
                    if (isPersonalized)
                    {
                        _logger.LogInformation("Skipping vulnerability ID {Id} ({CveId}) - already has personalized recommendations", vuln.Id, vuln.CveId);
                        results.Add(new
                        {
                            vulnerabilityId = vuln.Id,
                            cveId = vuln.CveId,
                            status = "skipped",
                            reason = "Already has personalized recommendations"
                        });
                        skippedCount++;
                        continue;
                    }
                    
                    _logger.LogInformation("Processing vulnerability ID {Id} ({CveId}) - needs regeneration", vuln.Id, vuln.CveId);
                    
                    // Delete existing recommendations if they exist
                    if (existingRecs.Any())
                    {
                        _context.ActionRecommendations.RemoveRange(existingRecs);
                        await _context.SaveChangesAsync();
                    }

                    // Generate new personalized recommendations
                    var recommendations = await _recommendationService.GenerateRecommendationsAsync(vuln.Id);
                    
                    results.Add(new
                    {
                        vulnerabilityId = vuln.Id,
                        cveId = vuln.CveId,
                        status = "success",
                        recommendationsGenerated = recommendations.Count,
                        previousCount = existingRecs.Count
                    });
                    successCount++;
                    _logger.LogDebug("Regenerated {Count} recommendations for {CveId}", recommendations.Count, vuln.CveId);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to regenerate recommendations for {CveId}", vuln.CveId);
                    results.Add(new
                    {
                        vulnerabilityId = vuln.Id,
                        cveId = vuln.CveId,
                        status = "failed",
                        error = ex.Message
                    });
                    failureCount++;
                }
            }

            _logger.LogInformation("Completed recommendation regeneration: {Success} succeeded, {Failure} failed, {Skipped} skipped out of {Total}",
                successCount, failureCount, skippedCount, analyzedVulnerabilities.Count);

            return Ok(new
            {
                message = $"Regenerated recommendations for {successCount} vulnerabilities. {failureCount} failed. {skippedCount} skipped (already personalized).",
                totalFound = analyzedVulnerabilities.Count,
                successCount,
                failureCount,
                skippedCount,
                results
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in batch recommendation regeneration");
            return StatusCode(500, new { message = "Internal server error during batch recommendation regeneration", error = ex.Message });
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

