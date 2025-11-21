using Microsoft.AspNetCore.Mvc;
using ProjectTutwiler.Data;
using ProjectTutwiler.Services.AI;
using ProjectTutwiler.Services.AI.DTOs;

namespace ProjectTutwiler.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AnalysisController : ControllerBase
{
    private readonly VulnerabilityAnalysisService _analysisService;
    private readonly BioImpactAnalyzer _bioAnalyzer;
    private readonly IVulnerabilityRepository _repository;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<AnalysisController> _logger;

    public AnalysisController(
        VulnerabilityAnalysisService analysisService,
        BioImpactAnalyzer bioAnalyzer,
        IVulnerabilityRepository repository,
        ApplicationDbContext context,
        ILogger<AnalysisController> logger)
    {
        _analysisService = analysisService;
        _bioAnalyzer = bioAnalyzer;
        _repository = repository;
        _context = context;
        _logger = logger;
    }

    /// <summary>
    /// Trigger AI analysis for a specific vulnerability
    /// </summary>
    /// <param name="id">Vulnerability ID</param>
    /// <returns>Bio-relevance analysis result</returns>
    [HttpPost("vulnerability/{id}")]
    public async Task<ActionResult<BioRelevanceAnalysis>> AnalyzeVulnerability(int id)
    {
        try
        {
            _logger.LogInformation("Analyzing vulnerability ID {Id}", id);

            var analysis = await _analysisService.AnalyzeAndScoreVulnerabilityAsync(id);

            return Ok(analysis);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "Vulnerability {Id} not found", id);
            return NotFound(new { error = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing vulnerability {Id}", id);
            return StatusCode(500, new
            {
                error = "Analysis failed",
                message = ex.Message,
                timestamp = DateTime.UtcNow
            });
        }
    }

    /// <summary>
    /// Analyze multiple unanalyzed vulnerabilities in batch
    /// </summary>
    /// <param name="limit">Maximum number of vulnerabilities to analyze (default: 10, max: 50)</param>
    /// <returns>Batch analysis results</returns>
    [HttpPost("batch")]
    public async Task<ActionResult<object>> AnalyzeBatch([FromQuery] int limit = 10)
    {
        try
        {
            if (limit < 1 || limit > 50)
            {
                return BadRequest(new { error = "Limit must be between 1 and 50" });
            }

            _logger.LogInformation("Starting batch analysis for up to {Limit} vulnerabilities", limit);

            // Find vulnerabilities without BioImpactScores
            var unanalyzed = _context.Vulnerabilities
                .Where(v => v.BioImpactScore == null)
                .OrderByDescending(v => v.CreatedAt)
                .Take(limit)
                .ToList();

            if (unanalyzed.Count == 0)
            {
                return Ok(new
                {
                    message = "No unanalyzed vulnerabilities found",
                    processed = 0,
                    results = new List<object>()
                });
            }

            _logger.LogInformation("Found {Count} unanalyzed vulnerabilities", unanalyzed.Count);

            var results = new List<object>();
            int successCount = 0;
            int failureCount = 0;

            foreach (var vulnerability in unanalyzed)
            {
                try
                {
                    var analysis = await _analysisService.AnalyzeAndScoreVulnerabilityAsync(vulnerability.Id);
                    
                    results.Add(new
                    {
                        vulnerabilityId = vulnerability.Id,
                        cveId = vulnerability.CveId,
                        compositeScore = analysis?.CompositeScore,
                        priorityLevel = analysis?.PriorityLevel.ToString(),
                        affectedBioSectors = analysis?.AffectedBioSectors,
                        confidence = analysis?.BioRelevanceConfidence,
                        status = "success"
                    });

                    successCount++;
                    _logger.LogInformation("Successfully analyzed {CveId}", vulnerability.CveId);

                    // Add small delay between analyses to avoid overwhelming Ollama
                    if (unanalyzed.IndexOf(vulnerability) < unanalyzed.Count - 1)
                    {
                        await Task.Delay(500);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to analyze {CveId}", vulnerability.CveId);
                    
                    results.Add(new
                    {
                        vulnerabilityId = vulnerability.Id,
                        cveId = vulnerability.CveId,
                        status = "failed",
                        error = ex.Message
                    });

                    failureCount++;
                }
            }

            return Ok(new
            {
                message = $"Batch analysis completed: {successCount} succeeded, {failureCount} failed",
                processed = unanalyzed.Count,
                successCount,
                failureCount,
                results,
                timestamp = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during batch analysis");
            return StatusCode(500, new
            {
                error = "Batch analysis failed",
                message = ex.Message,
                timestamp = DateTime.UtcNow
            });
        }
    }

    /// <summary>
    /// Test AI analysis on a specific CVE without saving to database
    /// </summary>
    /// <param name="cveId">CVE ID (e.g., CVE-2024-12345)</param>
    /// <returns>Analysis result (not saved)</returns>
    [HttpGet("test")]
    public async Task<ActionResult<BioRelevanceAnalysis>> TestAnalysis([FromQuery] string cveId)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(cveId))
            {
                return BadRequest(new { error = "cveId parameter is required" });
            }

            _logger.LogInformation("Test analysis for {CveId}", cveId);

            var vulnerability = await _repository.GetByCveIdAsync(cveId);
            
            if (vulnerability == null)
            {
                return NotFound(new { error = $"Vulnerability {cveId} not found" });
            }

            // Run analysis without saving
            var analysis = await _bioAnalyzer.AnalyzeVulnerabilityAsync(vulnerability);

            return Ok(new
            {
                cveId = vulnerability.CveId,
                description = vulnerability.Description,
                vendor = vulnerability.VendorName,
                cvssScore = vulnerability.CvssScore,
                knownExploited = vulnerability.KnownExploited,
                analysis,
                note = "Test analysis - not saved to database",
                timestamp = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during test analysis for {CveId}", cveId);
            return StatusCode(500, new
            {
                error = "Test analysis failed",
                message = ex.Message,
                timestamp = DateTime.UtcNow
            });
        }
    }

    /// <summary>
    /// Get analysis statistics
    /// </summary>
    /// <returns>Statistics about analyzed vulnerabilities</returns>
    [HttpGet("stats")]
    public ActionResult<object> GetAnalysisStats()
    {
        try
        {
            var totalVulnerabilities = _context.Vulnerabilities.Count();
            var analyzedCount = _context.BioImpactScores.Count();
            var unanalyzedCount = totalVulnerabilities - analyzedCount;

            var bioRelevantCount = _context.BioImpactScores
                .Where(s => s.HumanSafetyScore > 30)
                .Count();

            var bySector = _context.BioImpactScores
                .Where(s => !string.IsNullOrEmpty(s.AffectedBioSectors))
                .AsEnumerable()
                .SelectMany(s =>
                {
                    try
                    {
                        return System.Text.Json.JsonSerializer.Deserialize<List<string>>(s.AffectedBioSectors ?? "[]") ?? new List<string>();
                    }
                    catch
                    {
                        return new List<string>();
                    }
                })
                .GroupBy(sector => sector)
                .Select(g => new { sector = g.Key, count = g.Count() })
                .OrderByDescending(x => x.count)
                .ToList();

            return Ok(new
            {
                totalVulnerabilities,
                analyzedCount,
                unanalyzedCount,
                bioRelevantCount,
                analysisProgress = totalVulnerabilities > 0
                    ? Math.Round((double)analyzedCount / totalVulnerabilities * 100, 2)
                    : 0,
                sectorBreakdown = bySector,
                timestamp = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving analysis statistics");
            return StatusCode(500, new
            {
                error = "Failed to retrieve statistics",
                message = ex.Message
            });
        }
    }
}

