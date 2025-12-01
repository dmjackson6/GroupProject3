using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ProjectTutwiler.Data;
using ProjectTutwiler.Services.AI;
using ProjectTutwiler.Services.AI.DTOs;
using Microsoft.Extensions.DependencyInjection;

namespace ProjectTutwiler.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AnalysisController : ControllerBase
{
    private readonly VulnerabilityAnalysisService _analysisService;
    private readonly BioImpactAnalyzer _bioAnalyzer;
    private readonly IVulnerabilityRepository _repository;
    private readonly ApplicationDbContext _context;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<AnalysisController> _logger;

    public AnalysisController(
        VulnerabilityAnalysisService analysisService,
        BioImpactAnalyzer bioAnalyzer,
        IVulnerabilityRepository repository,
        ApplicationDbContext context,
        IServiceProvider serviceProvider,
        ILogger<AnalysisController> logger)
    {
        _analysisService = analysisService;
        _bioAnalyzer = bioAnalyzer;
        _repository = repository;
        _context = context;
        _serviceProvider = serviceProvider;
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
    /// Analyze ALL unanalyzed vulnerabilities in parallel (batch processing)
    /// </summary>
    /// <param name="maxConcurrency">Maximum concurrent analyses (default: 5, max: 10)</param>
    /// <returns>Batch analysis results with progress</returns>
    [HttpPost("analyze-all")]
    public async Task<ActionResult<object>> AnalyzeAll([FromQuery] int maxConcurrency = 5)
    {
        try
        {
            if (maxConcurrency < 1 || maxConcurrency > 10)
            {
                return BadRequest(new { error = "maxConcurrency must be between 1 and 10" });
            }

            _logger.LogInformation("Starting batch analysis for ALL unanalyzed vulnerabilities (max concurrency: {Concurrency})", maxConcurrency);

            // Find all vulnerabilities without BioImpactScores, prioritize by known exploited and CVSS
            var unanalyzed = await _context.Vulnerabilities
                .Where(v => v.BioImpactScore == null)
                .OrderByDescending(v => v.KnownExploited) // Prioritize exploited
                .ThenByDescending(v => v.CvssScore) // Then by severity
                .ThenByDescending(v => v.CreatedAt) // Then by recency
                .Select(v => v.Id)
                .ToListAsync();

            if (unanalyzed.Count == 0)
            {
                return Ok(new
                {
                    message = "No unanalyzed vulnerabilities found",
                    totalCount = 0,
                    processed = 0,
                    successCount = 0,
                    failureCount = 0,
                    results = new List<object>()
                });
            }

            _logger.LogInformation("Found {Count} unanalyzed vulnerabilities to process", unanalyzed.Count);

            // Get CVE IDs before parallel processing to avoid DbContext thread-safety issues
            var cveIdMap = await _context.Vulnerabilities
                .Where(v => unanalyzed.Contains(v.Id))
                .ToDictionaryAsync(v => v.Id, v => v.CveId);

            var semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);
            var results = new List<object>();
            int successCount = 0;
            int failureCount = 0;
            var tasks = new List<Task>();

            foreach (var vulnerabilityId in unanalyzed)
            {
                await semaphore.WaitAsync();
                tasks.Add(Task.Run(async () =>
                {
                    // Create a new scope for this task to get thread-safe services
                    using var scope = _serviceProvider.CreateScope();
                    var scopedAnalysisService = scope.ServiceProvider.GetRequiredService<VulnerabilityAnalysisService>();
                    
                    try
                    {
                        var analysis = await scopedAnalysisService.AnalyzeAndScoreVulnerabilityAsync(vulnerabilityId);
                        
                        var cveId = cveIdMap.GetValueOrDefault(vulnerabilityId, "Unknown");
                        lock (results)
                        {
                            results.Add(new
                            {
                                vulnerabilityId = vulnerabilityId,
                                cveId = cveId,
                                compositeScore = analysis?.CompositeScore,
                                priorityLevel = analysis?.PriorityLevel.ToString(),
                                status = "success"
                            });
                            successCount++;
                        }
                        
                        _logger.LogDebug("Successfully analyzed vulnerability ID {Id} ({CveId})", vulnerabilityId, cveId);
                    }
                    catch (Exception ex)
                    {
                        var cveId = cveIdMap.GetValueOrDefault(vulnerabilityId, "Unknown");
                        _logger.LogError(ex, "Failed to analyze {CveId}", cveId);
                        
                        lock (results)
                        {
                            results.Add(new
                            {
                                vulnerabilityId = vulnerabilityId,
                                cveId = cveId,
                                status = "failed",
                                error = ex.Message
                            });
                            failureCount++;
                        }
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            // Wait for all tasks to complete
            // Use a very long timeout (60 minutes) to handle large batches
            var timeoutTask = Task.Delay(TimeSpan.FromMinutes(60));
            var completedTask = await Task.WhenAny(Task.WhenAll(tasks), timeoutTask);
            
            if (completedTask == timeoutTask)
            {
                _logger.LogWarning("Batch analysis timed out after 60 minutes. {Success} succeeded, {Failure} failed out of {Total}",
                    successCount, failureCount, unanalyzed.Count);
                
                return Ok(new
                {
                    message = $"Batch analysis timed out after 60 minutes. {successCount} succeeded, {failureCount} failed. Some may still be processing.",
                    totalCount = unanalyzed.Count,
                    processed = successCount + failureCount,
                    successCount,
                    failureCount,
                    timedOut = true,
                    // Don't order results - just return them as-is to avoid issues with missing properties
                    results = results.ToList(),
                    timestamp = DateTime.UtcNow
                });
            }

            // Verify all were processed
            var processedCount = successCount + failureCount;
            var processedIds = results.Select(r => (int)((dynamic)r).vulnerabilityId).ToHashSet();
            var missingIds = unanalyzed.Where(id => !processedIds.Contains(id)).ToList();
            
            if (processedCount < unanalyzed.Count)
            {
                _logger.LogWarning("Not all vulnerabilities were processed. Expected {Expected}, got {Processed}. Missing {Missing} IDs",
                    unanalyzed.Count, processedCount, missingIds.Count);
                
                // Try to process missing ones (they might have been analyzed by another process)
                foreach (var missingId in missingIds)
                {
                    try
                    {
                        using var scope = _serviceProvider.CreateScope();
                        var scopedContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                        var alreadyAnalyzed = await scopedContext.BioImpactScores
                            .AnyAsync(b => b.VulnerabilityId == missingId);
                        
                        if (!alreadyAnalyzed)
                        {
                            _logger.LogWarning("Vulnerability ID {Id} was not processed and is not analyzed", missingId);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error checking missing vulnerability ID {Id}", missingId);
                    }
                }
            }

            _logger.LogInformation("Batch analysis completed: {Success} succeeded, {Failure} failed out of {Total}",
                successCount, failureCount, unanalyzed.Count);

            return Ok(new
            {
                message = $"Batch analysis completed: {successCount} succeeded, {failureCount} failed out of {unanalyzed.Count} total",
                totalCount = unanalyzed.Count,
                processed = processedCount,
                successCount,
                failureCount,
                timedOut = false,
                // Don't order results - just return them as-is to avoid issues with missing properties
                results = results.ToList(),
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
    /// Analyze multiple unanalyzed vulnerabilities in batch (limited)
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

