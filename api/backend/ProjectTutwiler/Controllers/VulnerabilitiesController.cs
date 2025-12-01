using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ProjectTutwiler.Data;
using ProjectTutwiler.DTOs;
using ProjectTutwiler.Models.Enums;
using MySqlConnector;

namespace ProjectTutwiler.Controllers;

[ApiController]
[Route("api/[controller]")]
public class VulnerabilitiesController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<VulnerabilitiesController> _logger;

    public VulnerabilitiesController(ApplicationDbContext context, ILogger<VulnerabilitiesController> logger)
    {
        _context = context;
        _logger = logger;
    }

    /// <summary>
    /// Get paginated list of vulnerabilities with optional filtering
    /// </summary>
    [HttpGet]
    public async Task<ActionResult> GetVulnerabilities(
        [FromQuery] PriorityLevel? priorityLevel = null,
        [FromQuery] int? daysBack = null,
        [FromQuery] int skip = 0,
        [FromQuery] int take = 50)
    {
        try
        {
            if (take > 100) take = 100; // Limit max page size
            if (skip < 0) skip = 0;

            var query = _context.Vulnerabilities
                .Include(v => v.BioImpactScore)
                .Include(v => v.ActionRecommendations)
                .AsQueryable();

            // Filter by priority level
            if (priorityLevel.HasValue)
            {
                query = query.Where(v => 
                    v.BioImpactScore != null && 
                    v.BioImpactScore.PriorityLevel == priorityLevel.Value);
            }

            // Filter by date range
            if (daysBack.HasValue && daysBack.Value > 0)
            {
                var cutoffDate = DateTime.UtcNow.AddDays(-daysBack.Value);
                query = query.Where(v => v.PublishedDate >= cutoffDate);
            }

            // Get total count before pagination
            var totalCount = await query.CountAsync();

            // Apply pagination and ordering
            // Order by composite score (nulls last), then by other criteria
            var vulnerabilities = await query
                .OrderByDescending(v => v.BioImpactScore != null ? (decimal?)v.BioImpactScore.CompositeScore : null)
                .ThenByDescending(v => v.KnownExploited)
                .ThenByDescending(v => v.CvssScore ?? 0)
                .ThenByDescending(v => v.PublishedDate ?? DateTime.MinValue)
                .Skip(skip)
                .Take(take)
                .ToListAsync();

            var dtoList = vulnerabilities.Select(VulnerabilitySummaryDto.FromEntity).ToList();

            return Ok(new
            {
                TotalCount = totalCount,
                Skip = skip,
                Take = take,
                PageCount = (int)Math.Ceiling(totalCount / (double)take),
                CurrentPage = (skip / take) + 1,
                Filters = new
                {
                    PriorityLevel = priorityLevel?.ToString(),
                    DaysBack = daysBack
                },
                Data = dtoList
            });
        }
        catch (MySqlException mysqlEx) when (mysqlEx.Message.Contains("max_questions"))
        {
            _logger.LogError(mysqlEx, "Database query limit exceeded. Please wait for the limit to reset.");
            return StatusCode(503, new { 
                message = "Database query limit exceeded. Please try again in a few minutes.",
                error = "Service temporarily unavailable due to database limits"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving vulnerabilities. Skip: {Skip}, Take: {Take}, Exception: {ExceptionType}, Message: {Message}", 
                skip, take, ex.GetType().Name, ex.Message);
            return StatusCode(500, new { 
                message = "Internal server error",
                error = ex.Message,
                details = ex.GetType().Name
            });
        }
    }

    /// <summary>
    /// Get single vulnerability by ID with all details
    /// </summary>
    [HttpGet("{id}")]
    public async Task<ActionResult> GetVulnerability(int id)
    {
        try
        {
            var vulnerability = await _context.Vulnerabilities
                .Include(v => v.BioImpactScore)
                .Include(v => v.ActionRecommendations)
                .FirstOrDefaultAsync(v => v.Id == id);

            if (vulnerability == null)
            {
                return NotFound(new { message = $"Vulnerability with ID {id} not found" });
            }

            var dto = VulnerabilityDto.FromEntity(vulnerability);
            return Ok(dto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving vulnerability {Id}", id);
            return StatusCode(500, new { message = "Internal server error" });
        }
    }

    /// <summary>
    /// Get comprehensive statistics for dashboard
    /// </summary>
    [HttpGet("stats")]
    public async Task<ActionResult<DashboardStatsDto>> GetStats()
    {
        try
        {
            var stats = new DashboardStatsDto();

            // Optimize: Get multiple counts in parallel to reduce query time
            var totalTask = _context.Vulnerabilities.CountAsync();
            var analyzedTask = _context.BioImpactScores.CountAsync();
            var exploitedTask = _context.Vulnerabilities.Where(v => v.KnownExploited).CountAsync();
            
            await Task.WhenAll(totalTask, analyzedTask, exploitedTask);
            
            stats.TotalVulnerabilities = await totalTask;
            stats.AnalyzedVulnerabilities = await analyzedTask;
            stats.UnanalyzedVulnerabilities = stats.TotalVulnerabilities - stats.AnalyzedVulnerabilities;
            stats.KnownExploitedCount = await exploitedTask;

            // Priority breakdown
            var priorityCounts = await _context.BioImpactScores
                .GroupBy(b => b.PriorityLevel)
                .Select(g => new { Priority = g.Key, Count = g.Count() })
                .ToListAsync();

            foreach (var pc in priorityCounts)
            {
                switch (pc.Priority)
                {
                    case PriorityLevel.CRITICAL:
                        stats.PriorityBreakdown.Critical = pc.Count;
                        break;
                    case PriorityLevel.HIGH:
                        stats.PriorityBreakdown.High = pc.Count;
                        break;
                    case PriorityLevel.MEDIUM:
                        stats.PriorityBreakdown.Medium = pc.Count;
                        break;
                    case PriorityLevel.LOW:
                        stats.PriorityBreakdown.Low = pc.Count;
                        break;
                }
            }

            // Recent activity - optimize with parallel queries
            var latestTask = _context.Vulnerabilities
                .OrderByDescending(v => v.CreatedAt)
                .Select(v => v.CreatedAt)
                .FirstOrDefaultAsync();
            
            var twentyFourHoursAgo = DateTime.UtcNow.AddHours(-24);
            var last24HoursTask = _context.Vulnerabilities
                .Where(v => v.CreatedAt >= twentyFourHoursAgo)
                .CountAsync();

            var sevenDaysAgo = DateTime.UtcNow.AddDays(-7);
            var last7DaysTask = _context.Vulnerabilities
                .Where(v => v.CreatedAt >= sevenDaysAgo)
                .CountAsync();
            
            await Task.WhenAll(latestTask, last24HoursTask, last7DaysTask);
            
            stats.LastIngestionTime = await latestTask;
            stats.VulnerabilitiesLast24Hours = await last24HoursTask;
            stats.VulnerabilitiesLast7Days = await last7DaysTask;

            // CVSS distribution
            var cvssDistribution = await _context.Vulnerabilities
                .GroupBy(v => v.CvssScore.HasValue
                    ? v.CvssScore >= 9.0m ? "Critical"
                    : v.CvssScore >= 7.0m ? "High"
                    : v.CvssScore >= 4.0m ? "Medium"
                    : "Low"
                    : "Unknown")
                .Select(g => new { Severity = g.Key, Count = g.Count() })
                .ToListAsync();

            foreach (var cd in cvssDistribution)
            {
                switch (cd.Severity)
                {
                    case "Critical":
                        stats.CvssDistribution.Critical = cd.Count;
                        break;
                    case "High":
                        stats.CvssDistribution.High = cd.Count;
                        break;
                    case "Medium":
                        stats.CvssDistribution.Medium = cd.Count;
                        break;
                    case "Low":
                        stats.CvssDistribution.Low = cd.Count;
                        break;
                    case "Unknown":
                        stats.CvssDistribution.Unknown = cd.Count;
                        break;
                }
            }

            // Average composite score
            var avgScoreTask = _context.BioImpactScores.AverageAsync(b => (double?)b.CompositeScore);
            var avgScore = await avgScoreTask;
            stats.AverageCompositeScore = avgScore.HasValue ? (decimal)Math.Round(avgScore.Value, 2) : 0;

            return Ok(stats);
        }
        catch (MySqlConnector.MySqlException mysqlEx) when (mysqlEx.Message.Contains("max_questions"))
        {
            _logger.LogError(mysqlEx, "Database query limit exceeded. Please wait for the limit to reset.");
            return StatusCode(503, new { 
                message = "Database query limit exceeded. Please try again in a few minutes.",
                error = "Service temporarily unavailable due to database limits"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving vulnerability statistics. Exception: {ExceptionType}, Message: {Message}", 
                ex.GetType().Name, ex.Message);
            return StatusCode(500, new { 
                message = "Internal server error",
                error = ex.Message,
                details = ex.GetType().Name
            });
        }
    }

    /// <summary>
    /// Search vulnerabilities by CVE ID or description text
    /// </summary>
    [HttpGet("search")]
    public async Task<ActionResult> SearchVulnerabilities([FromQuery] string query, [FromQuery] int limit = 20)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(query))
            {
                return BadRequest(new { message = "Query parameter is required" });
            }

            if (limit > 100) limit = 100;

            var searchTerm = query.Trim().ToLower();

            var results = await _context.Vulnerabilities
                .Include(v => v.BioImpactScore)
                .Include(v => v.ActionRecommendations)
                .Where(v => 
                    v.CveId.ToLower().Contains(searchTerm) || 
                    v.Description.ToLower().Contains(searchTerm) ||
                    (v.VendorName != null && v.VendorName.ToLower().Contains(searchTerm)))
                .OrderByDescending(v => v.BioImpactScore != null ? v.BioImpactScore.CompositeScore : 0)
                .ThenByDescending(v => v.KnownExploited)
                .Take(limit)
                .ToListAsync();

            var dtoList = results.Select(VulnerabilitySummaryDto.FromEntity).ToList();

            return Ok(new
            {
                Query = query,
                ResultCount = dtoList.Count,
                Data = dtoList
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error searching vulnerabilities with query: {Query}", query);
            return StatusCode(500, new { message = "Internal server error" });
        }
    }

    /// <summary>
    /// Get vulnerabilities by vendor name
    /// </summary>
    [HttpGet("by-vendor/{vendorName}")]
    public async Task<ActionResult> GetByVendor(string vendorName, [FromQuery] int limit = 50)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(vendorName))
            {
                return BadRequest(new { message = "Vendor name is required" });
            }

            if (limit > 100) limit = 100;

            var vulnerabilities = await _context.Vulnerabilities
                .Include(v => v.BioImpactScore)
                .Where(v => v.VendorName != null && v.VendorName.ToLower().Contains(vendorName.ToLower()))
                .OrderByDescending(v => v.BioImpactScore != null ? v.BioImpactScore.CompositeScore : 0)
                .Take(limit)
                .ToListAsync();

            var dtoList = vulnerabilities.Select(VulnerabilitySummaryDto.FromEntity).ToList();

            return Ok(new
            {
                VendorName = vendorName,
                ResultCount = dtoList.Count,
                Data = dtoList
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving vulnerabilities for vendor: {Vendor}", vendorName);
            return StatusCode(500, new { message = "Internal server error" });
        }
    }
}

