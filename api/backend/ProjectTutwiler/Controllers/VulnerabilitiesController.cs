using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ProjectTutwiler.Data;
using ProjectTutwiler.DTOs;
using ProjectTutwiler.Models.Enums;

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
            var vulnerabilities = await query
                .OrderByDescending(v => v.BioImpactScore != null ? v.BioImpactScore.CompositeScore : 0)
                .ThenByDescending(v => v.KnownExploited)
                .ThenByDescending(v => v.CvssScore)
                .ThenByDescending(v => v.PublishedDate)
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
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving vulnerabilities");
            return StatusCode(500, new { message = "Internal server error" });
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

            // Overall counts
            stats.TotalVulnerabilities = await _context.Vulnerabilities.CountAsync();
            stats.AnalyzedVulnerabilities = await _context.BioImpactScores.CountAsync();
            stats.UnanalyzedVulnerabilities = stats.TotalVulnerabilities - stats.AnalyzedVulnerabilities;
            stats.KnownExploitedCount = await _context.Vulnerabilities
                .Where(v => v.KnownExploited)
                .CountAsync();

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

            // Recent activity
            var latestVulnerability = await _context.Vulnerabilities
                .OrderByDescending(v => v.CreatedAt)
                .FirstOrDefaultAsync();
            stats.LastIngestionTime = latestVulnerability?.CreatedAt;

            var twentyFourHoursAgo = DateTime.UtcNow.AddHours(-24);
            stats.VulnerabilitiesLast24Hours = await _context.Vulnerabilities
                .Where(v => v.CreatedAt >= twentyFourHoursAgo)
                .CountAsync();

            var sevenDaysAgo = DateTime.UtcNow.AddDays(-7);
            stats.VulnerabilitiesLast7Days = await _context.Vulnerabilities
                .Where(v => v.CreatedAt >= sevenDaysAgo)
                .CountAsync();

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
            var avgScore = await _context.BioImpactScores.AverageAsync(b => (double?)b.CompositeScore);
            stats.AverageCompositeScore = avgScore.HasValue ? (decimal)Math.Round(avgScore.Value, 2) : 0;

            return Ok(stats);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving vulnerability statistics");
            return StatusCode(500, new { message = "Internal server error" });
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

