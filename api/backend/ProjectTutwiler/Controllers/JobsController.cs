using Hangfire;
using Microsoft.AspNetCore.Mvc;
using ProjectTutwiler.BackgroundJobs;

namespace ProjectTutwiler.Controllers;

[ApiController]
[Route("api/[controller]")]
public class JobsController : ControllerBase
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<JobsController> _logger;

    public JobsController(IServiceProvider serviceProvider, ILogger<JobsController> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    /// <summary>
    /// Manually trigger vulnerability ingestion job
    /// </summary>
    [HttpPost("trigger-ingestion")]
    public ActionResult TriggerIngestion([FromQuery] int daysBack = 7)
    {
        try
        {
            // Queue the job to run in the background immediately
            var jobId = BackgroundJob.Enqueue(
                () => VulnerabilityJobs.RunScheduledIngestionAsync(_serviceProvider)
            );

            _logger.LogInformation("Manually triggered ingestion job with ID: {JobId}, daysBack: {DaysBack}", jobId, daysBack);

            return Ok(new
            {
                Message = "Ingestion job has been queued",
                JobId = jobId,
                DaysBack = daysBack,
                DashboardUrl = "/hangfire"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error triggering ingestion job");
            return StatusCode(500, new { message = "Error queueing ingestion job" });
        }
    }

    /// <summary>
    /// Manually trigger vulnerability processing/analysis job
    /// </summary>
    [HttpPost("trigger-processing")]
    public ActionResult TriggerProcessing()
    {
        try
        {
            // Queue the job to run in the background immediately
            var jobId = BackgroundJob.Enqueue(
                () => VulnerabilityJobs.ProcessUnanalyzedVulnerabilitiesAsync(_serviceProvider)
            );

            _logger.LogInformation("Manually triggered processing job with ID: {JobId}", jobId);

            return Ok(new
            {
                Message = "Processing job has been queued",
                JobId = jobId,
                DashboardUrl = "/hangfire"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error triggering processing job");
            return StatusCode(500, new { message = "Error queueing processing job" });
        }
    }

    /// <summary>
    /// Get Hangfire dashboard URL
    /// </summary>
    [HttpGet("dashboard-url")]
    public ActionResult GetDashboardUrl()
    {
        return Ok(new
        {
            DashboardUrl = "/hangfire",
            FullUrl = $"{Request.Scheme}://{Request.Host}/hangfire",
            Description = "Navigate to this URL to view the Hangfire dashboard with job status and history"
        });
    }

    /// <summary>
    /// Get status of recurring jobs
    /// </summary>
    [HttpGet("recurring-jobs")]
    public ActionResult GetRecurringJobs()
    {
        try
        {
            var recurringJobs = new[]
            {
                new
                {
                    JobId = "ingest-vulnerabilities",
                    Description = "Ingest vulnerabilities from NVD and CISA KEV",
                    Schedule = "Every 12 hours (0 */12 * * *)",
                    NextRun = "Check dashboard for exact time"
                },
                new
                {
                    JobId = "process-vulnerabilities",
                    Description = "Process and analyze unanalyzed vulnerabilities with AI",
                    Schedule = "Every 30 minutes (*/30 * * * *)",
                    NextRun = "Check dashboard for exact time"
                }
            };

            return Ok(new
            {
                TotalRecurringJobs = recurringJobs.Length,
                Jobs = recurringJobs,
                DashboardUrl = "/hangfire"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving recurring jobs");
            return StatusCode(500, new { message = "Error retrieving job information" });
        }
    }

    /// <summary>
    /// Trigger immediate analysis for a specific vulnerability
    /// </summary>
    [HttpPost("analyze-vulnerability/{id}")]
    public ActionResult AnalyzeVulnerability(int id)
    {
        try
        {
            // Queue immediate analysis for specific vulnerability
            var jobId = BackgroundJob.Enqueue<ProjectTutwiler.Services.AI.VulnerabilityAnalysisService>(
                service => service.AnalyzeAndScoreVulnerabilityAsync(id)
            );

            _logger.LogInformation("Queued analysis job for vulnerability ID {VulnId}, Job ID: {JobId}", id, jobId);

            return Ok(new
            {
                Message = $"Analysis job queued for vulnerability ID {id}",
                VulnerabilityId = id,
                JobId = jobId,
                DashboardUrl = "/hangfire"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error queueing analysis for vulnerability {Id}", id);
            return StatusCode(500, new { message = "Error queueing analysis job" });
        }
    }
}

