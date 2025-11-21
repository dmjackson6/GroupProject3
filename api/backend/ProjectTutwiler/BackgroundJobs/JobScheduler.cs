using Hangfire;

namespace ProjectTutwiler.BackgroundJobs;

public static class JobScheduler
{
    /// <summary>
    /// Configure all recurring background jobs
    /// </summary>
    public static void ConfigureRecurringJobs(IServiceProvider serviceProvider)
    {
        // Job 1: Ingest vulnerabilities from NVD and CISA KEV
        // Runs every 12 hours at minute 0
        RecurringJob.AddOrUpdate(
            "ingest-vulnerabilities",
            () => VulnerabilityJobs.RunScheduledIngestionAsync(serviceProvider),
            "0 */12 * * *", // Cron: At minute 0 past every 12th hour
            new RecurringJobOptions
            {
                TimeZone = TimeZoneInfo.Utc
            }
        );

        // Job 2: Process unanalyzed vulnerabilities with AI
        // Runs every 30 minutes
        RecurringJob.AddOrUpdate(
            "process-vulnerabilities",
            () => VulnerabilityJobs.ProcessUnanalyzedVulnerabilitiesAsync(serviceProvider),
            "*/30 * * * *", // Cron: Every 30 minutes
            new RecurringJobOptions
            {
                TimeZone = TimeZoneInfo.Utc
            }
        );

        var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
        logger.LogInformation("Hangfire recurring jobs configured:");
        logger.LogInformation("  - ingest-vulnerabilities: Every 12 hours");
        logger.LogInformation("  - process-vulnerabilities: Every 30 minutes");
    }
}

