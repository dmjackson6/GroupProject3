using ProjectTutwiler.Models;
using ProjectTutwiler.Services.AI.DTOs;

namespace ProjectTutwiler.Services.Scoring;

public class PatchAvailabilityScorer
{
    private readonly ILogger<PatchAvailabilityScorer> _logger;

    public PatchAvailabilityScorer(ILogger<PatchAvailabilityScorer> logger)
    {
        _logger = logger;
    }

    public int Calculate(Vulnerability vulnerability, BioRelevanceAnalysis aiAnalysis)
    {
        // Calculate days since published
        if (!vulnerability.PublishedDate.HasValue)
        {
            _logger.LogDebug("No published date: default score 60");
            return 60; // Default score if no date available
        }

        var daysSincePublished = (DateTime.UtcNow - vulnerability.PublishedDate.Value).Days;
        _logger.LogDebug("Days since published: {Days} for {CveId}", daysSincePublished, vulnerability.CveId);

        int score;

        // Critical recent vulnerabilities with high CVSS
        if (daysSincePublished < 7 && vulnerability.CvssScore >= 9.0m)
        {
            score = 100;
            _logger.LogDebug("Less than 7 days old with CVSS >= 9.0: score 100");
        }
        else if (daysSincePublished < 14 && vulnerability.CvssScore >= 7.0m)
        {
            score = 80;
            _logger.LogDebug("Less than 14 days old with CVSS >= 7.0: score 80");
        }
        else if (daysSincePublished < 30)
        {
            score = 60;
            _logger.LogDebug("Less than 30 days old: score 60");
        }
        else if (daysSincePublished < 90)
        {
            score = 40;
            _logger.LogDebug("Less than 90 days old: score 40");
        }
        else
        {
            score = 20;
            _logger.LogDebug("90+ days old: score 20");
        }

        _logger.LogInformation("Patch Availability Score calculated: {Score} for {CveId}", score, vulnerability.CveId);
        return score;
    }
}

