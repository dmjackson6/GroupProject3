using ProjectTutwiler.Models;
using ProjectTutwiler.Services.AI.DTOs;

namespace ProjectTutwiler.Services.Scoring;

public class HumanSafetyScorer
{
    private readonly ILogger<HumanSafetyScorer> _logger;

    public HumanSafetyScorer(ILogger<HumanSafetyScorer> logger)
    {
        _logger = logger;
    }

    public int Calculate(Vulnerability vulnerability, BioRelevanceAnalysis aiAnalysis)
    {
        int score;

        // Base score from AI analysis human safety impact
        switch (aiAnalysis.HumanSafetyImpact.ToUpperInvariant())
        {
            case "HIGH":
                score = 100;
                _logger.LogDebug("Human safety HIGH impact: base score 100");
                break;
            case "MEDIUM":
                score = 75;
                _logger.LogDebug("Human safety MEDIUM impact: base score 75");
                break;
            case "LOW":
                score = 50;
                _logger.LogDebug("Human safety LOW impact: base score 50");
                break;
            default:
                score = Math.Min(aiAnalysis.BioRelevanceScore, 100);
                _logger.LogDebug("Human safety default: using bio relevance score {Score}", score);
                break;
        }

        // Boost for critical sectors (Hospitals or Clinical Labs)
        var criticalSectors = aiAnalysis.AffectedBioSectors.Any(s =>
            s.Contains("Hospitals", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("Clinical Labs", StringComparison.OrdinalIgnoreCase));

        if (criticalSectors)
        {
            score = Math.Min(score + 10, 100);
            _logger.LogDebug("Critical sector boost applied: +10 (capped at 100)");
        }

        _logger.LogInformation("Human Safety Score calculated: {Score} for {CveId}", score, vulnerability.CveId);
        return score;
    }
}

