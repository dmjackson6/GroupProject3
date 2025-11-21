using ProjectTutwiler.Models;
using ProjectTutwiler.Services.AI.DTOs;

namespace ProjectTutwiler.Services.Scoring;

public class SupplyChainScorer
{
    private readonly ILogger<SupplyChainScorer> _logger;

    public SupplyChainScorer(ILogger<SupplyChainScorer> logger)
    {
        _logger = logger;
    }

    public int Calculate(Vulnerability vulnerability, BioRelevanceAnalysis aiAnalysis)
    {
        int score;

        // Base score from number of affected sectors
        int sectorCount = aiAnalysis.AffectedBioSectors.Count;

        if (sectorCount >= 4)
        {
            score = 80;
            _logger.LogDebug("4+ sectors affected: base score 80");
        }
        else if (sectorCount == 3)
        {
            score = 60;
            _logger.LogDebug("3 sectors affected: base score 60");
        }
        else if (sectorCount == 2)
        {
            score = 50;
            _logger.LogDebug("2 sectors affected: base score 50");
        }
        else if (sectorCount == 1)
        {
            score = 40;
            _logger.LogDebug("1 sector affected: base score 40");
        }
        else
        {
            score = 40; // Default
            _logger.LogDebug("No sectors specified: default base score 40");
        }

        // Boost for critical supply chain sectors
        var criticalSupplyChainSector = aiAnalysis.AffectedBioSectors.Any(s =>
            s.Contains("Biomanufacturing", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("Pharmaceutical", StringComparison.OrdinalIgnoreCase));

        if (criticalSupplyChainSector)
        {
            score = Math.Min(score + 20, 100);
            _logger.LogDebug("Critical supply chain sector boost: +20 (capped at 100)");
        }

        _logger.LogInformation("Supply Chain Score calculated: {Score} for {CveId}", score, vulnerability.CveId);
        return score;
    }
}

