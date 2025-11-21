using ProjectTutwiler.Models;
using ProjectTutwiler.Models.Enums;
using ProjectTutwiler.Services.AI.DTOs;

namespace ProjectTutwiler.Services.Scoring;

public class CompositeScorer
{
    private readonly HumanSafetyScorer _humanSafetyScorer;
    private readonly SupplyChainScorer _supplyChainScorer;
    private readonly ExploitabilityScorer _exploitabilityScorer;
    private readonly PatchAvailabilityScorer _patchAvailabilityScorer;
    private readonly ILogger<CompositeScorer> _logger;

    // Scoring weights
    private const decimal HUMAN_SAFETY_WEIGHT = 0.40m;
    private const decimal SUPPLY_CHAIN_WEIGHT = 0.25m;
    private const decimal EXPLOITABILITY_WEIGHT = 0.20m;
    private const decimal PATCH_AVAILABILITY_WEIGHT = 0.15m;

    public CompositeScorer(
        HumanSafetyScorer humanSafetyScorer,
        SupplyChainScorer supplyChainScorer,
        ExploitabilityScorer exploitabilityScorer,
        PatchAvailabilityScorer patchAvailabilityScorer,
        ILogger<CompositeScorer> logger)
    {
        _humanSafetyScorer = humanSafetyScorer;
        _supplyChainScorer = supplyChainScorer;
        _exploitabilityScorer = exploitabilityScorer;
        _patchAvailabilityScorer = patchAvailabilityScorer;
        _logger = logger;
    }

    public BioImpactScore CalculateCompositeScore(Vulnerability vulnerability, BioRelevanceAnalysis aiAnalysis)
    {
        _logger.LogInformation("Calculating composite score for {CveId}", vulnerability.CveId);

        // Calculate each dimension score
        int humanSafetyScore = _humanSafetyScorer.Calculate(vulnerability, aiAnalysis);
        int supplyChainScore = _supplyChainScorer.Calculate(vulnerability, aiAnalysis);
        int exploitabilityScore = _exploitabilityScorer.Calculate(vulnerability, aiAnalysis);
        int patchAvailabilityScore = _patchAvailabilityScorer.Calculate(vulnerability, aiAnalysis);

        // Apply weighted formula
        decimal compositeScore = (humanSafetyScore * HUMAN_SAFETY_WEIGHT) +
                                 (supplyChainScore * SUPPLY_CHAIN_WEIGHT) +
                                 (exploitabilityScore * EXPLOITABILITY_WEIGHT) +
                                 (patchAvailabilityScore * PATCH_AVAILABILITY_WEIGHT);

        // Round to 2 decimal places
        compositeScore = Math.Round(compositeScore, 2);

        // Determine priority level
        PriorityLevel priorityLevel = DeterminePriorityLevel(compositeScore);

        _logger.LogInformation(
            "Composite score calculated for {CveId}: {CompositeScore} ({PriorityLevel}) - " +
            "HS:{HS}, SC:{SC}, EXP:{EXP}, PA:{PA}",
            vulnerability.CveId, compositeScore, priorityLevel,
            humanSafetyScore, supplyChainScore, exploitabilityScore, patchAvailabilityScore);

        // Create BioImpactScore entity
        var bioImpactScore = new BioImpactScore
        {
            VulnerabilityId = vulnerability.Id,
            HumanSafetyScore = humanSafetyScore,
            SupplyChainScore = supplyChainScore,
            ExploitabilityScore = exploitabilityScore,
            PatchAvailabilityScore = patchAvailabilityScore,
            CompositeScore = compositeScore,
            PriorityLevel = priorityLevel,
            BioRelevanceConfidence = aiAnalysis.ConfidenceLevel,
            AffectedBioSectors = aiAnalysis.AffectedBioSectors != null && aiAnalysis.AffectedBioSectors.Any()
                ? string.Join(", ", aiAnalysis.AffectedBioSectors)
                : null,
            AiAnalysis = aiAnalysis.RawAiResponse,
            AiModelVersion = "llama3.1:8b", // TODO: Make configurable
            HumanReviewed = false,
            CreatedAt = DateTime.UtcNow
        };

        return bioImpactScore;
    }

    private PriorityLevel DeterminePriorityLevel(decimal compositeScore)
    {
        if (compositeScore >= 85)
        {
            return PriorityLevel.CRITICAL;
        }
        else if (compositeScore >= 70)
        {
            return PriorityLevel.HIGH;
        }
        else if (compositeScore >= 50)
        {
            return PriorityLevel.MEDIUM;
        }
        else
        {
            return PriorityLevel.LOW;
        }
    }
}

