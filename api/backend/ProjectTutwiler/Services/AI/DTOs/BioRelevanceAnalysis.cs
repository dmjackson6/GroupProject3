namespace ProjectTutwiler.Services.AI.DTOs;

public class BioRelevanceAnalysis
{
    public bool BioRelevant { get; set; }
    public int BioRelevanceScore { get; set; } // 0-100
    public List<string> AffectedBioSectors { get; set; } = new();
    public string HumanSafetyImpact { get; set; } = string.Empty; // HIGH, MEDIUM, LOW, NONE
    public string KeyConcern { get; set; } = string.Empty;
    public string RecommendedPriority { get; set; } = string.Empty; // CRITICAL, HIGH, MEDIUM, LOW
    public decimal ConfidenceLevel { get; set; } // 0.00 to 1.00
    public string RawAiResponse { get; set; } = string.Empty;
}

