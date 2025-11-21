namespace ProjectTutwiler.Services.DataIngestion;

public class CombinedIngestionResult
{
    public IngestionResult NvdResults { get; set; } = new();
    public IngestionResult KevResults { get; set; } = new();
    public int TotalVulnerabilities { get; set; }
    public int TotalKnownExploited { get; set; }
    public DateTime CompletedAt { get; set; } = DateTime.UtcNow;
    public string Message { get; set; } = string.Empty;
}

