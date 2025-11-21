namespace ProjectTutwiler.Services.DataIngestion;

public class IngestionResult
{
    public int TotalFetched { get; set; }
    public int NewAdded { get; set; }
    public int DuplicatesSkipped { get; set; }
    public int Errors { get; set; }
    public string Message { get; set; } = string.Empty;
    public DateTime IngestedAt { get; set; } = DateTime.UtcNow;
}

