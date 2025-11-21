using ProjectTutwiler.Data;

namespace ProjectTutwiler.Services.DataIngestion;

public class IngestionOrchestrator
{
    private readonly VulnerabilityIngestionService _ingestionService;
    private readonly IVulnerabilityRepository _repository;
    private readonly ILogger<IngestionOrchestrator> _logger;

    public IngestionOrchestrator(
        VulnerabilityIngestionService ingestionService,
        IVulnerabilityRepository repository,
        ILogger<IngestionOrchestrator> logger)
    {
        _ingestionService = ingestionService;
        _repository = repository;
        _logger = logger;
    }

    public async Task<CombinedIngestionResult> RunFullIngestionAsync(int nvdDaysBack = 7)
    {
        var combinedResult = new CombinedIngestionResult();

        try
        {
            _logger.LogInformation("Starting full ingestion: NVD + CISA KEV");

            // Step 1: Run NVD ingestion
            _logger.LogInformation("Step 1: Running NVD ingestion for last {DaysBack} days", nvdDaysBack);
            combinedResult.NvdResults = await _ingestionService.IngestFromNvdAsync(nvdDaysBack);

            // Step 2: Wait for rate limiting courtesy
            _logger.LogInformation("Waiting 2 seconds before CISA KEV ingestion...");
            await Task.Delay(TimeSpan.FromSeconds(2));

            // Step 3: Run CISA KEV ingestion
            _logger.LogInformation("Step 2: Running CISA KEV ingestion");
            combinedResult.KevResults = await _ingestionService.IngestFromCisaKevAsync();

            // Step 4: Get database statistics
            var allVulns = await _repository.GetAllAsync(skip: 0, take: 10000);
            combinedResult.TotalVulnerabilities = allVulns.Count;
            combinedResult.TotalKnownExploited = await _repository.CountKnownExploitedAsync();

            combinedResult.CompletedAt = DateTime.UtcNow;
            combinedResult.Message = $"Full ingestion completed. NVD: {combinedResult.NvdResults.NewAdded} new, KEV: {combinedResult.KevResults.NewAdded} new, {combinedResult.KevResults.DuplicatesSkipped} marked exploited";

            _logger.LogInformation(combinedResult.Message);
            _logger.LogInformation("Total vulnerabilities in database: {Total}, Known exploited: {Exploited}",
                combinedResult.TotalVulnerabilities, combinedResult.TotalKnownExploited);

            return combinedResult;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during full ingestion");
            combinedResult.Message = $"Full ingestion failed: {ex.Message}";
            return combinedResult;
        }
    }
}

