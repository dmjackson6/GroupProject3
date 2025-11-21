using Newtonsoft.Json;

namespace ProjectTutwiler.Services.DataIngestion.DTOs;

public class NvdResponse
{
    [JsonProperty("resultsPerPage")]
    public int ResultsPerPage { get; set; }

    [JsonProperty("startIndex")]
    public int StartIndex { get; set; }

    [JsonProperty("totalResults")]
    public int TotalResults { get; set; }

    [JsonProperty("vulnerabilities")]
    public List<NvdVulnerability> Vulnerabilities { get; set; } = new();
}

