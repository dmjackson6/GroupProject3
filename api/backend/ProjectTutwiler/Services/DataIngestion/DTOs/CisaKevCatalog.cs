using Newtonsoft.Json;

namespace ProjectTutwiler.Services.DataIngestion.DTOs;

public class CisaKevCatalog
{
    [JsonProperty("title")]
    public string Title { get; set; } = string.Empty;

    [JsonProperty("catalogVersion")]
    public string CatalogVersion { get; set; } = string.Empty;

    [JsonProperty("dateReleased")]
    public string DateReleased { get; set; } = string.Empty;

    [JsonProperty("count")]
    public int Count { get; set; }

    [JsonProperty("vulnerabilities")]
    public List<CisaKevVulnerability> Vulnerabilities { get; set; } = new();
}

