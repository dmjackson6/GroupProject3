using Newtonsoft.Json;

namespace ProjectTutwiler.Services.DataIngestion.DTOs;

public class NvdCve
{
    [JsonProperty("id")]
    public string Id { get; set; } = string.Empty;

    [JsonProperty("published")]
    public string Published { get; set; } = string.Empty;

    [JsonProperty("descriptions")]
    public List<NvdDescription> Descriptions { get; set; } = new();

    [JsonProperty("metrics")]
    public NvdMetrics? Metrics { get; set; }

    [JsonProperty("references")]
    public List<NvdReference> References { get; set; } = new();
}

