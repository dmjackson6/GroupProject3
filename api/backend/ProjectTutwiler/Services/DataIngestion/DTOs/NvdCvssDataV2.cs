using Newtonsoft.Json;

namespace ProjectTutwiler.Services.DataIngestion.DTOs;

public class NvdCvssDataV2
{
    [JsonProperty("baseScore")]
    public decimal BaseScore { get; set; }

    [JsonProperty("vectorString")]
    public string VectorString { get; set; } = string.Empty;
}

