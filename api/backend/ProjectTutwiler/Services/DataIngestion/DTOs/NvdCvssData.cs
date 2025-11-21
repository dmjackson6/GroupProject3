using Newtonsoft.Json;

namespace ProjectTutwiler.Services.DataIngestion.DTOs;

public class NvdCvssData
{
    [JsonProperty("baseScore")]
    public decimal BaseScore { get; set; }

    [JsonProperty("vectorString")]
    public string VectorString { get; set; } = string.Empty;
}

