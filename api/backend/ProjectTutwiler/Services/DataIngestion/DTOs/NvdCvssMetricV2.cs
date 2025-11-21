using Newtonsoft.Json;

namespace ProjectTutwiler.Services.DataIngestion.DTOs;

public class NvdCvssMetricV2
{
    [JsonProperty("cvssData")]
    public NvdCvssDataV2 CvssData { get; set; } = null!;
}

