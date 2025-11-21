using Newtonsoft.Json;

namespace ProjectTutwiler.Services.DataIngestion.DTOs;

public class NvdCvssMetricV31
{
    [JsonProperty("cvssData")]
    public NvdCvssData CvssData { get; set; } = null!;
}

