using Newtonsoft.Json;

namespace ProjectTutwiler.Services.DataIngestion.DTOs;

public class NvdMetrics
{
    [JsonProperty("cvssMetricV31")]
    public List<NvdCvssMetricV31>? CvssMetricV31 { get; set; }

    [JsonProperty("cvssMetricV30")]
    public List<NvdCvssMetricV30>? CvssMetricV30 { get; set; }

    [JsonProperty("cvssMetricV2")]
    public List<NvdCvssMetricV2>? CvssMetricV2 { get; set; }
}

