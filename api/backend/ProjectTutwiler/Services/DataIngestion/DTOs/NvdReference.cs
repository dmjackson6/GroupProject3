using Newtonsoft.Json;

namespace ProjectTutwiler.Services.DataIngestion.DTOs;

public class NvdReference
{
    [JsonProperty("url")]
    public string Url { get; set; } = string.Empty;
}

