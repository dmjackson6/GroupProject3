using Newtonsoft.Json;

namespace ProjectTutwiler.Services.DataIngestion.DTOs;

public class NvdDescription
{
    [JsonProperty("lang")]
    public string Lang { get; set; } = string.Empty;

    [JsonProperty("value")]
    public string Value { get; set; } = string.Empty;
}

