using Newtonsoft.Json;
using System.Text;

namespace ProjectTutwiler.Services.AI;

public class OllamaClient
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    private readonly ILogger<OllamaClient> _logger;
    private readonly string _baseUrl;
    private readonly string _model;

    public OllamaClient(HttpClient httpClient, IConfiguration configuration, ILogger<OllamaClient> logger)
    {
        _httpClient = httpClient;
        _configuration = configuration;
        _logger = logger;
        
        _baseUrl = _configuration["OllamaSettings:BaseUrl"] ?? "http://localhost:11434";
        _model = _configuration["OllamaSettings:Model"] ?? "llama3.1:8b";
        
        // Set timeout
        _httpClient.Timeout = TimeSpan.FromSeconds(30);
    }

    public async Task<string> GenerateCompletionAsync(string prompt, double temperature = 0.3)
    {
        try
        {
            _logger.LogInformation("Calling Ollama API with model {Model}, temp {Temperature}", _model, temperature);

            var requestBody = new
            {
                model = _model,
                prompt = prompt,
                temperature = temperature,
                stream = false
            };

            var jsonContent = JsonConvert.SerializeObject(requestBody);
            var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

            var url = $"{_baseUrl}/api/generate";
            _logger.LogDebug("POST to {Url}", url);

            var response = await _httpClient.PostAsync(url, content);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("Ollama API returned {StatusCode}: {Error}", response.StatusCode, errorContent);
                throw new HttpRequestException($"Ollama API error: {response.StatusCode}");
            }

            var responseContent = await response.Content.ReadAsStringAsync();
            _logger.LogDebug("Ollama response received: {Length} characters", responseContent.Length);

            // Parse response
            var responseObj = JsonConvert.DeserializeObject<OllamaResponse>(responseContent);

            if (responseObj == null || string.IsNullOrWhiteSpace(responseObj.Response))
            {
                _logger.LogWarning("Ollama returned empty response");
                throw new InvalidOperationException("Empty response from Ollama");
            }

            _logger.LogInformation("Ollama completion successful: {Length} characters", responseObj.Response.Length);
            return responseObj.Response;
        }
        catch (TaskCanceledException ex)
        {
            _logger.LogError(ex, "Ollama request timed out after 30 seconds");
            throw new TimeoutException("Ollama request timed out", ex);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "HTTP error calling Ollama API");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error calling Ollama API");
            throw;
        }
    }

    public async Task<bool> IsAvailableAsync()
    {
        try
        {
            var url = $"{_baseUrl}/api/tags";
            var response = await _httpClient.GetAsync(url);
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    private class OllamaResponse
    {
        [JsonProperty("model")]
        public string Model { get; set; } = string.Empty;

        [JsonProperty("response")]
        public string Response { get; set; } = string.Empty;

        [JsonProperty("done")]
        public bool Done { get; set; }

        [JsonProperty("context")]
        public int[]? Context { get; set; }

        [JsonProperty("total_duration")]
        public long? TotalDuration { get; set; }
    }
}

