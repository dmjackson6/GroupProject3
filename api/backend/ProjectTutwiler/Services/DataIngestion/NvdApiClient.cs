using Newtonsoft.Json;
using ProjectTutwiler.Models;
using ProjectTutwiler.Services.DataIngestion.DTOs;

namespace ProjectTutwiler.Services.DataIngestion;

public class NvdApiClient
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    private readonly ILogger<NvdApiClient> _logger;
    private readonly string _apiKey;
    private const string NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    public NvdApiClient(HttpClient httpClient, IConfiguration configuration, ILogger<NvdApiClient> logger)
    {
        _httpClient = httpClient;
        _configuration = configuration;
        _logger = logger;
        _apiKey = _configuration["NvdApiKey"] ?? throw new InvalidOperationException("NVD API Key not configured");
    }

    public async Task<List<Vulnerability>> FetchRecentVulnerabilitiesAsync(int daysBack = 7)
    {
        var vulnerabilities = new List<Vulnerability>();
        var endDate = DateTime.UtcNow;
        var startDate = endDate.AddDays(-daysBack);

        try
        {
            _logger.LogInformation("Fetching vulnerabilities from NVD for last {DaysBack} days", daysBack);

            var url = BuildNvdApiUrl(startDate, endDate);
            var nvdResponse = await FetchWithRetryAsync(url);

            if (nvdResponse?.Vulnerabilities == null || nvdResponse.Vulnerabilities.Count == 0)
            {
                _logger.LogWarning("No vulnerabilities found in NVD response");
                return vulnerabilities;
            }

            _logger.LogInformation("Retrieved {Count} vulnerabilities from NVD", nvdResponse.Vulnerabilities.Count);

            foreach (var nvdVuln in nvdResponse.Vulnerabilities)
            {
                try
                {
                    var vulnerability = await MapNvdToVulnerability(nvdVuln.Cve);
                    vulnerabilities.Add(vulnerability);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error mapping NVD CVE {CveId}", nvdVuln.Cve?.Id ?? "Unknown");
                }
            }

            return vulnerabilities;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching vulnerabilities from NVD");
            return vulnerabilities;
        }
    }

    private string BuildNvdApiUrl(DateTime startDate, DateTime endDate)
    {
        var pubStartDate = startDate.ToString("yyyy-MM-ddTHH:mm:ss.000");
        var pubEndDate = endDate.ToString("yyyy-MM-ddTHH:mm:ss.000");

        return $"{NVD_BASE_URL}?pubStartDate={pubStartDate}&pubEndDate={pubEndDate}&resultsPerPage=100";
    }

    private async Task<NvdResponse?> FetchWithRetryAsync(string url, int maxRetries = 3)
    {
        for (int attempt = 1; attempt <= maxRetries; attempt++)
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.Add("apiKey", _apiKey);

                _logger.LogInformation("Attempt {Attempt} of {MaxRetries}: Calling NVD API", attempt, maxRetries);

                var response = await _httpClient.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    var jsonContent = await response.Content.ReadAsStringAsync();
                    var nvdResponse = JsonConvert.DeserializeObject<NvdResponse>(jsonContent);
                    
                    _logger.LogInformation("Successfully fetched data from NVD API");
                    return nvdResponse;
                }

                if (response.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                {
                    _logger.LogWarning("Rate limit hit on attempt {Attempt}. Waiting before retry...", attempt);
                    await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, attempt))); // Exponential backoff
                    continue;
                }

                _logger.LogWarning("NVD API returned status code: {StatusCode}", response.StatusCode);
                
                if (attempt < maxRetries)
                {
                    await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, attempt)));
                }
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP error on attempt {Attempt}", attempt);
                
                if (attempt < maxRetries)
                {
                    await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, attempt)));
                }
                else
                {
                    throw;
                }
            }
        }

        throw new Exception($"Failed to fetch from NVD API after {maxRetries} attempts");
    }

    public async Task<Vulnerability> MapNvdToVulnerability(NvdCve nvdCve)
    {
        return await Task.Run(() =>
        {
            var vulnerability = new Vulnerability
            {
                CveId = nvdCve.Id,
                SourceName = "NVD",
                Description = ExtractEnglishDescription(nvdCve.Descriptions),
                PublishedDate = ParsePublishedDate(nvdCve.Published),
                RawData = JsonConvert.SerializeObject(nvdCve),
                References = JsonConvert.SerializeObject(nvdCve.References.Select(r => r.Url).ToList()),
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            // Extract CVSS score and vector
            ExtractCvssInfo(nvdCve.Metrics, vulnerability);

            return vulnerability;
        });
    }

    private string ExtractEnglishDescription(List<NvdDescription> descriptions)
    {
        var englishDesc = descriptions.FirstOrDefault(d => d.Lang == "en");
        if (englishDesc != null)
        {
            return englishDesc.Value;
        }

        // Fallback to first description if no English available
        return descriptions.FirstOrDefault()?.Value ?? "No description available";
    }

    private DateTime? ParsePublishedDate(string publishedDate)
    {
        if (DateTime.TryParse(publishedDate, out var parsedDate))
        {
            return parsedDate;
        }

        _logger.LogWarning("Could not parse published date: {PublishedDate}", publishedDate);
        return null;
    }

    private void ExtractCvssInfo(NvdMetrics? metrics, Vulnerability vulnerability)
    {
        if (metrics == null)
        {
            return;
        }

        // Priority: V3.1 > V3.0 > V2
        if (metrics.CvssMetricV31 != null && metrics.CvssMetricV31.Count > 0)
        {
            var cvss = metrics.CvssMetricV31.First().CvssData;
            vulnerability.CvssScore = cvss.BaseScore;
            vulnerability.CvssVector = cvss.VectorString;
        }
        else if (metrics.CvssMetricV30 != null && metrics.CvssMetricV30.Count > 0)
        {
            var cvss = metrics.CvssMetricV30.First().CvssData;
            vulnerability.CvssScore = cvss.BaseScore;
            vulnerability.CvssVector = cvss.VectorString;
        }
        else if (metrics.CvssMetricV2 != null && metrics.CvssMetricV2.Count > 0)
        {
            var cvss = metrics.CvssMetricV2.First().CvssData;
            vulnerability.CvssScore = cvss.BaseScore;
            vulnerability.CvssVector = cvss.VectorString;
        }
    }
}

