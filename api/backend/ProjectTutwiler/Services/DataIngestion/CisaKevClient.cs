using Microsoft.Extensions.Caching.Memory;
using Newtonsoft.Json;
using ProjectTutwiler.Services.DataIngestion.DTOs;

namespace ProjectTutwiler.Services.DataIngestion;

public class CisaKevClient
{
    private readonly HttpClient _httpClient;
    private readonly IMemoryCache _cache;
    private readonly ILogger<CisaKevClient> _logger;
    private const string KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private const string CACHE_KEY = "CISA_KEV_CATALOG";
    private readonly TimeSpan CACHE_DURATION = TimeSpan.FromHours(24);

    public CisaKevClient(HttpClient httpClient, IMemoryCache cache, ILogger<CisaKevClient> logger)
    {
        _httpClient = httpClient;
        _cache = cache;
        _logger = logger;
    }

    public async Task<List<CisaKevVulnerability>> FetchKevCatalogAsync()
    {
        try
        {
            // Check cache first
            if (_cache.TryGetValue(CACHE_KEY, out List<CisaKevVulnerability>? cachedVulnerabilities))
            {
                _logger.LogInformation("Returning CISA KEV catalog from cache ({Count} vulnerabilities)", cachedVulnerabilities?.Count ?? 0);
                return cachedVulnerabilities ?? new List<CisaKevVulnerability>();
            }

            _logger.LogInformation("Fetching CISA KEV catalog from {Url}", KEV_CATALOG_URL);

            var response = await _httpClient.GetAsync(KEV_CATALOG_URL);
            response.EnsureSuccessStatusCode();

            var jsonContent = await response.Content.ReadAsStringAsync();
            var catalog = JsonConvert.DeserializeObject<CisaKevCatalog>(jsonContent);

            if (catalog == null || catalog.Vulnerabilities == null)
            {
                _logger.LogWarning("CISA KEV catalog deserialization returned null");
                return new List<CisaKevVulnerability>();
            }

            _logger.LogInformation("Successfully fetched CISA KEV catalog: {Count} known exploited vulnerabilities", catalog.Count);

            // Cache the result
            var cacheOptions = new MemoryCacheEntryOptions()
                .SetAbsoluteExpiration(CACHE_DURATION);

            _cache.Set(CACHE_KEY, catalog.Vulnerabilities, cacheOptions);

            return catalog.Vulnerabilities;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "HTTP error fetching CISA KEV catalog");
            throw;
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "JSON deserialization error for CISA KEV catalog");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error fetching CISA KEV catalog");
            throw;
        }
    }

    public void ClearCache()
    {
        _cache.Remove(CACHE_KEY);
        _logger.LogInformation("CISA KEV catalog cache cleared");
    }
}

