using Newtonsoft.Json;
using ProjectTutwiler.Models;
using ProjectTutwiler.Services.AI.DTOs;
using System.Text.RegularExpressions;

namespace ProjectTutwiler.Services.AI;

public class BioImpactAnalyzer
{
    private readonly OllamaClient _ollamaClient;
    private readonly BioKeywordFilter _keywordFilter;
    private readonly PromptSafetyFilter _safetyFilter;
    private readonly ILogger<BioImpactAnalyzer> _logger;

    public BioImpactAnalyzer(
        OllamaClient ollamaClient,
        BioKeywordFilter keywordFilter,
        PromptSafetyFilter safetyFilter,
        ILogger<BioImpactAnalyzer> logger)
    {
        _ollamaClient = ollamaClient;
        _keywordFilter = keywordFilter;
        _safetyFilter = safetyFilter;
        _logger = logger;
    }

    public async Task<BioRelevanceAnalysis> AnalyzeVulnerabilityAsync(Vulnerability vulnerability)
    {
        try
        {
            _logger.LogInformation("Starting bio-relevance analysis for {CveId}", vulnerability.CveId);

            // Step 1: Check for bio keywords
            var combinedText = $"{vulnerability.Description} {vulnerability.VendorName} {vulnerability.AffectedProducts}";
            
            if (!_keywordFilter.HasBioKeywords(combinedText))
            {
                _logger.LogInformation("No bio keywords found in {CveId}, skipping AI analysis", vulnerability.CveId);
                return new BioRelevanceAnalysis
                {
                    BioRelevant = false,
                    BioRelevanceScore = 0,
                    HumanSafetyImpact = "NONE",
                    KeyConcern = "Not bio-relevant based on keyword analysis",
                    RecommendedPriority = "LOW",
                    ConfidenceLevel = 0.95m,
                    RawAiResponse = "Skipped - no bio keywords detected"
                };
            }

            // Step 2: Sanitize input
            var sanitizedDescription = _safetyFilter.SanitizeInput(vulnerability.Description ?? "");
            var sanitizedVendor = _safetyFilter.SanitizeInput(vulnerability.VendorName ?? "");

            if (_safetyFilter.IsSuspicious(vulnerability.Description ?? ""))
            {
                _logger.LogWarning("Suspicious input detected in {CveId}, using fallback", vulnerability.CveId);
                return FallbackHeuristicAnalysis(vulnerability);
            }

            // Step 3: Build prompt
            var prompt = BuildAnalysisPrompt(vulnerability.CveId, sanitizedDescription, sanitizedVendor, vulnerability.CvssScore);

            // Step 4: Call Ollama
            _logger.LogInformation("Calling Ollama AI for {CveId}", vulnerability.CveId);
            var aiResponse = await _ollamaClient.GenerateCompletionAsync(prompt, temperature: 0.3);

            // Step 5: Parse response
            var analysis = ParseAiResponse(aiResponse, vulnerability);

            _logger.LogInformation("Analysis complete for {CveId}: Relevant={BioRelevant}, Score={Score}",
                vulnerability.CveId, analysis.BioRelevant, analysis.BioRelevanceScore);

            return analysis;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing {CveId}, using fallback", vulnerability.CveId);
            return FallbackHeuristicAnalysis(vulnerability);
        }
    }

    private string BuildAnalysisPrompt(string cveId, string description, string vendor, decimal? cvssScore)
    {
        return $@"You are a cyberbiosecurity expert analyzing vulnerability {cveId}.

Task: Determine if this vulnerability affects biosecurity/healthcare systems and assess its bio-impact.

Vulnerability Description:
{description}

Vendor: {vendor}
CVSS Score: {cvssScore?.ToString() ?? "N/A"}

Analyze this vulnerability for biosecurity relevance. Consider:
1. Does it affect medical devices, laboratory equipment, hospital systems, or biomanufacturing?
2. Could it impact patient safety, lab operations, or biological research?
3. What are the specific risks to healthcare/bio sectors?

Respond ONLY with valid JSON in this exact format (no markdown, no extra text):
{{
  ""bioRelevant"": true or false,
  ""bioRelevanceScore"": 0-100,
  ""affectedBioSectors"": [""Clinical Labs"", ""Hospitals"", etc],
  ""humanSafetyImpact"": ""HIGH"" or ""MEDIUM"" or ""LOW"" or ""NONE"",
  ""keyConcern"": ""one sentence explaining the main concern"",
  ""recommendedPriority"": ""CRITICAL"" or ""HIGH"" or ""MEDIUM"" or ""LOW"",
  ""confidenceLevel"": 0.0 to 1.0
}}

Valid sectors: Clinical Labs, Hospitals, Research Labs, Biomanufacturing, Food/Agriculture, Pharmaceutical
";
    }

    private BioRelevanceAnalysis ParseAiResponse(string aiResponse, Vulnerability vulnerability)
    {
        var analysis = new BioRelevanceAnalysis
        {
            RawAiResponse = aiResponse
        };

        try
        {
            // Try to extract JSON from response (AI might add extra text)
            var jsonMatch = Regex.Match(aiResponse, @"\{.*\}", RegexOptions.Singleline);
            if (jsonMatch.Success)
            {
                var jsonString = jsonMatch.Value;
                var parsed = JsonConvert.DeserializeObject<AiAnalysisResponse>(jsonString);

                if (parsed != null)
                {
                    analysis.BioRelevant = parsed.BioRelevant;
                    analysis.BioRelevanceScore = Math.Clamp(parsed.BioRelevanceScore, 0, 100);
                    analysis.AffectedBioSectors = parsed.AffectedBioSectors ?? new List<string>();
                    analysis.HumanSafetyImpact = ValidateEnum(parsed.HumanSafetyImpact, "NONE", new[] { "HIGH", "MEDIUM", "LOW", "NONE" });
                    analysis.KeyConcern = parsed.KeyConcern ?? "No specific concern identified";
                    analysis.RecommendedPriority = ValidateEnum(parsed.RecommendedPriority, "LOW", new[] { "CRITICAL", "HIGH", "MEDIUM", "LOW" });
                    analysis.ConfidenceLevel = Math.Clamp(parsed.ConfidenceLevel, 0m, 1m);

                    _logger.LogInformation("Successfully parsed JSON response for vulnerability");
                    return analysis;
                }
            }

            // JSON parsing failed, try regex extraction
            _logger.LogWarning("JSON parsing failed, attempting regex extraction");
            return ExtractWithRegex(aiResponse, vulnerability);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error parsing AI response, using fallback");
            return FallbackHeuristicAnalysis(vulnerability);
        }
    }

    private BioRelevanceAnalysis ExtractWithRegex(string response, Vulnerability vulnerability)
    {
        var analysis = new BioRelevanceAnalysis
        {
            RawAiResponse = response
        };

        // Try to extract individual fields
        var bioRelevantMatch = Regex.Match(response, @"""bioRelevant"":\s*(true|false)", RegexOptions.IgnoreCase);
        analysis.BioRelevant = bioRelevantMatch.Success && bioRelevantMatch.Groups[1].Value.ToLower() == "true";

        var scoreMatch = Regex.Match(response, @"""bioRelevanceScore"":\s*(\d+)");
        analysis.BioRelevanceScore = scoreMatch.Success ? int.Parse(scoreMatch.Groups[1].Value) : _keywordFilter.QuickRelevanceScore(vulnerability.Description ?? "");

        analysis.HumanSafetyImpact = "MEDIUM";
        analysis.KeyConcern = "Analysis completed with partial data extraction";
        analysis.RecommendedPriority = analysis.BioRelevanceScore > 60 ? "HIGH" : "MEDIUM";
        analysis.ConfidenceLevel = 0.6m;

        _logger.LogWarning("Used regex extraction as fallback");
        return analysis;
    }

    public BioRelevanceAnalysis FallbackHeuristicAnalysis(Vulnerability vulnerability)
    {
        _logger.LogInformation("Using fallback heuristic analysis for {CveId}", vulnerability.CveId);

        var matchedKeywords = _keywordFilter.GetMatchedKeywords(vulnerability.Description ?? "");
        var keywordScore = _keywordFilter.QuickRelevanceScore(vulnerability.Description ?? "");
        
        // Adjust score based on CVSS
        var adjustedScore = keywordScore;
        if (vulnerability.CvssScore.HasValue)
        {
            if (vulnerability.CvssScore >= 9.0m) adjustedScore += 10;
            else if (vulnerability.CvssScore >= 7.0m) adjustedScore += 5;
        }

        adjustedScore = Math.Min(adjustedScore, 100);

        var bioRelevant = matchedKeywords.Count > 0;

        return new BioRelevanceAnalysis
        {
            BioRelevant = bioRelevant,
            BioRelevanceScore = adjustedScore,
            AffectedBioSectors = DetermineSectorsFromKeywords(matchedKeywords),
            HumanSafetyImpact = adjustedScore > 50 ? "MEDIUM" : "LOW",
            KeyConcern = $"Heuristic analysis based on {matchedKeywords.Count} bio keyword matches",
            RecommendedPriority = adjustedScore > 70 ? "HIGH" : adjustedScore > 40 ? "MEDIUM" : "LOW",
            ConfidenceLevel = 0.5m,
            RawAiResponse = "Fallback heuristic analysis used (AI unavailable or failed)"
        };
    }

    private List<string> DetermineSectorsFromKeywords(List<string> keywords)
    {
        var sectors = new HashSet<string>();

        foreach (var keyword in keywords)
        {
            var lower = keyword.ToLowerInvariant();
            
            if (lower.Contains("hospital") || lower.Contains("clinical") || lower.Contains("patient"))
                sectors.Add("Hospitals");
            
            if (lower.Contains("lab") || lower.Contains("diagnostic") || lower.Contains("specimen"))
                sectors.Add("Clinical Labs");
            
            if (lower.Contains("research") || lower.Contains("biobank"))
                sectors.Add("Research Labs");
            
            if (lower.Contains("pharmaceutical") || lower.Contains("drug"))
                sectors.Add("Pharmaceutical");
            
            if (lower.Contains("bioreactor") || lower.Contains("bioprocess") || lower.Contains("fermentation"))
                sectors.Add("Biomanufacturing");
            
            if (lower.Contains("food") || lower.Contains("agriculture") || lower.Contains("farming"))
                sectors.Add("Food/Agriculture");
        }

        return sectors.ToList();
    }

    private string ValidateEnum(string value, string defaultValue, string[] validValues)
    {
        if (string.IsNullOrWhiteSpace(value))
            return defaultValue;

        return validValues.Contains(value.ToUpperInvariant()) ? value.ToUpperInvariant() : defaultValue;
    }

    private class AiAnalysisResponse
    {
        [JsonProperty("bioRelevant")]
        public bool BioRelevant { get; set; }

        [JsonProperty("bioRelevanceScore")]
        public int BioRelevanceScore { get; set; }

        [JsonProperty("affectedBioSectors")]
        public List<string>? AffectedBioSectors { get; set; }

        [JsonProperty("humanSafetyImpact")]
        public string HumanSafetyImpact { get; set; } = string.Empty;

        [JsonProperty("keyConcern")]
        public string KeyConcern { get; set; } = string.Empty;

        [JsonProperty("recommendedPriority")]
        public string RecommendedPriority { get; set; } = string.Empty;

        [JsonProperty("confidenceLevel")]
        public decimal ConfidenceLevel { get; set; }
    }
}

