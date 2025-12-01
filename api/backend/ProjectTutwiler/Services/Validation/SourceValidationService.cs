using ProjectTutwiler.Models;

namespace ProjectTutwiler.Services.Validation;

/// <summary>
/// Service to validate and score trustworthiness of vulnerability data sources
/// </summary>
public class SourceValidationService
{
    private readonly ILogger<SourceValidationService> _logger;

    // Trust scores for known sources (0-100, higher = more trusted)
    private readonly Dictionary<string, int> _sourceTrustScores = new()
    {
        { "NVD", 95 }, // National Vulnerability Database - highly trusted
        { "CISA KEV", 100 }, // Known Exploited Vulnerabilities - authoritative
        { "CERT", 90 }, // Computer Emergency Response Teams
        { "CSIRT", 90 }, // Computer Security Incident Response Teams
        { "US-CERT", 95 }, // US CERT
        { "Vendor Advisory", 75 }, // Vendor advisories - generally trusted but may have bias
        { "Security Researcher", 70 }, // Individual researchers - variable trust
        { "OSINT", 60 }, // Open Source Intelligence - lower trust, needs validation
        { "Ransomware Leak Site", 50 }, // Leak sites - useful but unverified
        { "Unknown", 30 } // Unknown sources - low trust
    };

    public SourceValidationService(ILogger<SourceValidationService> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Get trust score for a source
    /// </summary>
    public int GetSourceTrustScore(string sourceName)
    {
        if (string.IsNullOrWhiteSpace(sourceName))
        {
            return 30; // Unknown source
        }

        // Check exact match first
        if (_sourceTrustScores.TryGetValue(sourceName, out var score))
        {
            return score;
        }

        // Check partial matches
        var upperSource = sourceName.ToUpperInvariant();
        
        if (upperSource.Contains("NVD") || upperSource.Contains("NATIONAL VULNERABILITY"))
            return 95;
        if (upperSource.Contains("CISA") || upperSource.Contains("KEV"))
            return 100;
        if (upperSource.Contains("CERT") || upperSource.Contains("CSIRT"))
            return 90;
        if (upperSource.Contains("VENDOR") || upperSource.Contains("ADVISORY"))
            return 75;
        if (upperSource.Contains("RESEARCHER") || upperSource.Contains("RESEARCH"))
            return 70;
        if (upperSource.Contains("OSINT") || upperSource.Contains("OPEN SOURCE"))
            return 60;
        if (upperSource.Contains("LEAK") || upperSource.Contains("RANSOMWARE"))
            return 50;

        _logger.LogWarning("Unknown source type: {Source}, assigning default trust score", sourceName);
        return 30; // Default for unknown
    }

    /// <summary>
    /// Validate a vulnerability record based on source trust and data completeness
    /// </summary>
    public ValidationResult ValidateVulnerability(Vulnerability vulnerability)
    {
        var sourceTrust = GetSourceTrustScore(vulnerability.SourceName);
        var dataCompleteness = CalculateDataCompleteness(vulnerability);
        var overallScore = (sourceTrust * 0.6m) + (dataCompleteness * 0.4m);

        var isValid = overallScore >= 50; // Minimum threshold
        var confidence = Math.Min(100, (int)overallScore);

        return new ValidationResult
        {
            IsValid = isValid,
            Confidence = confidence,
            SourceTrustScore = sourceTrust,
            DataCompletenessScore = dataCompleteness,
            OverallScore = overallScore,
            Issues = GetValidationIssues(vulnerability, sourceTrust)
        };
    }

    /// <summary>
    /// Calculate data completeness score (0-100)
    /// </summary>
    private int CalculateDataCompleteness(Vulnerability v)
    {
        int score = 0;

        if (!string.IsNullOrWhiteSpace(v.CveId)) score += 15;
        if (!string.IsNullOrWhiteSpace(v.Description) && v.Description.Length > 50) score += 20;
        if (v.CvssScore.HasValue) score += 20;
        if (!string.IsNullOrWhiteSpace(v.VendorName)) score += 15;
        if (v.PublishedDate.HasValue) score += 15;
        if (!string.IsNullOrWhiteSpace(v.AffectedProducts)) score += 10;
        if (!string.IsNullOrWhiteSpace(v.CvssVector)) score += 5;

        return score;
    }

    /// <summary>
    /// Get validation issues for a vulnerability
    /// </summary>
    private List<string> GetValidationIssues(Vulnerability v, int sourceTrust)
    {
        var issues = new List<string>();

        if (sourceTrust < 50)
        {
            issues.Add($"Low trust source: {v.SourceName} (trust score: {sourceTrust})");
        }

        if (string.IsNullOrWhiteSpace(v.Description) || v.Description.Length < 50)
        {
            issues.Add("Incomplete or missing description");
        }

        if (!v.CvssScore.HasValue)
        {
            issues.Add("Missing CVSS score");
        }

        if (string.IsNullOrWhiteSpace(v.VendorName))
        {
            issues.Add("Missing vendor information");
        }

        if (!v.PublishedDate.HasValue)
        {
            issues.Add("Missing publication date");
        }

        return issues;
    }
}

public class ValidationResult
{
    public bool IsValid { get; set; }
    public int Confidence { get; set; }
    public int SourceTrustScore { get; set; }
    public int DataCompletenessScore { get; set; }
    public decimal OverallScore { get; set; }
    public List<string> Issues { get; set; } = new();
}

