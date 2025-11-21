using System.Text.RegularExpressions;

namespace ProjectTutwiler.Services.AI;

public class PromptSafetyFilter
{
    private static readonly string[] DangerousPatterns = new[]
    {
        "ignore previous instructions",
        "ignore all previous",
        "disregard previous",
        "you are now",
        "pretend you are",
        "system:",
        "assistant:",
        "user:",
        "###",
        "<|",
        "|>",
        "forget everything",
        "new instructions",
        "role play"
    };

    private readonly ILogger<PromptSafetyFilter> _logger;

    public PromptSafetyFilter(ILogger<PromptSafetyFilter> logger)
    {
        _logger = logger;
    }

    public string SanitizeInput(string userInput)
    {
        if (string.IsNullOrWhiteSpace(userInput))
        {
            return string.Empty;
        }

        var sanitized = userInput;

        // Remove dangerous patterns
        foreach (var pattern in DangerousPatterns)
        {
            if (sanitized.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Dangerous pattern detected and removed: {Pattern}", pattern);
                sanitized = Regex.Replace(sanitized, Regex.Escape(pattern), string.Empty, RegexOptions.IgnoreCase);
            }
        }

        // Remove excessive newlines
        sanitized = Regex.Replace(sanitized, @"\n{3,}", "\n\n");
        
        // Remove control characters except newline and tab
        sanitized = Regex.Replace(sanitized, @"[\x00-\x08\x0B\x0C\x0E-\x1F]", string.Empty);

        // Truncate to max 1000 characters
        if (sanitized.Length > 1000)
        {
            _logger.LogWarning("Input truncated from {Original} to 1000 characters", sanitized.Length);
            sanitized = sanitized.Substring(0, 1000);
        }

        return sanitized.Trim();
    }

    public bool IsSuspicious(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        int redFlagCount = 0;

        foreach (var pattern in DangerousPatterns)
        {
            if (input.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                redFlagCount++;
            }
        }

        // Suspicious if 2 or more red flags
        if (redFlagCount >= 2)
        {
            _logger.LogWarning("Suspicious input detected with {Count} red flags", redFlagCount);
            return true;
        }

        return false;
    }
}

