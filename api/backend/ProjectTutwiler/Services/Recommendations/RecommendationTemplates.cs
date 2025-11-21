using ProjectTutwiler.Models;
using ProjectTutwiler.Models.Enums;

namespace ProjectTutwiler.Services.Recommendations;

public static class RecommendationTemplates
{
    /// <summary>
    /// Generate recommendations for CRITICAL priority vulnerabilities
    /// Focus: Immediate defensive actions without disrupting operations
    /// </summary>
    public static List<ActionRecommendation> CreateCriticalRecommendations(Vulnerability vulnerability)
    {
        var nvdUrl = $"https://nvd.nist.gov/vuln/detail/{vulnerability.CveId}";

        return new List<ActionRecommendation>
        {
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.IMMEDIATE,
                ActionText = "Enable Enhanced Monitoring: Increase log collection frequency to every 15 minutes for affected systems. Review logs daily for suspicious activity patterns.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.IMMEDIATE,
                ActionText = "Network Segmentation Review: Verify that affected systems are properly isolated from critical production networks and patient data systems. Document current network topology.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.IMMEDIATE,
                ActionText = "Access Control Audit: Review and remove unnecessary user permissions on affected systems. Enforce multi-factor authentication (MFA) for all administrative access immediately.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.ESCALATE,
                ActionText = $"Request Tier-2 Guidance: Escalate to Bio-ISAC analyst for specialized cyberbiosecurity review and remediation planning. Reference CVE: {vulnerability.CveId}",
                SafeToImplement = true,
                RequiresTier2 = true
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.IMMEDIATE,
                ActionText = $"Review Complete Vendor Advisory: Access the full technical details and vendor-specific guidance at {nvdUrl}. Document all affected product versions.",
                SafeToImplement = true,
                RequiresTier2 = false
            }
        };
    }

    /// <summary>
    /// Generate recommendations for HIGH priority vulnerabilities
    /// Focus: Planned remediation with testing and stakeholder coordination
    /// </summary>
    public static List<ActionRecommendation> CreateHighRecommendations(Vulnerability vulnerability)
    {
        var nvdUrl = $"https://nvd.nist.gov/vuln/detail/{vulnerability.CveId}";

        return new List<ActionRecommendation>
        {
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.IMMEDIATE,
                ActionText = $"Review Vendor Advisory: Examine complete vulnerability details and vendor recommendations at {nvdUrl}. Check for available security patches.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.IMMEDIATE,
                ActionText = "Inventory Affected Assets: Identify all systems, devices, and applications using the vulnerable software version. Document software versions and configurations.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.SCHEDULED,
                ActionText = "Test Patch in Non-Production: If vendor patch available, deploy to development/test environment first. Validate functionality of critical workflows for minimum 48 hours.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.SCHEDULED,
                ActionText = "Schedule Maintenance Window: Plan remediation within 7 days. Notify all stakeholders 48 hours in advance. Prepare rollback procedures before implementation.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.MONITOR,
                ActionText = "Enhanced Monitoring: Configure alerts for unusual network traffic or authentication attempts on affected systems. Review security logs weekly.",
                SafeToImplement = true,
                RequiresTier2 = false
            }
        };
    }

    /// <summary>
    /// Generate recommendations for MEDIUM priority vulnerabilities
    /// Focus: Regular maintenance cycle with monitoring
    /// </summary>
    public static List<ActionRecommendation> CreateMediumRecommendations(Vulnerability vulnerability)
    {
        var nvdUrl = $"https://nvd.nist.gov/vuln/detail/{vulnerability.CveId}";

        return new List<ActionRecommendation>
        {
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.SCHEDULED,
                ActionText = "Review During Next Maintenance: Add to 30-day maintenance schedule. Coordinate with vendor support for recommended remediation approach.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.MONITOR,
                ActionText = "Monitor for Exploitation: Subscribe to threat intelligence feeds for this vulnerability. Check CISA KEV catalog weekly for exploitation activity.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.IMMEDIATE,
                ActionText = $"Document Vulnerability Details: Record CVE information and potentially affected systems in asset management system. Reference: {nvdUrl}",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.MONITOR,
                ActionText = "Verify Existing Controls: Confirm that network segmentation, firewalls, and access controls provide adequate defense-in-depth against this vulnerability class.",
                SafeToImplement = true,
                RequiresTier2 = false
            }
        };
    }

    /// <summary>
    /// Generate recommendations for LOW priority vulnerabilities
    /// Focus: Awareness and inclusion in regular updates
    /// </summary>
    public static List<ActionRecommendation> CreateLowRecommendations(Vulnerability vulnerability)
    {
        var nvdUrl = $"https://nvd.nist.gov/vuln/detail/{vulnerability.CveId}";

        return new List<ActionRecommendation>
        {
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.MONITOR,
                ActionText = "Awareness Only: Include in monthly security bulletin. No immediate action required unless threat landscape changes.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.SCHEDULED,
                ActionText = "Include in Regular Updates: Address during next quarterly patch cycle if vendor patch becomes available. Document in maintenance tracking system.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.MONITOR,
                ActionText = $"Reference for Future Planning: Bookmark CVE details at {nvdUrl}. Reassess if CVSS score increases or exploitation is detected.",
                SafeToImplement = true,
                RequiresTier2 = false
            }
        };
    }
}

