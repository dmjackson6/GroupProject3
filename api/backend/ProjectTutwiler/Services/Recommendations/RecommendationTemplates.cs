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
        var vendor = vulnerability.VendorName ?? "the vendor";
        var cvssText = vulnerability.CvssScore.HasValue ? $"CVSS {vulnerability.CvssScore:F1}" : "high severity";
        var exploitedText = vulnerability.KnownExploited 
            ? "⚠️ ACTIVE EXPLOITATION DETECTED - " 
            : "";
        var patchAvailable = vulnerability.BioImpactScore?.PatchAvailabilityScore >= 50;
        var patchText = patchAvailable 
            ? "Vendor patch is available - prioritize immediate deployment." 
            : "No vendor patch currently available - implement compensating controls.";

        return new List<ActionRecommendation>
        {
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.IMMEDIATE,
                ActionText = $"{exploitedText}Enable Enhanced Monitoring: Increase log collection frequency to every 15 minutes for {vendor} systems affected by {vulnerability.CveId} ({cvssText}). Review logs daily for suspicious activity patterns.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.IMMEDIATE,
                ActionText = $"Network Segmentation Review: Verify that {vendor} systems are properly isolated from critical production networks and patient data systems. Document current network topology for {vulnerability.CveId}.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.IMMEDIATE,
                ActionText = $"Access Control Audit: Review and remove unnecessary user permissions on affected {vendor} systems. Enforce multi-factor authentication (MFA) for all administrative access immediately.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = patchAvailable ? RecommendationType.IMMEDIATE : RecommendationType.ESCALATE,
                ActionText = patchAvailable 
                    ? $"Apply Vendor Patch Immediately: {patchText} Test in non-production first, then deploy to production within 24 hours. Reference: {nvdUrl}"
                    : $"Request Tier-2 Guidance: {patchText} Escalate to Bio-ISAC analyst for specialized cyberbiosecurity review and remediation planning. Reference CVE: {vulnerability.CveId}",
                SafeToImplement = true,
                RequiresTier2 = !patchAvailable
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.IMMEDIATE,
                ActionText = $"Review {vendor} Advisory: Access complete technical details and {vendor}-specific guidance at {nvdUrl}. Document all affected product versions and configurations.",
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
        var vendor = vulnerability.VendorName ?? "the vendor";
        var cvssText = vulnerability.CvssScore.HasValue ? $"CVSS {vulnerability.CvssScore:F1}" : "high severity";
        var exploitedText = vulnerability.KnownExploited 
            ? "⚠️ Known Exploited - " 
            : "";
        var patchAvailable = vulnerability.BioImpactScore?.PatchAvailabilityScore >= 50;
        var urgencyDays = vulnerability.KnownExploited ? "3-5 days" : "7 days";

        return new List<ActionRecommendation>
        {
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.IMMEDIATE,
                ActionText = $"{exploitedText}Review {vendor} Advisory: Examine complete vulnerability details ({cvssText}) and {vendor} recommendations at {nvdUrl}. Check for available security patches.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.IMMEDIATE,
                ActionText = $"Inventory Affected {vendor} Assets: Identify all systems, devices, and applications using the vulnerable {vendor} software version. Document software versions and configurations for {vulnerability.CveId}.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = patchAvailable ? RecommendationType.SCHEDULED : RecommendationType.MONITOR,
                ActionText = patchAvailable
                    ? $"Test {vendor} Patch in Non-Production: Deploy to development/test environment first. Validate functionality of critical workflows for minimum 48 hours before production deployment."
                    : $"Monitor for {vendor} Patch Availability: Check {vendor} security advisories weekly. No patch currently available - implement compensating controls.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.SCHEDULED,
                ActionText = $"Schedule Maintenance Window: Plan remediation within {urgencyDays}. Notify all stakeholders 48 hours in advance. Prepare rollback procedures before implementation.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.MONITOR,
                ActionText = $"Enhanced Monitoring for {vendor} Systems: Configure alerts for unusual network traffic or authentication attempts on affected systems. Review security logs weekly for {vulnerability.CveId}.",
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
        var vendor = vulnerability.VendorName ?? "the vendor";
        var cvssText = vulnerability.CvssScore.HasValue ? $"CVSS {vulnerability.CvssScore:F1}" : "moderate severity";
        var exploitedText = vulnerability.KnownExploited 
            ? "⚠️ Known Exploited - prioritize in next maintenance cycle. " 
            : "";

        return new List<ActionRecommendation>
        {
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.SCHEDULED,
                ActionText = $"{exploitedText}Review During Next Maintenance: Add {vulnerability.CveId} ({cvssText}) to 30-day maintenance schedule. Coordinate with {vendor} support for recommended remediation approach.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.MONITOR,
                ActionText = $"Monitor for {vendor} Exploitation: Subscribe to threat intelligence feeds for {vulnerability.CveId}. Check CISA KEV catalog weekly for exploitation activity affecting {vendor} products.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.IMMEDIATE,
                ActionText = $"Document {vendor} Vulnerability Details: Record CVE information ({vulnerability.CveId}) and potentially affected {vendor} systems in asset management system. Reference: {nvdUrl}",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.MONITOR,
                ActionText = $"Verify Existing Controls for {vendor} Systems: Confirm that network segmentation, firewalls, and access controls provide adequate defense-in-depth against this {vendor} vulnerability class.",
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
        var vendor = vulnerability.VendorName ?? "the vendor";
        var cvssText = vulnerability.CvssScore.HasValue ? $"CVSS {vulnerability.CvssScore:F1}" : "low severity";
        var exploitedText = vulnerability.KnownExploited 
            ? "⚠️ Note: This vulnerability is known to be exploited. " 
            : "";

        return new List<ActionRecommendation>
        {
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.MONITOR,
                ActionText = $"{exploitedText}Awareness Only: Include {vulnerability.CveId} ({cvssText}) in monthly security bulletin for {vendor} systems. No immediate action required unless threat landscape changes.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.SCHEDULED,
                ActionText = $"Include {vendor} Updates in Regular Cycle: Address {vulnerability.CveId} during next quarterly patch cycle if {vendor} patch becomes available. Document in maintenance tracking system.",
                SafeToImplement = true,
                RequiresTier2 = false
            },
            new ActionRecommendation
            {
                VulnerabilityId = vulnerability.Id,
                RecommendationType = RecommendationType.MONITOR,
                ActionText = $"Reference for Future Planning: Bookmark {vendor} CVE details at {nvdUrl}. Reassess if CVSS score increases or exploitation is detected for {vulnerability.CveId}.",
                SafeToImplement = true,
                RequiresTier2 = false
            }
        };
    }
}

