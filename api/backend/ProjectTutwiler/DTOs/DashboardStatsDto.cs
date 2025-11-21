namespace ProjectTutwiler.DTOs;

/// <summary>
/// Summary metrics for dashboard overview
/// </summary>
public class DashboardStatsDto
{
    // Overall Counts
    public int TotalVulnerabilities { get; set; }
    public int AnalyzedVulnerabilities { get; set; }
    public int UnanalyzedVulnerabilities { get; set; }
    public int KnownExploitedCount { get; set; }

    // Priority Breakdown
    public PriorityBreakdown PriorityBreakdown { get; set; } = new();

    // Recent Activity
    public DateTime? LastIngestionTime { get; set; }
    public string LastIngestionTimeFormatted => LastIngestionTime?.ToString("yyyy-MM-dd HH:mm UTC") ?? "Never";
    public int VulnerabilitiesLast24Hours { get; set; }
    public int VulnerabilitiesLast7Days { get; set; }

    // CVSS Distribution
    public CvssDistribution CvssDistribution { get; set; } = new();

    // Analysis Performance
    public decimal AverageCompositeScore { get; set; }
    public int HighPriorityCount => PriorityBreakdown.Critical + PriorityBreakdown.High;
}

public class PriorityBreakdown
{
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
}

public class CvssDistribution
{
    public int Critical { get; set; }  // 9.0-10.0
    public int High { get; set; }      // 7.0-8.9
    public int Medium { get; set; }    // 4.0-6.9
    public int Low { get; set; }       // 0.0-3.9
    public int Unknown { get; set; }   // No CVSS
}

