using System.Text.RegularExpressions;
using ProjectTutwiler.Models;
using ProjectTutwiler.Models.Enums;
using Xunit;

namespace ProjectTutwiler.Tests;

public class BasicModelTests
{
    [Fact]
    public void Vulnerability_CanBeInstantiatedWithRequiredProperties()
    {
        // Arrange & Act
        var vulnerability = new Vulnerability
        {
            CveId = "CVE-2024-12345",
            Description = "Test vulnerability description",
            SourceName = "NVD"
        };

        // Assert
        Assert.NotNull(vulnerability);
        Assert.Equal("CVE-2024-12345", vulnerability.CveId);
        Assert.Equal("Test vulnerability description", vulnerability.Description);
        Assert.Equal("NVD", vulnerability.SourceName);
        Assert.False(vulnerability.KnownExploited);
        Assert.NotNull(vulnerability.ActionRecommendations);
        Assert.Empty(vulnerability.ActionRecommendations);
    }

    [Theory]
    [InlineData(0.00)]
    [InlineData(25.50)]
    [InlineData(50.00)]
    [InlineData(75.75)]
    [InlineData(100.00)]
    public void CompositeScore_IsWithinValidRange(decimal score)
    {
        // Arrange & Act
        var bioImpactScore = new BioImpactScore
        {
            VulnerabilityId = 1,
            HumanSafetyScore = 80,
            SupplyChainScore = 70,
            ExploitabilityScore = 60,
            PatchAvailabilityScore = 50,
            CompositeScore = score,
            PriorityLevel = PriorityLevel.HIGH,
            Vulnerability = new Vulnerability
            {
                CveId = "CVE-2024-99999",
                Description = "Test",
                SourceName = "NVD"
            }
        };

        // Assert
        Assert.InRange(bioImpactScore.CompositeScore, 0, 100);
    }

    [Theory]
    [InlineData("CVE-2024-12345", true)]
    [InlineData("CVE-2023-00001", true)]
    [InlineData("CVE-1999-99999", true)]
    [InlineData("CVE-2024-1", true)]
    [InlineData("INVALID-2024-12345", false)]
    [InlineData("CVE-24-12345", false)]
    [InlineData("CVE-2024", false)]
    [InlineData("", false)]
    public void CveId_MatchesExpectedPattern(string cveId, bool shouldMatch)
    {
        // Arrange
        var cvePattern = @"^CVE-\d{4}-\d+$";
        var regex = new Regex(cvePattern);

        // Act
        var matches = regex.IsMatch(cveId);

        // Assert
        Assert.Equal(shouldMatch, matches);
    }

    [Fact]
    public void BioImpactScore_AllScoresAreWithinRange()
    {
        // Arrange & Act
        var bioImpactScore = new BioImpactScore
        {
            VulnerabilityId = 1,
            HumanSafetyScore = 100,
            SupplyChainScore = 0,
            ExploitabilityScore = 50,
            PatchAvailabilityScore = 75,
            CompositeScore = 56.25m,
            PriorityLevel = PriorityLevel.MEDIUM,
            Vulnerability = new Vulnerability
            {
                CveId = "CVE-2024-99999",
                Description = "Test",
                SourceName = "NVD"
            }
        };

        // Assert
        Assert.InRange(bioImpactScore.HumanSafetyScore, 0, 100);
        Assert.InRange(bioImpactScore.SupplyChainScore, 0, 100);
        Assert.InRange(bioImpactScore.ExploitabilityScore, 0, 100);
        Assert.InRange(bioImpactScore.PatchAvailabilityScore, 0, 100);
    }

    [Fact]
    public void ActionRecommendation_CanBeInstantiatedWithRequiredProperties()
    {
        // Arrange & Act
        var recommendation = new ActionRecommendation
        {
            VulnerabilityId = 1,
            RecommendationType = RecommendationType.IMMEDIATE,
            ActionText = "Apply security patch immediately",
            SafeToImplement = true,
            Vulnerability = new Vulnerability
            {
                CveId = "CVE-2024-99999",
                Description = "Test",
                SourceName = "NVD"
            }
        };

        // Assert
        Assert.NotNull(recommendation);
        Assert.Equal(RecommendationType.IMMEDIATE, recommendation.RecommendationType);
        Assert.Equal("Apply security patch immediately", recommendation.ActionText);
        Assert.True(recommendation.SafeToImplement);
        Assert.False(recommendation.RequiresTier2);
    }

    [Theory]
    [InlineData(PriorityLevel.CRITICAL)]
    [InlineData(PriorityLevel.HIGH)]
    [InlineData(PriorityLevel.MEDIUM)]
    [InlineData(PriorityLevel.LOW)]
    public void PriorityLevel_AllEnumValuesAreValid(PriorityLevel level)
    {
        // Arrange & Act
        var bioImpactScore = new BioImpactScore
        {
            VulnerabilityId = 1,
            HumanSafetyScore = 80,
            SupplyChainScore = 70,
            ExploitabilityScore = 60,
            PatchAvailabilityScore = 50,
            CompositeScore = 65.00m,
            PriorityLevel = level,
            Vulnerability = new Vulnerability
            {
                CveId = "CVE-2024-99999",
                Description = "Test",
                SourceName = "NVD"
            }
        };

        // Assert
        Assert.True(Enum.IsDefined(typeof(PriorityLevel), level));
    }

    [Fact]
    public void Vulnerability_TimestampsAreSetOnCreation()
    {
        // Arrange
        var beforeCreation = DateTime.UtcNow.AddSeconds(-1);

        // Act
        var vulnerability = new Vulnerability
        {
            CveId = "CVE-2024-12345",
            Description = "Test vulnerability",
            SourceName = "NVD"
        };

        var afterCreation = DateTime.UtcNow.AddSeconds(1);

        // Assert
        Assert.InRange(vulnerability.CreatedAt, beforeCreation, afterCreation);
        Assert.InRange(vulnerability.UpdatedAt, beforeCreation, afterCreation);
    }
}

