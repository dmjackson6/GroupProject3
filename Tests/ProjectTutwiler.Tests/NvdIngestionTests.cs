using System.Text.RegularExpressions;
using Newtonsoft.Json;
using ProjectTutwiler.Models;
using ProjectTutwiler.Services.DataIngestion.DTOs;
using Xunit;

namespace ProjectTutwiler.Tests;

public class NvdIngestionTests
{
    [Fact]
    public void NvdResponse_CanDeserializeFromJson()
    {
        // Arrange
        var sampleJson = @"{
            ""resultsPerPage"": 2,
            ""startIndex"": 0,
            ""totalResults"": 2,
            ""vulnerabilities"": [
                {
                    ""cve"": {
                        ""id"": ""CVE-2024-12345"",
                        ""published"": ""2024-11-01T10:15:00.000"",
                        ""descriptions"": [
                            {
                                ""lang"": ""en"",
                                ""value"": ""Test vulnerability description""
                            }
                        ],
                        ""metrics"": {
                            ""cvssMetricV31"": [
                                {
                                    ""cvssData"": {
                                        ""baseScore"": 7.5,
                                        ""vectorString"": ""CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N""
                                    }
                                }
                            ]
                        },
                        ""references"": [
                            {
                                ""url"": ""https://example.com/advisory""
                            }
                        ]
                    }
                }
            ]
        }";

        // Act
        var nvdResponse = JsonConvert.DeserializeObject<NvdResponse>(sampleJson);

        // Assert
        Assert.NotNull(nvdResponse);
        Assert.Equal(2, nvdResponse.ResultsPerPage);
        Assert.Equal(2, nvdResponse.TotalResults);
        Assert.Single(nvdResponse.Vulnerabilities);
        Assert.Equal("CVE-2024-12345", nvdResponse.Vulnerabilities[0].Cve.Id);
    }

    [Theory]
    [InlineData("CVE-2024-12345")]
    [InlineData("CVE-2023-00001")]
    [InlineData("CVE-1999-99999")]
    [InlineData("CVE-2024-1")]
    public void CveId_FormatExtraction_IsValid(string cveId)
    {
        // Arrange
        var cvePattern = @"^CVE-\d{4}-\d+$";
        var regex = new Regex(cvePattern);

        // Act
        var isValid = regex.IsMatch(cveId);

        // Assert
        Assert.True(isValid, $"CVE ID {cveId} should match expected pattern");
    }

    [Fact]
    public void NvdCvssMetricV31_ExtractsBaseScoreCorrectly()
    {
        // Arrange
        var sampleJson = @"{
            ""cvssMetricV31"": [
                {
                    ""cvssData"": {
                        ""baseScore"": 9.8,
                        ""vectorString"": ""CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H""
                    }
                }
            ]
        }";

        // Act
        var metrics = JsonConvert.DeserializeObject<NvdMetrics>(sampleJson);

        // Assert
        Assert.NotNull(metrics);
        Assert.NotNull(metrics.CvssMetricV31);
        Assert.Single(metrics.CvssMetricV31);
        Assert.Equal(9.8m, metrics.CvssMetricV31[0].CvssData.BaseScore);
        Assert.Equal("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", metrics.CvssMetricV31[0].CvssData.VectorString);
    }

    [Fact]
    public void CvssScore_Priority_V31OverV30OverV2()
    {
        // Arrange - Metrics with all three versions
        var metricsWithV31 = new NvdMetrics
        {
            CvssMetricV31 = new List<NvdCvssMetricV31>
            {
                new NvdCvssMetricV31 { CvssData = new NvdCvssData { BaseScore = 9.8m, VectorString = "V31" } }
            },
            CvssMetricV30 = new List<NvdCvssMetricV30>
            {
                new NvdCvssMetricV30 { CvssData = new NvdCvssData { BaseScore = 8.0m, VectorString = "V30" } }
            },
            CvssMetricV2 = new List<NvdCvssMetricV2>
            {
                new NvdCvssMetricV2 { CvssData = new NvdCvssDataV2 { BaseScore = 7.0m, VectorString = "V2" } }
            }
        };

        // Act - Simulate priority selection (V3.1 should be chosen)
        decimal? selectedScore = null;
        if (metricsWithV31.CvssMetricV31 != null && metricsWithV31.CvssMetricV31.Count > 0)
        {
            selectedScore = metricsWithV31.CvssMetricV31.First().CvssData.BaseScore;
        }
        else if (metricsWithV31.CvssMetricV30 != null && metricsWithV31.CvssMetricV30.Count > 0)
        {
            selectedScore = metricsWithV31.CvssMetricV30.First().CvssData.BaseScore;
        }
        else if (metricsWithV31.CvssMetricV2 != null && metricsWithV31.CvssMetricV2.Count > 0)
        {
            selectedScore = metricsWithV31.CvssMetricV2.First().CvssData.BaseScore;
        }

        // Assert - V3.1 score should be selected
        Assert.Equal(9.8m, selectedScore);
    }

    [Fact]
    public void EnglishDescription_IsExtracted_WhenMultipleLanguagesPresent()
    {
        // Arrange
        var descriptions = new List<NvdDescription>
        {
            new NvdDescription { Lang = "es", Value = "Descripción en español" },
            new NvdDescription { Lang = "en", Value = "English description" },
            new NvdDescription { Lang = "fr", Value = "Description en français" }
        };

        // Act
        var englishDesc = descriptions.FirstOrDefault(d => d.Lang == "en");

        // Assert
        Assert.NotNull(englishDesc);
        Assert.Equal("English description", englishDesc.Value);
    }

    [Fact]
    public void Vulnerability_MapsFromNvdCve_WithRequiredFields()
    {
        // Arrange
        var nvdCve = new NvdCve
        {
            Id = "CVE-2024-99999",
            Published = "2024-11-20T10:00:00.000",
            Descriptions = new List<NvdDescription>
            {
                new NvdDescription { Lang = "en", Value = "Test description" }
            },
            Metrics = new NvdMetrics
            {
                CvssMetricV31 = new List<NvdCvssMetricV31>
                {
                    new NvdCvssMetricV31
                    {
                        CvssData = new NvdCvssData
                        {
                            BaseScore = 7.5m,
                            VectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                        }
                    }
                }
            },
            References = new List<NvdReference>
            {
                new NvdReference { Url = "https://example.com" }
            }
        };

        // Act
        var vulnerability = new Vulnerability
        {
            CveId = nvdCve.Id,
            SourceName = "NVD",
            Description = nvdCve.Descriptions.First(d => d.Lang == "en").Value,
            CvssScore = nvdCve.Metrics?.CvssMetricV31?.First().CvssData.BaseScore,
            CvssVector = nvdCve.Metrics?.CvssMetricV31?.First().CvssData.VectorString,
            RawData = JsonConvert.SerializeObject(nvdCve)
        };

        // Assert
        Assert.Equal("CVE-2024-99999", vulnerability.CveId);
        Assert.Equal("NVD", vulnerability.SourceName);
        Assert.Equal("Test description", vulnerability.Description);
        Assert.Equal(7.5m, vulnerability.CvssScore);
        Assert.Equal("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", vulnerability.CvssVector);
        Assert.NotNull(vulnerability.RawData);
    }

    [Fact]
    public void IngestionResult_TracksStatisticsCorrectly()
    {
        // Arrange & Act
        var result = new ProjectTutwiler.Services.DataIngestion.IngestionResult
        {
            TotalFetched = 10,
            NewAdded = 7,
            DuplicatesSkipped = 3,
            Errors = 0,
            Message = "Success"
        };

        // Assert
        Assert.Equal(10, result.TotalFetched);
        Assert.Equal(7, result.NewAdded);
        Assert.Equal(3, result.DuplicatesSkipped);
        Assert.Equal(0, result.Errors);
        Assert.Equal(10, result.NewAdded + result.DuplicatesSkipped);
    }

    [Theory]
    [InlineData("2024-11-20T10:15:30.000", true)]
    [InlineData("2024-01-01T00:00:00.000", true)]
    [InlineData("InvalidDate", false)]
    public void PublishedDate_ParsesCorrectly(string dateString, bool shouldParse)
    {
        // Act
        var parsed = DateTime.TryParse(dateString, out var result);

        // Assert
        Assert.Equal(shouldParse, parsed);
    }
}

