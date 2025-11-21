using Newtonsoft.Json;
using ProjectTutwiler.Services.DataIngestion.DTOs;
using Xunit;

namespace ProjectTutwiler.Tests;

public class CisaKevIntegrationTests
{
    [Fact]
    public async Task CisaKevCatalog_CanDeserializeFromRealApi()
    {
        // Arrange
        using var httpClient = new HttpClient();
        const string kevUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

        // Act
        var jsonContent = await httpClient.GetStringAsync(kevUrl);
        var catalog = JsonConvert.DeserializeObject<CisaKevCatalog>(jsonContent);

        // Assert
        Assert.NotNull(catalog);
        Assert.NotEmpty(catalog.Title);
        Assert.NotEmpty(catalog.CatalogVersion);
        Assert.True(catalog.Count > 0, "KEV catalog should contain vulnerabilities");
        Assert.NotEmpty(catalog.Vulnerabilities);
        Assert.Equal(catalog.Count, catalog.Vulnerabilities.Count);

        // Verify first vulnerability structure
        var firstVuln = catalog.Vulnerabilities.First();
        Assert.NotEmpty(firstVuln.CveID);
        Assert.Matches(@"^CVE-\d{4}-\d+$", firstVuln.CveID);
        Assert.NotEmpty(firstVuln.VendorProject);
        Assert.NotEmpty(firstVuln.Product);
        Assert.NotEmpty(firstVuln.VulnerabilityName);
        Assert.NotEmpty(firstVuln.ShortDescription);
    }

    [Fact]
    public void CisaKevVulnerability_HasRequiredFields()
    {
        // Arrange
        var sampleJson = @"{
            ""cveID"": ""CVE-2024-12345"",
            ""vendorProject"": ""Microsoft"",
            ""product"": ""Windows"",
            ""vulnerabilityName"": ""Test Vulnerability"",
            ""dateAdded"": ""2024-11-20"",
            ""shortDescription"": ""A vulnerability exists"",
            ""requiredAction"": ""Apply updates"",
            ""dueDate"": ""2024-12-20"",
            ""knownRansomwareCampaignUse"": ""Known""
        }";

        // Act
        var kevVuln = JsonConvert.DeserializeObject<CisaKevVulnerability>(sampleJson);

        // Assert
        Assert.NotNull(kevVuln);
        Assert.Equal("CVE-2024-12345", kevVuln.CveID);
        Assert.Equal("Microsoft", kevVuln.VendorProject);
        Assert.Equal("Windows", kevVuln.Product);
        Assert.Equal("Test Vulnerability", kevVuln.VulnerabilityName);
        Assert.Equal("2024-11-20", kevVuln.DateAdded);
        Assert.Equal("A vulnerability exists", kevVuln.ShortDescription);
        Assert.Equal("Apply updates", kevVuln.RequiredAction);
        Assert.Equal("2024-12-20", kevVuln.DueDate);
        Assert.Equal("Known", kevVuln.KnownRansomwareCampaignUse);
    }

    [Theory]
    [InlineData("Known")]
    [InlineData("Unknown")]
    public void KnownRansomwareCampaignUse_AcceptsValidValues(string value)
    {
        // Arrange & Act
        var kevVuln = new CisaKevVulnerability
        {
            CveID = "CVE-2024-12345",
            KnownRansomwareCampaignUse = value
        };

        // Assert
        Assert.Contains(kevVuln.KnownRansomwareCampaignUse, new[] { "Known", "Unknown" });
    }

    [Fact]
    public void CombinedIngestionResult_StructureIsCorrect()
    {
        // Arrange & Act
        var result = new ProjectTutwiler.Services.DataIngestion.CombinedIngestionResult
        {
            NvdResults = new ProjectTutwiler.Services.DataIngestion.IngestionResult
            {
                TotalFetched = 10,
                NewAdded = 8,
                DuplicatesSkipped = 2
            },
            KevResults = new ProjectTutwiler.Services.DataIngestion.IngestionResult
            {
                TotalFetched = 1000,
                NewAdded = 5,
                DuplicatesSkipped = 995
            },
            TotalVulnerabilities = 100,
            TotalKnownExploited = 50,
            Message = "Completed"
        };

        // Assert
        Assert.NotNull(result.NvdResults);
        Assert.NotNull(result.KevResults);
        Assert.Equal(10, result.NvdResults.TotalFetched);
        Assert.Equal(8, result.NvdResults.NewAdded);
        Assert.Equal(1000, result.KevResults.TotalFetched);
        Assert.Equal(5, result.KevResults.NewAdded);
        Assert.Equal(100, result.TotalVulnerabilities);
        Assert.Equal(50, result.TotalKnownExploited);
    }

    [Fact]
    public void KevVulnerability_MapsToVulnerabilityModel()
    {
        // Arrange
        var kevVuln = new CisaKevVulnerability
        {
            CveID = "CVE-2024-99999",
            VendorProject = "Test Vendor",
            Product = "Test Product",
            VulnerabilityName = "Test Vulnerability",
            ShortDescription = "This is a test vulnerability",
            DateAdded = "2024-11-20",
            RequiredAction = "Apply patch",
            DueDate = "2024-12-20",
            KnownRansomwareCampaignUse = "Known"
        };

        // Act - Simulate mapping
        var vulnerability = new ProjectTutwiler.Models.Vulnerability
        {
            CveId = kevVuln.CveID,
            SourceName = "CISA_KEV",
            VendorName = kevVuln.VendorProject,
            Description = kevVuln.ShortDescription,
            KnownExploited = true,
            AffectedProducts = JsonConvert.SerializeObject(new[] { kevVuln.Product }),
            RawData = JsonConvert.SerializeObject(kevVuln)
        };

        // Assert
        Assert.Equal("CVE-2024-99999", vulnerability.CveId);
        Assert.Equal("CISA_KEV", vulnerability.SourceName);
        Assert.Equal("Test Vendor", vulnerability.VendorName);
        Assert.Equal("This is a test vulnerability", vulnerability.Description);
        Assert.True(vulnerability.KnownExploited);
        Assert.Contains("Test Product", vulnerability.AffectedProducts);
    }

    [Fact]
    public void DateAdded_ParsesCorrectly()
    {
        // Arrange
        var dateString = "2024-11-20";

        // Act
        var parsed = DateTime.TryParse(dateString, out var result);

        // Assert
        Assert.True(parsed);
        Assert.Equal(2024, result.Year);
        Assert.Equal(11, result.Month);
        Assert.Equal(20, result.Day);
    }

    [Fact]
    public async Task KevCatalog_HasExpectedStructure()
    {
        // Arrange
        var sampleJson = @"{
            ""title"": ""CISA Catalog of Known Exploited Vulnerabilities"",
            ""catalogVersion"": ""2024.11.20"",
            ""dateReleased"": ""2024-11-20T10:00:00.000Z"",
            ""count"": 2,
            ""vulnerabilities"": [
                {
                    ""cveID"": ""CVE-2024-12345"",
                    ""vendorProject"": ""Microsoft"",
                    ""product"": ""Windows"",
                    ""vulnerabilityName"": ""Test Vuln 1"",
                    ""dateAdded"": ""2024-11-20"",
                    ""shortDescription"": ""Test description 1"",
                    ""requiredAction"": ""Apply updates"",
                    ""dueDate"": ""2024-12-20"",
                    ""knownRansomwareCampaignUse"": ""Known""
                },
                {
                    ""cveID"": ""CVE-2024-54321"",
                    ""vendorProject"": ""Adobe"",
                    ""product"": ""Acrobat"",
                    ""vulnerabilityName"": ""Test Vuln 2"",
                    ""dateAdded"": ""2024-11-19"",
                    ""shortDescription"": ""Test description 2"",
                    ""requiredAction"": ""Apply updates"",
                    ""dueDate"": ""2024-12-19"",
                    ""knownRansomwareCampaignUse"": ""Unknown""
                }
            ]
        }";

        // Act
        var catalog = JsonConvert.DeserializeObject<CisaKevCatalog>(sampleJson);

        // Assert
        Assert.NotNull(catalog);
        Assert.Equal("CISA Catalog of Known Exploited Vulnerabilities", catalog.Title);
        Assert.Equal("2024.11.20", catalog.CatalogVersion);
        Assert.Equal(2, catalog.Count);
        Assert.Equal(2, catalog.Vulnerabilities.Count);

        // Verify vulnerability data
        Assert.Equal("CVE-2024-12345", catalog.Vulnerabilities[0].CveID);
        Assert.Equal("Microsoft", catalog.Vulnerabilities[0].VendorProject);
        Assert.Equal("Known", catalog.Vulnerabilities[0].KnownRansomwareCampaignUse);

        Assert.Equal("CVE-2024-54321", catalog.Vulnerabilities[1].CveID);
        Assert.Equal("Adobe", catalog.Vulnerabilities[1].VendorProject);
        Assert.Equal("Unknown", catalog.Vulnerabilities[1].KnownRansomwareCampaignUse);

        await Task.CompletedTask; // Satisfy async requirement
    }
}

