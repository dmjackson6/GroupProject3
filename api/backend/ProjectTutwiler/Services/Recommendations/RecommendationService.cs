using Microsoft.EntityFrameworkCore;
using ProjectTutwiler.Data;
using ProjectTutwiler.Models;
using ProjectTutwiler.Models.Enums;

namespace ProjectTutwiler.Services.Recommendations;

public class RecommendationService
{
    private readonly IVulnerabilityRepository _repository;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<RecommendationService> _logger;

    public RecommendationService(
        IVulnerabilityRepository repository,
        ApplicationDbContext context,
        ILogger<RecommendationService> logger)
    {
        _repository = repository;
        _context = context;
        _logger = logger;
    }

    /// <summary>
    /// Generate and save action recommendations based on vulnerability priority level
    /// </summary>
    public async Task<List<ActionRecommendation>> GenerateRecommendationsAsync(int vulnerabilityId)
    {
        try
        {
            _logger.LogInformation("Generating recommendations for vulnerability ID {Id}", vulnerabilityId);

            // Fetch vulnerability with bio impact score
            var vulnerability = await _context.Vulnerabilities
                .Include(v => v.BioImpactScore)
                .FirstOrDefaultAsync(v => v.Id == vulnerabilityId);

            if (vulnerability == null)
            {
                _logger.LogWarning("Vulnerability {Id} not found", vulnerabilityId);
                throw new InvalidOperationException($"Vulnerability {vulnerabilityId} not found");
            }

            if (vulnerability.BioImpactScore == null)
            {
                _logger.LogWarning("Vulnerability {CveId} has not been analyzed yet", vulnerability.CveId);
                throw new InvalidOperationException($"Vulnerability {vulnerability.CveId} must be analyzed before generating recommendations");
            }

            // Check if recommendations already exist
            var existingRecommendations = await _context.ActionRecommendations
                .Where(r => r.VulnerabilityId == vulnerabilityId)
                .ToListAsync();

            if (existingRecommendations.Any())
            {
                _logger.LogInformation("Recommendations already exist for {CveId}, returning existing", vulnerability.CveId);
                return existingRecommendations;
            }

            // Generate recommendations based on priority level
            List<ActionRecommendation> recommendations;

            switch (vulnerability.BioImpactScore.PriorityLevel)
            {
                case PriorityLevel.CRITICAL:
                    recommendations = RecommendationTemplates.CreateCriticalRecommendations(vulnerability);
                    _logger.LogInformation("Generated {Count} CRITICAL recommendations for {CveId}", 
                        recommendations.Count, vulnerability.CveId);
                    break;

                case PriorityLevel.HIGH:
                    recommendations = RecommendationTemplates.CreateHighRecommendations(vulnerability);
                    _logger.LogInformation("Generated {Count} HIGH recommendations for {CveId}", 
                        recommendations.Count, vulnerability.CveId);
                    break;

                case PriorityLevel.MEDIUM:
                    recommendations = RecommendationTemplates.CreateMediumRecommendations(vulnerability);
                    _logger.LogInformation("Generated {Count} MEDIUM recommendations for {CveId}", 
                        recommendations.Count, vulnerability.CveId);
                    break;

                case PriorityLevel.LOW:
                    recommendations = RecommendationTemplates.CreateLowRecommendations(vulnerability);
                    _logger.LogInformation("Generated {Count} LOW recommendations for {CveId}", 
                        recommendations.Count, vulnerability.CveId);
                    break;

                default:
                    _logger.LogWarning("Unknown priority level {Priority} for {CveId}, using MEDIUM template", 
                        vulnerability.BioImpactScore.PriorityLevel, vulnerability.CveId);
                    recommendations = RecommendationTemplates.CreateMediumRecommendations(vulnerability);
                    break;
            }

            // Save all recommendations to database
            await _context.ActionRecommendations.AddRangeAsync(recommendations);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Successfully saved {Count} recommendations for {CveId}", 
                recommendations.Count, vulnerability.CveId);

            return recommendations;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating recommendations for vulnerability {Id}", vulnerabilityId);
            throw;
        }
    }
}

