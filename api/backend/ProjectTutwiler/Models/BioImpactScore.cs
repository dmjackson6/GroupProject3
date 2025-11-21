using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using ProjectTutwiler.Models.Enums;

namespace ProjectTutwiler.Models;

public class BioImpactScore
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }

    [Required]
    public int VulnerabilityId { get; set; }

    [Required]
    [Range(0, 100)]
    public int HumanSafetyScore { get; set; }

    [Required]
    [Range(0, 100)]
    public int SupplyChainScore { get; set; }

    [Required]
    [Range(0, 100)]
    public int ExploitabilityScore { get; set; }

    [Required]
    [Range(0, 100)]
    public int PatchAvailabilityScore { get; set; }

    [Required]
    [Column(TypeName = "decimal(5,2)")]
    public decimal CompositeScore { get; set; }

    [Required]
    public PriorityLevel PriorityLevel { get; set; }

    [Column(TypeName = "decimal(3,2)")]
    public decimal? BioRelevanceConfidence { get; set; }

    [Column(TypeName = "text")]
    public string? AffectedBioSectors { get; set; }

    [Column(TypeName = "text")]
    public string? AiAnalysis { get; set; }

    [MaxLength(50)]
    public string? AiModelVersion { get; set; }

    public bool HumanReviewed { get; set; } = false;

    [Column(TypeName = "text")]
    public string? ReviewerNotes { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // Navigation property
    [Required]
    public Vulnerability Vulnerability { get; set; } = null!;
}
