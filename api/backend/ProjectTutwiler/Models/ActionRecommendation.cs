using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using ProjectTutwiler.Models.Enums;

namespace ProjectTutwiler.Models;

public class ActionRecommendation
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }

    [Required]
    public int VulnerabilityId { get; set; }

    [Required]
    public RecommendationType RecommendationType { get; set; }

    [Required]
    [Column(TypeName = "text")]
    public string ActionText { get; set; } = string.Empty;

    [Required]
    public bool SafeToImplement { get; set; }

    public bool RequiresTier2 { get; set; } = false;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // Navigation property
    [Required]
    public Vulnerability Vulnerability { get; set; } = null!;
}

