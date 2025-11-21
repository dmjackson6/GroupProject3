using Microsoft.EntityFrameworkCore;
using ProjectTutwiler.Models;
using ProjectTutwiler.Models.Enums;

namespace ProjectTutwiler.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    // DbSet properties
    public DbSet<Vulnerability> Vulnerabilities { get; set; }
    public DbSet<BioImpactScore> BioImpactScores { get; set; }
    public DbSet<ActionRecommendation> ActionRecommendations { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            // Fallback configuration if not configured via DI
            // This will be overridden by the connection string in Program.cs
        }
        base.OnConfiguring(optionsBuilder);
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Vulnerability entity configuration
        modelBuilder.Entity<Vulnerability>(entity =>
        {
            entity.HasKey(v => v.Id);

            // Unique index on CveId
            entity.HasIndex(v => v.CveId)
                .IsUnique();

            // Default values for timestamps
            entity.Property(v => v.CreatedAt)
                .HasDefaultValueSql("CURRENT_TIMESTAMP(6)");

            entity.Property(v => v.UpdatedAt)
                .HasDefaultValueSql("CURRENT_TIMESTAMP(6)")
                .ValueGeneratedOnAddOrUpdate();

            entity.Property(v => v.KnownExploited)
                .HasDefaultValue(false);

            // One-to-one relationship with BioImpactScore
            entity.HasOne(v => v.BioImpactScore)
                .WithOne(b => b.Vulnerability)
                .HasForeignKey<BioImpactScore>(b => b.VulnerabilityId)
                .OnDelete(DeleteBehavior.Cascade);

            // One-to-many relationship with ActionRecommendations
            entity.HasMany(v => v.ActionRecommendations)
                .WithOne(a => a.Vulnerability)
                .HasForeignKey(a => a.VulnerabilityId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // BioImpactScore entity configuration
        modelBuilder.Entity<BioImpactScore>(entity =>
        {
            entity.HasKey(b => b.Id);

            // Index on PriorityLevel for faster filtering
            entity.HasIndex(b => b.PriorityLevel);

            // Convert enum to string
            entity.Property(b => b.PriorityLevel)
                .HasConversion<string>()
                .IsRequired();

            // Decimal precision
            entity.Property(b => b.CompositeScore)
                .HasPrecision(5, 2);

            entity.Property(b => b.BioRelevanceConfidence)
                .HasPrecision(3, 2);

            // Default values
            entity.Property(b => b.HumanReviewed)
                .HasDefaultValue(false);

            entity.Property(b => b.CreatedAt)
                .HasDefaultValueSql("CURRENT_TIMESTAMP(6)");
        });

        // ActionRecommendation entity configuration
        modelBuilder.Entity<ActionRecommendation>(entity =>
        {
            entity.HasKey(a => a.Id);

            // Convert enum to string
            entity.Property(a => a.RecommendationType)
                .HasConversion<string>()
                .IsRequired();

            // Default values
            entity.Property(a => a.RequiresTier2)
                .HasDefaultValue(false);

            entity.Property(a => a.CreatedAt)
                .HasDefaultValueSql("CURRENT_TIMESTAMP(6)");
        });
    }
}
