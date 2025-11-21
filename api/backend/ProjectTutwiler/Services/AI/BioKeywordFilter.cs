namespace ProjectTutwiler.Services.AI;

public class BioKeywordFilter
{
    private static readonly HashSet<string> BioKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        // Medical devices and equipment
        "medical", "hospital", "clinical", "patient", "diagnostic", "infusion", "ventilator",
        "MRI", "CT scan", "ultrasound", "defibrillator", "pacemaker", "insulin pump",
        "dialysis", "anesthesia", "surgical", "implantable", "prosthetic",
        
        // Laboratory equipment
        "laboratory", "lab", "centrifuge", "microscope", "sequencer", "PCR",
        "spectrometer", "analyzer", "assay", "plate reader", "incubator",
        "autoclave", "pipette", "thermal cycler", "electrophoresis",
        
        // Biomanufacturing
        "bioreactor", "fermentation", "chromatography", "lyophilizer", "bioprocess",
        "pharmaceutical", "vaccine", "biologics", "biotech", "biotechnology",
        "cell culture", "upstream", "downstream", "purification",
        
        // IT systems
        "LIMS", "EHR", "EMR", "laboratory information", "health records",
        "biobank", "specimen", "pathology", "radiology", "PACS",
        "health information", "medical records", "patient data",
        
        // Food and agriculture
        "food safety", "pasteurization", "sterilization", "food processing",
        "agriculture", "farming", "irrigation", "greenhouse", "livestock",
        
        // Healthcare facilities
        "healthcare", "clinic", "urgent care", "emergency room", "ICU",
        "surgery center", "pharmacy", "blood bank", "medical center",
        
        // Biological terms
        "genome", "DNA", "RNA", "protein", "enzyme", "antibody", "bacteria",
        "virus", "pathogen", "microorganism", "biological", "bio-safety"
    };

    private readonly ILogger<BioKeywordFilter> _logger;

    public BioKeywordFilter(ILogger<BioKeywordFilter> logger)
    {
        _logger = logger;
    }

    public bool HasBioKeywords(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var lowerText = text.ToLowerInvariant();

        foreach (var keyword in BioKeywords)
        {
            if (lowerText.Contains(keyword.ToLowerInvariant()))
            {
                _logger.LogDebug("Bio keyword found: {Keyword} in text", keyword);
                return true;
            }
        }

        return false;
    }

    public int QuickRelevanceScore(string description)
    {
        if (string.IsNullOrWhiteSpace(description))
        {
            return 0;
        }

        var lowerText = description.ToLowerInvariant();
        int matchCount = 0;

        foreach (var keyword in BioKeywords)
        {
            if (lowerText.Contains(keyword.ToLowerInvariant()))
            {
                matchCount++;
            }
        }

        // Score based on keyword matches
        if (matchCount == 0) return 0;
        if (matchCount <= 2) return 25;
        if (matchCount <= 4) return 50;
        return 75; // 5+ matches
    }

    public List<string> GetMatchedKeywords(string text)
    {
        var matched = new List<string>();
        
        if (string.IsNullOrWhiteSpace(text))
        {
            return matched;
        }

        var lowerText = text.ToLowerInvariant();

        foreach (var keyword in BioKeywords)
        {
            if (lowerText.Contains(keyword.ToLowerInvariant()))
            {
                matched.Add(keyword);
            }
        }

        return matched;
    }
}

