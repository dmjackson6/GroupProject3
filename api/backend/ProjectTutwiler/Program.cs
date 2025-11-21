using Microsoft.EntityFrameworkCore;
using ProjectTutwiler.Data;
using Hangfire;
using Hangfire.MySql;
using ProjectTutwiler.BackgroundJobs;
using Microsoft.Extensions.FileProviders;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Register DbContext with MySQL
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
var serverVersion = new MySqlServerVersion(new Version(8, 0, 33));

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseMySql(connectionString, serverVersion)
);

// Register repositories
builder.Services.AddScoped<IVulnerabilityRepository, VulnerabilityRepository>();

// Register data ingestion services
builder.Services.AddHttpClient<ProjectTutwiler.Services.DataIngestion.NvdApiClient>();
builder.Services.AddHttpClient<ProjectTutwiler.Services.DataIngestion.CisaKevClient>();
builder.Services.AddScoped<ProjectTutwiler.Services.DataIngestion.VulnerabilityIngestionService>();
builder.Services.AddScoped<ProjectTutwiler.Services.DataIngestion.IngestionOrchestrator>();

// Register AI analysis services
builder.Services.AddHttpClient<ProjectTutwiler.Services.AI.OllamaClient>();
builder.Services.AddSingleton<ProjectTutwiler.Services.AI.BioKeywordFilter>();
builder.Services.AddSingleton<ProjectTutwiler.Services.AI.PromptSafetyFilter>();
builder.Services.AddScoped<ProjectTutwiler.Services.AI.BioImpactAnalyzer>();
builder.Services.AddScoped<ProjectTutwiler.Services.AI.VulnerabilityAnalysisService>();

// Register scoring services
builder.Services.AddScoped<ProjectTutwiler.Services.Scoring.HumanSafetyScorer>();
builder.Services.AddScoped<ProjectTutwiler.Services.Scoring.SupplyChainScorer>();
builder.Services.AddScoped<ProjectTutwiler.Services.Scoring.ExploitabilityScorer>();
builder.Services.AddScoped<ProjectTutwiler.Services.Scoring.PatchAvailabilityScorer>();
builder.Services.AddScoped<ProjectTutwiler.Services.Scoring.CompositeScorer>();

// Register recommendation services
builder.Services.AddScoped<ProjectTutwiler.Services.Recommendations.RecommendationService>();

// Add memory cache for KEV caching
builder.Services.AddMemoryCache();

// Configure CORS for frontend access
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(corsBuilder =>
    {
        corsBuilder.AllowAnyOrigin()
               .AllowAnyMethod()
               .AllowAnyHeader();
    });
});

// Add Swagger/OpenAPI documentation
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure Hangfire for background job processing
builder.Services.AddHangfire(config =>
    config.UseStorage(new MySqlStorage(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        new MySqlStorageOptions 
        { 
            TablesPrefix = "Hangfire_",
            TransactionIsolationLevel = System.Transactions.IsolationLevel.ReadCommitted,
            QueuePollInterval = TimeSpan.FromSeconds(15)
        }
    ))
);
builder.Services.AddHangfireServer(options => 
{ 
    options.WorkerCount = 2; 
    options.ServerName = "ProjectTutwiler-Server";
});

// Add Controllers
builder.Services.AddControllers();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "Project Tutwiler API v1");
        options.RoutePrefix = "swagger";
        options.DocumentTitle = "Project Tutwiler API Documentation";
    });
}

app.UseHttpsRedirection();

// Enable CORS
app.UseCors();

// Enable Hangfire Dashboard for job monitoring
app.UseHangfireDashboard("/hangfire");

app.MapControllers();

// Serve static files from client folder (three directories up from bin)
var clientPath = Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "client");
var fileProvider = new PhysicalFileProvider(clientPath);

// Serve default file (index.html)
app.UseDefaultFiles(new DefaultFilesOptions
{
    FileProvider = fileProvider
});

// Serve all static files from client folder
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = fileProvider
});

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast =  Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast");

// Configure recurring background jobs
JobScheduler.ConfigureRecurringJobs(app.Services);

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
