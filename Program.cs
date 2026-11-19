using EmailShield.Data;
using EmailShield.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
string activeTarget = builder.Configuration["DatabaseSettings:ActiveTarget"] ?? "Online";
string connectionString = activeTarget.Equals("Local", StringComparison.OrdinalIgnoreCase)
    ? (builder.Configuration.GetConnectionString("LocalConnection") ?? builder.Configuration.GetConnectionString("DefaultConnection")!)
    : (builder.Configuration.GetConnectionString("OnlineConnection") ?? builder.Configuration.GetConnectionString("DefaultConnection")!);

builder.Services.AddDbContext<EmailShieldDbContext>(options =>
    options.UseSqlServer(connectionString));

builder.Services.AddSingleton<SystemSettingsService>();
builder.Services.AddScoped<EmailAnalysisService>();
builder.Services.AddScoped<DatabaseSyncService>();
builder.Services.AddHostedService<DatabaseSyncBackgroundService>();

builder.Services.AddControllers();
// Configure Swagger/OpenAPI at /swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Seed default users if needed (gracefully handled)
using (var scope = app.Services.CreateScope())
{
    try
    {
        var db = scope.ServiceProvider.GetRequiredService<EmailShieldDbContext>();
        DbInitializer.SeedDemoUsers(db);
    }
    catch (Exception ex)
    {
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
        logger.LogWarning("Startup database seed check skipped: {Message}", ex.Message);
    }
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Route Protection & Anti-Forced Browsing Middleware
app.Use(async (context, next) =>
{
    var path = context.Request.Path.Value?.ToLower() ?? "";
    if (path.StartsWith("/admin/") || path.StartsWith("/analyst/") || path.StartsWith("/viewer/"))
    {
        // Direct URL Access / Forced Browsing blocked if no active session cookie exists
        if (!context.Request.Cookies.ContainsKey("EmailShield_Session"))
        {
            context.Response.Redirect("/");
            return;
        }
    }
    await next();
});

// Serve HTML5 / CSS / JavaScript frontend from wwwroot
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseAuthorization();

app.MapControllers();

app.Run();
