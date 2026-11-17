using EmailShield.Data;
using EmailShield.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<EmailShieldDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddSingleton<SystemSettingsService>();
builder.Services.AddScoped<EmailAnalysisService>();

builder.Services.AddControllers();
// Configure Swagger/OpenAPI at /swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Seed default users if needed
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<EmailShieldDbContext>();
    DbInitializer.SeedDemoUsers(db);
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
