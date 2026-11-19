using EmailShield.Services;

namespace EmailShield.Services;

public class DatabaseSyncBackgroundService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IConfiguration _configuration;
    private readonly ILogger<DatabaseSyncBackgroundService> _logger;

    public DatabaseSyncBackgroundService(
        IServiceProvider serviceProvider, 
        IConfiguration configuration,
        ILogger<DatabaseSyncBackgroundService> logger)
    {
        _serviceProvider = serviceProvider;
        _configuration = configuration;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[DatabaseSync] Background synchronization service started.");

        // Initial delay on boot to allow app to finish startup
        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                bool autoSyncEnabled = _configuration.GetValue<bool>("DatabaseSettings:EnableAutoSync", true);
                if (autoSyncEnabled)
                {
                    using var scope = _serviceProvider.CreateScope();
                    var syncService = scope.ServiceProvider.GetRequiredService<DatabaseSyncService>();

                    var status = await syncService.GetStatusAsync();
                    if (status.Local.IsConnected && status.Online.IsConnected)
                    {
                        var result = await syncService.SyncDatabasesAsync("Bidirectional");
                        if (result.Success && (result.UsersSynced > 0 || result.EmailSamplesSynced > 0 || result.AuditLogsSynced > 0))
                        {
                            _logger.LogInformation("[DatabaseSync] Periodic sync complete: {Message}", result.Message);
                        }
                    }
                    else
                    {
                        _logger.LogDebug("[DatabaseSync] Periodic sync skipped. Local connected: {Local}, Online connected: {Online}", 
                            status.Local.IsConnected, status.Online.IsConnected);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning("[DatabaseSync] Background sync encountered an error: {Message}", ex.Message);
            }

            int intervalMinutes = _configuration.GetValue<int>("DatabaseSettings:SyncIntervalMinutes", 5);
            if (intervalMinutes < 1) intervalMinutes = 5;

            await Task.Delay(TimeSpan.FromMinutes(intervalMinutes), stoppingToken);
        }

        _logger.LogInformation("[DatabaseSync] Background synchronization service stopped.");
    }
}
