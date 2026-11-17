using System.Text.Json;
using EmailShield.DTOs;

namespace EmailShield.Services;

public class SystemSettingsService
{
    private readonly string _settingsFilePath;
    private SystemSettingsDto _currentSettings;
    private readonly object _lock = new();

    public SystemSettingsService(IWebHostEnvironment env)
    {
        _settingsFilePath = Path.Combine(env.ContentRootPath, "system_settings.json");
        _currentSettings = LoadSettings();
    }

    public SystemSettingsDto GetSettings()
    {
        lock (_lock)
        {
            return _currentSettings;
        }
    }

    public void UpdateSettings(SystemSettingsDto newSettings)
    {
        lock (_lock)
        {
            _currentSettings = newSettings;
            SaveSettings();
        }
    }

    public SystemSettingsDto ResetToDefaults()
    {
        lock (_lock)
        {
            _currentSettings = new SystemSettingsDto();
            SaveSettings();
            return _currentSettings;
        }
    }

    private SystemSettingsDto LoadSettings()
    {
        try
        {
            if (File.Exists(_settingsFilePath))
            {
                string json = File.ReadAllText(_settingsFilePath);
                var loaded = JsonSerializer.Deserialize<SystemSettingsDto>(json);
                if (loaded != null) return loaded;
            }
        }
        catch
        {
            // Fallback to defaults on error
        }

        var defaults = new SystemSettingsDto();
        try
        {
            string json = JsonSerializer.Serialize(defaults, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_settingsFilePath, json);
        }
        catch {}

        return defaults;
    }

    private void SaveSettings()
    {
        try
        {
            string json = JsonSerializer.Serialize(_currentSettings, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_settingsFilePath, json);
        }
        catch {}
    }
}

