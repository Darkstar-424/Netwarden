using System.Text.Json;
using System.Text.Json.Serialization;
using NetWarden.Core.Models;
using NetWarden.Core.Profiles;

namespace NetWarden.Data.Storage;

/// <summary>Built-in profiles plus custom ones saved as JSON files in the data folder.</summary>
public sealed class ProfileStore
{
    private readonly string _folder;

    public ProfileStore(string folder)
    {
        _folder = folder;
        Directory.CreateDirectory(folder);
    }

    public IReadOnlyList<ScanProfile> All()
    {
        var list = BuiltInProfiles.All.Select(p => BuiltInProfiles.Get(p.Name)).ToList();
        foreach (var file in Directory.EnumerateFiles(_folder, "*.json").OrderBy(f => f))
        {
            try
            {
                var p = ProfileJson.Deserialize(File.ReadAllText(file));
                p.BuiltIn = false;
                if (list.All(x => !string.Equals(x.Name, p.Name, StringComparison.OrdinalIgnoreCase))) list.Add(p);
            }
            catch (Exception ex) when (ex is JsonException or IOException or InvalidDataException)
            {
                // skip unreadable profiles; the UI reports via log
            }
        }
        return list;
    }

    public ScanProfile? Find(string name) => All().FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));

    public void Save(ScanProfile profile)
    {
        if (BuiltInProfiles.All.Any(b => string.Equals(b.Name, profile.Name, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException($"'{profile.Name}' is a built-in profile name. Choose another name.");
        File.WriteAllText(PathFor(profile.Name), ProfileJson.Serialize(profile));
    }

    public void Delete(string name)
    {
        var path = PathFor(name);
        if (File.Exists(path)) File.Delete(path);
    }

    public static ScanProfile Import(string path) => ProfileJson.Deserialize(File.ReadAllText(path));

    public static void Export(ScanProfile profile, string path) => File.WriteAllText(path, ProfileJson.Serialize(profile));

    private string PathFor(string name)
    {
        var safe = string.Concat(name.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c)).Trim();
        if (safe.Length == 0) safe = "profile";
        return Path.Combine(_folder, safe + ".json");
    }
}

public enum ThemeChoice { System, Light, Dark }
public enum UiMode { Simple, Advanced }

public sealed class NotificationSettings
{
    public bool Enabled { get; set; }
    public Severity MinimumSeverity { get; set; } = Severity.Critical;
    public string SmtpHost { get; set; } = "";
    public int SmtpPort { get; set; } = 587;
    public bool SmtpStartTls { get; set; } = true;
    public string SmtpUser { get; set; } = "";
    public string From { get; set; } = "";
    public string To { get; set; } = "";
    /// <summary>Secrets (SMTP password, Teams webhook URL) live in Windows Credential Manager, not in this file.</summary>
    public bool UseTeams { get; set; }
}

public sealed class AppSettings
{
    public ThemeChoice Theme { get; set; } = ThemeChoice.System;
    public UiMode Mode { get; set; } = UiMode.Simple;
    public string? LastScopeId { get; set; }
    public string LastProfile { get; set; } = BuiltInProfiles.Standard;
    public string NvdApiKey { get; set; } = "";
    public bool FirstRunCompleted { get; set; }
    public NotificationSettings Notifications { get; set; } = new();
}

public sealed class SettingsStore
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly string _path;
    public SettingsStore(string path) => _path = path;

    public AppSettings Load()
    {
        try
        {
            if (File.Exists(_path)) return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(_path), Options) ?? new AppSettings();
        }
        catch (Exception ex) when (ex is JsonException or IOException) { }
        return new AppSettings();
    }

    public void Save(AppSettings settings)
    {
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(settings, Options));
        File.Move(tmp, _path, overwrite: true);
    }
}
