namespace NetWarden.Data.Storage;

/// <summary>
/// Where NetWarden keeps its data. Portable by default: a "NetWarden-data" folder next to the exe.
/// If that folder can't be written (e.g. the exe sits in Program Files), falls back to %LocalAppData%\NetWarden.
/// </summary>
public sealed class AppPaths
{
    public const string PortableFolderName = "NetWarden-data";

    public string Root { get; }
    public bool IsPortable { get; }
    public string HistoryDb => Path.Combine(Root, "history.db");
    public string CveDb => Path.Combine(Root, "cve.db");
    public string Logs => Path.Combine(Root, "logs");
    public string Profiles => Path.Combine(Root, "profiles");
    public string CheckPacks => Path.Combine(Root, "checks");
    public string Reports => Path.Combine(Root, "reports");
    public string SettingsFile => Path.Combine(Root, "settings.json");
    public string OuiCsv => Path.Combine(Root, "oui.csv");

    public AppPaths(string root, bool portable)
    {
        Root = root;
        IsPortable = portable;
        foreach (var d in new[] { Root, Logs, Profiles, CheckPacks, Reports }) Directory.CreateDirectory(d);
    }

    public static AppPaths Resolve(string? exeDirectory = null)
    {
        var overridePath = Environment.GetEnvironmentVariable("NETWARDEN_DATA");
        if (!string.IsNullOrWhiteSpace(overridePath)) return new AppPaths(overridePath, portable: false);

        exeDirectory ??= AppContext.BaseDirectory;
        var portable = Path.Combine(exeDirectory, PortableFolderName);
        if (CanWrite(exeDirectory, portable)) return new AppPaths(portable, portable: true);

        var local = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetWarden");
        return new AppPaths(local, portable: false);
    }

    private static bool CanWrite(string exeDir, string portableDir)
    {
        try
        {
            Directory.CreateDirectory(portableDir);
            var probe = Path.Combine(portableDir, ".write-test");
            File.WriteAllText(probe, "ok");
            File.Delete(probe);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
