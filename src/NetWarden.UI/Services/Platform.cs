using NetWarden.Data.Storage;

namespace NetWarden.UI.Services;

/// <summary>UI-only operations implemented by the WPF app (dialogs, theme, shell, secrets, scheduling).</summary>
public interface IPlatform
{
    void ShowMessage(string title, string message, bool isError = false);
    bool Confirm(string title, string message);
    string? PromptText(string title, string label, string initial = "");
    string? PickSaveFile(string title, string filter, string defaultName);
    string? PickOpenFile(string title, string filter);
    void ApplyTheme(ThemeChoice theme);
    void OpenPath(string path);
    void OpenUrl(string url);
    void CopyText(string text);
}

/// <summary>Stores secrets (SMTP password, Teams webhook) outside the settings file — Windows Credential Manager in the app.</summary>
public interface ISecretStore
{
    string? Get(string name);
    void Set(string name, string? value);
}

public enum ScheduleFrequency { Daily, Weekly, Monthly }

public sealed record ScheduledScan(string Name, string Scope, string Profile, ScheduleFrequency Frequency, DayOfWeek Day, TimeSpan Time, string? NextRun, string? Status);

public interface IScanScheduler
{
    IReadOnlyList<ScheduledScan> List();
    void Create(ScheduledScan scan, string executablePath, bool notify);
    void Delete(string name);
}

/// <summary>In-memory fallbacks used by tests and non-Windows builds.</summary>
public sealed class MemorySecretStore : ISecretStore
{
    private readonly Dictionary<string, string> _values = new();
    public string? Get(string name) => _values.TryGetValue(name, out var v) ? v : null;
    public void Set(string name, string? value) { if (value == null) _values.Remove(name); else _values[name] = value; }
}

public sealed class NoScheduler : IScanScheduler
{
    public IReadOnlyList<ScheduledScan> List() => Array.Empty<ScheduledScan>();
    public void Create(ScheduledScan scan, string executablePath, bool notify) => throw new PlatformNotSupportedException("Scheduling needs Windows Task Scheduler.");
    public void Delete(string name) { }
}
