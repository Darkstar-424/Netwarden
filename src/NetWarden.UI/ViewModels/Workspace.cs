using System.Collections.ObjectModel;
using NetWarden.Core.Models;
using NetWarden.Core.Targeting;
using NetWarden.Data.History;
using NetWarden.Data.Storage;
using NetWarden.UI.Mvvm;
using NetWarden.UI.Services;

namespace NetWarden.UI.ViewModels;

/// <summary>State shared by all pages: mode, scopes, scan history and the scan being looked at.</summary>
public sealed class Workspace : ObservableObject
{
    public AppServices Services { get; }
    public IPlatform Platform { get; }

    public Workspace(AppServices services, IPlatform platform)
    {
        Services = services;
        Platform = platform;
        _isAdvanced = services.Settings.Mode == UiMode.Advanced;
        ReloadScopes();
        ReloadScans();
        var latest = Scans.FirstOrDefault(s => s.State is ScanState.Completed or ScanState.Imported or ScanState.Cancelled);
        if (latest != null) CurrentScan = services.History.LoadScan(latest.Id);
    }

    public event Action<string>? NavigateRequested;
    public void Navigate(string page) => NavigateRequested?.Invoke(page);

    private bool _isAdvanced;
    public bool IsAdvanced
    {
        get => _isAdvanced;
        set
        {
            if (!Set(ref _isAdvanced, value)) return;
            Raise(nameof(IsSimple));
            Services.Settings.Mode = value ? UiMode.Advanced : UiMode.Simple;
            Services.SaveSettings();
        }
    }
    public bool IsSimple { get => !IsAdvanced; set => IsAdvanced = !value; }

    public ObservableCollection<ScanScope> Scopes { get; } = new();

    private ScanScope? _selectedScope;
    public ScanScope? SelectedScope
    {
        get => _selectedScope;
        set
        {
            if (!Set(ref _selectedScope, value)) return;
            Raise(nameof(ScopeSummary), nameof(HasScope));
            if (value != null)
            {
                Services.Settings.LastScopeId = value.Id.ToString();
                Services.SaveSettings();
            }
        }
    }

    public bool HasScope => SelectedScope != null;
    public string ScopeSummary => SelectedScope == null ? "No scope yet" : $"{SelectedScope.Name} · {TextTargets(SelectedScope)}";

    private static string TextTargets(ScanScope s)
    {
        var t = s.Targets.Replace("\r", "").Split(new[] { '\n', ',' }, StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).ToList();
        return t.Count <= 2 ? string.Join(", ", t) : $"{t[0]}, {t[1]} +{t.Count - 2}";
    }

    public void ReloadScopes()
    {
        var keep = SelectedScope?.Id.ToString() ?? Services.Settings.LastScopeId;
        Scopes.Clear();
        foreach (var s in Services.History.ListScopes()) Scopes.Add(s);
        SelectedScope = Scopes.FirstOrDefault(s => s.Id.ToString() == keep) ?? Scopes.FirstOrDefault();
    }

    public ObservableCollection<ScanSummary> Scans { get; } = new();

    public void ReloadScans()
    {
        Scans.Clear();
        foreach (var s in Services.History.ListScans()) Scans.Add(s);
        Raise(nameof(HasScans));
    }

    public bool HasScans => Scans.Count > 0;

    private ScanResult? _currentScan;
    /// <summary>The scan shown on the dashboard, hosts, findings and map pages.</summary>
    public ScanResult? CurrentScan
    {
        get => _currentScan;
        set
        {
            if (!Set(ref _currentScan, value)) return;
            Raise(nameof(HasCurrentScan), nameof(CurrentScanLabel));
            CurrentScanChanged?.Invoke();
        }
    }

    public bool HasCurrentScan => CurrentScan != null;
    public string CurrentScanLabel => CurrentScan == null ? "No scan yet" : $"{CurrentScan.Started.ToLocalTime():g} · {CurrentScan.ProfileName} · {CurrentScan.ScopeName}";

    public event Action? CurrentScanChanged;

    /// <summary>Called when finding statuses change so every page refreshes counts.</summary>
    public void NotifyFindingsChanged() => CurrentScanChanged?.Invoke();

    public void ShowScan(Guid id)
    {
        var scan = Services.History.LoadScan(id);
        if (scan != null) CurrentScan = scan;
    }

    public void Error(Exception ex)
    {
        Services.Log.Error("UI error", ex);
        Platform.ShowMessage("Something went wrong", ex.Message, isError: true);
    }
}
