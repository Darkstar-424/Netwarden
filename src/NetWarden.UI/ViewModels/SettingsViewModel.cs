using System.Collections.ObjectModel;
using System.Windows.Input;
using NetWarden.Core.Checks;
using NetWarden.Core.Models;
using NetWarden.Core.Profiles;
using NetWarden.Data.CveStore;
using NetWarden.Data.Feeds;
using NetWarden.Data.History;
using NetWarden.Data.Storage;
using NetWarden.Reporting.Notify;
using NetWarden.UI.Mvvm;
using NetWarden.UI.Services;

namespace NetWarden.UI.ViewModels;

public sealed record CheckRow(string Id, string Name, string Category, string Level, bool Anonymous)
{
    public string LevelText => Anonymous ? Level + " · anonymous login (opt-in)" : Level;
}

public sealed class SettingsViewModel : ObservableObject
{
    private readonly Workspace _ws;
    private readonly AppServices _s;
    private CancellationTokenSource? _updateCts;

    public SettingsViewModel(Workspace ws)
    {
        _ws = ws;
        _s = ws.Services;
        _theme = _s.Settings.Theme;
        _apiKey = _s.Settings.NvdApiKey;
        var n = _s.Settings.Notifications;
        _notifyEnabled = n.Enabled; _minSeverity = n.MinimumSeverity; _smtpHost = n.SmtpHost; _smtpPort = n.SmtpPort; _smtpTls = n.SmtpStartTls;
        _smtpUser = n.SmtpUser; _from = n.From; _to = n.To; _useTeams = n.UseTeams;
        _smtpPassword = _s.Secrets.Get(AppServices.SmtpPasswordSecret) ?? "";
        _teamsWebhook = _s.Secrets.Get(AppServices.TeamsWebhookSecret) ?? "";

        UpdateCveCommand = new AsyncCommand(UpdateCveAsync);
        CancelUpdateCommand = new RelayCommand(() => _updateCts?.Cancel(), () => _updateCts != null);
        ImportBundleCommand = new AsyncCommand(ImportBundleAsync);
        ExportBundleCommand = new AsyncCommand(ExportBundleAsync);
        ImportOuiCommand = new RelayCommand(ImportOui);
        OpenDataFolderCommand = new RelayCommand(() => _ws.Platform.OpenPath(_s.Paths.Root));
        OpenLogsCommand = new RelayCommand(() => _ws.Platform.OpenPath(_s.Paths.Logs));
        SaveNotificationsCommand = new RelayCommand(SaveNotifications);
        TestNotificationCommand = new AsyncCommand(TestNotificationAsync);
        AddScheduleCommand = new RelayCommand(AddSchedule, () => ScheduleScope != null && ScheduleProfile != null && !string.IsNullOrWhiteSpace(ScheduleName));
        DeleteScheduleCommand = new RelayCommand(p => DeleteSchedule(p as ScheduledScan));
        RefreshAuditCommand = new RelayCommand(RefreshAudit);
        RefreshSchedulesCommand = new RelayCommand(RefreshSchedules);
        OpenNvdKeyPageCommand = new RelayCommand(() => _ws.Platform.OpenUrl("https://nvd.nist.gov/developers/request-an-api-key"));

        foreach (var c in _s.Checks)
            Checks.Add(new CheckRow(c.Id, c.Name, c.Category, c.Level == ProbeLevel.SafeProbe ? "Safe probe" : "Version / configuration", c.RequiresAnonymousLogin));
        foreach (var p in _s.Profiles.All()) ScheduleProfiles.Add(p.Name);
        ScheduleProfile = BuiltInProfiles.Standard;
        RefreshCveStats();
        RefreshAudit();
        RefreshSchedules();
    }

    public Workspace Workspace => _ws;

    // ---- Appearance ----
    public IReadOnlyList<ThemeChoice> ThemeOptions { get; } = Enum.GetValues<ThemeChoice>();
    private ThemeChoice _theme;
    public ThemeChoice Theme
    {
        get => _theme;
        set
        {
            if (!Set(ref _theme, value)) return;
            _s.Settings.Theme = value;
            _s.SaveSettings();
            _ws.Platform.ApplyTheme(value);
        }
    }

    public string DataFolder => _s.Paths.Root;
    public string DataFolderNote => _s.Paths.IsPortable
        ? "Portable mode: data is stored next to NetWarden.exe. Copy the whole folder to move NetWarden with its history. Scan results describe your network's weak spots, so keep the folder somewhere safe."
        : "Data is stored in your user profile because the folder next to NetWarden.exe can't be written to.";
    public ICommand OpenDataFolderCommand { get; }
    public ICommand OpenLogsCommand { get; }

    // ---- CVE database ----
    private string _cveStatus = "", _cveProgress = "", _apiKey;
    private double _cveFraction;
    public string CveStatus { get => _cveStatus; private set => Set(ref _cveStatus, value); }
    public string CveProgress { get => _cveProgress; private set => Set(ref _cveProgress, value); }
    public double CveFraction { get => _cveFraction; private set => Set(ref _cveFraction, value); }
    public string NvdApiKey { get => _apiKey; set { if (Set(ref _apiKey, value)) { _s.Settings.NvdApiKey = value.Trim(); _s.SaveSettings(); } } }
    public AsyncCommand UpdateCveCommand { get; }
    public RelayCommand CancelUpdateCommand { get; }
    public AsyncCommand ImportBundleCommand { get; }
    public AsyncCommand ExportBundleCommand { get; }
    public ICommand ImportOuiCommand { get; }
    public ICommand OpenNvdKeyPageCommand { get; }
    private bool _updating;
    public bool IsUpdating { get => _updating; private set => Set(ref _updating, value); }

    private void RefreshCveStats()
    {
        try
        {
            var st = _s.Cves.Stats();
            CveStatus = st.CveCount == 0
                ? "No CVE data yet. Download it to match software versions against known vulnerabilities (takes 15–30 minutes the first time, a few seconds afterwards)."
                : $"{st.CveCount:N0} CVEs, {st.RuleCount:N0} product rules, {st.KevCount:N0} actively exploited (KEV). " +
                  $"NVD updated {(st.LastNvdSync?.ToLocalTime().ToString("g") ?? "never")}, KEV updated {(st.LastKevSync?.ToLocalTime().ToString("g") ?? "never")}.";
        }
        catch (Exception ex)
        {
            CveStatus = "CVE database unavailable: " + ex.Message;
        }
    }

    private async Task UpdateCveAsync()
    {
        _updateCts = new CancellationTokenSource();
        CancelUpdateCommand.NotifyCanExecuteChanged();
        IsUpdating = true;
        var progress = new Progress<FeedProgress>(p =>
        {
            CveProgress = p.Message;
            CveFraction = p.Total > 0 ? Math.Clamp((double)p.Done / p.Total, 0, 1) : 0;
        });
        try
        {
            _s.History.Audit("cve-update-start", _s.CurrentUser);
            var nvd = new NvdClient(_s.Settings.NvdApiKey);
            await Task.Run(async () =>
            {
                await nvd.SyncAsync(_s.Cves, progress, _updateCts.Token);
                await new KevClient().SyncAsync(_s.Cves, progress, _updateCts.Token);
            });
            CveProgress = nvd.ApiKeyRejected
                ? "Update complete, but NVD didn't accept your API key, so it ran at the slower keyless speed. Check the key matches the one in your NVD email exactly and that you clicked the activation link."
                : "Update complete.";
            _s.History.Audit("cve-update-end", _s.CurrentUser);
        }
        catch (OperationCanceledException)
        {
            CveProgress = "Update cancelled. Data downloaded so far was kept; the next update picks up where this one stopped.";
        }
        catch (Exception ex) when (ex is FeedException or HttpRequestException or IOException)
        {
            CveProgress = "Update failed: " + ex.Message;
            _s.Log.Warn("CVE update failed", ex);
        }
        finally
        {
            IsUpdating = false;
            _updateCts.Dispose();
            _updateCts = null;
            CancelUpdateCommand.NotifyCanExecuteChanged();
            RefreshCveStats();
        }
    }

    private async Task ImportBundleAsync()
    {
        var path = _ws.Platform.PickOpenFile("Import offline CVE bundle", "NetWarden CVE bundle (*.zip)|*.zip");
        if (path == null) return;
        CveProgress = "Verifying bundle…";
        var tmp = await Task.Run(() => OfflineBundle.VerifyAndExtract(path));
        _s.DbFactory.ReleaseAll();
        _s.Cves.InvalidateCache();
        File.Copy(tmp, _s.Paths.CveDb, overwrite: true);
        foreach (var side in new[] { "-wal", "-shm" })
            if (File.Exists(_s.Paths.CveDb + side)) File.Delete(_s.Paths.CveDb + side);
        File.Delete(tmp);
        _s.History.Audit("cve-bundle-import", _s.CurrentUser, details: path);
        CveProgress = "Bundle verified (SHA-256 matched) and imported.";
        RefreshCveStats();
    }

    private async Task ExportBundleAsync()
    {
        var path = _ws.Platform.PickSaveFile("Export offline CVE bundle", "NetWarden CVE bundle (*.zip)|*.zip", $"netwarden-cve-{DateTime.Now:yyyyMMdd}.zip");
        if (path == null) return;
        CveProgress = "Exporting…";
        var count = _s.Cves.Stats().CveCount;
        _s.DbFactory.ReleaseAll();
        await Task.Run(() => OfflineBundle.Export(_s.Paths.CveDb, path, count));
        CveProgress = $"Exported {Path.GetFileName(path)}. Copy it to the offline PC and use Import there.";
    }

    private void ImportOui()
    {
        var path = _ws.Platform.PickOpenFile("Import IEEE MAC vendor list (oui.csv)", "IEEE OUI list (*.csv)|*.csv");
        if (path == null) return;
        File.Copy(path, _s.Paths.OuiCsv, overwrite: true);
        _ws.Platform.ShowMessage("Vendor list imported", "The full MAC vendor list will be used from the next start of NetWarden.");
    }

    // ---- Notifications ----
    private bool _notifyEnabled, _smtpTls, _useTeams;
    private Severity _minSeverity;
    private string _smtpHost, _smtpUser, _from, _to, _smtpPassword, _teamsWebhook, _notifyStatus = "";
    private int _smtpPort;
    public bool NotificationsEnabled { get => _notifyEnabled; set => Set(ref _notifyEnabled, value); }
    public IReadOnlyList<Severity> SeverityOptions { get; } = new[] { Severity.Critical, Severity.High, Severity.Medium };
    public Severity MinimumSeverity { get => _minSeverity; set => Set(ref _minSeverity, value); }
    public string SmtpHost { get => _smtpHost; set => Set(ref _smtpHost, value); }
    public int SmtpPort { get => _smtpPort; set => Set(ref _smtpPort, value); }
    public bool SmtpStartTls { get => _smtpTls; set => Set(ref _smtpTls, value); }
    public string SmtpUser { get => _smtpUser; set => Set(ref _smtpUser, value); }
    public string SmtpPassword { get => _smtpPassword; set => Set(ref _smtpPassword, value); }
    public string From { get => _from; set => Set(ref _from, value); }
    public string To { get => _to; set => Set(ref _to, value); }
    public bool UseTeams { get => _useTeams; set => Set(ref _useTeams, value); }
    public string TeamsWebhook { get => _teamsWebhook; set => Set(ref _teamsWebhook, value); }
    public string NotificationStatus { get => _notifyStatus; private set => Set(ref _notifyStatus, value); }
    public ICommand SaveNotificationsCommand { get; }
    public AsyncCommand TestNotificationCommand { get; }

    private void SaveNotifications()
    {
        var n = _s.Settings.Notifications;
        n.Enabled = NotificationsEnabled; n.MinimumSeverity = MinimumSeverity; n.SmtpHost = SmtpHost.Trim(); n.SmtpPort = SmtpPort;
        n.SmtpStartTls = SmtpStartTls; n.SmtpUser = SmtpUser.Trim(); n.From = From.Trim(); n.To = To.Trim(); n.UseTeams = UseTeams;
        _s.SaveSettings();
        _s.Secrets.Set(AppServices.SmtpPasswordSecret, string.IsNullOrEmpty(SmtpPassword) ? null : SmtpPassword);
        _s.Secrets.Set(AppServices.TeamsWebhookSecret, string.IsNullOrWhiteSpace(TeamsWebhook) ? null : TeamsWebhook.Trim());
        NotificationStatus = "Saved. Passwords and the webhook address are kept in Windows Credential Manager, not in the settings file.";
    }

    private async Task TestNotificationAsync()
    {
        SaveNotifications();
        var sample = new ScanResult { ScopeName = "Test", ProfileName = "Test", Finished = DateTimeOffset.Now };
        var finding = new Finding { Title = "This is a test notification from NetWarden", Severity = Severity.Info, Host = "127.0.0.1" };
        try
        {
            await _s.NotifyAsync(sample, new[] { finding }, CancellationToken.None);
            NotificationStatus = "Test sent. Check your inbox / Teams channel.";
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.Net.Mail.SmtpException or HttpRequestException or FormatException)
        {
            NotificationStatus = "Test failed: " + ex.Message;
        }
    }

    // ---- Scheduled scans ----
    public ObservableCollection<ScheduledScan> Schedules { get; } = new();
    public ObservableCollection<string> ScheduleProfiles { get; } = new();
    public IReadOnlyList<ScheduleFrequency> FrequencyOptions { get; } = Enum.GetValues<ScheduleFrequency>();
    public IReadOnlyList<DayOfWeek> DayOptions { get; } = Enum.GetValues<DayOfWeek>();
    private string _scheduleName = "Weekly health check", _scheduleTime = "02:00", _scheduleStatus = "";
    private string? _scheduleProfile;
    private ScopeRef? _scheduleScope;
    private ScheduleFrequency _frequency = ScheduleFrequency.Weekly;
    private DayOfWeek _day = DayOfWeek.Sunday;
    private bool _scheduleNotify = true;
    public string ScheduleName { get => _scheduleName; set { if (Set(ref _scheduleName, value)) AddScheduleCommand.NotifyCanExecuteChanged(); } }
    public ScopeRef? ScheduleScope { get => _scheduleScope; set { if (Set(ref _scheduleScope, value)) AddScheduleCommand.NotifyCanExecuteChanged(); } }
    public string? ScheduleProfile { get => _scheduleProfile; set { if (Set(ref _scheduleProfile, value)) AddScheduleCommand.NotifyCanExecuteChanged(); } }
    public ScheduleFrequency Frequency { get => _frequency; set => Set(ref _frequency, value); }
    public DayOfWeek Day { get => _day; set => Set(ref _day, value); }
    public string ScheduleTime { get => _scheduleTime; set => Set(ref _scheduleTime, value); }
    public bool ScheduleNotify { get => _scheduleNotify; set => Set(ref _scheduleNotify, value); }
    public string ScheduleStatus { get => _scheduleStatus; private set => Set(ref _scheduleStatus, value); }
    public ObservableCollection<ScopeRef> ScheduleScopes { get; } = new();
    public RelayCommand AddScheduleCommand { get; }
    public ICommand DeleteScheduleCommand { get; }
    public ICommand RefreshSchedulesCommand { get; }

    private void RefreshSchedules()
    {
        ScheduleScopes.Clear();
        foreach (var s in _ws.Scopes.Where(s => s.Authorized)) ScheduleScopes.Add(new ScopeRef(s.Name));
        ScheduleScope ??= ScheduleScopes.FirstOrDefault();
        Schedules.Clear();
        try
        {
            foreach (var s in _s.Scheduler.List()) Schedules.Add(s);
        }
        catch (Exception ex) when (ex is InvalidOperationException or PlatformNotSupportedException or System.ComponentModel.Win32Exception)
        {
            ScheduleStatus = "Couldn't read scheduled tasks: " + ex.Message;
        }
    }

    private void AddSchedule()
    {
        if (ScheduleScope == null || ScheduleProfile == null) return;
        if (!TimeSpan.TryParse(ScheduleTime, out var time) || time < TimeSpan.Zero || time >= TimeSpan.FromDays(1))
        {
            ScheduleStatus = "Enter the time as HH:mm, for example 02:00.";
            return;
        }
        var name = string.Concat(ScheduleName.Where(c => char.IsLetterOrDigit(c) || c is ' ' or '-' or '_')).Trim();
        if (name.Length == 0) { ScheduleStatus = "Enter a name."; return; }
        try
        {
            _s.Scheduler.Create(new ScheduledScan(name, ScheduleScope.Name, ScheduleProfile, Frequency, Day, time, null, null), _s.ExecutablePath, ScheduleNotify);
            _s.History.Audit("schedule-created", _s.CurrentUser, ScheduleScope.Name, null, ScheduleProfile, $"{name}: {Frequency} {Day} {time:hh\\:mm}");
            ScheduleStatus = $"Scheduled \"{name}\". It runs while you are signed in to Windows. If you move NetWarden.exe, re-create the schedule.";
        }
        catch (Exception ex) when (ex is InvalidOperationException or PlatformNotSupportedException or System.ComponentModel.Win32Exception)
        {
            ScheduleStatus = "Couldn't create the schedule: " + ex.Message;
        }
        RefreshSchedules();
    }

    private void DeleteSchedule(ScheduledScan? s)
    {
        if (s == null || !_ws.Platform.Confirm("Delete schedule", $"Delete the scheduled scan \"{s.Name}\"?")) return;
        try
        {
            _s.Scheduler.Delete(s.Name);
            _s.History.Audit("schedule-deleted", _s.CurrentUser, s.Scope, null, s.Profile, s.Name);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            ScheduleStatus = "Couldn't delete the schedule: " + ex.Message;
        }
        RefreshSchedules();
    }

    // ---- Audit log & checks ----
    public ObservableCollection<AuditEntry> Audit { get; } = new();
    public ICommand RefreshAuditCommand { get; }
    public ObservableCollection<CheckRow> Checks { get; } = new();

    private void RefreshAudit()
    {
        Audit.Clear();
        foreach (var a in _s.History.ReadAudit(500)) Audit.Add(a);
    }

    public string Version => typeof(SettingsViewModel).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
    public string ResponsibleUse => Reporting.ReportText.ResponsibleUse;
}

/// <summary>Lightweight scope reference for pickers.</summary>
public sealed record ScopeRef(string Name)
{
    public override string ToString() => Name;
}
