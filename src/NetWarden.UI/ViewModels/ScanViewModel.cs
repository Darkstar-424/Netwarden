using System.Collections.ObjectModel;
using System.Windows.Input;
using NetWarden.Core;
using NetWarden.Core.Models;
using NetWarden.Core.Profiles;
using NetWarden.Core.Targeting;
using NetWarden.Core.Util;
using NetWarden.Data.Storage;
using NetWarden.UI.Mvvm;

namespace NetWarden.UI.ViewModels;

public sealed class ProfileOption
{
    public ScanProfile Profile { get; }
    public ProfileOption(ScanProfile p) => Profile = p;
    public string Name => Profile.Name;
    public string Goal => string.IsNullOrEmpty(Profile.Goal) ? Profile.Name : Profile.Goal;
    public string Description => Profile.Description;
    public bool BuiltIn => Profile.BuiltIn;
}

/// <summary>Profile choice, the advanced profile editor, and the live scan view.</summary>
public sealed class ScanViewModel : ObservableObject, IScanObserver
{
    private readonly Workspace _ws;
    private CancellationTokenSource? _cts;
    private readonly PauseTokenSource _pause = new();

    public ScanViewModel(Workspace ws)
    {
        _ws = ws;
        StartCommand = new AsyncCommand(StartAsync, () => !IsRunning && _ws.SelectedScope is { Authorized: true } && SelectedProfile != null && PortsError.Length == 0);
        PauseCommand = new RelayCommand(() => { _pause.Pause(); IsPaused = true; Status = "Paused. Connections in progress will finish."; }, () => IsRunning && !IsPaused);
        ResumeCommand = new RelayCommand(() => { _pause.Resume(); IsPaused = false; Status = "Resumed."; }, () => IsRunning && IsPaused);
        CancelCommand = new RelayCommand(() => { _cts?.Cancel(); _pause.Resume(); Status = "Cancelling…"; }, () => IsRunning);
        SaveProfileCommand = new RelayCommand(SaveProfile);
        ImportProfileCommand = new RelayCommand(ImportProfile);
        ExportProfileCommand = new RelayCommand(ExportProfile);
        DeleteProfileCommand = new RelayCommand(DeleteProfile, () => SelectedProfile is { BuiltIn: false });
        EditScopeCommand = new RelayCommand(() => _ws.Navigate("scope"));
        ViewResultsCommand = new RelayCommand(() => _ws.Navigate(_ws.IsAdvanced ? "findings" : "dashboard"));
        CopyCliCommand = new RelayCommand(() => _ws.Platform.CopyText(CliCommand));
        ReloadProfiles();
        _ws.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(Workspace.SelectedScope)) { Raise(nameof(ScopeText), nameof(CanStartText), nameof(CliCommand)); StartCommand.NotifyCanExecuteChanged(); }
        };
    }

    public Workspace Workspace => _ws;
    public AsyncCommand StartCommand { get; }
    public RelayCommand PauseCommand { get; }
    public RelayCommand ResumeCommand { get; }
    public RelayCommand CancelCommand { get; }
    public ICommand SaveProfileCommand { get; }
    public ICommand ImportProfileCommand { get; }
    public ICommand ExportProfileCommand { get; }
    public RelayCommand DeleteProfileCommand { get; }
    public ICommand EditScopeCommand { get; }
    public ICommand ViewResultsCommand { get; }
    public ICommand CopyCliCommand { get; }

    public ObservableCollection<ProfileOption> Profiles { get; } = new();
    public IReadOnlyList<TimingTemplate> TimingOptions { get; } = Enum.GetValues<TimingTemplate>();

    private ProfileOption? _selected;
    public ProfileOption? SelectedProfile
    {
        get => _selected;
        set
        {
            if (!Set(ref _selected, value) || value == null) return;
            LoadEditor(value.Profile);
            _ws.Services.Settings.LastProfile = value.Name;
            _ws.Services.SaveSettings();
            DeleteProfileCommand.NotifyCanExecuteChanged();
            StartCommand.NotifyCanExecuteChanged();
            Raise(nameof(CliCommand));
        }
    }

    public string ScopeText => _ws.SelectedScope == null ? "No scope selected" : _ws.ScopeSummary;
    public string CanStartText => _ws.SelectedScope == null ? "Set up a scope first: tell NetWarden which network you're allowed to check."
        : !_ws.SelectedScope.Authorized ? "This scope hasn't been authorized yet. Open the scope and tick the permission box." : "";

    // ---- Profile editor (Advanced mode) ----
    private string _ports = "", _portsError = "";
    private bool _udp, _tls, _svc, _vuln, _safe, _anon, _assumeUp, _os, _icmp, _tcpPing;
    private TimingTemplate _timing;
    private int? _concurrency, _timeoutMs, _rate;

    public string Ports { get => _ports; set { if (Set(ref _ports, value)) { PortsError = PortSpec.TryValidate(value, out var e) ? "" : e ?? ""; Raise(nameof(PortCountText)); } } }
    public string PortsError { get => _portsError; private set { if (Set(ref _portsError, value)) StartCommand.NotifyCanExecuteChanged(); } }
    public string PortCountText => PortSpec.TryValidate(Ports, out _) ? $"{PortSpec.Parse(Ports).Count:N0} TCP ports" : "";
    public bool UdpProbes { get => _udp; set => Set(ref _udp, value); }
    public bool TlsInspection { get => _tls; set => Set(ref _tls, value); }
    public bool ServiceDetection { get => _svc; set => Set(ref _svc, value); }
    public bool VulnerabilityChecks { get => _vuln; set => Set(ref _vuln, value); }
    public bool SafeProbes { get => _safe; set => Set(ref _safe, value); }
    public bool AnonymousChecks { get => _anon; set => Set(ref _anon, value); }
    public bool AssumeUp { get => _assumeUp; set => Set(ref _assumeUp, value); }
    public bool OsDetection { get => _os; set => Set(ref _os, value); }
    public bool IcmpPing { get => _icmp; set => Set(ref _icmp, value); }
    public bool TcpPing { get => _tcpPing; set => Set(ref _tcpPing, value); }
    public TimingTemplate Timing { get => _timing; set { if (Set(ref _timing, value)) Raise(nameof(TimingText)); } }
    public int? MaxConcurrency { get => _concurrency; set => Set(ref _concurrency, value); }
    public int? TimeoutMs { get => _timeoutMs; set => Set(ref _timeoutMs, value); }
    public int? MaxRate { get => _rate; set => Set(ref _rate, value); }
    public string TimingText
    {
        get
        {
            var t = TimingSettings.For(Timing);
            return $"{t.Concurrency} connections at once, {t.RatePerSecond}/s, {t.TimeoutMs} ms timeout";
        }
    }

    private void LoadEditor(ScanProfile p)
    {
        Ports = p.TcpPorts;
        UdpProbes = p.UdpProbes;
        TlsInspection = p.TlsInspection;
        ServiceDetection = p.ServiceDetection;
        VulnerabilityChecks = p.VulnerabilityChecks;
        SafeProbes = p.MaxProbeLevel == ProbeLevel.SafeProbe;
        AnonymousChecks = p.AllowAnonymousLoginChecks;
        AssumeUp = p.TreatAllHostsAsUp;
        OsDetection = p.OsDetection;
        IcmpPing = p.IcmpPing;
        TcpPing = p.TcpPing;
        Timing = p.Timing;
        MaxConcurrency = p.MaxConcurrency;
        TimeoutMs = p.TimeoutMs;
        MaxRate = p.MaxRatePerSecond;
    }

    /// <summary>The profile actually used: in Simple mode the preset as-is, in Advanced mode the edited copy.</summary>
    public ScanProfile BuildProfile()
    {
        var baseProfile = SelectedProfile?.Profile ?? BuiltInProfiles.Get(BuiltInProfiles.Standard);
        if (!_ws.IsAdvanced) return baseProfile.Clone(baseProfile.Name);
        var p = baseProfile.Clone(baseProfile.Name);
        p.TcpPorts = Ports;
        p.UdpProbes = UdpProbes;
        p.TlsInspection = TlsInspection;
        p.ServiceDetection = ServiceDetection;
        p.VulnerabilityChecks = VulnerabilityChecks;
        p.MaxProbeLevel = SafeProbes ? ProbeLevel.SafeProbe : ProbeLevel.VersionOnly;
        p.AllowAnonymousLoginChecks = AnonymousChecks;
        p.TreatAllHostsAsUp = AssumeUp;
        p.OsDetection = OsDetection;
        p.IcmpPing = IcmpPing;
        p.TcpPing = TcpPing;
        p.Timing = Timing;
        p.MaxConcurrency = MaxConcurrency;
        p.TimeoutMs = TimeoutMs;
        p.MaxRatePerSecond = MaxRate;
        return p;
    }

    public string CliCommand
    {
        get
        {
            var scope = _ws.SelectedScope?.Name ?? "<scope>";
            var profile = SelectedProfile?.Name ?? BuiltInProfiles.Standard;
            return $"NetWarden.exe scan --scope \"{scope}\" --profile \"{profile}\" --report \"report.html\"";
        }
    }

    private void ReloadProfiles(string? select = null)
    {
        Profiles.Clear();
        foreach (var p in _ws.Services.Profiles.All()) Profiles.Add(new ProfileOption(p));
        var name = select ?? _ws.Services.Settings.LastProfile;
        SelectedProfile = Profiles.FirstOrDefault(p => p.Name == name) ?? Profiles.FirstOrDefault(p => p.Name == BuiltInProfiles.Standard);
    }

    private void SaveProfile()
    {
        var name = _ws.Platform.PromptText("Save profile", "Name for this custom profile:", SelectedProfile is { BuiltIn: false } s ? s.Name : "My profile");
        if (string.IsNullOrWhiteSpace(name)) return;
        var p = BuildProfile();
        p.Name = name.Trim();
        p.BuiltIn = false;
        p.Goal = name.Trim();
        p.Description = "Custom profile";
        try
        {
            _ws.Services.Profiles.Save(p);
            ReloadProfiles(p.Name);
        }
        catch (InvalidOperationException ex) { _ws.Platform.ShowMessage("Can't save profile", ex.Message, true); }
    }

    private void ImportProfile()
    {
        var path = _ws.Platform.PickOpenFile("Import scan profile", "Scan profile (*.json)|*.json");
        if (path == null) return;
        try
        {
            var p = ProfileStore.Import(path);
            if (!PortSpec.TryValidate(p.TcpPorts, out var err)) throw new InvalidDataException(err);
            if (BuiltInProfiles.All.Any(b => b.Name.Equals(p.Name, StringComparison.OrdinalIgnoreCase))) p.Name += " (imported)";
            _ws.Services.Profiles.Save(p);
            ReloadProfiles(p.Name);
        }
        catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or InvalidDataException or InvalidOperationException)
        {
            _ws.Platform.ShowMessage("Can't import profile", ex.Message, true);
        }
    }

    private void ExportProfile()
    {
        var p = BuildProfile();
        var path = _ws.Platform.PickSaveFile("Export scan profile", "Scan profile (*.json)|*.json", p.Name + ".json");
        if (path != null) ProfileStore.Export(p, path);
    }

    private void DeleteProfile()
    {
        if (SelectedProfile is not { BuiltIn: false } s) return;
        if (!_ws.Platform.Confirm("Delete profile", $"Delete the custom profile \"{s.Name}\"?")) return;
        _ws.Services.Profiles.Delete(s.Name);
        ReloadProfiles(BuiltInProfiles.Standard);
    }

    // ---- Live scan ----
    private bool _running, _paused;
    private double _progress;
    private string _status = "Choose a check and press Start scan.", _phase = "Ready", _eta = "", _counts = "";

    public bool IsRunning { get => _running; private set { if (Set(ref _running, value)) { Raise(nameof(IsIdle)); NotifyAll(); } } }
    public bool IsIdle => !IsRunning;
    public bool IsPaused { get => _paused; private set { if (Set(ref _paused, value)) NotifyAll(); } }
    public double Progress { get => _progress; private set => Set(ref _progress, value); }
    public string Status { get => _status; private set => Set(ref _status, value); }
    public string Phase { get => _phase; private set => Set(ref _phase, value); }
    public string Eta { get => _eta; private set => Set(ref _eta, value); }
    public string Counts { get => _counts; private set => Set(ref _counts, value); }
    private bool _finished;
    public bool HasFinished { get => _finished; private set => Set(ref _finished, value); }

    public ObservableCollection<HostRow> LiveHosts { get; } = new();
    public ObservableCollection<FindingRow> LiveFindings { get; } = new();
    public ObservableCollection<string> Log { get; } = new();

    private void NotifyAll()
    {
        StartCommand.NotifyCanExecuteChanged();
        PauseCommand.NotifyCanExecuteChanged();
        ResumeCommand.NotifyCanExecuteChanged();
        CancelCommand.NotifyCanExecuteChanged();
    }

    private async Task StartAsync()
    {
        var scope = _ws.SelectedScope;
        if (scope == null) return;
        var profile = BuildProfile();
        try { scope.Validate(); }
        catch (ScopeException ex) { _ws.Platform.ShowMessage("Can't start the scan", ex.Message, true); return; }

        LiveHosts.Clear();
        LiveFindings.Clear();
        Log.Clear();
        HasFinished = false;
        Progress = 0;
        Eta = "";
        Counts = "";
        IsPaused = false;
        IsRunning = true;
        Status = $"Starting {profile.Name} on {scope.Name}…";
        AddLog($"Scan started by {_ws.Services.CurrentUser}: {profile.Name} on {scope.Name}.");
        _cts = new CancellationTokenSource();
        try
        {
            var result = await Task.Run(() => _ws.Services.RunScanAsync(scope, profile, this, _pause.Token, _cts.Token));
            _ws.ReloadScans();
            _ws.CurrentScan = result;
            Status = result.State switch
            {
                ScanState.Completed => $"Done: {result.LiveHosts.Count()} device(s), {result.OpenPortCount} open service(s), {result.AllFindings.Count(f => f.Status == FindingStatus.Open)} issue(s).",
                ScanState.Cancelled => "Scan cancelled. Partial results were saved.",
                _ => "Scan failed: " + string.Join("; ", result.Errors)
            };
            foreach (var w in result.Warnings) AddLog(w);
            Progress = 1;
            HasFinished = true;
        }
        finally
        {
            IsRunning = false;
            IsPaused = false;
            _cts.Dispose();
            _cts = null;
        }
    }

    private void AddLog(string line) => UiThread.Post(() =>
    {
        Log.Insert(0, $"{DateTime.Now:HH:mm:ss}  {line}");
        while (Log.Count > 500) Log.RemoveAt(Log.Count - 1);
    });

    // IScanObserver (called from worker threads)
    public void OnProgress(ScanProgress p) => UiThread.Post(() =>
    {
        Progress = p.Fraction;
        Phase = p.Phase switch
        {
            ScanPhase.Discovery => "Looking for devices",
            ScanPhase.PortScan => "Checking ports",
            ScanPhase.UdpProbes => "Checking UDP services",
            ScanPhase.ServiceDetection => "Identifying services",
            ScanPhase.VulnerabilityChecks => "Checking for weaknesses",
            ScanPhase.Finished => "Finished",
            _ => "Preparing"
        };
        if (!string.IsNullOrEmpty(p.Message) && !IsPaused) Status = p.Message;
        Eta = p.Eta is TimeSpan eta ? "About " + Display.Duration(eta) + " left" : "";
        Counts = $"{LiveHosts.Count} device(s) · {p.OpenPorts} open port(s) · {p.Findings} finding(s)";
    });

    public void OnHostUpdated(HostResult host) => UiThread.Post(() =>
    {
        var row = LiveHosts.FirstOrDefault(h => h.Address == host.Address);
        if (row == null) LiveHosts.Add(new HostRow(host)); else row.Refresh(host);
    });

    public void OnFinding(Finding finding) => UiThread.Post(() =>
    {
        var row = new FindingRow(finding);
        var i = 0;
        while (i < LiveFindings.Count && LiveFindings[i].Severity >= finding.Severity) i++;
        LiveFindings.Insert(i, row);
    });

    public void OnMessage(string message) => AddLog(message);
}
