using System.Collections.ObjectModel;
using System.Windows.Input;
using NetWarden.Core.Models;
using NetWarden.Data.History;
using NetWarden.Reporting;
using NetWarden.UI.Mvvm;

namespace NetWarden.UI.ViewModels;

public sealed class DashboardViewModel : ObservableObject
{
    private readonly Workspace _ws;

    public DashboardViewModel(Workspace ws)
    {
        _ws = ws;
        ws.CurrentScanChanged += Refresh;
        ws.Scans.CollectionChanged += (_, _) => RefreshTrend();
        RunScanCommand = new RelayCommand(() => _ws.Navigate(_ws.HasScope ? "scan" : "scope"));
        SetupScopeCommand = new RelayCommand(() => _ws.Navigate("scope"));
        OpenFindingsCommand = new RelayCommand(() => _ws.Navigate("findings"));
        OpenHostsCommand = new RelayCommand(() => _ws.Navigate("hosts"));
        OpenReportsCommand = new RelayCommand(() => _ws.Navigate("reports"));
        OpenScanCommand = new RelayCommand(p => { if (p is ScanSummary s) _ws.ShowScan(s.Id); });
        CompareCommand = new RelayCommand(() => _ws.Navigate("compare"));
        ShowFixCommand = new RelayCommand(p =>
        {
            if (p is FixItemRow row) _ws.Platform.ShowMessage(row.Action, (row.Why.Length > 0 ? row.Why + "\n\n" : "") + "How to fix:\n" + string.Join("\n", row.Steps.Select((s, i) => $"{i + 1}. {s}")) + "\n\n" + row.AppliesTo);
        });
        Refresh();
    }

    public Workspace Workspace => _ws;
    public ICommand RunScanCommand { get; }
    public ICommand SetupScopeCommand { get; }
    public ICommand OpenFindingsCommand { get; }
    public ICommand OpenHostsCommand { get; }
    public ICommand OpenReportsCommand { get; }
    public ICommand OpenScanCommand { get; }
    public ICommand CompareCommand { get; }
    public ICommand ShowFixCommand { get; }

    public ObservableCollection<FixItemRow> FixItems { get; } = new();
    public ObservableCollection<DonutSlice> Slices { get; } = new();
    public ObservableCollection<TrendBar> Trend { get; } = new();

    private string _headline = "", _subHeadline = "", _lastScan = "", _hostsDelta = "", _portsDelta = "", _findingsDelta = "", _kevText = "";
    private int _devices, _services, _issues, _critical, _high, _medium, _low, _info, _kev;

    public string Headline { get => _headline; private set => Set(ref _headline, value); }
    public string SubHeadline { get => _subHeadline; private set => Set(ref _subHeadline, value); }
    public string LastScanText { get => _lastScan; private set => Set(ref _lastScan, value); }
    public int Devices { get => _devices; private set => Set(ref _devices, value); }
    public int Services { get => _services; private set => Set(ref _services, value); }
    public int Issues { get => _issues; private set => Set(ref _issues, value); }
    public int Critical { get => _critical; private set => Set(ref _critical, value); }
    public int High { get => _high; private set => Set(ref _high, value); }
    public int Medium { get => _medium; private set => Set(ref _medium, value); }
    public int Low { get => _low; private set => Set(ref _low, value); }
    public int Info { get => _info; private set => Set(ref _info, value); }
    public int KevCount { get => _kev; private set => Set(ref _kev, value); }
    public string KevText { get => _kevText; private set => Set(ref _kevText, value); }
    public string HostsDelta { get => _hostsDelta; private set => Set(ref _hostsDelta, value); }
    public string PortsDelta { get => _portsDelta; private set => Set(ref _portsDelta, value); }
    public string FindingsDelta { get => _findingsDelta; private set => Set(ref _findingsDelta, value); }
    public bool HasScan => _ws.CurrentScan != null;
    public bool NoScan => _ws.CurrentScan == null;
    public bool AllClear => HasScan && FixItems.Count == 0;
    public bool NeedsAttention => FixItems.Count > 0;
    public string SeverityBreakdown => $"{Critical} critical · {High} high · {Medium} medium · {Low} low";

    public void Refresh()
    {
        var scan = _ws.CurrentScan;
        FixItems.Clear();
        Slices.Clear();
        if (scan == null)
        {
            Headline = _ws.HasScope ? "Ready for your first check" : "Welcome to NetWarden";
            SubHeadline = _ws.HasScope
                ? "Run a quick health check to see which devices are on your network and whether any need attention."
                : "Start by telling NetWarden which network you're allowed to check.";
            LastScanText = "";
            Devices = Services = Issues = Critical = High = Medium = Low = Info = KevCount = 0;
            Raise(nameof(HasScan), nameof(NoScan), nameof(AllClear), nameof(NeedsAttention), nameof(SeverityBreakdown));
            RefreshTrend();
            return;
        }

        var report = ReportBuilder.Build(scan);
        int n = 1;
        foreach (var fix in report.FixFirst.Where(f => f.Severity >= Severity.Low).Take(5)) FixItems.Add(new FixItemRow(fix, n++));
        Devices = scan.LiveHosts.Count();
        Services = scan.OpenPortCount;
        Issues = report.Findings.Count;
        Critical = report.Count(Severity.Critical);
        High = report.Count(Severity.High);
        Medium = report.Count(Severity.Medium);
        Low = report.Count(Severity.Low);
        Info = report.Count(Severity.Info);
        KevCount = report.KevCount;
        KevText = KevCount == 0 ? "None" : string.Join(", ", report.Findings.Where(f => f.Kev).SelectMany(f => f.Cves).Distinct().Take(3));
        var actionable = report.FixFirst.Count(f => f.Severity >= Severity.Low);
        Headline = actionable switch
        {
            0 => "No problems need your attention",
            1 => "1 thing needs your attention",
            _ => $"{actionable} things need your attention"
        };
        SubHeadline = actionable == 0
            ? "Nothing on your network was changed by this check."
            : (Critical > 0 || KevCount > 0 ? "Fixing the first item removes your most serious risk. " : "") + "Nothing on your network was changed by this check.";
        LastScanText = $"Last checked {scan.Started.ToLocalTime():g} with {scan.ProfileName} · {Devices} device(s) found";
        foreach (var (sev, label) in new[] { (Severity.Critical, "Critical"), (Severity.High, "High"), (Severity.Medium, "Medium"), (Severity.Low, "Low") })
            Slices.Add(new DonutSlice(sev, label, report.Count(sev)));

        // Deltas vs the previous scan of the same scope
        var previous = _ws.Scans.Where(s => s.Scope == scan.ScopeName && s.Started < scan.Started && s.State == ScanState.Completed).OrderByDescending(s => s.Started).FirstOrDefault();
        if (previous != null)
        {
            HostsDelta = Delta(Devices - previous.HostsUp, "vs " + previous.Started.ToLocalTime().ToString("d MMM"));
            PortsDelta = Delta(Services - previous.OpenPorts, "since last scan");
            FindingsDelta = Delta(Issues - previous.TotalFindings, "since last scan");
        }
        else HostsDelta = PortsDelta = FindingsDelta = "first scan of this scope";
        Raise(nameof(HasScan), nameof(NoScan), nameof(AllClear), nameof(NeedsAttention), nameof(SeverityBreakdown));
        RefreshTrend();
    }

    private static string Delta(int d, string suffix) => d == 0 ? "no change " + suffix : (d > 0 ? "+" : "−") + Math.Abs(d) + " " + suffix;

    private void RefreshTrend()
    {
        Trend.Clear();
        var scope = _ws.CurrentScan?.ScopeName ?? _ws.SelectedScope?.Name;
        var scans = _ws.Scans.Where(s => scope == null || s.Scope == scope).Where(s => s.State is ScanState.Completed or ScanState.Imported).OrderBy(s => s.Started).TakeLast(8).ToList();
        if (scans.Count == 0) return;
        var max = Math.Max(1, scans.Max(s => s.TotalFindings));
        foreach (var s in scans)
            Trend.Add(new TrendBar(s.Started.ToLocalTime().ToString("d MMM"), s.TotalFindings, 8 + 132.0 * s.TotalFindings / max, s.Id == _ws.CurrentScan?.Id));
    }
}
