using System.Collections.ObjectModel;
using System.Windows.Input;
using NetWarden.Core.Models;
using NetWarden.Reporting;
using NetWarden.UI.Mvvm;

namespace NetWarden.UI.ViewModels;

public sealed class HostsViewModel : ObservableObject
{
    private readonly Workspace _ws;
    private List<HostRow> _all = new();

    public HostsViewModel(Workspace ws)
    {
        _ws = ws;
        ws.CurrentScanChanged += Refresh;
        ShowFindingsCommand = new RelayCommand(() =>
        {
            if (SelectedHost == null) return;
            _ws.Navigate("findings:host:" + SelectedHost.Address);
        });
        Refresh();
    }

    public Workspace Workspace => _ws;
    public BulkObservableCollection<HostRow> Hosts { get; } = new();
    public ICommand ShowFindingsCommand { get; }

    private string _filter = "";
    public string Filter { get => _filter; set { if (Set(ref _filter, value)) Apply(); } }

    private HostRow? _selected;
    public HostRow? SelectedHost { get => _selected; set { if (Set(ref _selected, value)) Raise(nameof(HasSelection)); } }
    public bool HasSelection => SelectedHost != null;
    public string Summary => _ws.CurrentScan == null ? "" : $"{_all.Count} device(s) · {_all.Sum(h => h.OpenPortCount)} open port(s) · {_ws.CurrentScanLabel}";

    public void Select(string address)
    {
        Filter = "";
        SelectedHost = Hosts.FirstOrDefault(h => h.Address == address);
    }

    private void Refresh()
    {
        var keep = SelectedHost?.Address;
        _all = _ws.CurrentScan?.LiveHosts.Select(h => new HostRow(h)).ToList() ?? new List<HostRow>();
        Apply();
        SelectedHost = Hosts.FirstOrDefault(h => h.Address == keep) ?? Hosts.FirstOrDefault();
        Raise(nameof(Summary));
    }

    private void Apply()
    {
        var f = Filter.Trim();
        Hosts.Reset(f.Length == 0 ? _all : _all.Where(h =>
            h.Address.Contains(f, StringComparison.OrdinalIgnoreCase) || h.Name.Contains(f, StringComparison.OrdinalIgnoreCase) ||
            h.Os.Contains(f, StringComparison.OrdinalIgnoreCase) || h.Vendor.Contains(f, StringComparison.OrdinalIgnoreCase) ||
            h.Services.Contains(f, StringComparison.OrdinalIgnoreCase) || h.OpenPorts.Split(", ").Contains(f) ||
            h.DeviceDetail.Contains(f, StringComparison.OrdinalIgnoreCase) ||
            h.Model.Apps.Any(a => a.Name.Contains(f, StringComparison.OrdinalIgnoreCase) || a.Category.Contains(f, StringComparison.OrdinalIgnoreCase))));
    }
}

public sealed class FindingsViewModel : ObservableObject
{
    private readonly Workspace _ws;
    private List<FindingRow> _all = new();

    public FindingsViewModel(Workspace ws)
    {
        _ws = ws;
        ws.CurrentScanChanged += Refresh;
        MarkFixedCommand = new RelayCommand(() => SetStatus(FindingStatus.Fixed, false), () => SelectedFinding != null);
        AcceptRiskCommand = new RelayCommand(() => SetStatus(FindingStatus.AcceptedRisk, true), () => SelectedFinding != null);
        FalsePositiveCommand = new RelayCommand(() => SetStatus(FindingStatus.FalsePositive, true), () => SelectedFinding != null);
        ReopenCommand = new RelayCommand(() => SetStatus(FindingStatus.Open, false), () => SelectedFinding is { IsOpen: false });
        CopyStepsCommand = new RelayCommand(() =>
        {
            if (SelectedFinding is { } f) _ws.Platform.CopyText(f.Title + "\n" + string.Join("\n", f.Remediation.Select((s, i) => $"{i + 1}. {s}")));
        }, () => SelectedFinding != null);
        OpenReferenceCommand = new RelayCommand(p => { if (p is string url && url.StartsWith("http", StringComparison.OrdinalIgnoreCase)) _ws.Platform.OpenUrl(url); });
        ClearFiltersCommand = new RelayCommand(() => { _suspend = true; Query = ""; SeverityFilter = "All"; KevOnly = false; StatusFilter = "Open"; _suspend = false; Apply(); });
        Refresh();
    }

    public Workspace Workspace => _ws;
    public BulkObservableCollection<FindingRow> Findings { get; } = new();
    public ObservableCollection<FixItemRow> FixGroups { get; } = new();
    public RelayCommand MarkFixedCommand { get; }
    public RelayCommand AcceptRiskCommand { get; }
    public RelayCommand FalsePositiveCommand { get; }
    public RelayCommand ReopenCommand { get; }
    public RelayCommand CopyStepsCommand { get; }
    public ICommand OpenReferenceCommand { get; }
    public ICommand ClearFiltersCommand { get; }

    public IReadOnlyList<string> SeverityOptions { get; } = new[] { "All", "Critical", "High", "Medium", "Low", "Info" };
    public IReadOnlyList<string> StatusOptions { get; } = new[] { "Open", "All", "Accepted risk", "False positive", "Fixed" };

    private bool _suspend;
    private string _query = "", _severity = "All", _status = "Open", _queryError = "";
    private bool _kevOnly;

    public string Query { get => _query; set { if (Set(ref _query, value)) Apply(); } }
    public string QueryError { get => _queryError; private set => Set(ref _queryError, value); }
    public string SeverityFilter { get => _severity; set { if (Set(ref _severity, value)) Apply(); } }
    public string StatusFilter { get => _status; set { if (Set(ref _status, value)) Apply(); } }
    public bool KevOnly { get => _kevOnly; set { if (Set(ref _kevOnly, value)) Apply(); } }

    private FindingRow? _selected;
    public FindingRow? SelectedFinding
    {
        get => _selected;
        set
        {
            if (!Set(ref _selected, value)) return;
            Raise(nameof(HasSelection));
            foreach (var c in new[] { MarkFixedCommand, AcceptRiskCommand, FalsePositiveCommand, ReopenCommand, CopyStepsCommand }) c.NotifyCanExecuteChanged();
        }
    }
    public bool HasSelection => SelectedFinding != null;

    public int OpenCount => _all.Count(f => f.IsOpen);
    public int AcceptedCount => _all.Count(f => f.Model.Status == FindingStatus.AcceptedRisk);
    public int FalsePositiveCount => _all.Count(f => f.Model.Status == FindingStatus.FalsePositive);
    public int FixedCount => _all.Count(f => f.Model.Status == FindingStatus.Fixed);
    public string Summary => _ws.CurrentScan == null ? "" : $"{Findings.Count} shown · {OpenCount} open · {AcceptedCount} accepted · {FalsePositiveCount} false positive · {FixedCount} fixed";

    public void FilterHost(string host)
    {
        _suspend = true;
        Query = "host:" + host;
        StatusFilter = "All";
        _suspend = false;
        Apply();
    }

    private void Refresh()
    {
        var keep = SelectedFinding?.Model.Key;
        _all = _ws.CurrentScan?.AllFindings.Select(f => new FindingRow(f)).ToList() ?? new List<FindingRow>();
        FixGroups.Clear();
        if (_ws.CurrentScan != null)
        {
            int n = 1;
            foreach (var g in ReportBuilder.GroupFixes(_ws.CurrentScan.AllFindings.Where(f => f.Status == FindingStatus.Open))) FixGroups.Add(new FixItemRow(g, n++));
        }
        Apply();
        SelectedFinding = Findings.FirstOrDefault(f => f.Model.Key == keep) ?? Findings.FirstOrDefault();
    }

    private void Apply()
    {
        if (_suspend) return;
        var q = FindingQuery.Parse(Query);
        QueryError = q.Errors.Count == 0 ? "" : "Not understood: " + string.Join(", ", q.Errors) + ". Try severity>=high, kev:true, host:10.0.0.5, port:445, cve:2023, status:open, conf:confirmed.";
        IEnumerable<FindingRow> items = _all.Where(f => q.Matches(f.Model));
        if (SeverityFilter != "All" && Enum.TryParse<Severity>(SeverityFilter, out var sev)) items = items.Where(f => f.Severity == sev);
        if (KevOnly) items = items.Where(f => f.Kev);
        items = StatusFilter switch
        {
            "Open" when q.Status == null => items.Where(f => f.Model.Status == FindingStatus.Open),
            "Accepted risk" => items.Where(f => f.Model.Status == FindingStatus.AcceptedRisk),
            "False positive" => items.Where(f => f.Model.Status == FindingStatus.FalsePositive),
            "Fixed" => items.Where(f => f.Model.Status == FindingStatus.Fixed),
            _ => items
        };
        Findings.Reset(items.OrderByDescending(f => f.Kev).ThenByDescending(f => f.Severity).ThenByDescending(f => f.CvssValue).ThenBy(f => f.HostAddress));
        Raise(nameof(Summary), nameof(OpenCount), nameof(AcceptedCount), nameof(FalsePositiveCount), nameof(FixedCount));
    }

    private void SetStatus(FindingStatus status, bool askNote)
    {
        var f = SelectedFinding;
        if (f == null) return;
        string? note = null;
        if (askNote)
        {
            note = _ws.Platform.PromptText(Display.StatusText(status), "Why? (kept in reports and the audit trail)", f.StatusNote ?? "");
            if (note == null) return;
        }
        var services = _ws.Services;
        services.History.SetStatus(f.Model.Key, status, note, services.CurrentUser);
        services.History.Audit("finding-status", services.CurrentUser, _ws.CurrentScan?.ScopeName, f.Location, null, $"{f.Title}: {status}{(string.IsNullOrEmpty(note) ? "" : " – " + note)}");
        f.SetStatus(status, note);
        if (_ws.CurrentScan != null) services.History.SaveScan(_ws.CurrentScan);
        _ws.ReloadScans();
        var index = Findings.IndexOf(f);
        Apply();
        SelectedFinding = Findings.FirstOrDefault(x => x.Model.Key == f.Model.Key) ?? (Findings.Count > 0 ? Findings[Math.Min(Math.Max(index, 0), Findings.Count - 1)] : null);
        _ws.NotifyFindingsChanged();
    }
}

public sealed class MapNode
{
    public required HostRow Host { get; init; }
    public double X { get; init; }
    public double Y { get; init; }
    public string Label => string.IsNullOrEmpty(Host.Name) ? Host.Address : Host.Name;
    public string Tooltip => $"{Host.Address}\n{Host.Os}\n{Host.OpenPortCount} open port(s), {Host.FindingCount} issue(s)";
    public Severity? Worst => Host.WorstSeverity;
    public int WorstRank => Host.WorstRank;
}

public sealed record MapEdge(double X1, double Y1, double X2, double Y2);

public sealed class MapSubnet
{
    public required string Name { get; init; }
    public required IReadOnlyList<MapNode> Nodes { get; init; }
    public required IReadOnlyList<MapEdge> Edges { get; init; }
    public double Width { get; init; }
    public double Height { get; init; }
    public double HubX { get; init; }
    public double HubY { get; init; }
    public string Summary => $"{Nodes.Count} device(s) · {Nodes.Sum(n => n.Host.FindingCount)} issue(s)";
}

/// <summary>Simple topology: one cluster per /24 subnet, devices arranged in rings around a subnet hub.</summary>
public sealed class NetworkMapViewModel : ObservableObject
{
    private readonly Workspace _ws;
    public const double NodeSize = 96;

    public NetworkMapViewModel(Workspace ws)
    {
        _ws = ws;
        ws.CurrentScanChanged += Refresh;
        OpenHostCommand = new RelayCommand(p => { if (p is MapNode n) _ws.Navigate("hosts:" + n.Host.Address); });
        Refresh();
    }

    public Workspace Workspace => _ws;
    public ObservableCollection<MapSubnet> Subnets { get; } = new();
    public ICommand OpenHostCommand { get; }

    private void Refresh()
    {
        Subnets.Clear();
        var scan = _ws.CurrentScan;
        if (scan == null) return;
        foreach (var group in scan.LiveHosts.Select(h => new HostRow(h)).GroupBy(h => h.SubnetKey).OrderBy(g => g.Key))
            Subnets.Add(Layout(group.Key, group.ToList()));
    }

    public static MapSubnet Layout(string name, IReadOnlyList<HostRow> hosts)
    {
        var nodes = new List<MapNode>();
        var edges = new List<MapEdge>();
        // Rings of increasing size: 8, 16, 24... devices.
        int ring = 0, placed = 0;
        var maxRadius = 0.0;
        var positions = new List<(double X, double Y)>();
        while (placed < hosts.Count)
        {
            ring++;
            var capacity = 8 * ring;
            var count = Math.Min(capacity, hosts.Count - placed);
            var radius = 70 + ring * 95;
            maxRadius = radius;
            for (int i = 0; i < count; i++)
            {
                var angle = 2 * Math.PI * i / count - Math.PI / 2 + (ring % 2 == 0 ? Math.PI / count : 0);
                positions.Add((radius * Math.Cos(angle), radius * Math.Sin(angle)));
            }
            placed += count;
        }
        var size = 2 * maxRadius + NodeSize + 40;
        var center = size / 2;
        for (int i = 0; i < hosts.Count; i++)
        {
            var x = center + positions[i].X;
            var y = center + positions[i].Y;
            nodes.Add(new MapNode { Host = hosts[i], X = x - NodeSize / 2, Y = y - 22 });
            edges.Add(new MapEdge(center, center, x, y));
        }
        return new MapSubnet { Name = name, Nodes = nodes, Edges = edges, Width = size, Height = size, HubX = center - 60, HubY = center - 20 };
    }
}

public sealed class CompareViewModel : ObservableObject
{
    private readonly Workspace _ws;

    public CompareViewModel(Workspace ws)
    {
        _ws = ws;
        CompareCommand = new RelayCommand(Compare, () => Before != null && After != null && Before.Id != After.Id);
        ws.Scans.CollectionChanged += (_, _) => Defaults();
        Defaults();
    }

    public Workspace Workspace => _ws;
    public RelayCommand CompareCommand { get; }

    private Data.History.ScanSummary? _before, _after;
    public Data.History.ScanSummary? Before { get => _before; set { if (Set(ref _before, value)) CompareCommand.NotifyCanExecuteChanged(); } }
    public Data.History.ScanSummary? After { get => _after; set { if (Set(ref _after, value)) CompareCommand.NotifyCanExecuteChanged(); } }

    public ObservableCollection<string> NewHosts { get; } = new();
    public ObservableCollection<string> GoneHosts { get; } = new();
    public ObservableCollection<string> NewPorts { get; } = new();
    public ObservableCollection<string> ClosedPorts { get; } = new();
    public ObservableCollection<FindingRow> NewFindings { get; } = new();
    public ObservableCollection<FindingRow> ResolvedFindings { get; } = new();

    private string _summary = "Pick two scans of the same network and press Compare.";
    public string Summary { get => _summary; private set => Set(ref _summary, value); }
    private bool _hasResult;
    public bool HasResult { get => _hasResult; private set => Set(ref _hasResult, value); }

    private void Defaults()
    {
        if (_ws.Scans.Count >= 2 && (Before == null || After == null))
        {
            After = _ws.Scans[0];
            Before = _ws.Scans.Skip(1).FirstOrDefault(s => s.Scope == After.Scope) ?? _ws.Scans[1];
        }
    }

    private void Compare()
    {
        if (Before == null || After == null) return;
        var (b, a) = Before.Started <= After.Started ? (Before, After) : (After, Before);
        var before = _ws.Services.History.LoadScan(b.Id);
        var after = _ws.Services.History.LoadScan(a.Id);
        if (before == null || after == null) return;
        var diff = Reporting.ScanDiff.Compare(before, after);
        NewHosts.Clear(); GoneHosts.Clear(); NewPorts.Clear(); ClosedPorts.Clear(); NewFindings.Clear(); ResolvedFindings.Clear();
        foreach (var h in diff.NewHosts) NewHosts.Add($"{h.Address}  {h.DisplayName}  {h.Os?.Display}");
        foreach (var h in diff.GoneHosts) GoneHosts.Add($"{h.Address}  {h.DisplayName}");
        foreach (var (host, port) in diff.NewPorts) NewPorts.Add($"{host}  {port.Label}  {port.Service?.Display}");
        foreach (var (host, port) in diff.ClosedPorts) ClosedPorts.Add($"{host}  {port.Label}  {port.Service?.Display}");
        foreach (var f in diff.NewFindings) NewFindings.Add(new FindingRow(f));
        foreach (var f in diff.ResolvedFindings) ResolvedFindings.Add(new FindingRow(f));
        Summary = diff.IsEmpty ? "No differences between these scans."
            : $"{diff.NewHosts.Count} new device(s), {diff.GoneHosts.Count} gone · {diff.NewPorts.Count} newly opened port(s), {diff.ClosedPorts.Count} closed · {diff.NewFindings.Count} new finding(s), {diff.ResolvedFindings.Count} resolved";
        HasResult = true;
    }
}
