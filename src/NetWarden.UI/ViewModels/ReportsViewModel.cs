using System.Windows.Input;
using NetWarden.Core.Models;
using NetWarden.Core.Profiles;
using NetWarden.Data.History;
using NetWarden.Data.Import;
using NetWarden.Reporting;
using NetWarden.UI.Mvvm;

namespace NetWarden.UI.ViewModels;

public sealed class ReportsViewModel : ObservableObject
{
    private readonly Workspace _ws;

    public ReportsViewModel(Workspace ws)
    {
        _ws = ws;
        ExportCommand = new AsyncCommand(p => ExportAsync(p as string ?? "html"), _ => SelectedScan != null);
        ImportNmapCommand = new AsyncCommand(ImportNmapAsync);
        OpenReportsFolderCommand = new RelayCommand(() => _ws.Platform.OpenPath(_ws.Services.Paths.Reports));
        DeleteScanCommand = new RelayCommand(DeleteScan, () => SelectedScan != null);
        ShowScanCommand = new RelayCommand(() => { if (SelectedScan != null) { _ws.ShowScan(SelectedScan.Id); _ws.Navigate("dashboard"); } }, () => SelectedScan != null);
        ws.Scans.CollectionChanged += (_, _) => { if (SelectedScan == null || !_ws.Scans.Contains(SelectedScan)) SelectedScan = _ws.Scans.FirstOrDefault(); };
        ws.CurrentScanChanged += () => SelectedScan = _ws.Scans.FirstOrDefault(s => s.Id == _ws.CurrentScan?.Id) ?? SelectedScan;
        SelectedScan = _ws.Scans.FirstOrDefault(s => s.Id == _ws.CurrentScan?.Id) ?? _ws.Scans.FirstOrDefault();
    }

    public Workspace Workspace => _ws;
    public AsyncCommand ExportCommand { get; }
    public AsyncCommand ImportNmapCommand { get; }
    public ICommand OpenReportsFolderCommand { get; }
    public RelayCommand DeleteScanCommand { get; }
    public RelayCommand ShowScanCommand { get; }

    private ScanSummary? _selected;
    public ScanSummary? SelectedScan
    {
        get => _selected;
        set
        {
            if (!Set(ref _selected, value)) return;
            if (value != null) Title = $"Network security assessment – {value.Scope}";
            ExportCommand.NotifyCanExecuteChanged();
            DeleteScanCommand.NotifyCanExecuteChanged();
            ShowScanCommand.NotifyCanExecuteChanged();
        }
    }

    private string _title = "Network security assessment", _status = "";
    public string Title { get => _title; set => Set(ref _title, value); }
    public string Status { get => _status; private set => Set(ref _status, value); }

    private async Task ExportAsync(string format)
    {
        if (SelectedScan == null) return;
        var scan = _ws.Services.History.LoadScan(SelectedScan.Id);
        if (scan == null) return;
        var (fmt, filter, ext) = format.ToLowerInvariant() switch
        {
            "pdf" => (ReportFormat.Pdf, "PDF report (*.pdf)|*.pdf", ".pdf"),
            "csv" => (ReportFormat.Csv, "CSV spreadsheet (*.csv)|*.csv", ".csv"),
            "json" => (ReportFormat.Json, "JSON data (*.json)|*.json", ".json"),
            _ => (ReportFormat.Html, "Web page (*.html)|*.html", ".html")
        };
        var name = $"NetWarden-{scan.ScopeName}-{scan.Started.ToLocalTime():yyyyMMdd-HHmm}{ext}";
        name = string.Concat(name.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
        var path = _ws.Platform.PickSaveFile("Save report", filter, Path.Combine(_ws.Services.Paths.Reports, name));
        if (path == null) return;
        Status = "Writing report…";
        await ReportWriter.WriteAsync(scan, fmt, path, Title);
        _ws.Services.History.Audit("report-export", _ws.Services.CurrentUser, scan.ScopeName, null, scan.ProfileName, $"{fmt} → {path}");
        Status = $"Saved {Path.GetFileName(path)}" + (fmt == ReportFormat.Csv ? " (and the matching -hosts.csv)" : "");
        if (fmt is ReportFormat.Pdf or ReportFormat.Html) _ws.Platform.OpenPath(path);
    }

    private async Task ImportNmapAsync()
    {
        var path = _ws.Platform.PickOpenFile("Import Nmap XML results", "Nmap XML (*.xml)|*.xml");
        if (path == null) return;
        Status = "Importing and analysing…";
        ScanResult result;
        await using (var stream = File.OpenRead(path))
            result = NmapXmlImporter.Import(stream, _ws.Services.CurrentUser, Path.GetFileName(path));
        var profile = BuiltInProfiles.Get(BuiltInProfiles.Standard);
        await _ws.Services.Orchestrator.AnalyzeOfflineAsync(result, profile, CancellationToken.None);
        _ws.Services.History.ApplyStatuses(result);
        _ws.Services.History.SaveScan(result);
        _ws.Services.History.Audit("import-nmap", _ws.Services.CurrentUser, result.ScopeName, string.Join(" ", result.Hosts.Select(h => h.Address).Take(50)), null, path);
        _ws.ReloadScans();
        _ws.CurrentScan = result;
        Status = $"Imported {result.LiveHosts.Count()} host(s) and found {result.AllFindings.Count()} issue(s) from version and configuration data.";
        if (!_ws.Services.Cves.IsAvailable)
            Status += " Tip: download the CVE database in Settings to match versions against known vulnerabilities.";
    }

    private void DeleteScan()
    {
        if (SelectedScan == null) return;
        if (!_ws.Platform.Confirm("Delete scan", $"Delete the scan from {SelectedScan.Started.ToLocalTime():g}? The audit log keeps a record that it was run.")) return;
        _ws.Services.History.DeleteScan(SelectedScan.Id);
        _ws.Services.History.Audit("scan-deleted", _ws.Services.CurrentUser, SelectedScan.Scope, null, SelectedScan.Profile, SelectedScan.Id.ToString());
        var wasCurrent = _ws.CurrentScan?.Id == SelectedScan.Id;
        _ws.ReloadScans();
        if (wasCurrent) _ws.CurrentScan = _ws.Scans.FirstOrDefault() is { } s ? _ws.Services.History.LoadScan(s.Id) : null;
    }
}
