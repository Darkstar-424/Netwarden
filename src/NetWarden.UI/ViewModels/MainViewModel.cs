using System.Collections.ObjectModel;
using System.Windows.Input;
using NetWarden.Data.Storage;
using NetWarden.UI.Mvvm;
using NetWarden.UI.Services;

namespace NetWarden.UI.ViewModels;

public sealed class NavItem : ObservableObject
{
    private readonly Workspace _ws;
    public string Key { get; }
    public string SimpleLabel { get; }
    public string AdvancedLabel { get; }
    /// <summary>SVG path data for a 24×24 stroke icon.</summary>
    public string Icon { get; }
    public string Tooltip { get; }
    public bool AdvancedOnly { get; }

    public NavItem(Workspace ws, string key, string simple, string advanced, string icon, string tooltip, bool advancedOnly = false)
    {
        _ws = ws;
        Key = key; SimpleLabel = simple; AdvancedLabel = advanced; Icon = icon; Tooltip = tooltip; AdvancedOnly = advancedOnly;
        ws.PropertyChanged += (_, e) => { if (e.PropertyName == nameof(Workspace.IsAdvanced)) Raise(nameof(Label), nameof(IsVisible)); };
    }

    public string Label => _ws.IsAdvanced ? AdvancedLabel : SimpleLabel;
    public bool IsVisible => !AdvancedOnly || _ws.IsAdvanced;

    private int _badge;
    public int Badge { get => _badge; set { if (Set(ref _badge, value)) Raise(nameof(HasBadge)); } }
    public bool HasBadge => Badge > 0;
}

public sealed class MainViewModel : ObservableObject
{
    public Workspace Workspace { get; }
    public DashboardViewModel Dashboard { get; }
    public ScopeViewModel Scope { get; }
    public ScanViewModel Scan { get; }
    public HostsViewModel Hosts { get; }
    public FindingsViewModel Findings { get; }
    public NetworkMapViewModel Map { get; }
    public CompareViewModel Compare { get; }
    public ReportsViewModel Reports { get; }
    public SettingsViewModel Settings { get; }

    public ObservableCollection<NavItem> NavItems { get; } = new();

    public MainViewModel(AppServices services, IPlatform platform)
    {
        Workspace = new Workspace(services, platform);
        AsyncCommand.ErrorHandler = Workspace.Error;
        Dashboard = new DashboardViewModel(Workspace);
        Scope = new ScopeViewModel(Workspace);
        Scan = new ScanViewModel(Workspace);
        Hosts = new HostsViewModel(Workspace);
        Findings = new FindingsViewModel(Workspace);
        Map = new NetworkMapViewModel(Workspace);
        Compare = new CompareViewModel(Workspace);
        Reports = new ReportsViewModel(Workspace);
        Settings = new SettingsViewModel(Workspace);

        NavItems.Add(new NavItem(Workspace, "dashboard", "Home", "Dashboard", "M3 3h7v9H3z M14 3h7v5h-7z M14 12h7v9h-7z M3 16h7v5H3z", "Overview of your network"));
        NavItems.Add(new NavItem(Workspace, "scope", "What to check", "Scope & targets", "M12 4a8 8 0 1 0 0 16a8 8 0 1 0 0-16z M12 9a3 3 0 1 0 0 6a3 3 0 1 0 0-6z", "Choose which devices you are allowed to check"));
        NavItems.Add(new NavItem(Workspace, "scan", "Run a check", "New scan", "M6 4l14 8l-14 8z", "Start a scan and watch it live"));
        NavItems.Add(new NavItem(Workspace, "hosts", "Devices", "Hosts", "M3 4h18v12H3z M8 20h8 M12 16v4", "Everything that answered on your network"));
        NavItems.Add(new NavItem(Workspace, "findings", "Issues", "Findings", "M12 3l9 16H3z M12 10v4 M12 17v.01", "Problems found, with fix steps"));
        NavItems.Add(new NavItem(Workspace, "map", "Network map", "Network map", "M5 9.5a2.5 2.5 0 1 0 0 5a2.5 2.5 0 1 0 0-5z M19 3.5a2.5 2.5 0 1 0 0 5a2.5 2.5 0 1 0 0-5z M19 15.5a2.5 2.5 0 1 0 0 5a2.5 2.5 0 1 0 0-5z M7.3 11l9.4-4 M7.3 13l9.4 4", "Devices grouped by subnet"));
        NavItems.Add(new NavItem(Workspace, "compare", "Compare checks", "Compare scans", "M4 7h16 M4 12h10 M4 17h6", "What changed between two scans", advancedOnly: true));
        NavItems.Add(new NavItem(Workspace, "reports", "Reports", "Reports & import", "M6 3h9l4 4v14H6z M9 12h7 M9 16h7", "Save PDF/HTML/CSV/JSON reports, import Nmap results"));
        NavItems.Add(new NavItem(Workspace, "settings", "Settings", "Settings", "M12 9a3 3 0 1 0 0 6a3 3 0 1 0 0-6z M12 2v3 M12 19v3 M2 12h3 M19 12h3 M5 5l2 2 M17 17l2 2 M5 19l2-2 M17 7l2-2", "Theme, CVE database, schedules, notifications, audit log"));

        Workspace.NavigateRequested += Navigate;
        Workspace.CurrentScanChanged += UpdateBadges;
        SetSimpleCommand = new RelayCommand(() => Workspace.IsAdvanced = false);
        SetAdvancedCommand = new RelayCommand(() => Workspace.IsAdvanced = true);
        ToggleThemeCommand = new RelayCommand(() => Settings.Theme = EffectiveDark ? ThemeChoice.Light : ThemeChoice.Dark);
        NewScanCommand = new RelayCommand(() => Navigate(Workspace.HasScope ? "scan" : "scope"));
        NavigateCommand = new RelayCommand(p => { if (p is string key) Navigate(key); });
        UpdateBadges();
        Navigate(Workspace.Scopes.Count == 0 ? "scope" : "dashboard");
    }

    public ICommand SetSimpleCommand { get; }
    public ICommand SetAdvancedCommand { get; }
    public ICommand ToggleThemeCommand { get; }
    public ICommand NewScanCommand { get; }
    public ICommand NavigateCommand { get; }

    /// <summary>Set by the app when the OS/app theme resolves to dark.</summary>
    public bool EffectiveDark { get; set; }

    private NavItem? _selectedNav;
    public NavItem? SelectedNav
    {
        get => _selectedNav;
        set
        {
            if (value == null || !Set(ref _selectedNav, value)) return;
            CurrentPage = value.Key switch
            {
                "dashboard" => Dashboard,
                "scope" => Scope,
                "scan" => Scan,
                "hosts" => Hosts,
                "findings" => Findings,
                "map" => Map,
                "compare" => Compare,
                "reports" => Reports,
                "settings" => Settings,
                _ => Dashboard
            };
        }
    }

    private object? _currentPage;
    public object? CurrentPage { get => _currentPage; private set => Set(ref _currentPage, value); }

    /// <summary>Keys: "dashboard", "findings", "findings:host:1.2.3.4", "hosts:1.2.3.4", …</summary>
    public void Navigate(string key)
    {
        var parts = key.Split(':', 2);
        var page = parts[0];
        if (page == "compare" && !Workspace.IsAdvanced) Workspace.IsAdvanced = true;
        SelectedNav = NavItems.FirstOrDefault(n => n.Key == page) ?? NavItems[0];
        if (parts.Length > 1)
        {
            if (page == "findings" && parts[1].StartsWith("host:", StringComparison.Ordinal)) Findings.FilterHost(parts[1][5..]);
            if (page == "hosts") Hosts.Select(parts[1]);
        }
    }

    private void UpdateBadges()
    {
        var open = Workspace.CurrentScan?.AllFindings.Count(f => f.Status == Core.Models.FindingStatus.Open && f.Severity >= Core.Models.Severity.Low) ?? 0;
        var findings = NavItems.FirstOrDefault(n => n.Key == "findings");
        if (findings != null) findings.Badge = open;
    }

    public string Title => "NetWarden";
    public IReadOnlyList<string> StartupWarnings => Workspace.Services.StartupWarnings;
}
