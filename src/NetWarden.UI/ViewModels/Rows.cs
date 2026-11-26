using NetWarden.Core.Models;
using NetWarden.Reporting;
using NetWarden.UI.Mvvm;

namespace NetWarden.UI.ViewModels;

public static class Display
{
    public static string SeverityText(Severity s) => s switch
    {
        Severity.Critical => "● Critical",
        Severity.High => "▲ High",
        Severity.Medium => "■ Medium",
        Severity.Low => "◆ Low",
        _ => "○ Info"
    };

    public static string StatusText(FindingStatus s) => s switch
    {
        FindingStatus.AcceptedRisk => "Accepted risk",
        FindingStatus.FalsePositive => "False positive",
        FindingStatus.Fixed => "Fixed",
        _ => "Open"
    };

    public static string Duration(TimeSpan? t) => t is not { } d ? "" : d.TotalHours >= 1 ? $"{(int)d.TotalHours} h {d.Minutes} m" : d.TotalMinutes >= 1 ? $"{(int)d.TotalMinutes} m {d.Seconds:00} s" : $"{d.Seconds} s";
}

public sealed class FindingRow : ObservableObject
{
    public Finding Model { get; }
    public FindingRow(Finding f) => Model = f;

    public Severity Severity => Model.Severity;
    public string SeverityText => Display.SeverityText(Model.Severity);
    public int SeverityRank => (int)Model.Severity;
    public string Title => Model.Title;
    public string Host => Model.HostName != null ? $"{Model.HostName} · {Model.Host}" : Model.Host;
    public string HostAddress => Model.Host;
    public string Port => Model.Port is int p ? $"{p}/{(Model.Protocol == TransportProtocol.Udp ? "udp" : "tcp")}" : "";
    public string Confidence => Model.Confidence switch { Core.Models.Confidence.Confirmed => "Confirmed", Core.Models.Confidence.Configuration => "Configuration", _ => "Potential" };
    public string Cvss => Model.Cvss?.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) ?? "";
    public double CvssValue => Model.Cvss ?? 0;
    public bool Kev => Model.Kev;
    public string Cves => string.Join(", ", Model.Cves);
    public string Description => Model.Description;
    public string Evidence => Model.Evidence;
    public string CvssVector => Model.CvssVector ?? "";
    public IReadOnlyList<string> Remediation => Model.Remediation;
    public IReadOnlyList<string> References => Model.References;
    public string FixAction => Model.FixAction;
    public string StatusText => Display.StatusText(Model.Status);
    public string? StatusNote => Model.StatusNote;
    public bool IsOpen => Model.Status == FindingStatus.Open;
    public string Location => Model.Location;

    public void SetStatus(FindingStatus status, string? note)
    {
        Model.Status = status;
        Model.StatusNote = note;
        Raise(nameof(StatusText), nameof(StatusNote), nameof(IsOpen));
    }
}

public sealed class PortRow
{
    public PortResult Model { get; }
    public PortRow(PortResult p) => Model = p;
    public string Port => Model.Label;
    public int Number => Model.Port;
    public string Service => Model.Service?.Name ?? "";
    public string Product => string.Join(' ', new[] { Model.Service?.Product, Model.Service?.Version }.Where(s => !string.IsNullOrEmpty(s)));
    public string Banner => Model.Service?.Banner ?? "";
    public string Tls => Model.Tls == null ? "" : string.Join(", ", Model.Tls.Protocols);
    public string Certificate => Model.Tls?.Certificate is { } c ? $"{c.Subject} (expires {c.NotAfter:yyyy-MM-dd})" : "";
    public string Facts => Model.Service == null ? "" : string.Join("\n", Model.Service.Facts.Where(kv => !kv.Key.StartsWith("http.header", StringComparison.Ordinal) && !kv.Key.StartsWith("ssh.", StringComparison.Ordinal) || kv.Key == "ssh.banner").Select(kv => $"{kv.Key}: {kv.Value}"));
}

public sealed class AppRow
{
    public AppInfo Model { get; }
    public AppRow(AppInfo a) => Model = a;
    public string Name => Model.Display;
    public string Category => Model.Category;
    public string Where => Model.Where;
    public string Detail => string.Join(" · ", new[] { Model.Detail, "found by " + Model.Source }.Where(s => !string.IsNullOrEmpty(s)));
}

public sealed class HostRow : ObservableObject
{
    public HostResult Model { get; private set; }
    public HostRow(HostResult h) => Model = h;

    public void Refresh(HostResult h)
    {
        Model = h;
        Raise(nameof(Name), nameof(Os), nameof(OpenPorts), nameof(OpenPortCount), nameof(FindingCount), nameof(WorstSeverity), nameof(WorstSeverityText), nameof(Severity), nameof(Mac), nameof(Vendor), nameof(Services), nameof(Device), nameof(DeviceDetail), nameof(Apps), nameof(AppSummary), nameof(HasApps));
    }

    public string Address => Model.Address;
    public string Name => Model.NetBiosName ?? Model.HostName ?? "";
    public string Os => Model.Os?.Display ?? "";
    public string OsDetail => Model.Os == null ? "" : $"{Model.Os.Display} – {Model.Os.Confidence}% confident ({Model.Os.Basis})";
    public string Mac => Model.MacAddress ?? "";
    public string Vendor => Model.Vendor ?? "";
    /// <summary>Short "what is this" label for the device list: model, else type, else vendor.</summary>
    public string Device => Model.DeviceModel ?? Model.DeviceType ?? Model.Vendor ?? "";
    public string DeviceDetail => string.Join(" · ", new[] { Model.DeviceType, Model.DeviceModel, Model.FriendlyName is { } f ? $"\"{f}\"" : null }.Where(s => !string.IsNullOrEmpty(s)));
    public IReadOnlyList<AppRow> Apps => Model.Apps.Select(a => new AppRow(a)).ToList();
    public bool HasApps => Model.Apps.Count > 0;
    public string AppSummary => string.Join(", ", Model.Apps.Where(a => a.Category is not ("Network service" or "Web server" or "Windows services" or "Device info")).Select(a => a.Name).Take(6));
    public string Discovery => Model.DiscoveryMethod;
    public string Latency => Model.LatencyMs is double l ? $"{l:0} ms" : "";
    public int OpenPortCount => Model.OpenPorts.Count();
    public string OpenPorts => string.Join(", ", Model.OpenPorts.Select(p => p.Port.ToString(System.Globalization.CultureInfo.InvariantCulture)));
    public string Services => string.Join(", ", Model.OpenPorts.Select(p => p.Service?.Name).Where(n => !string.IsNullOrEmpty(n)).Distinct());
    public int FindingCount => Model.Findings.Count(f => f.Status == FindingStatus.Open);
    public Severity? WorstSeverity => Model.Findings.Where(f => f.Status == FindingStatus.Open).Select(f => (Severity?)f.Severity).Max();
    public string WorstSeverityText => WorstSeverity is Severity s ? Display.SeverityText(s) : "";
    /// <summary>Same as WorstSeverity; named Severity so the shared badge style can bind to it.</summary>
    public Severity? Severity => WorstSeverity;
    public int WorstRank => WorstSeverity is Severity s ? (int)s : -1;
    public IReadOnlyList<PortRow> Ports => Model.Ports.Where(p => p.State == PortState.Open).OrderBy(p => p.Protocol).ThenBy(p => p.Port).Select(p => new PortRow(p)).ToList();
    public IReadOnlyList<FindingRow> Findings => Model.Findings.OrderByDescending(f => f.Severity).Select(f => new FindingRow(f)).ToList();
    public string SubnetKey => Core.Targeting.IpMath.SubnetKey(Model.Address);
}

public sealed class FixItemRow
{
    public FixItem Model { get; }
    public int Number { get; }
    public FixItemRow(FixItem item, int number) { Model = item; Number = number; }
    public Severity Severity => Model.Severity;
    public string SeverityText => Display.SeverityText(Model.Severity);
    public bool Kev => Model.Kev;
    public string Action => Model.Action;
    public string Why => Model.WhyItMatters;
    public string AppliesTo => "Applies to: " + string.Join(", ", Model.Hosts.Take(4)) + (Model.Hosts.Count > 4 ? $" and {Model.Hosts.Count - 4} more" : "");
    public IReadOnlyList<string> Steps => Model.Steps;
    public string CountText => Model.FindingCount == 1 ? "1 issue" : $"{Model.FindingCount} issues";
}

public sealed record TrendBar(string Label, int Value, double Height, bool IsLatest);

public sealed record DonutSlice(Severity Severity, string Label, int Value);
