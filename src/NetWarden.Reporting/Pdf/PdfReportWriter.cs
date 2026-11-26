using System.Globalization;
using NetWarden.Core.Models;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace NetWarden.Reporting.Pdf;

/// <summary>PDF report: executive summary first, then technical detail per finding and an asset inventory.</summary>
public static class PdfReportWriter
{
    private const string Accent = "#005FB8";
    private const string Muted = "#5C5C5C";
    private const string Line = "#E0E0E0";

    public static void Register()
    {
        QuestPDF.Settings.License = LicenseType.Community;
        ReportWriter.PdfWriter = (model, path) => Task.Run(() => Write(model, path));
    }

    private static (string Bg, string Fg) SevColors(Severity s) => s switch
    {
        Severity.Critical => ("#FDE7E9", "#A4262C"),
        Severity.High => ("#FFF1E5", "#B3420B"),
        Severity.Medium => ("#FFF4CE", "#7A4F00"),
        Severity.Low => ("#E8F1FB", "#0F5BA7"),
        _ => ("#F0F0F0", "#505050")
    };

    public static void Write(ReportModel m, string path)
    {
        QuestPDF.Settings.License = LicenseType.Community;
        var scan = m.Scan;
        Document.Create(doc =>
        {
            doc.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.Margin(40);
                page.DefaultTextStyle(t => t.FontSize(10).FontColor("#1B1B1B"));

                page.Header().PaddingBottom(10).BorderBottom(2).BorderColor(Accent).Row(row =>
                {
                    row.RelativeItem().Column(c =>
                    {
                        c.Item().Text("NetWarden").FontColor(Accent).SemiBold();
                        c.Item().Text(m.Title).FontSize(16).SemiBold();
                    });
                    row.ConstantItem(170).AlignRight().AlignBottom().Text(m.Generated.ToLocalTime().ToString("d MMM yyyy HH:mm", CultureInfo.CurrentCulture)).FontColor(Muted);
                });

                page.Content().PaddingTop(14).Column(col =>
                {
                    col.Spacing(10);

                    // ---- Executive summary ----
                    col.Item().Text("Executive summary").FontSize(15).SemiBold();
                    var (riskBg, riskFg) = m.RiskRating switch
                    {
                        "Critical" => SevColors(Severity.Critical),
                        "High" => SevColors(Severity.High),
                        "Medium" => SevColors(Severity.Medium),
                        _ => SevColors(Severity.Low)
                    };
                    col.Item().Background(riskBg).Padding(12).Column(c =>
                    {
                        c.Item().Text("OVERALL RISK").FontSize(8).FontColor(Muted);
                        c.Item().Text(m.RiskRating).FontSize(20).Bold().FontColor(riskFg);
                        c.Item().Text(m.RiskExplanation);
                    });

                    col.Item().Row(row =>
                    {
                        row.Spacing(8);
                        void Stat(string label, string value) => row.RelativeItem().Border(1).BorderColor(Line).Padding(8).Column(c =>
                        {
                            c.Item().Text(label).FontColor(Muted).FontSize(9);
                            c.Item().Text(value).FontSize(18).SemiBold();
                        });
                        Stat("Devices found", scan.LiveHosts.Count().ToString(CultureInfo.InvariantCulture));
                        Stat("Open services", scan.OpenPortCount.ToString(CultureInfo.InvariantCulture));
                        Stat("Open findings", m.Findings.Count.ToString(CultureInfo.InvariantCulture));
                        Stat("Actively exploited", m.KevCount.ToString(CultureInfo.InvariantCulture));
                    });

                    col.Item().Row(row =>
                    {
                        row.Spacing(6);
                        foreach (var sev in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Info })
                        {
                            var (bg, fg) = SevColors(sev);
                            row.RelativeItem().Background(bg).Padding(6).AlignCenter().Text(t =>
                            {
                                t.Span(m.Count(sev).ToString(CultureInfo.InvariantCulture) + " ").Bold().FontColor(fg);
                                t.Span(sev.ToString()).FontColor(fg);
                            });
                        }
                    });

                    col.Item().Text(t =>
                    {
                        t.Span("Scope: ").SemiBold();
                        t.Span($"{scan.ScopeName} ({string.Join(", ", scan.Targets)})  ");
                        t.Span("Profile: ").SemiBold();
                        t.Span($"{scan.ProfileName}  ");
                        t.Span("Run by: ").SemiBold();
                        t.Span($"{scan.StartedBy} on {scan.Started.ToLocalTime():g}");
                    });

                    if (m.FixFirst.Count > 0)
                    {
                        col.Item().PaddingTop(6).Text("Fix these first").FontSize(13).SemiBold();
                        int n = 1;
                        foreach (var fix in m.FixFirst.Take(10))
                        {
                            var (bg, fg) = SevColors(fix.Severity);
                            col.Item().Border(1).BorderColor(Line).Padding(8).Row(r =>
                            {
                                r.ConstantItem(22).Text((n++).ToString(CultureInfo.InvariantCulture)).Bold();
                                r.RelativeItem().Column(c =>
                                {
                                    c.Item().Text(t =>
                                    {
                                        t.Span(fix.Severity.ToString().ToUpperInvariant()).FontColor(fg).Bold().FontSize(8);
                                        if (fix.Kev) t.Span("   ACTIVELY EXPLOITED").Bold().FontSize(8);
                                    });
                                    c.Item().Text(fix.Action).SemiBold();
                                    if (!string.IsNullOrEmpty(fix.WhyItMatters)) c.Item().Text(fix.WhyItMatters).FontColor(Muted);
                                    c.Item().Text("Affects: " + string.Join(", ", fix.Hosts.Take(6)) + (fix.Hosts.Count > 6 ? $" and {fix.Hosts.Count - 6} more" : "")).FontSize(9).FontColor(Muted);
                                });
                            });
                        }
                    }

                    // ---- Findings ----
                    col.Item().PageBreak();
                    col.Item().Text("Technical findings").FontSize(15).SemiBold();
                    if (m.Findings.Count == 0) col.Item().Text("No open findings.");
                    foreach (var f in m.Findings)
                    {
                        var (bg, fg) = SevColors(f.Severity);
                        col.Item().Border(1).BorderColor(Line).Column(card =>
                        {
                            card.Item().Background(bg).PaddingHorizontal(8).PaddingVertical(5).Row(r =>
                            {
                                r.RelativeItem().Text(t =>
                                {
                                    t.Span(f.Severity.ToString().ToUpperInvariant() + "  ").Bold().FontColor(fg);
                                    t.Span(f.Title).SemiBold();
                                });
                                if (f.Cvss is double cvss) r.ConstantItem(70).AlignRight().Text($"CVSS {cvss.ToString("0.0", CultureInfo.InvariantCulture)}").FontColor(fg);
                            });
                            card.Item().Padding(8).Column(c =>
                            {
                                c.Spacing(4);
                                c.Item().Text(t =>
                                {
                                    t.Span((f.HostName != null ? f.HostName + " · " : "") + f.Location).FontColor(Muted);
                                    t.Span("   " + ReportText.ConfidenceLabel(f.Confidence)).FontColor(Muted).Italic();
                                    if (f.Kev) t.Span("   Actively exploited (CISA KEV)").Bold();
                                });
                                c.Item().Text(f.Description);
                                if (!string.IsNullOrEmpty(f.Evidence))
                                {
                                    c.Item().Text("Evidence").FontSize(8).FontColor(Muted).SemiBold();
                                    c.Item().Background("#F4F5F7").Padding(6).Text(f.Evidence).FontFamily("Consolas").FontSize(8.5f);
                                }
                                if (f.Cves.Count > 0) c.Item().Text(string.Join(", ", f.Cves) + (f.CvssVector != null ? "  ·  " + f.CvssVector : "")).FontSize(8.5f).FontColor(Muted);
                                if (f.Remediation.Count > 0)
                                {
                                    c.Item().Text("How to fix").FontSize(8).FontColor(Muted).SemiBold();
                                    int i = 1;
                                    foreach (var step in f.Remediation)
                                        c.Item().Row(r =>
                                        {
                                            r.ConstantItem(16).Text($"{i++}.");
                                            r.RelativeItem().Text(step);
                                        });
                                }
                                if (f.References.Count > 0)
                                    c.Item().Text("References: " + string.Join("  ", f.References.Take(4))).FontSize(8).FontColor(Accent);
                            });
                        });
                    }

                    // ---- Inventory ----
                    col.Item().PageBreak();
                    col.Item().Text("Devices and services").FontSize(15).SemiBold();
                    col.Item().Table(table =>
                    {
                        table.ColumnsDefinition(cd =>
                        {
                            cd.ConstantColumn(90);
                            cd.RelativeColumn(2);
                            cd.RelativeColumn(2);
                            cd.RelativeColumn(4);
                            cd.ConstantColumn(45);
                        });
                        table.Header(h =>
                        {
                            foreach (var title in new[] { "Address", "Name / vendor", "OS guess", "Open services", "Issues" })
                                h.Cell().Background("#F7F8FA").Padding(5).Text(title).SemiBold().FontColor(Muted);
                        });
                        foreach (var host in scan.LiveHosts)
                        {
                            table.Cell().BorderTop(1).BorderColor(Line).Padding(5).Text(host.Address).FontFamily("Consolas").FontSize(9);
                            table.Cell().BorderTop(1).BorderColor(Line).Padding(5).Text(string.Join("\n", new[] { host.NetBiosName ?? host.HostName, host.DeviceModel ?? host.Vendor, host.DeviceType }.Where(x => !string.IsNullOrEmpty(x))));
                            table.Cell().BorderTop(1).BorderColor(Line).Padding(5).Text(host.Os?.Display ?? "");
                            table.Cell().BorderTop(1).BorderColor(Line).Padding(5).Text((host.Apps.Where(a => a.Category is not ("Network service" or "Web server" or "Windows services" or "Device info")).Select(a => a.Display).Take(8).ToList() is { Count: > 0 } named ? "Apps: " + string.Join(", ", named) + "\n" : "")
                                + string.Join("\n", host.OpenPorts.Select(p => $"{p.Label}  {p.Service?.Display}"))).FontSize(9);
                            table.Cell().BorderTop(1).BorderColor(Line).Padding(5).Text(host.Findings.Count(x => x.Status == FindingStatus.Open).ToString(CultureInfo.InvariantCulture));
                        }
                    });

                    col.Item().PaddingTop(16).Text(ReportText.ResponsibleUse).FontSize(8).FontColor(Muted);
                });

                page.Footer().AlignCenter().Text(t =>
                {
                    t.DefaultTextStyle(s => s.FontSize(8).FontColor(Muted));
                    t.Span("NetWarden report · page ");
                    t.CurrentPageNumber();
                    t.Span(" of ");
                    t.TotalPages();
                });
            });
        }).GeneratePdf(path);
    }
}
