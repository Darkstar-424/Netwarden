using System.Net;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using NetWarden.Core.Models;

namespace NetWarden.Reporting.Notify;

public sealed class EmailOptions
{
    public string Host { get; init; } = "";
    public int Port { get; init; } = 587;
    public bool StartTls { get; init; } = true;
    public string? User { get; init; }
    public string? Password { get; init; }
    public string From { get; init; } = "";
    public string To { get; init; } = "";
}

/// <summary>Sends a short alert when a scan finds new serious issues (email and/or Microsoft Teams Workflows webhook).</summary>
public sealed class Notifier
{
    private readonly HttpClient _http;
    public Notifier(HttpClient? http = null) => _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

    public static (string Subject, string Body) Compose(ScanResult scan, IReadOnlyList<Finding> newFindings)
    {
        var worst = newFindings.Max(f => f.Severity);
        var subject = $"NetWarden: {newFindings.Count} new {worst.ToString().ToLowerInvariant()} finding(s) on {scan.ScopeName}";
        var sb = new StringBuilder();
        sb.AppendLine($"Scan '{scan.ProfileName}' of {scan.ScopeName} finished {scan.Finished?.ToLocalTime():g}.");
        sb.AppendLine();
        foreach (var f in newFindings.Take(20))
            sb.AppendLine($"- [{f.Severity}{(f.Kev ? ", actively exploited" : "")}] {f.Title} – {f.HostName ?? f.Host}{(f.Port is int p ? ":" + p : "")}");
        if (newFindings.Count > 20) sb.AppendLine($"…and {newFindings.Count - 20} more.");
        sb.AppendLine();
        sb.AppendLine("Open NetWarden to see details and fix steps.");
        return (subject, sb.ToString());
    }

    public async Task SendEmailAsync(EmailOptions o, string subject, string body, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(o.Host) || string.IsNullOrWhiteSpace(o.To) || string.IsNullOrWhiteSpace(o.From))
            throw new InvalidOperationException("Email notifications need an SMTP server, a From address and a To address.");
        using var client = new SmtpClient(o.Host, o.Port) { EnableSsl = o.StartTls, DeliveryMethod = SmtpDeliveryMethod.Network };
        if (!string.IsNullOrEmpty(o.User)) client.Credentials = new NetworkCredential(o.User, o.Password);
        using var msg = new MailMessage { From = new MailAddress(o.From), Subject = subject, Body = body, BodyEncoding = Encoding.UTF8, SubjectEncoding = Encoding.UTF8 };
        foreach (var to in o.To.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)) msg.To.Add(to);
        await client.SendMailAsync(msg, ct).ConfigureAwait(false);
    }

    /// <summary>Posts an Adaptive Card to a Teams "Workflows" incoming-webhook URL.</summary>
    public async Task SendTeamsAsync(string webhookUrl, string subject, string body, CancellationToken ct)
    {
        if (!Uri.TryCreate(webhookUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("The Teams webhook must be an https:// URL.");
        var payload = new
        {
            type = "message",
            attachments = new[]
            {
                new
                {
                    contentType = "application/vnd.microsoft.card.adaptive",
                    content = new Dictionary<string, object>
                    {
                        ["$schema"] = "http://adaptivecards.io/schemas/adaptive-card.json",
                        ["type"] = "AdaptiveCard",
                        ["version"] = "1.4",
                        ["body"] = new object[]
                        {
                            new { type = "TextBlock", size = "Medium", weight = "Bolder", text = subject, wrap = true },
                            new { type = "TextBlock", text = body, wrap = true }
                        }
                    }
                }
            }
        };
        using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        using var resp = await _http.PostAsync(uri, content, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode) throw new InvalidOperationException($"Teams webhook returned HTTP {(int)resp.StatusCode}.");
    }
}
