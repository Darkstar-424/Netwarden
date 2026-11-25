using NetWarden.Checks;
using NetWarden.Core;
using NetWarden.Core.Checks;
using NetWarden.Core.Discovery;
using NetWarden.Core.Models;
using NetWarden.Core.Profiles;
using NetWarden.Core.Targeting;
using NetWarden.Core.Util;
using NetWarden.Data.CveStore;
using NetWarden.Data.History;
using NetWarden.Data.Storage;
using NetWarden.Reporting;
using NetWarden.Reporting.Notify;

namespace NetWarden.UI.Services;

/// <summary>Composition root shared by the GUI and the command line.</summary>
public sealed class AppServices
{
    public const string SmtpPasswordSecret = "NetWarden/SmtpPassword";
    public const string TeamsWebhookSecret = "NetWarden/TeamsWebhook";

    public AppPaths Paths { get; }
    public SettingsStore SettingsStore { get; }
    public AppSettings Settings { get; }
    public HistoryStore History { get; }
    public CveDatabase Cves { get; }
    public ProfileStore Profiles { get; }
    public IReadOnlyList<IVulnerabilityCheck> Checks { get; }
    public ScanOrchestrator Orchestrator { get; }
    public INwLog Log { get; }
    public ISecretStore Secrets { get; }
    public IScanScheduler Scheduler { get; }
    public IDbConnectionFactory DbFactory { get; }
    public string CurrentUser { get; }
    public string ExecutablePath { get; }
    public List<string> StartupWarnings { get; } = new();

    public AppServices(AppPaths paths, IDbConnectionFactory dbFactory, INwLog log, ISecretStore secrets, IScanScheduler scheduler, string? executablePath = null)
    {
        Paths = paths;
        DbFactory = dbFactory;
        Log = log;
        Secrets = secrets;
        Scheduler = scheduler;
        SettingsStore = new SettingsStore(paths.SettingsFile);
        Settings = SettingsStore.Load();
        History = new HistoryStore(dbFactory, paths.HistoryDb);
        Cves = new CveDatabase(dbFactory, paths.CveDb);
        Profiles = new ProfileStore(paths.Profiles);
        Checks = CheckRegistry.CreateAll(extraPackFolder: paths.CheckPacks, warn: w => { StartupWarnings.Add(w); log.Warn(w); });
        Orchestrator = new ScanOrchestrator(Checks, Cves, log, NetworkProbeClient.Instance, new OuiLookup(paths.OuiCsv));
        CurrentUser = string.IsNullOrEmpty(Environment.UserDomainName) ? Environment.UserName : $"{Environment.UserDomainName}\\{Environment.UserName}";
        ExecutablePath = executablePath ?? Environment.ProcessPath ?? "NetWarden.exe";
    }

    public void SaveSettings() => SettingsStore.Save(Settings);

    /// <summary>Runs a scan end to end: audit, scan, carry statuses forward, save, notify. Used by both GUI and CLI.</summary>
    public async Task<ScanResult> RunScanAsync(ScanScope scope, ScanProfile profile, IScanObserver? observer, PauseToken pause, CancellationToken ct, bool sendNotifications = true)
    {
        History.Audit("scan-start", CurrentUser, scope.Name, scope.Targets.Replace("\r", "").Replace('\n', ' '), profile.Name,
            $"exclusions: {scope.Exclusions.Replace("\r", "").Replace('\n', ' ')}; safe probes: {profile.MaxProbeLevel}; anonymous checks: {profile.AllowAnonymousLoginChecks}");
        var previous = History.ListScans().FirstOrDefault(s => s.Scope == scope.Name && s.State == ScanState.Completed);
        var result = await Orchestrator.RunAsync(new ScanRequest { Scope = scope, Profile = profile, StartedBy = CurrentUser }, observer, pause, ct).ConfigureAwait(false);
        History.ApplyStatuses(result);
        History.SaveScan(result);
        History.Audit("scan-end", CurrentUser, scope.Name, null, profile.Name,
            $"state: {result.State}; hosts: {result.LiveHosts.Count()}; open ports: {result.OpenPortCount}; findings: {result.AllFindings.Count()}");

        if (sendNotifications && result.State == ScanState.Completed && Settings.Notifications.Enabled)
        {
            try
            {
                var before = previous == null ? null : History.LoadScan(previous.Id);
                var fresh = before == null
                    ? result.AllFindings.ToList()
                    : ScanDiff.Compare(before, result).NewFindings.ToList();
                fresh = fresh.Where(f => f.Status == FindingStatus.Open && (f.Severity >= Settings.Notifications.MinimumSeverity || f.Kev)).ToList();
                if (fresh.Count > 0) await NotifyAsync(result, fresh, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log.Warn("Notification failed", ex);
                result.Warnings.Add("Notification failed: " + ex.Message);
            }
        }
        return result;
    }

    public async Task NotifyAsync(ScanResult result, IReadOnlyList<Finding> findings, CancellationToken ct)
    {
        var n = Settings.Notifications;
        var (subject, body) = Notifier.Compose(result, findings);
        var notifier = new Notifier();
        if (!string.IsNullOrWhiteSpace(n.SmtpHost))
        {
            await notifier.SendEmailAsync(new EmailOptions
            {
                Host = n.SmtpHost, Port = n.SmtpPort, StartTls = n.SmtpStartTls, User = n.SmtpUser,
                Password = Secrets.Get(SmtpPasswordSecret), From = n.From, To = n.To
            }, subject, body, ct).ConfigureAwait(false);
        }
        if (n.UseTeams && Secrets.Get(TeamsWebhookSecret) is string hook && hook.Length > 0)
            await notifier.SendTeamsAsync(hook, subject, body, ct).ConfigureAwait(false);
    }

    public ScanProfile ResolveProfile(string name)
        => Profiles.Find(name) ?? BuiltInProfiles.Get(BuiltInProfiles.Standard);
}
