using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using NetWarden.Core.Checks;
using NetWarden.Core.Discovery;
using NetWarden.Core.Fingerprinting;
using NetWarden.Core.Models;
using NetWarden.Core.Profiles;
using NetWarden.Core.Scanning;
using NetWarden.Core.Targeting;
using NetWarden.Core.Tls;
using NetWarden.Core.Util;

namespace NetWarden.Core;

public interface IScanObserver
{
    void OnProgress(ScanProgress progress);
    void OnHostUpdated(HostResult host);
    void OnFinding(Finding finding);
    void OnMessage(string message);
}

public sealed class NullScanObserver : IScanObserver
{
    public static readonly NullScanObserver Instance = new();
    public void OnProgress(ScanProgress progress) { }
    public void OnHostUpdated(HostResult host) { }
    public void OnFinding(Finding finding) { }
    public void OnMessage(string message) { }
}

public sealed class ScanRequest
{
    public required ScanScope Scope { get; init; }
    public required ScanProfile Profile { get; init; }
    public required string StartedBy { get; init; }
}

/// <summary>
/// Runs the scan pipeline: scope check → discovery → ports → UDP → services/TLS → OS → vulnerability checks.
/// Everything is asynchronous, cancellable and pausable; the scope is enforced here, not only in the UI.
/// </summary>
public sealed class ScanOrchestrator
{
    private readonly IReadOnlyList<IVulnerabilityCheck> _checks;
    private readonly ICveRepository? _cves;
    private readonly IProbeClient _probe;
    private readonly INwLog _log;
    private readonly OuiLookup _oui;

    public ScanOrchestrator(IEnumerable<IVulnerabilityCheck> checks, ICveRepository? cves, INwLog? log = null, IProbeClient? probe = null, OuiLookup? oui = null)
    {
        _checks = checks.ToList();
        _cves = cves;
        _log = log ?? NullLog.Instance;
        _probe = probe ?? NetworkProbeClient.Instance;
        _oui = oui ?? new OuiLookup();
    }

    public IReadOnlyList<IVulnerabilityCheck> Checks => _checks;

    public async Task<ScanResult> RunAsync(ScanRequest request, IScanObserver? observer, PauseToken pause, CancellationToken ct)
    {
        observer ??= NullScanObserver.Instance;
        var scope = request.Scope;
        var profile = request.Profile;
        var timing = profile.EffectiveTiming;
        var timeout = TimeSpan.FromMilliseconds(timing.TimeoutMs);
        var result = new ScanResult
        {
            Started = DateTimeOffset.Now,
            ProfileName = profile.Name,
            ScopeName = scope.Name,
            StartedBy = request.StartedBy,
            State = ScanState.Running,
            Targets = scope.ParsedTargets().Select(t => t.Original).ToList()
        };

        // ---- Scope enforcement -------------------------------------------------------------
        result.Warnings.AddRange(scope.Validate());
        var specs = scope.ParsedTargets();
        var addresses = TargetParser.ExpandAddresses(specs).Where(a => !scope.IsExcluded(a)).ToList();
        foreach (var hostSpec in specs.Where(s => s.Kind == TargetKind.HostName))
        {
            try
            {
                var resolved = await Dns.GetHostAddressesAsync(hostSpec.HostName!, ct).ConfigureAwait(false);
                foreach (var ip in resolved.Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
                {
                    if (scope.IsExcluded(ip)) continue;
                    if (!AddressClassifier.IsPrivate(ip) && !scope.PublicAddressesAcknowledged)
                    {
                        result.Warnings.Add($"{hostSpec.HostName} resolved to public address {ip}; skipped because public addresses were not confirmed for this scope.");
                        continue;
                    }
                    if (!addresses.Contains(ip)) addresses.Add(ip);
                }
            }
            catch (SocketException)
            {
                result.Warnings.Add($"Could not resolve {hostSpec.HostName}.");
            }
        }
        foreach (var w in result.Warnings) observer.OnMessage(w);

        var progress = new ProgressTracker(observer, result);
        progress.AddWork(addresses.Count);
        using var throttle = new Throttle(timing.Concurrency, timing.RatePerSecond);
        var hosts = new ConcurrentBag<HostResult>();

        try
        {
            // ---- Discovery -----------------------------------------------------------------
            progress.Phase(ScanPhase.Discovery, $"Looking for devices among {addresses.Count:N0} addresses…");
            var icmp = new IcmpPinger(timing.TimeoutMs);
            var tcpPing = new TcpPinger(timing.TimeoutMs, PortSpec.TcpPingPorts);
            await Parallel.ForEachAsync(addresses, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(4, timing.Concurrency / 2), CancellationToken = ct },
                async (ip, token) =>
                {
                    await pause.WaitWhilePausedAsync(token).ConfigureAwait(false);
                    var host = await DiscoverAsync(ip, profile, icmp, tcpPing, throttle, token).ConfigureAwait(false);
                    if (host.IsUp)
                    {
                        hosts.Add(host);
                        observer.OnHostUpdated(host);
                    }
                    progress.Done(1, host.IsUp ? $"Found {host.Address}" : null);
                }).ConfigureAwait(false);

            var live = hosts.OrderBy(h => SortKey(h.Address)).ToList();
            result.Hosts.AddRange(live);
            observer.OnMessage($"{live.Count} device(s) answered.");

            // ---- Per-host deep scan --------------------------------------------------------
            var ports = PortSpec.Parse(profile.TcpPorts);
            progress.AddWork(live.Count * ((long)ports.Count + 2 + (profile.UdpProbes ? 1 : 0)));
            progress.Phase(ScanPhase.PortScan, ports.Count > 0 ? $"Checking {ports.Count:N0} ports on {live.Count} device(s)…" : "Identifying devices…");

            var scanner = new TcpConnectScanner(throttle, timing.TimeoutMs, timing.Retries);
            var detector = new ServiceDetector(_probe, timeout, _log);
            var tls = new TlsInspector(_probe, _log);
            var udp = new UdpProber(_probe, timeout);
            var names = new NameResolver(_probe, timeout);

            await Parallel.ForEachAsync(live, new ParallelOptions { MaxDegreeOfParallelism = timing.HostParallelism, CancellationToken = ct },
                async (host, token) =>
                {
                    await ScanHostAsync(host, profile, ports, scanner, detector, tls, udp, names, timeout, progress, observer, pause, token).ConfigureAwait(false);
                }).ConfigureAwait(false);

            result.State = ScanState.Completed;
            progress.Phase(ScanPhase.Finished, $"Finished: {live.Count} device(s), {result.OpenPortCount} open port(s), {result.AllFindings.Count()} finding(s).");
        }
        catch (OperationCanceledException)
        {
            result.State = ScanState.Cancelled;
            result.Hosts.Clear();
            result.Hosts.AddRange(hosts.OrderBy(h => SortKey(h.Address)));
            observer.OnMessage("Scan cancelled. Partial results were kept.");
        }
        catch (Exception ex)
        {
            result.State = ScanState.Failed;
            result.Errors.Add(ex.Message);
            _log.Error("Scan failed", ex);
            observer.OnMessage("Scan failed: " + ex.Message);
        }
        finally
        {
            result.Finished = DateTimeOffset.Now;
        }
        return result;
    }

    private async Task<HostResult> DiscoverAsync(IPAddress ip, ScanProfile profile, IcmpPinger icmp, TcpPinger tcpPing, Throttle throttle, CancellationToken ct)
    {
        var host = new HostResult { Address = ip.ToString() };
        if (profile.TreatAllHostsAsUp)
        {
            host.IsUp = true;
            host.DiscoveryMethod = "assumed up (no ping)";
        }
        if (!host.IsUp && profile.IcmpPing)
        {
            using (await throttle.AcquireAsync(ct).ConfigureAwait(false))
            {
                var r = await icmp.PingAsync(ip, ct).ConfigureAwait(false);
                if (r.Alive) { host.IsUp = true; host.DiscoveryMethod = r.Method; host.Ttl = r.Ttl; host.LatencyMs = r.RoundTripMs; }
            }
        }
        if (!host.IsUp && profile.TcpPing)
        {
            var r = await tcpPing.PingAsync(ip, ct).ConfigureAwait(false);
            if (r.Alive) { host.IsUp = true; host.DiscoveryMethod = r.Method; host.LatencyMs = r.RoundTripMs; }
        }
        if (profile.ArpDiscovery && ArpResolver.IsSupported)
        {
            var mac = await ArpResolver.ResolveAsync(ip, ct).ConfigureAwait(false);
            if (mac != null)
            {
                host.MacAddress = mac;
                host.Vendor = _oui.Lookup(mac);
                if (!host.IsUp) { host.IsUp = true; host.DiscoveryMethod = "ARP"; }
            }
        }
        return host;
    }

    private async Task ScanHostAsync(HostResult host, ScanProfile profile, IReadOnlyList<int> ports, TcpConnectScanner scanner,
        ServiceDetector detector, TlsInspector tls, UdpProber udp, NameResolver names, TimeSpan timeout,
        ProgressTracker progress, IScanObserver observer, PauseToken pause, CancellationToken ct)
    {
        var ip = IPAddress.Parse(host.Address);

        if (profile.ResolveNames)
        {
            var n = await names.ResolveAsync(ip, ct).ConfigureAwait(false);
            host.HostName = n.DnsName;
            host.NetBiosName = n.NetBiosName;
            if (host.MacAddress == null && n.NetBiosMac != null)
            {
                host.MacAddress = n.NetBiosMac;
                host.Vendor = _oui.Lookup(n.NetBiosMac);
            }
        }
        progress.Done(1, null);

        // TCP ports
        var open = new ConcurrentBag<int>();
        await Parallel.ForEachAsync(ports, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(8, profile.EffectiveTiming.Concurrency / Math.Max(1, profile.EffectiveTiming.HostParallelism)), CancellationToken = ct },
            async (port, token) =>
            {
                await pause.WaitWhilePausedAsync(token).ConfigureAwait(false);
                var state = await scanner.ProbeAsync(ip, port, token).ConfigureAwait(false);
                if (state == PortState.Open)
                {
                    open.Add(port);
                    progress.OpenPort();
                }
                progress.Done(1, null);
            }).ConfigureAwait(false);

        lock (host)
        {
            foreach (var p in open.OrderBy(p => p))
                host.Ports.Add(new PortResult { Port = p, Protocol = TransportProtocol.Tcp, State = PortState.Open, Service = new ServiceInfo { Name = WellKnownPorts.NameFor(p) } });
        }
        observer.OnHostUpdated(host);

        // UDP
        if (profile.UdpProbes && ip.AddressFamily == AddressFamily.InterNetwork)
        {
            await pause.WaitWhilePausedAsync(ct).ConfigureAwait(false);
            progress.Phase(ScanPhase.UdpProbes, null);
            foreach (var r in await udp.ProbeAsync(host.Address, ct).ConfigureAwait(false))
            {
                var svc = new ServiceInfo { Name = r.Service, Banner = r.Detail };
                foreach (var kv in r.Facts) svc.Facts[kv.Key] = kv.Value;
                lock (host) host.Ports.Add(new PortResult { Port = r.Port, Protocol = TransportProtocol.Udp, State = PortState.Open, Service = svc });
                if (r.Facts.TryGetValue("netbios.name", out var nb) && host.NetBiosName == null) host.NetBiosName = nb;
                progress.OpenPort();
            }
            progress.Done(1, null);
        }

        // Services and TLS
        if (profile.ServiceDetection)
        {
            progress.Phase(ScanPhase.ServiceDetection, null);
            using var perHost = new SemaphoreSlim(6);
            var tasks = host.Ports.Where(p => p.Protocol == TransportProtocol.Tcp).Select(async p =>
            {
                await perHost.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    await pause.WaitWhilePausedAsync(ct).ConfigureAwait(false);
                    p.Service = await detector.DetectAsync(host.Address, p.Port, ct).ConfigureAwait(false);
                    if (profile.TlsInspection && NeedsTls(p))
                    {
                        p.Tls = await tls.InspectAsync(host.Address, p.Port, host.HostName, timeout, ct).ConfigureAwait(false);
                        if (p.Tls != null && p.Service != null) p.Service.Tls = true;
                    }
                }
                finally
                {
                    perHost.Release();
                }
            });
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        if (profile.OsDetection) host.Os = OsFingerprinter.Guess(host);
        progress.Done(1, null);
        observer.OnHostUpdated(host);

        // Vulnerability checks
        if (profile.VulnerabilityChecks)
        {
            progress.Phase(ScanPhase.VulnerabilityChecks, null);
            var findings = await RunChecksAsync(host, profile, timeout, networkAllowed: true, ct).ConfigureAwait(false);
            foreach (var f in findings)
            {
                observer.OnFinding(f);
                progress.Finding();
            }
        }
        progress.Done(1, $"Finished {host.DisplayName}");
        observer.OnHostUpdated(host);
    }

    private static bool NeedsTls(PortResult p)
        => p.Service is { } s && (s.Tls || s.Fact("http.scheme") == "https" || s.Name is "https" or "https-alt" or "ssl/unknown" or "ldaps" or "imaps" or "pop3s" or "smtps" or "ftps" or "winrm-https")
           || WellKnownPorts.LikelyTls(p.Port);

    /// <summary>Runs all applicable checks for one host and stores the findings on it.</summary>
    public async Task<IReadOnlyList<Finding>> RunChecksAsync(HostResult host, ScanProfile profile, TimeSpan timeout, bool networkAllowed, CancellationToken ct)
    {
        var selected = _checks.Where(c =>
            c.Level <= profile.MaxProbeLevel &&
            (!c.RequiresAnonymousLogin || profile.AllowAnonymousLoginChecks) &&
            (networkAllowed || !c.RequiresNetwork) &&
            !profile.DisabledChecks.Contains(c.Id, StringComparer.OrdinalIgnoreCase)).ToList();

        var targets = new List<CheckTarget> { new(host, null) };
        targets.AddRange(host.Ports.Where(p => p.State == PortState.Open).Select(p => new CheckTarget(host, p)));
        var found = new List<Finding>();
        foreach (var target in targets)
        {
            foreach (var check in selected)
            {
                if ((check.Scope == CheckScope.Host) != (target.Port == null)) continue;
                ct.ThrowIfCancellationRequested();
                bool applies;
                try { applies = check.AppliesTo(target); }
                catch (Exception ex) { _log.Warn($"Check {check.Id} AppliesTo failed", ex); continue; }
                if (!applies) continue;
                try
                {
                    var ctx = new CheckContext { Target = target, Profile = profile, Probe = _probe, Cves = _cves, Log = _log, Timeout = timeout };
                    var results = await check.RunAsync(ctx, ct).ConfigureAwait(false);
                    found.AddRange(results);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    _log.Warn($"Check {check.Id} failed on {target.Host.Address}:{target.Port?.Port}", ex);
                }
            }
        }
        // De-duplicate by key and attach.
        var unique = found.GroupBy(f => f.Key).Select(g => g.OrderByDescending(f => f.Severity).First()).ToList();
        lock (host)
        {
            host.Findings.RemoveAll(f => unique.Any(u => u.Key == f.Key));
            host.Findings.AddRange(unique);
        }
        return unique;
    }

    /// <summary>Re-analyses imported or stored results with checks that need no network access.</summary>
    public async Task AnalyzeOfflineAsync(ScanResult result, ScanProfile profile, CancellationToken ct)
    {
        foreach (var host in result.Hosts.Where(h => h.IsUp))
        {
            if (host.Os == null) host.Os = OsFingerprinter.Guess(host);
            foreach (var p in host.Ports)
                if (p.Service != null)
                    foreach (var cpe in CpeMapper.Map(p.Service.Product, p.Service.Version))
                        if (!p.Service.Cpes.Contains(cpe)) p.Service.Cpes.Add(cpe);
            await RunChecksAsync(host, profile, TimeSpan.FromSeconds(1), networkAllowed: false, ct).ConfigureAwait(false);
        }
    }

    private static string SortKey(string address)
        => IPAddress.TryParse(address, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork
            ? IpMath.ToUInt32(ip).ToString("D10")
            : "z" + address;

    private sealed class ProgressTracker
    {
        private readonly IScanObserver _observer;
        private readonly ScanResult _result;
        private readonly Stopwatch _sw = Stopwatch.StartNew();
        private long _total, _done;
        private int _openPorts, _findings;
        private ScanPhase _phase = ScanPhase.Preparing;
        private string _message = "";
        private long _lastReportTicks;

        public ProgressTracker(IScanObserver observer, ScanResult result)
        {
            _observer = observer;
            _result = result;
        }

        public void AddWork(long units) => Interlocked.Add(ref _total, units);
        public void OpenPort() => Interlocked.Increment(ref _openPorts);
        public void Finding() => Interlocked.Increment(ref _findings);

        public void Phase(ScanPhase phase, string? message)
        {
            _phase = phase;
            if (message != null) _message = message;
            Report(force: true);
        }

        public void Done(long units, string? message)
        {
            Interlocked.Add(ref _done, units);
            if (message != null) _message = message;
            Report(force: false);
        }

        private void Report(bool force)
        {
            var now = _sw.ElapsedTicks;
            var last = Interlocked.Read(ref _lastReportTicks);
            if (!force && now - last < Stopwatch.Frequency / 5) return;
            Interlocked.Exchange(ref _lastReportTicks, now);
            var done = Interlocked.Read(ref _done);
            var total = Math.Max(Interlocked.Read(ref _total), done);
            TimeSpan? eta = null;
            if (done > 0 && total > done && _sw.Elapsed.TotalSeconds > 3)
                eta = TimeSpan.FromSeconds(_sw.Elapsed.TotalSeconds / done * (total - done));
            _observer.OnProgress(new ScanProgress
            {
                Phase = _phase,
                Completed = done,
                Total = total,
                Message = _message,
                Eta = eta,
                HostsUp = _result.Hosts.Count,
                OpenPorts = _openPorts,
                Findings = _findings
            });
        }
    }
}
