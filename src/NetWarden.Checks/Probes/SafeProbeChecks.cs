using System.Text;
using System.Text.RegularExpressions;
using NetWarden.Core.Checks;
using NetWarden.Core.Fingerprinting;
using NetWarden.Core.Models;
using NetWarden.Core.Protocols;
using NetWarden.Core.Targeting;

namespace NetWarden.Checks.Probes;

/// <summary>Sends the read-only INFO command. If Redis answers without asking for a password, it is open to anyone.</summary>
public sealed class RedisUnauthenticatedCheck : CheckBase
{
    public override string Id => "db.redis-noauth";
    public override string Name => "Redis without authentication";
    public override string Category => "Databases";
    public override ProbeLevel Level => ProbeLevel.SafeProbe;

    public override bool AppliesTo(CheckTarget t) => t.Port is { Protocol: TransportProtocol.Tcp } p && (p.Port == 6379 || p.Service?.Name == "redis");

    public override async Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        await using var s = await ctx.Probe.ConnectAsync(ctx.Host.Address, ctx.Port!.Port, ctx.Timeout, ct).ConfigureAwait(false);
        if (s == null) return Array.Empty<Finding>();
        await s.SendAsync(Encoding.ASCII.GetBytes("*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"), ct).ConfigureAwait(false);
        var data = await s.ReceiveAsync(8192, ctx.Timeout, ct).ConfigureAwait(false);
        var text = Encoding.ASCII.GetString(data);
        if (!text.Contains("redis_version:", StringComparison.Ordinal)) return Array.Empty<Finding>();
        var version = Regex.Match(text, @"redis_version:(?<v>[\d.]+)").Groups["v"].Value;
        if (ctx.Service != null)
        {
            ctx.Service.Name = "redis";
            ctx.Service.Product = "Redis";
            if (version.Length > 0)
            {
                ctx.Service.Version = version;
                foreach (var cpe in CpeMapper.Map("redis", version))
                    if (!ctx.Service.Cpes.Contains(cpe)) ctx.Service.Cpes.Add(cpe);
            }
        }
        var f = ctx.NewFinding(this, "Redis accepts commands without a password", Severity.High, Confidence.Confirmed);
        f.Description = "Anyone who can reach this Redis server can read and change all of its data. Open Redis servers are often abused to plant SSH keys or cron jobs and take over the host.";
        f.Evidence = $"INFO server answered without authentication (redis_version {version}). Only server information was requested.";
        f.Cvss = 8.1;
        f.FixAction = "Require a Redis password and restrict access";
        f.Remediation.AddRange(new[]
        {
            "Set 'requirepass' or Redis 6+ ACL users in redis.conf, and keep 'protected-mode yes'.",
            "Bind Redis to localhost or the application network only ('bind 127.0.0.1').",
            "Block TCP 6379 at the firewall for everything except the application servers."
        });
        f.References.Add("https://redis.io/docs/latest/operate/oss_and_stack/management/security/");
        return new[] { f };
    }
}

/// <summary>Only meaningful for public addresses: internal DNS servers are supposed to resolve names for clients.</summary>
public sealed class DnsOpenResolverCheck : CheckBase
{
    public override string Id => "dns.open-resolver";
    public override string Name => "Open DNS resolver on a public address";
    public override string Category => "Network services";
    public override ProbeLevel Level => ProbeLevel.SafeProbe;

    public override bool AppliesTo(CheckTarget t) =>
        t.Port is { Protocol: TransportProtocol.Udp, Port: 53 } &&
        System.Net.IPAddress.TryParse(t.Host.Address, out var ip) && !AddressClassifier.IsPrivate(ip);

    public override async Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var resp = await ctx.Probe.UdpExchangeAsync(ctx.Host.Address, 53, DnsPackets.Query("example.com", 1, recursionDesired: true), ctx.Timeout, ct).ConfigureAwait(false);
        var h = resp == null ? null : DnsPackets.ParseHeader(resp);
        if (h is not { IsResponse: true, RecursionAvailable: true, ResponseCode: 0 } || h.AnswerCount == 0) return Array.Empty<Finding>();
        var f = ctx.NewFinding(this, "DNS server resolves names for anyone on the internet", Severity.Medium, Confidence.Confirmed);
        f.Description = "Open resolvers are abused for DNS amplification DDoS attacks and cache poisoning.";
        f.Evidence = $"Recursive query for example.com answered with {h.AnswerCount} record(s) and the RA flag set.";
        f.FixAction = "Limit recursion to your own clients";
        f.Remediation.Add("Windows DNS: disable recursion on internet-facing servers (Server Properties › Advanced › Disable recursion).");
        f.Remediation.Add("BIND: allow-recursion { trusted-networks; }; Unbound: access-control.");
        return new[] { f };
    }
}
