using System.Net;
using NetWarden.Core.Fingerprinting;
using NetWarden.Core.Models;
using NetWarden.Core.Protocols;
using NetWarden.Core.Util;

namespace NetWarden.Core.Scanning;

/// <summary>
/// Finds out what a device says about itself, using the same read-only discovery protocols that phones, printer
/// dialogs and media apps use: Bonjour/mDNS service lists and the UPnP device description.
/// </summary>
public sealed class DeviceIdentifier
{
    private readonly IProbeClient _probe;
    private readonly TimeSpan _timeout;
    private readonly INwLog _log;
    private const int MaxServiceTypes = 24;

    public DeviceIdentifier(IProbeClient probe, TimeSpan timeout, INwLog? log = null)
    {
        _probe = probe;
        _timeout = timeout;
        _log = log ?? NullLog.Instance;
    }

    public sealed record BonjourService(string ServiceType, string Instance, int Port, IReadOnlyDictionary<string, string> Txt);

    public sealed record BonjourResult(string? HostName, IReadOnlyList<BonjourService> Services);

    /// <summary>Asks the device which Bonjour services it offers, then asks for the details of each.</summary>
    public async Task<BonjourResult?> BonjourAsync(string host, CancellationToken ct)
    {
        try
        {
            var first = await _probe.UdpExchangeAsync(host, 5353,
                MdnsPackets.Query(new[] { (MdnsPackets.ServicesMetaQuery, MdnsPackets.TypePtr) }), _timeout, ct).ConfigureAwait(false);
            var meta = first == null ? null : MdnsPackets.Parse(first);
            if (meta == null) return null;
            var types = meta.Where(r => r.Type == MdnsPackets.TypePtr && r.Name.Equals(MdnsPackets.ServicesMetaQuery, StringComparison.OrdinalIgnoreCase) && r.Target != null)
                .Select(r => r.Target!.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ? r.Target![..^6] : r.Target!)
                .Where(t => t.StartsWith('_'))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(MaxServiceTypes)
                .ToList();
            var records = new List<MdnsPackets.Record>(meta);
            // Ask for the instances of each type in small batches so answers fit in one UDP packet.
            foreach (var batch in types.Chunk(6))
            {
                var resp = await _probe.UdpExchangeAsync(host, 5353,
                    MdnsPackets.Query(batch.Select(t => (t + ".local", MdnsPackets.TypePtr))), _timeout, ct).ConfigureAwait(false);
                if (resp != null && MdnsPackets.Parse(resp) is { } rs) records.AddRange(rs);
            }
            // Instances whose SRV/TXT didn't come along as additional records: ask for them directly.
            var instances = records.Where(r => r.Type == MdnsPackets.TypePtr && r.Target != null && !r.Name.Equals(MdnsPackets.ServicesMetaQuery, StringComparison.OrdinalIgnoreCase))
                .Select(r => r.Target!).Distinct(StringComparer.OrdinalIgnoreCase).Take(40).ToList();
            var missing = instances.Where(i => !records.Any(r => r.Type == MdnsPackets.TypeSrv && r.Name.Equals(i, StringComparison.OrdinalIgnoreCase))).ToList();
            foreach (var batch in missing.Chunk(4))
            {
                var resp = await _probe.UdpExchangeAsync(host, 5353,
                    MdnsPackets.Query(batch.SelectMany(i => new[] { (i, MdnsPackets.TypeSrv), (i, MdnsPackets.TypeTxt) })), _timeout, ct).ConfigureAwait(false);
                if (resp != null && MdnsPackets.Parse(resp) is { } rs) records.AddRange(rs);
            }
            return Build(records, types);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Debug($"Bonjour query to {host} failed: {ex.Message}");
            return null;
        }
    }

    /// <summary>Assembles services from parsed records. Public for tests.</summary>
    public static BonjourResult Build(IReadOnlyList<MdnsPackets.Record> records, IReadOnlyList<string> advertisedTypes)
    {
        var services = new List<BonjourService>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? hostName = null;
        foreach (var srv in records.Where(r => r.Type == MdnsPackets.TypeSrv))
        {
            if (!seen.Add(srv.Name) || MdnsPackets.SplitInstance(srv.Name) is not { } parts) continue;
            var txt = records.FirstOrDefault(r => r.Type == MdnsPackets.TypeTxt && r.Name.Equals(srv.Name, StringComparison.OrdinalIgnoreCase))?.Txt
                      ?? new Dictionary<string, string>();
            services.Add(new BonjourService(parts.ServiceType, Unescape(parts.Instance), srv.Port, txt));
            if (hostName == null && srv.Target is { Length: > 0 } t) hostName = t.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ? t[..^6] : t;
        }
        // PTR answers without SRV still tell us the service exists.
        foreach (var ptr in records.Where(r => r.Type == MdnsPackets.TypePtr && r.Target != null && !r.Name.Equals(MdnsPackets.ServicesMetaQuery, StringComparison.OrdinalIgnoreCase)))
        {
            if (seen.Contains(ptr.Target!) || MdnsPackets.SplitInstance(ptr.Target!) is not { } parts) continue;
            seen.Add(ptr.Target!);
            var txt = records.FirstOrDefault(r => r.Type == MdnsPackets.TypeTxt && r.Name.Equals(ptr.Target, StringComparison.OrdinalIgnoreCase))?.Txt
                      ?? new Dictionary<string, string>();
            services.Add(new BonjourService(parts.ServiceType, Unescape(parts.Instance), 0, txt));
        }
        // Device-info TXT is usually attached without being listed as a service type.
        foreach (var txt in records.Where(r => r.Type == MdnsPackets.TypeTxt && r.Txt != null && r.Name.Contains("._device-info._tcp", StringComparison.OrdinalIgnoreCase)))
            if (seen.Add(txt.Name) && MdnsPackets.SplitInstance(txt.Name) is { } p)
                services.Add(new BonjourService(p.ServiceType, Unescape(p.Instance), 0, txt.Txt!));
        // Types that were advertised but returned no instance.
        foreach (var t in advertisedTypes.Where(t => !services.Any(s => s.ServiceType.Equals(t, StringComparison.OrdinalIgnoreCase))))
            services.Add(new BonjourService(t, "", 0, new Dictionary<string, string>()));
        return new BonjourResult(hostName, services);
    }

    private static string Unescape(string s) => s.Replace("\\032", " ").Replace("\\.", ".");

    /// <summary>Reads the UPnP device description, but only from the device being scanned.</summary>
    public async Task<UpnpDescription.Info?> UpnpAsync(string host, string location, CancellationToken ct)
    {
        try
        {
            if (!Uri.TryCreate(location, UriKind.Absolute, out var u) || (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps)) return null;
            // Never follow a LOCATION that points somewhere else: we only talk to devices in scope.
            if (!IPAddress.TryParse(u.Host.Trim('[', ']'), out var ip) || ip.ToString() != host) return null;
            var resp = await _probe.HttpRequestAsync(host, u.Port, u.Scheme == Uri.UriSchemeHttps, "GET", u.PathAndQuery, _timeout + _timeout, ct, 262144).ConfigureAwait(false);
            return resp is { StatusCode: 200 } ? UpnpDescription.Parse(resp.Body) : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Debug($"UPnP description from {host} failed: {ex.Message}");
            return null;
        }
    }
}

/// <summary>Builds the host's plain-English list of apps and services and infers the device type.</summary>
public static class AppInventory
{
    public static void Build(HostResult host, DeviceIdentifier.BonjourResult? bonjour, UpnpDescription.Info? upnp)
    {
        var apps = new List<AppInfo>();
        var deviceHints = new List<string>();

        void Add(string name, string category, string? version, string where, string source, string? detail = null)
        {
            var existing = apps.FirstOrDefault(a => a.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (existing != null)
            {
                if (!existing.Where.Split(", ").Contains(where)) existing.Where = existing.Where.Length == 0 ? where : existing.Where + ", " + where;
                existing.Version ??= version;
                existing.Detail ??= detail;
                return;
            }
            apps.Add(new AppInfo { Name = name, Category = category, Version = version, Where = where, Source = source, Detail = detail });
        }

        foreach (var p in host.OpenPorts.OrderBy(p => p.Protocol).ThenBy(p => p.Port))
        {
            var s = p.Service;
            if (s == null) continue;
            if (s.Fact("app.name") is string app)
            {
                Add(app, s.Fact("app.category") ?? "Web app", s.Fact("app.version"), p.Label, s.Fact("app.source") ?? "web page",
                    s.Fact("http.title") is string t ? $"Page title: {t}" : null);
                if (s.Fact("app.device") is string d) deviceHints.Add(d);
                continue;
            }
            var described = ServiceCatalog.Describe(s.Name);
            var product = string.IsNullOrEmpty(s.Product) || s.Product == "SMB" ? null : s.Product;
            if (described is { } dsc)
            {
                var name = product != null && !dsc.Name.Contains(product, StringComparison.OrdinalIgnoreCase) ? $"{dsc.Name}: {product}" : dsc.Name;
                Add(name, dsc.Category, product != null ? s.Version : null, p.Label, "service fingerprint",
                    s.Fact("http.title") is string t ? $"Page title: {t}" : null);
                if (dsc.Category == "Printing") deviceHints.Add("Printer");
            }
            else if (product != null)
            {
                Add(product, "Other", s.Version, p.Label, "service banner");
            }
        }

        if (bonjour != null)
        {
            foreach (var svc in bonjour.Services)
            {
                var d = MdnsServiceCatalog.Describe(svc.ServiceType);
                var model = MdnsServiceCatalog.ModelFromTxt(svc.ServiceType, svc.Txt);
                if (svc.ServiceType.Equals("_device-info._tcp", StringComparison.OrdinalIgnoreCase))
                {
                    if (model != null) host.DeviceModel ??= model;
                    continue;
                }
                if (model != null && host.DeviceModel == null && svc.ServiceType is "_googlecast._tcp" or "_ipp._tcp" or "_ipps._tcp" or "_printer._tcp" or "_airplay._tcp" or "_hap._tcp")
                    host.DeviceModel = model;
                if (svc.ServiceType.Equals("_googlecast._tcp", StringComparison.OrdinalIgnoreCase) && svc.Txt.TryGetValue("fn", out var fn) && fn.Length > 0)
                    host.FriendlyName ??= fn;
                else if (svc.Instance.Length > 0 && svc.ServiceType is "_airplay._tcp" or "_googlecast._tcp" or "_ipp._tcp" or "_smb._tcp" or "_companion-link._tcp" or "_workstation._tcp")
                    host.FriendlyName ??= svc.Instance;
                var where = svc.Port > 0 ? $"Bonjour, port {svc.Port}" : "Bonjour";
                var detail = svc.Instance.Length > 0 ? $"Advertised as \"{svc.Instance}\"" : null;
                Add(d.Name, d.Category, null, where, "Bonjour advertisement", detail);
                if (d.Device != null) deviceHints.Add(d.Device);
            }
            if (bonjour.HostName != null && host.HostName == null) host.HostName = bonjour.HostName + ".local";
        }

        if (upnp != null)
        {
            var model = string.Join(' ', new[] { upnp.Manufacturer, upnp.ModelName, upnp.ModelNumber }
                .Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.OrdinalIgnoreCase));
            if (model.Length > 0) host.DeviceModel ??= model;
            host.FriendlyName ??= upnp.FriendlyName;
            if (host.Vendor == null && upnp.Manufacturer != null) host.Vendor = upnp.Manufacturer;
            foreach (var d in UpnpDescription.Describe(upnp))
            {
                if (d.Name == "UPnP device" && apps.Any(a => a.Source == "UPnP description")) continue;
                Add(d.Name, d.Category, null, "UPnP", "UPnP description", upnp.ModelDescription);
                if (d.Device != null) deviceHints.Add(d.Device);
            }
        }

        host.Apps = apps.OrderBy(a => CategoryOrder(a.Category)).ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase).ToList();
        host.DeviceType ??= InferType(host, deviceHints);
    }

    private static string? InferType(HostResult host, List<string> hints)
    {
        // Specific hints from what the device itself says win; then fall back to the port/OS picture.
        var priority = new[] { "Printer", "NAS", "Camera", "Firewall", "Router", "Hypervisor", "Media server", "TV", "Speaker", "Media player",
            "Games console", "Smart home hub", "Smart home device", "3D printer", "Access point", "Network controller", "Network device", "Server", "Apple device", "Computer" };
        foreach (var p in priority)
            if (hints.Contains(p)) return p;
        var ports = host.OpenPorts.Where(p => p.Protocol == TransportProtocol.Tcp).Select(p => p.Port).ToHashSet();
        if (ports.Contains(88) && ports.Contains(389)) return "Domain controller";
        if (ports.Contains(9100) || ports.Contains(631) || ports.Contains(515)) return "Printer";
        if (ports.Contains(445) && ports.Contains(135)) return "Windows computer";
        if (ports.Contains(62078)) return "iPhone / iPad";
        return null;
    }

    private static int CategoryOrder(string c) => c switch
    {
        "Remote access" => 0,
        "File sharing" => 1,
        "Database" => 2,
        _ when c.StartsWith("Web", StringComparison.Ordinal) => 9,
        "Network service" => 10,
        "Other" => 20,
        _ => 5
    };
}
