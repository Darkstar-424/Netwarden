using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using NetWarden.Core.Fingerprinting;
using NetWarden.Core.Models;

namespace NetWarden.Data.Import;

/// <summary>Imports Nmap XML output (-oX) so existing scans can be analysed for vulnerabilities offline.</summary>
public static class NmapXmlImporter
{
    public static ScanResult Import(Stream xml, string importedBy, string sourceName)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, MaxCharactersFromEntities = 0 };
        using var reader = XmlReader.Create(xml, settings);
        var doc = XDocument.Load(reader);
        var run = doc.Root ?? throw new InvalidDataException("Empty XML file.");
        if (run.Name.LocalName != "nmaprun") throw new InvalidDataException("This is not an Nmap XML file (root element must be <nmaprun>).");

        var result = new ScanResult
        {
            ProfileName = "Imported from Nmap",
            ScopeName = sourceName,
            StartedBy = importedBy,
            State = ScanState.Imported,
            Started = FromUnix(run.Attribute("start")?.Value) ?? DateTimeOffset.Now,
            Finished = FromUnix(run.Element("runstats")?.Element("finished")?.Attribute("time")?.Value) ?? DateTimeOffset.Now
        };
        var args = run.Attribute("args")?.Value;
        if (!string.IsNullOrEmpty(args)) result.Warnings.Add($"Nmap command: {args}");

        foreach (var h in run.Elements("host"))
        {
            var host = new HostResult
            {
                IsUp = h.Element("status")?.Attribute("state")?.Value == "up",
                DiscoveryMethod = "Nmap: " + (h.Element("status")?.Attribute("reason")?.Value ?? "imported")
            };
            foreach (var a in h.Elements("address"))
            {
                var type = a.Attribute("addrtype")?.Value;
                if (type is "ipv4" or "ipv6") host.Address = a.Attribute("addr")?.Value ?? "";
                else if (type == "mac")
                {
                    host.MacAddress = a.Attribute("addr")?.Value;
                    host.Vendor = a.Attribute("vendor")?.Value;
                }
            }
            if (string.IsNullOrEmpty(host.Address)) continue;
            host.HostName = h.Element("hostnames")?.Elements("hostname").FirstOrDefault()?.Attribute("name")?.Value;
            if (int.TryParse(h.Element("distance")?.Attribute("value")?.Value, out _)) { }

            foreach (var p in h.Element("ports")?.Elements("port") ?? Enumerable.Empty<XElement>())
            {
                var state = p.Element("state")?.Attribute("state")?.Value;
                if (state != "open") continue;
                var port = new PortResult
                {
                    Port = int.Parse(p.Attribute("portid")!.Value, CultureInfo.InvariantCulture),
                    Protocol = p.Attribute("protocol")?.Value == "udp" ? TransportProtocol.Udp : TransportProtocol.Tcp,
                    State = PortState.Open
                };
                var svc = p.Element("service");
                var info = new ServiceInfo { Name = svc?.Attribute("name")?.Value ?? WellKnownPorts.NameFor(port.Port) };
                if (svc != null)
                {
                    info.Product = svc.Attribute("product")?.Value;
                    info.Version = svc.Attribute("version")?.Value;
                    var extra = svc.Attribute("extrainfo")?.Value;
                    info.Banner = string.Join(" ", new[] { info.Product, info.Version, extra }.Where(s => !string.IsNullOrEmpty(s)));
                    info.Tls = svc.Attribute("tunnel")?.Value == "ssl";
                    if (info.Tls) info.Facts["http.scheme"] = info.Name.Contains("http") ? "https" : "";
                    foreach (var cpe in svc.Elements("cpe"))
                    {
                        var c23 = CpeMapper.FromCpe22(cpe.Value.Trim());
                        if (c23 != null && CpeMapper.Parse(c23) is { Version: not "*" } && !info.Cpes.Contains(c23)) info.Cpes.Add(c23);
                    }
                    if (info.Name == "ssh" && info.Product == "OpenSSH" && info.Version != null)
                        info.Version = info.Version.Split(' ')[0];
                }
                foreach (var script in p.Elements("script"))
                {
                    var id = script.Attribute("id")?.Value ?? "";
                    var output = script.Attribute("output")?.Value ?? "";
                    info.Facts["nmap." + id] = output.Length > 2000 ? output[..2000] : output;
                    if (id == "smb-protocols" && output.Contains("NT LM 0.12", StringComparison.Ordinal)) info.Facts["smb1"] = "enabled";
                    if (id == "ssl-enum-ciphers") port.Tls = ParseSslEnumCiphers(output);
                }
                port.Service = info;
                host.Ports.Add(port);
            }
            foreach (var hs in h.Element("hostscript")?.Elements("script") ?? Enumerable.Empty<XElement>())
            {
                var id = hs.Attribute("id")?.Value ?? "";
                var output = hs.Attribute("output")?.Value ?? "";
                if (id == "smb2-security-mode")
                {
                    var smb = host.Ports.FirstOrDefault(x => x.Port == 445)?.Service;
                    if (smb != null)
                        smb.Facts["smb.signing"] = output.Contains("required", StringComparison.OrdinalIgnoreCase) && !output.Contains("not required", StringComparison.OrdinalIgnoreCase) ? "required" : "enabled";
                }
                if (id == "nbstat")
                {
                    var idx = output.IndexOf("NetBIOS name:", StringComparison.Ordinal);
                    if (idx >= 0) host.NetBiosName = output[(idx + 13)..].Split(',')[0].Trim();
                }
            }
            var osMatch = h.Element("os")?.Elements("osmatch").OrderByDescending(o => int.TryParse(o.Attribute("accuracy")?.Value, out var a) ? a : 0).FirstOrDefault();
            if (osMatch != null)
            {
                host.Os = new OsGuess
                {
                    Family = osMatch.Element("osclass")?.Attribute("osfamily")?.Value ?? "Unknown",
                    Detail = osMatch.Attribute("name")?.Value,
                    Confidence = int.TryParse(osMatch.Attribute("accuracy")?.Value, out var acc) ? acc : 0,
                    Basis = "Nmap OS detection"
                };
            }
            result.Hosts.Add(host);
        }
        return result;
    }

    private static TlsInfo? ParseSslEnumCiphers(string output)
    {
        var tls = new TlsInfo();
        string? current = null;
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith("SSLv", StringComparison.Ordinal) || line.StartsWith("TLSv", StringComparison.Ordinal))
            {
                current = line.TrimEnd(':').Replace("TLSv", "TLS ").Replace("SSLv3", "SSLv3");
                if (current == "TLS 1.0" || current == "TLS 1.1" || current == "TLS 1.2" || current == "TLS 1.3" || current == "SSLv3" || current == "SSLv2")
                    tls.Protocols.Add(current);
            }
            else if (current != null && line.StartsWith("TLS_", StringComparison.Ordinal))
            {
                var name = line.Split(' ')[0];
                var suite = new Core.Tls.CipherSuite(0, name);
                tls.Ciphers.Add(new CipherInfo { Name = name, Protocol = current, Weak = suite.Weak, ForwardSecret = suite.ForwardSecret });
            }
        }
        return tls.Protocols.Count > 0 ? tls : null;
    }

    private static DateTimeOffset? FromUnix(string? v)
        => long.TryParse(v, out var s) ? DateTimeOffset.FromUnixTimeSeconds(s).ToLocalTime() : null;
}
