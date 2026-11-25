using NetWarden.Core.Models;

namespace NetWarden.Core.Fingerprinting;

/// <summary>Best-effort OS guess from TTL, open ports and banners. Always shown with its basis and confidence.</summary>
public static class OsFingerprinter
{
    public static OsGuess Guess(HostResult host)
    {
        var votes = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var basis = new List<string>();
        string? detail = null;

        void Vote(string family, int weight, string why)
        {
            votes[family] = votes.GetValueOrDefault(family) + weight;
            basis.Add(why);
        }

        if (host.Ttl is int ttl)
        {
            if (ttl <= 64) Vote("Linux/Unix", 20, $"TTL {ttl} (≤64)");
            else if (ttl <= 128) Vote("Windows", 25, $"TTL {ttl} (≤128)");
            else Vote("Network device", 20, $"TTL {ttl} (>128)");
        }

        var open = host.OpenPorts.ToDictionary(p => p.Port);
        bool Has(int p) => open.ContainsKey(p);

        if (Has(135) && Has(445)) Vote("Windows", 30, "MSRPC + SMB ports");
        if (Has(3389)) Vote("Windows", 20, "Remote Desktop");
        if (Has(5985) || Has(5986)) Vote("Windows", 15, "WinRM");
        if (Has(88) && Has(389) && Has(445)) { Vote("Windows", 20, "Kerberos + LDAP + SMB"); detail ??= "likely a domain controller"; }
        if (Has(9100) || (Has(515) && Has(631))) Vote("Printer", 40, "printing ports (9100/515/631)");
        if (Has(62078)) Vote("Apple iOS", 50, "iPhone sync port 62078");
        if (Has(548)) Vote("macOS", 15, "AFP file sharing");

        foreach (var p in host.OpenPorts)
        {
            var s = p.Service;
            if (s == null) continue;
            var banner = (s.Banner ?? "") + " " + (s.Fact("ssh.comment") ?? "") + " " + (s.Fact("http.server") ?? "");
            if (banner.Contains("Ubuntu", StringComparison.OrdinalIgnoreCase)) { Vote("Linux/Unix", 40, "Ubuntu in banner"); detail ??= "Ubuntu"; }
            else if (banner.Contains("Debian", StringComparison.OrdinalIgnoreCase)) { Vote("Linux/Unix", 40, "Debian in banner"); detail ??= "Debian"; }
            else if (banner.Contains("Raspbian", StringComparison.OrdinalIgnoreCase)) { Vote("Linux/Unix", 40, "Raspbian in banner"); detail ??= "Raspberry Pi OS"; }
            else if (banner.Contains("FreeBSD", StringComparison.OrdinalIgnoreCase)) { Vote("BSD", 40, "FreeBSD in banner"); detail ??= "FreeBSD"; }
            else if (banner.Contains("CentOS", StringComparison.OrdinalIgnoreCase) || banner.Contains("Red Hat", StringComparison.OrdinalIgnoreCase)) { Vote("Linux/Unix", 40, "RHEL family in banner"); detail ??= "RHEL/CentOS"; }
            if (s.Product == "Microsoft IIS")
            {
                Vote("Windows", 40, "IIS web server");
                detail ??= s.Version switch
                {
                    "10.0" => "Windows 10/11 or Server 2016+",
                    "8.5" => "Windows 8.1 / Server 2012 R2",
                    "8.0" => "Windows 8 / Server 2012",
                    "7.5" => "Windows 7 / Server 2008 R2",
                    _ => null
                };
            }
            if (s.Product?.StartsWith("SQL Server", StringComparison.Ordinal) == true) Vote("Windows", 20, "Microsoft SQL Server");
            if (s.Product == "Microsoft-HTTPAPI") Vote("Windows", 15, "HTTP.sys");
            if (s.Name == "smb" && s.Fact("smb.dialect") is string d && host.OpenPorts.All(x => x.Port != 135)) Vote("Linux/Unix", 10, $"SMB {d} without MSRPC (Samba/NAS)");
            if (s.Product is "Dropbear") { Vote("Embedded Linux", 35, "Dropbear SSH"); }
            if (s.Product is "GoAhead embedded web server" or "Boa" or "mini_httpd") Vote("Embedded Linux", 30, $"{s.Product} web server");
        }

        if (host.Vendor is string vendor)
        {
            if (vendor.Contains("VMware", StringComparison.OrdinalIgnoreCase) || vendor.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase) || vendor.Contains("VirtualBox", StringComparison.OrdinalIgnoreCase))
                detail ??= "virtual machine";
            if (vendor.Contains("Apple", StringComparison.OrdinalIgnoreCase)) Vote("macOS", 15, "Apple network adapter");
            if (vendor.Contains("Raspberry", StringComparison.OrdinalIgnoreCase)) { Vote("Linux/Unix", 30, "Raspberry Pi adapter"); detail ??= "Raspberry Pi"; }
            if (vendor.Contains("Brother", StringComparison.OrdinalIgnoreCase) || vendor.Contains("Canon", StringComparison.OrdinalIgnoreCase) || vendor.Contains("Xerox", StringComparison.OrdinalIgnoreCase))
                Vote("Printer", 30, "printer manufacturer");
        }

        if (votes.Count == 0) return new OsGuess { Family = "Unknown", Confidence = 0, Basis = "no fingerprint data" };
        var best = votes.OrderByDescending(v => v.Value).First();
        var total = votes.Values.Sum();
        var confidence = Math.Min(95, (int)(100.0 * best.Value / Math.Max(total, 60)));
        return new OsGuess { Family = best.Key, Detail = detail, Confidence = confidence, Basis = string.Join("; ", basis.Distinct()) };
    }
}
