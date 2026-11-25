namespace NetWarden.UI.Services;

/// <summary>Plain-English explanations shown as tooltips next to technical terms. Bind with Path=[key].</summary>
public sealed class Glossary
{
    public static Glossary Instance { get; } = new();

    private readonly Dictionary<string, string> _terms = new(StringComparer.OrdinalIgnoreCase)
    {
        ["port"] = "A numbered door on a device. Each service (website, file share, remote desktop…) listens on its own port number.",
        ["service"] = "A program on a device that accepts connections over the network, like a website, a shared folder or remote desktop.",
        ["open port"] = "A port where a service answered. Every open port is something that can be reached over the network.",
        ["cve"] = "Common Vulnerabilities and Exposures: the public ID (e.g. CVE-2017-0144) given to a known software flaw.",
        ["cvss"] = "Common Vulnerability Scoring System: a 0–10 score for how severe a flaw is. 9+ is critical, 7–8.9 high, 4–6.9 medium.",
        ["kev"] = "CISA's Known Exploited Vulnerabilities list: flaws attackers are using right now. Fix these first.",
        ["cpe"] = "Common Platform Enumeration: a standard name for a product and version, used to match it against known flaws.",
        ["tls"] = "Transport Layer Security: the encryption behind https:// and many other secure connections. TLS 1.2 and 1.3 are current.",
        ["ssl"] = "The older, broken predecessor of TLS. SSLv2 and SSLv3 should never be enabled.",
        ["cipher"] = "The encryption method a TLS connection uses. Old ciphers such as RC4 or 3DES are weak.",
        ["certificate"] = "A digital ID card that proves a server's identity to browsers and apps. It has an expiry date.",
        ["smb"] = "Server Message Block: Windows file and printer sharing. SMBv1 is obsolete and dangerous; SMB 2/3 are current.",
        ["smb signing"] = "A digital signature on every file-sharing message so it can't be tampered with or relayed.",
        ["rdp"] = "Remote Desktop Protocol: lets someone use a Windows PC over the network.",
        ["nla"] = "Network Level Authentication: Remote Desktop checks your password before showing the login screen. It should always be required.",
        ["ssh"] = "Secure Shell: encrypted remote command-line access, mostly to Linux servers and network devices.",
        ["telnet"] = "An old remote-login protocol that sends everything, including passwords, without encryption.",
        ["ftp"] = "File Transfer Protocol: an old way of sending files that doesn't encrypt passwords.",
        ["snmp"] = "Simple Network Management Protocol: used by monitoring tools to read device information.",
        ["upnp"] = "Universal Plug and Play: lets devices open router ports automatically. Convenient, but risky.",
        ["ipmi"] = "A server's built-in management controller (iLO, iDRAC). It can control the server even when it is switched off.",
        ["ttl"] = "Time To Live: a number in network replies. Its starting value hints at the operating system (64 Linux, 128 Windows).",
        ["mac"] = "A network adapter's hardware address. The first half identifies the manufacturer.",
        ["netbios"] = "An old Windows naming system. It reveals computer names on the local network.",
        ["cidr"] = "A compact way to write a range of addresses: 192.168.1.0/24 means 192.168.1.1 to 192.168.1.254.",
        ["confidence"] = "Confirmed = proven by a safe test. Configuration = a setting read directly. Potential = matched by version only; the vendor may have patched it already.",
        ["potential"] = "Matched only by software version. Some vendors fix flaws without changing the version number, so double-check before acting.",
        ["accepted risk"] = "You've decided to live with this issue (for now). It stays visible in reports but no longer counts as open.",
        ["false positive"] = "NetWarden flagged something that isn't actually a problem. It is hidden from open findings.",
        ["polite"] = "Default speed: limits how many connections are made at once so fragile devices aren't overwhelmed.",
        ["safe probe"] = "An extra read-only request that confirms a weakness without exploiting it or changing anything.",
        ["exclusions"] = "Devices NetWarden must never touch, such as old printers or factory equipment that may not cope with being checked.",
        ["public address"] = "An internet address outside your private network. Only check public addresses you own or have written permission to test.",
        ["audit log"] = "A permanent record of who started each scan, when, and against what. Entries can't be edited or deleted.",
        ["forward secrecy"] = "With forward secrecy, stealing a server's key later doesn't let anyone decrypt traffic recorded earlier.",
        ["hsts"] = "HTTP Strict Transport Security: tells browsers to always use https for a site.",
        ["os guess"] = "NetWarden's best guess at the operating system, from reply details, open ports and software banners. Not always right.",
    };

    public string this[string key] => _terms.TryGetValue(key, out var v) ? v : key;

    public IReadOnlyDictionary<string, string> All => _terms;
}
