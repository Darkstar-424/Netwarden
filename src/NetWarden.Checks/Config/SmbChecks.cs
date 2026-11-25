using NetWarden.Core.Checks;
using NetWarden.Core.Models;
using NetWarden.Core.Protocols;

namespace NetWarden.Checks.Config;

public sealed class Smb1EnabledCheck : CheckBase
{
    public override string Id => "smb.smbv1";
    public override string Name => "SMBv1 enabled";
    public override string Category => "Windows / SMB";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Service?.Fact("smb1") == "enabled";

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var f = ctx.NewFinding(this, "SMBv1 is enabled", Severity.High, Confidence.Confirmed);
        f.Description = "The server still accepts SMB version 1, a 30-year-old file-sharing protocol with serious design flaws. " +
                        "Worms and ransomware such as WannaCry and NotPetya spread through SMBv1. Modern Windows, macOS and Linux clients don't need it.";
        f.Evidence = "SMB1 NEGOTIATE offering only \"NT LM 0.12\" was accepted by the server.";
        f.FixAction = "Turn off SMBv1";
        f.Remediation.AddRange(new[]
        {
            "Windows Server/PC (admin PowerShell): Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
            "Remove the feature completely: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol (restart required).",
            "Across a domain: Group Policy › Computer Configuration › Administrative Templates › MS Security Guide › Configure SMBv1 server = Disabled.",
            "NAS / Samba devices: set the minimum SMB protocol to SMB2 (Samba: 'server min protocol = SMB2_10').",
            "Rescan this host to confirm the finding is resolved."
        });
        f.References.AddRange(new[]
        {
            "https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
            "https://www.cisa.gov/news-events/alerts/2017/03/16/smb-security-best-practices"
        });
        return One(f);
    }
}

public sealed class SmbSigningCheck : CheckBase
{
    public override string Id => "smb.signing";
    public override string Name => "SMB signing not required";
    public override string Category => "Windows / SMB";
    public override bool RequiresNetwork => false;

    public override bool AppliesTo(CheckTarget t) => t.Port?.Port == 445 && t.Service?.Fact("smb.signing") is "enabled" or "disabled";

    public override Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        var state = ctx.Service!.Fact("smb.signing");
        var f = ctx.NewFinding(this, "SMB signing is not required", state == "disabled" ? Severity.Medium : Severity.Medium, Confidence.Configuration);
        f.Description = "Without mandatory SMB signing, an attacker on the local network can relay or tamper with file-sharing traffic " +
                        "(NTLM relay attacks). Domain controllers require signing by default; other servers often don't.";
        f.Evidence = $"SMB2 NEGOTIATE response SecurityMode: signing {state}, not required (dialect {ctx.Service.Fact("smb.dialect") ?? "?"}).";
        f.FixAction = "Require SMB signing";
        f.Remediation.AddRange(new[]
        {
            "Group Policy › Computer Configuration › Windows Settings › Security Settings › Local Policies › Security Options:",
            "  \"Microsoft network server: Digitally sign communications (always)\" = Enabled.",
            "Or per server (admin PowerShell): Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
            "Samba: set 'server signing = mandatory' in smb.conf.",
            "Run gpupdate /force, then rescan."
        });
        f.References.Add("https://learn.microsoft.com/troubleshoot/windows-server/networking/overview-server-message-block-signing");
        f.Cvss = 5.3;
        return One(f);
    }
}

/// <summary>
/// MS17-010 (EternalBlue) detection using the same harmless status-code probe as Nmap's smb-vuln-ms17-010:
/// anonymous session → IPC$ → PeekNamedPipe on FID 0. A patched server answers "invalid handle"/"access denied";
/// an unpatched one answers STATUS_INSUFF_SERVER_RESOURCES. No exploit code or payload is ever sent.
/// </summary>
public sealed class Ms17010Check : CheckBase
{
    public override string Id => "smb.ms17-010";
    public override string Name => "MS17-010 (EternalBlue) missing patch";
    public override string Category => "Windows / SMB";
    public override ProbeLevel Level => ProbeLevel.SafeProbe;
    public override bool RequiresAnonymousLogin => true;

    public override bool AppliesTo(CheckTarget t) => t.Port?.Port == 445 && t.Service?.Fact("smb1") == "enabled";

    public override async Task<IReadOnlyList<Finding>> RunAsync(CheckContext ctx, CancellationToken ct)
    {
        await using var s = await ctx.Probe.ConnectAsync(ctx.Host.Address, 445, ctx.Timeout, ct).ConfigureAwait(false);
        if (s == null) return Array.Empty<Finding>();
        await s.SendAsync(SmbPackets.Smb1Negotiate(), ct).ConfigureAwait(false);
        var neg = SmbPackets.ParseSmb1NegotiateResponse(await SmbPackets.ReadMessageAsync(s, ctx.Timeout, ct).ConfigureAwait(false));
        if (!neg.Accepted) return Array.Empty<Finding>();

        await s.SendAsync(SmbPackets.Smb1AnonymousSessionSetup(), ct).ConfigureAwait(false);
        var (sessStatus, uid) = SmbPackets.ParseSmb1Status(await SmbPackets.ReadMessageAsync(s, ctx.Timeout, ct).ConfigureAwait(false));
        if (sessStatus != SmbPackets.StatusSuccess) return Array.Empty<Finding>(); // anonymous sessions refused: cannot test

        await s.SendAsync(SmbPackets.Smb1TreeConnectIpc(ctx.Host.Address, uid), ct).ConfigureAwait(false);
        var treeResp = await SmbPackets.ReadMessageAsync(s, ctx.Timeout, ct).ConfigureAwait(false);
        var (treeStatus, _) = SmbPackets.ParseSmb1Status(treeResp);
        if (treeStatus != SmbPackets.StatusSuccess) return Array.Empty<Finding>();
        var tid = SmbPackets.ParseSmb1Tid(treeResp);

        await s.SendAsync(SmbPackets.Smb1PeekNamedPipeFid0(tid, uid), ct).ConfigureAwait(false);
        var (peekStatus, _) = SmbPackets.ParseSmb1Status(await SmbPackets.ReadMessageAsync(s, ctx.Timeout, ct).ConfigureAwait(false));
        if (peekStatus != SmbPackets.StatusInsuffServerResources) return Array.Empty<Finding>();

        var f = ctx.NewFinding(this, "MS17-010 security update missing (EternalBlue)", Severity.Critical, Confidence.Confirmed, "CVE-2017-0144");
        f.Description = "The server is missing the March 2017 MS17-010 update. Remote attackers can run code on it without a password; " +
                        "this flaw was used by WannaCry, NotPetya and many later attacks.";
        f.Evidence = "Anonymous PeekNamedPipe on FID 0 over IPC$ returned STATUS_INSUFF_SERVER_RESOURCES (0xC0000205), the response of an unpatched server.";
        f.Cves.AddRange(new[] { "CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0146", "CVE-2017-0147", "CVE-2017-0148" });
        f.Cvss = 8.1;
        f.CvssVector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H";
        f.Kev = true;
        f.FixAction = "Install MS17-010 and turn off SMBv1";
        f.Remediation.AddRange(new[]
        {
            "Install the MS17-010 security update, or any later cumulative update, through Windows Update or WSUS.",
            "Unsupported systems (Windows XP / Server 2003): apply the emergency KB4012598 update and plan a replacement.",
            "Disable SMBv1 (see the SMBv1 finding) and block TCP 445 at network boundaries.",
            "Rescan to confirm."
        });
        f.References.AddRange(new[]
        {
            "https://learn.microsoft.com/security-updates/securitybulletins/2017/ms17-010",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-0144"
        });
        return List(f);
    }
}
