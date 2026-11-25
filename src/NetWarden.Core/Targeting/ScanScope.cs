using System.Net;

namespace NetWarden.Core.Targeting;

/// <summary>
/// A named set of assets the user is authorized to assess. The engine refuses to scan anything
/// outside it, and refuses to start until the authorization statement has been confirmed.
/// </summary>
public sealed class ScanScope
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "My network";
    /// <summary>Targets, one per line or comma separated.</summary>
    public string Targets { get; set; } = "";
    /// <summary>Addresses or ranges never to touch (fragile printers, OT devices...).</summary>
    public string Exclusions { get; set; } = "";
    public bool Authorized { get; set; }
    public string? AuthorizedBy { get; set; }
    public DateTimeOffset? AuthorizedAt { get; set; }
    /// <summary>The user saw and accepted the public-address warning.</summary>
    public bool PublicAddressesAcknowledged { get; set; }
    public string Notes { get; set; } = "";

    public IReadOnlyList<TargetSpec> ParsedTargets() => TargetParser.ParseList(Targets);
    public IReadOnlyList<TargetSpec> ParsedExclusions() => TargetParser.ParseList(Exclusions);

    public bool HasPublicTargets() => ParsedTargets().Any(AddressClassifier.ContainsPublic);

    /// <summary>Is this address inside the scope and not excluded?</summary>
    public bool Allows(IPAddress ip)
    {
        if (ParsedExclusions().Any(e => e.Contains(ip))) return false;
        return ParsedTargets().Any(t => t.Contains(ip));
    }

    public bool IsExcluded(IPAddress ip) => ParsedExclusions().Any(e => e.Contains(ip));

    /// <summary>Throws if the scope cannot be scanned. Returns warnings to show the user otherwise.</summary>
    public IReadOnlyList<string> Validate()
    {
        var warnings = new List<string>();
        if (string.IsNullOrWhiteSpace(Targets))
            throw new ScopeException("The scope has no targets.");
        var targets = TargetParser.ParseList(Targets);
        TargetParser.ParseList(Exclusions); // validates syntax
        if (!Authorized)
            throw new ScopeException("Confirm that you are authorized to scan these assets before scanning.");
        if (targets.Any(AddressClassifier.ContainsPublic))
        {
            if (!PublicAddressesAcknowledged)
                throw new ScopeException("This scope contains public internet addresses. Confirm the public-address warning first.");
            warnings.Add("Scope contains public internet addresses.");
        }
        var count = TargetParser.CountAddresses(targets);
        if (count > TargetParser.MaxAddresses)
            throw new ScopeException($"The scope covers {count:N0} addresses; the limit is {TargetParser.MaxAddresses:N0}.");
        return warnings;
    }
}

public sealed class ScopeException : Exception
{
    public ScopeException(string message) : base(message) { }
}
