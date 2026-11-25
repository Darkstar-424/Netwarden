namespace NetWarden.Core.Models;

/// <summary>How serious a finding is. Ordered so comparisons work (Critical &gt; High ...).</summary>
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/// <summary>How sure NetWarden is that a finding is real.</summary>
public enum Confidence
{
    /// <summary>Software version matches a known CVE; vendor back-ports may mean it is already fixed.</summary>
    Potential = 0,
    /// <summary>A setting observed directly from the service.</summary>
    Configuration = 1,
    /// <summary>A safe, read-only probe confirmed the weakness.</summary>
    Confirmed = 2
}

public enum FindingStatus
{
    Open = 0,
    AcceptedRisk = 1,
    FalsePositive = 2,
    Fixed = 3
}

public enum TransportProtocol
{
    Tcp = 0,
    Udp = 1
}

public enum PortState
{
    Open = 0,
    Closed = 1,
    Filtered = 2,
    OpenFiltered = 3
}

public enum ScanState
{
    Pending = 0,
    Running = 1,
    Paused = 2,
    Completed = 3,
    Cancelled = 4,
    Failed = 5,
    Imported = 6
}

/// <summary>The furthest a check is allowed to go. Nothing beyond SafeProbe exists by design.</summary>
public enum ProbeLevel
{
    /// <summary>Only uses facts already collected (versions, banners, negotiated settings).</summary>
    VersionOnly = 0,
    /// <summary>May send extra harmless, read-only requests to confirm a weakness.</summary>
    SafeProbe = 1
}

public enum TimingTemplate
{
    Gentle = 0,
    Polite = 1,
    Normal = 2,
    Fast = 3
}

public enum ScanPhase
{
    Preparing,
    Discovery,
    PortScan,
    UdpProbes,
    ServiceDetection,
    VulnerabilityChecks,
    Finished
}
