using System.Data.Common;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetWarden.Core.Models;
using NetWarden.Core.Targeting;
using NetWarden.Data.Storage;

namespace NetWarden.Data.History;

public sealed record ScanSummary(
    Guid Id, DateTimeOffset Started, DateTimeOffset? Finished, string Profile, string Scope, string StartedBy, ScanState State,
    int HostsUp, int OpenPorts, int Critical, int High, int Medium, int Low, int Info)
{
    public int TotalFindings => Critical + High + Medium + Low + Info;
    public string Label => $"{Started.ToLocalTime():yyyy-MM-dd HH:mm} · {Profile} · {Scope}";
}

public sealed record AuditEntry(long Id, DateTimeOffset Timestamp, string User, string Machine, string Action, string Scope, string Targets, string Profile, string Details);

public sealed record FindingStatusRecord(string Key, FindingStatus Status, string? Note, DateTimeOffset Updated, string UpdatedBy);

public static class JsonOptions
{
    public static readonly JsonSerializerOptions Default = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static readonly JsonSerializerOptions Indented = new(Default) { WriteIndented = true };
}

/// <summary>Scan history, finding status, saved scopes and the append-only audit log (history.db).</summary>
public sealed class HistoryStore
{
    private readonly IDbConnectionFactory _factory;
    private readonly string _path;

    public const int SchemaVersion = 1;

    public static readonly string[] Schema =
    {
        @"CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)",
        @"CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY, started TEXT NOT NULL, finished TEXT, profile TEXT, scope TEXT, started_by TEXT, state TEXT,
            hosts_up INTEGER, open_ports INTEGER, critical INTEGER, high INTEGER, medium INTEGER, low INTEGER, info INTEGER,
            json TEXT NOT NULL)",
        @"CREATE INDEX IF NOT EXISTS ix_scans_started ON scans(started)",
        @"CREATE TABLE IF NOT EXISTS finding_status (
            finding_key TEXT PRIMARY KEY, status TEXT NOT NULL, note TEXT, updated TEXT NOT NULL, updated_by TEXT)",
        @"CREATE TABLE IF NOT EXISTS scopes (id TEXT PRIMARY KEY, name TEXT NOT NULL, json TEXT NOT NULL)",
        @"CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, user TEXT, machine TEXT, action TEXT NOT NULL,
            scope TEXT, targets TEXT, profile TEXT, details TEXT)",
        @"CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END",
        @"CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END"
    };

    public HistoryStore(IDbConnectionFactory factory, string path)
    {
        _factory = factory;
        _path = path;
        using var c = Open();
        foreach (var sql in Schema) Db.Execute(c, sql);
        Db.Execute(c, "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema', @v)", new { v = SchemaVersion.ToString() });
    }

    private DbConnection Open() => _factory.Open(_path);

    // ---------------- Scans ----------------

    public void SaveScan(ScanResult scan)
    {
        using var c = Open();
        var open = scan.AllFindings.Where(f => f.Status == FindingStatus.Open).ToList();
        Db.Execute(c, @"INSERT OR REPLACE INTO scans(id, started, finished, profile, scope, started_by, state, hosts_up, open_ports, critical, high, medium, low, info, json)
                        VALUES (@id, @started, @finished, @profile, @scope, @by, @state, @hosts, @ports, @crit, @high, @med, @low, @info, @json)",
            new
            {
                id = scan.Id.ToString(),
                started = Db.Iso(scan.Started),
                finished = scan.Finished is { } f ? Db.Iso(f) : null,
                profile = scan.ProfileName,
                scope = scan.ScopeName,
                by = scan.StartedBy,
                state = scan.State.ToString(),
                hosts = scan.LiveHosts.Count(),
                ports = scan.OpenPortCount,
                crit = open.Count(x => x.Severity == Severity.Critical),
                high = open.Count(x => x.Severity == Severity.High),
                med = open.Count(x => x.Severity == Severity.Medium),
                low = open.Count(x => x.Severity == Severity.Low),
                info = open.Count(x => x.Severity == Severity.Info),
                json = JsonSerializer.Serialize(scan, JsonOptions.Default)
            });
    }

    public IReadOnlyList<ScanSummary> ListScans(int limit = 500)
    {
        using var c = Open();
        return Db.Query(c, "SELECT * FROM scans ORDER BY started DESC LIMIT @limit", r => new ScanSummary(
            Guid.Parse(r.Str("id")!), r.Date("started") ?? DateTimeOffset.MinValue, r.Date("finished"), r.Str("profile") ?? "",
            r.Str("scope") ?? "", r.Str("started_by") ?? "", Enum.TryParse<ScanState>(r.Str("state"), out var st) ? st : ScanState.Completed,
            (int)r.Long("hosts_up"), (int)r.Long("open_ports"), (int)r.Long("critical"), (int)r.Long("high"), (int)r.Long("medium"),
            (int)r.Long("low"), (int)r.Long("info")), new { limit });
    }

    public ScanResult? LoadScan(Guid id)
    {
        using var c = Open();
        var json = Db.Scalar<string>(c, "SELECT json FROM scans WHERE id = @id", new { id = id.ToString() });
        if (json == null) return null;
        var scan = JsonSerializer.Deserialize<ScanResult>(json, JsonOptions.Default);
        if (scan != null) ApplyStatuses(scan);
        return scan;
    }

    public void DeleteScan(Guid id)
    {
        using var c = Open();
        Db.Execute(c, "DELETE FROM scans WHERE id = @id", new { id = id.ToString() });
    }

    // ---------------- Finding status ----------------

    public void SetStatus(string findingKey, FindingStatus status, string? note, string user)
    {
        using var c = Open();
        if (status == FindingStatus.Open && string.IsNullOrEmpty(note))
        {
            Db.Execute(c, "DELETE FROM finding_status WHERE finding_key = @k", new { k = findingKey });
            return;
        }
        Db.Execute(c, "INSERT OR REPLACE INTO finding_status(finding_key, status, note, updated, updated_by) VALUES (@k, @s, @n, @u, @by)",
            new { k = findingKey, s = status.ToString(), n = note, u = Db.Iso(DateTimeOffset.Now), by = user });
    }

    public IReadOnlyDictionary<string, FindingStatusRecord> GetStatuses()
    {
        using var c = Open();
        return Db.Query(c, "SELECT * FROM finding_status", r => new FindingStatusRecord(
                r.Str("finding_key")!, Enum.TryParse<FindingStatus>(r.Str("status"), out var s) ? s : FindingStatus.Open,
                r.Str("note"), r.Date("updated") ?? DateTimeOffset.MinValue, r.Str("updated_by") ?? ""))
            .ToDictionary(x => x.Key);
    }

    /// <summary>Carries accepted-risk / false-positive / fixed decisions forward onto a scan's findings.</summary>
    public void ApplyStatuses(ScanResult scan)
    {
        var statuses = GetStatuses();
        foreach (var f in scan.AllFindings)
        {
            if (statuses.TryGetValue(f.Key, out var s))
            {
                // A "fixed" finding that shows up again is re-opened automatically.
                if (s.Status == FindingStatus.Fixed && scan.Finished > s.Updated) { f.Status = FindingStatus.Open; f.StatusNote = $"Re-opened: still present after being marked fixed on {s.Updated.ToLocalTime():d}."; }
                else { f.Status = s.Status; f.StatusNote = s.Note; }
            }
        }
    }

    // ---------------- Scopes ----------------

    public IReadOnlyList<ScanScope> ListScopes()
    {
        using var c = Open();
        return Db.Query(c, "SELECT json FROM scopes ORDER BY name", r => JsonSerializer.Deserialize<ScanScope>(r.Str("json")!, JsonOptions.Default)!)
            .Where(s => s != null).ToList();
    }

    public void SaveScope(ScanScope scope)
    {
        using var c = Open();
        Db.Execute(c, "INSERT OR REPLACE INTO scopes(id, name, json) VALUES (@id, @name, @json)",
            new { id = scope.Id.ToString(), name = scope.Name, json = JsonSerializer.Serialize(scope, JsonOptions.Default) });
    }

    public void DeleteScope(Guid id)
    {
        using var c = Open();
        Db.Execute(c, "DELETE FROM scopes WHERE id = @id", new { id = id.ToString() });
    }

    public ScanScope? FindScope(string nameOrId)
        => ListScopes().FirstOrDefault(s => string.Equals(s.Name, nameOrId, StringComparison.OrdinalIgnoreCase) || s.Id.ToString() == nameOrId);

    // ---------------- Audit log ----------------

    public void Audit(string action, string user, string? scope = null, string? targets = null, string? profile = null, string? details = null)
    {
        using var c = Open();
        Db.Execute(c, "INSERT INTO audit_log(ts, user, machine, action, scope, targets, profile, details) VALUES (@ts, @user, @machine, @action, @scope, @targets, @profile, @details)",
            new { ts = Db.Iso(DateTimeOffset.Now), user, machine = Environment.MachineName, action, scope, targets, profile, details });
    }

    public IReadOnlyList<AuditEntry> ReadAudit(int limit = 1000)
    {
        using var c = Open();
        return Db.Query(c, "SELECT * FROM audit_log ORDER BY id DESC LIMIT @limit", r => new AuditEntry(
            r.Long("id"), r.Date("ts") ?? DateTimeOffset.MinValue, r.Str("user") ?? "", r.Str("machine") ?? "", r.Str("action") ?? "",
            r.Str("scope") ?? "", r.Str("targets") ?? "", r.Str("profile") ?? "", r.Str("details") ?? ""), new { limit });
    }
}
