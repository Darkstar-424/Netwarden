using System.Collections.Concurrent;
using System.Data.Common;
using System.Text.Json;
using NetWarden.Core.Checks;
using NetWarden.Data.Storage;

namespace NetWarden.Data.CveStore;

public sealed record CveDbStats(long CveCount, long RuleCount, long KevCount, DateTimeOffset? LastNvdSync, DateTimeOffset? LastKevSync);

public sealed class CveImportRecord
{
    public string Id { get; set; } = "";
    public string Description { get; set; } = "";
    public double? Cvss { get; set; }
    public string? CvssVector { get; set; }
    public string? Severity { get; set; }
    public DateTimeOffset? Published { get; set; }
    public DateTimeOffset? LastModified { get; set; }
    public List<string> References { get; set; } = new();
    public List<CveMatchRule> Rules { get; set; } = new();
}

public sealed record KevImportRecord(string CveId, string? Name, DateTimeOffset? DateAdded, DateTimeOffset? DueDate, string? RequiredAction, string? Ransomware);

/// <summary>Local CVE database (cve.db) built from the NVD API 2.0 and the CISA KEV catalog.</summary>
public sealed class CveDatabase : ICveRepository
{
    private readonly IDbConnectionFactory _factory;
    private readonly string _path;
    private readonly ConcurrentDictionary<string, IReadOnlyList<CveMatchRule>> _ruleCache = new(StringComparer.OrdinalIgnoreCase);

    public static readonly string[] Schema =
    {
        @"CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)",
        @"CREATE TABLE IF NOT EXISTS cve (
            id TEXT PRIMARY KEY, published TEXT, last_modified TEXT, description TEXT, cvss REAL, cvss_vector TEXT, severity TEXT,
            refs TEXT, kev INTEGER NOT NULL DEFAULT 0, kev_date_added TEXT, kev_due TEXT, kev_action TEXT, kev_ransomware TEXT)",
        @"CREATE TABLE IF NOT EXISTS cpe_match (
            cve_id TEXT NOT NULL, vendor TEXT NOT NULL, product TEXT NOT NULL, criteria TEXT NOT NULL,
            v_start_incl TEXT, v_start_excl TEXT, v_end_incl TEXT, v_end_excl TEXT)",
        @"CREATE INDEX IF NOT EXISTS ix_cpe_vp ON cpe_match(vendor, product)",
        @"CREATE INDEX IF NOT EXISTS ix_cpe_cve ON cpe_match(cve_id)"
    };

    public CveDatabase(IDbConnectionFactory factory, string path)
    {
        _factory = factory;
        _path = path;
        using var c = _factory.Open(_path);
        foreach (var sql in Schema) Db.Execute(c, sql);
    }

    public string Path => _path;

    public bool IsAvailable
    {
        get
        {
            try
            {
                using var c = _factory.Open(_path);
                return Db.Scalar<long>(c, "SELECT COUNT(*) FROM cve LIMIT 1") > 0;
            }
            catch (Exception ex) when (ex is DbException or InvalidOperationException)
            {
                return false;
            }
        }
    }

    public IReadOnlyList<CveMatchRule> GetRules(string vendor, string product)
        => _ruleCache.GetOrAdd(vendor + ":" + product, _ =>
        {
            using var c = _factory.Open(_path);
            return Db.Query(c, "SELECT * FROM cpe_match WHERE vendor = @vendor AND product = @product", r => new CveMatchRule(
                r.Str("cve_id")!, r.Str("vendor")!, r.Str("product")!, r.Str("criteria")!,
                r.Str("v_start_incl"), r.Str("v_start_excl"), r.Str("v_end_incl"), r.Str("v_end_excl")), new { vendor, product });
        });

    public CveRecord? Get(string cveId)
    {
        using var c = _factory.Open(_path);
        return Db.Query(c, "SELECT * FROM cve WHERE id = @id", r => new CveRecord(
            r.Str("id")!, r.Str("description") ?? "", r.Dbl("cvss"), r.Str("cvss_vector"), r.Str("severity"), r.Date("published"),
            JsonSerializer.Deserialize<List<string>>(r.Str("refs") ?? "[]") ?? new List<string>(),
            r.Long("kev") != 0, r.Str("kev_action"), r.Date("kev_date_added")), new { id = cveId }).FirstOrDefault();
    }

    public void InvalidateCache() => _ruleCache.Clear();

    public CveDbStats Stats()
    {
        using var c = _factory.Open(_path);
        return new CveDbStats(
            Db.Scalar<long>(c, "SELECT COUNT(*) FROM cve"),
            Db.Scalar<long>(c, "SELECT COUNT(*) FROM cpe_match"),
            Db.Scalar<long>(c, "SELECT COUNT(*) FROM cve WHERE kev = 1"),
            ParseDate(GetMeta(c, "last_nvd_sync")),
            ParseDate(GetMeta(c, "last_kev_sync")));
    }

    public string? GetMeta(string key)
    {
        using var c = _factory.Open(_path);
        return GetMeta(c, key);
    }

    public void SetMeta(string key, string value)
    {
        using var c = _factory.Open(_path);
        Db.Execute(c, "INSERT OR REPLACE INTO meta(key, value) VALUES (@key, @value)", new { key, value });
    }

    private static string? GetMeta(DbConnection c, string key) => Db.Scalar<string>(c, "SELECT value FROM meta WHERE key = @key", new { key });

    private static DateTimeOffset? ParseDate(string? s)
        => DateTimeOffset.TryParse(s, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var d) ? d : null;

    /// <summary>Inserts or replaces a batch of CVEs (and their CPE rules) in one transaction. KEV flags are preserved.</summary>
    public void Upsert(IReadOnlyCollection<CveImportRecord> batch)
    {
        if (batch.Count == 0) return;
        using var c = _factory.Open(_path);
        using var tx = c.BeginTransaction();
        foreach (var cve in batch)
        {
            Db.Execute(c, @"INSERT INTO cve(id, published, last_modified, description, cvss, cvss_vector, severity, refs)
                            VALUES (@id, @pub, @mod, @desc, @cvss, @vec, @sev, @refs)
                            ON CONFLICT(id) DO UPDATE SET published = excluded.published, last_modified = excluded.last_modified,
                                description = excluded.description, cvss = excluded.cvss, cvss_vector = excluded.cvss_vector,
                                severity = excluded.severity, refs = excluded.refs",
                new
                {
                    id = cve.Id,
                    pub = cve.Published is { } p ? Db.Iso(p) : null,
                    mod = cve.LastModified is { } m ? Db.Iso(m) : null,
                    desc = cve.Description,
                    cvss = cve.Cvss,
                    vec = cve.CvssVector,
                    sev = cve.Severity,
                    refs = JsonSerializer.Serialize(cve.References.Take(20))
                }, tx);
            Db.Execute(c, "DELETE FROM cpe_match WHERE cve_id = @id", new { id = cve.Id }, tx);
            foreach (var r in cve.Rules)
            {
                Db.Execute(c, @"INSERT INTO cpe_match(cve_id, vendor, product, criteria, v_start_incl, v_start_excl, v_end_incl, v_end_excl)
                                VALUES (@cve, @vendor, @product, @criteria, @si, @se, @ei, @ee)",
                    new
                    {
                        cve = cve.Id, vendor = r.Vendor, product = r.Product, criteria = r.Criteria,
                        si = r.VersionStartIncluding, se = r.VersionStartExcluding, ei = r.VersionEndIncluding, ee = r.VersionEndExcluding
                    }, tx);
            }
        }
        tx.Commit();
        _ruleCache.Clear();
    }

    /// <summary>Replaces all KEV flags with the current catalog. CVEs not yet in the NVD data get a stub row.</summary>
    public void ApplyKev(IReadOnlyCollection<KevImportRecord> kev)
    {
        using var c = _factory.Open(_path);
        using var tx = c.BeginTransaction();
        Db.Execute(c, "UPDATE cve SET kev = 0, kev_date_added = NULL, kev_due = NULL, kev_action = NULL, kev_ransomware = NULL", null, tx);
        foreach (var k in kev)
        {
            Db.Execute(c, @"INSERT INTO cve(id, description, kev, kev_date_added, kev_due, kev_action, kev_ransomware, refs)
                            VALUES (@id, @desc, 1, @added, @due, @action, @ransom, '[]')
                            ON CONFLICT(id) DO UPDATE SET kev = 1, kev_date_added = excluded.kev_date_added, kev_due = excluded.kev_due,
                                kev_action = excluded.kev_action, kev_ransomware = excluded.kev_ransomware",
                new
                {
                    id = k.CveId, desc = k.Name ?? "", added = k.DateAdded is { } a ? Db.Iso(a) : null, due = k.DueDate is { } d ? Db.Iso(d) : null,
                    action = k.RequiredAction, ransom = k.Ransomware
                }, tx);
        }
        tx.Commit();
    }
}
