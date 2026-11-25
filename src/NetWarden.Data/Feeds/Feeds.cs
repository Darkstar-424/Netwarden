using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using NetWarden.Core.Checks;
using NetWarden.Core.Fingerprinting;
using NetWarden.Data.CveStore;

namespace NetWarden.Data.Feeds;

public sealed record FeedProgress(string Stage, long Done, long Total, string Message);

public sealed class FeedException : Exception
{
    public FeedException(string message, Exception? inner = null) : base(message, inner) { }
}

internal static class FeedHttp
{
    public static HttpClient Create()
    {
        // Default certificate validation is kept on purpose: the feeds are only trusted over properly validated HTTPS.
        var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5)
        };
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(2) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("NetWarden/1.0");
        return client;
    }

    public static void RequireHttps(Uri uri)
    {
        if (uri.Scheme != Uri.UriSchemeHttps) throw new FeedException($"Refusing to download from a non-HTTPS address: {uri}");
    }
}

/// <summary>Downloads CVEs from the NVD API 2.0 (full or incremental) and stores them in the local database.</summary>
public sealed class NvdClient
{
    public const string BaseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static readonly Regex CveId = new(@"^CVE-\d{4}-\d{4,}$", RegexOptions.Compiled);
    private const int PageSize = 2000;

    private readonly HttpClient _http;
    private readonly string? _apiKey;

    public NvdClient(string? apiKey = null, HttpClient? http = null)
    {
        _http = http ?? FeedHttp.Create();
        _apiKey = string.IsNullOrWhiteSpace(apiKey) ? null : apiKey.Trim();
    }

    /// <summary>The NVD allows 5 requests per 30 s without a key and 50 with one.</summary>
    private TimeSpan Delay => _apiKey == null ? TimeSpan.FromSeconds(6.5) : TimeSpan.FromSeconds(0.7);

    public async Task<long> SyncAsync(CveDatabase db, IProgress<FeedProgress>? progress, CancellationToken ct)
    {
        var last = db.GetMeta("last_nvd_sync");
        var started = DateTimeOffset.UtcNow;
        long total = 0;
        if (last != null && DateTimeOffset.TryParse(last, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var since) && db.IsAvailable)
        {
            // Incremental: the API accepts at most 120 days per lastMod window.
            var from = since.AddMinutes(-5);
            while (from < started)
            {
                var to = from.AddDays(119) < started ? from.AddDays(119) : started;
                total += await DownloadAsync(db, $"&lastModStartDate={Fmt(from)}&lastModEndDate={Fmt(to)}", progress, ct).ConfigureAwait(false);
                from = to;
            }
        }
        else
        {
            total = await DownloadAsync(db, "", progress, ct).ConfigureAwait(false);
        }
        db.SetMeta("last_nvd_sync", started.ToString("o", CultureInfo.InvariantCulture));
        return total;
    }

    private static string Fmt(DateTimeOffset d) => Uri.EscapeDataString(d.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture));

    private async Task<long> DownloadAsync(CveDatabase db, string filter, IProgress<FeedProgress>? progress, CancellationToken ct)
    {
        int start = 0;
        long total = -1, done = 0;
        do
        {
            var uri = new Uri($"{BaseUrl}?resultsPerPage={PageSize}&startIndex={start}{filter}");
            FeedHttp.RequireHttps(uri);
            using var req = new HttpRequestMessage(HttpMethod.Get, uri);
            if (_apiKey != null) req.Headers.Add("apiKey", _apiKey);
            HttpResponseMessage resp;
            int attempt = 0;
            while (true)
            {
                resp = await _http.SendAsync(Clone(req), ct).ConfigureAwait(false);
                if (resp.IsSuccessStatusCode) break;
                if ((int)resp.StatusCode is 403 or 429 or 503 && attempt++ < 5)
                {
                    resp.Dispose();
                    await Task.Delay(TimeSpan.FromSeconds(30 * attempt), ct).ConfigureAwait(false);
                    continue;
                }
                throw new FeedException($"NVD returned HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}.");
            }
            await using (var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
            {
                var page = await ParsePageAsync(stream, ct).ConfigureAwait(false);
                total = page.TotalResults;
                db.Upsert(page.Items);
                done += page.Items.Count;
                start += PageSize;
            }
            resp.Dispose();
            progress?.Report(new FeedProgress("NVD", done, total, $"Downloaded {done:N0} of {total:N0} CVE records"));
            if (start < total) await Task.Delay(Delay, ct).ConfigureAwait(false);
        } while (start < total);
        return done;
    }

    private static HttpRequestMessage Clone(HttpRequestMessage r)
    {
        var c = new HttpRequestMessage(r.Method, r.RequestUri);
        foreach (var h in r.Headers) c.Headers.TryAddWithoutValidation(h.Key, h.Value);
        return c;
    }

    public sealed record Page(long TotalResults, List<CveImportRecord> Items);

    /// <summary>Parses and validates one NVD API 2.0 response page.</summary>
    public static async Task<Page> ParsePageAsync(Stream json, CancellationToken ct)
    {
        using var doc = await JsonDocument.ParseAsync(json, default, ct).ConfigureAwait(false);
        var root = doc.RootElement;
        if (!root.TryGetProperty("format", out var fmt) || fmt.GetString() != "NVD_CVE" || !root.TryGetProperty("vulnerabilities", out var vulns))
            throw new FeedException("Unexpected response from NVD (integrity check failed: not an NVD_CVE document).");
        var total = root.GetProperty("totalResults").GetInt64();
        var items = new List<CveImportRecord>();
        foreach (var v in vulns.EnumerateArray())
        {
            var cve = v.GetProperty("cve");
            var id = cve.GetProperty("id").GetString() ?? "";
            if (!CveId.IsMatch(id)) throw new FeedException($"Integrity check failed: invalid CVE id '{id}'.");
            if (cve.TryGetProperty("vulnStatus", out var status) && status.GetString() == "Rejected") continue;
            var rec = new CveImportRecord
            {
                Id = id,
                Published = cve.TryGetProperty("published", out var pub) && DateTimeOffset.TryParse(pub.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var p) ? p : null,
                LastModified = cve.TryGetProperty("lastModified", out var mod) && DateTimeOffset.TryParse(mod.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var m) ? m : null
            };
            if (cve.TryGetProperty("descriptions", out var descs))
            {
                var en = descs.EnumerateArray().FirstOrDefault(d => d.TryGetProperty("lang", out var l) && l.GetString() == "en");
                if (en.ValueKind == JsonValueKind.Object && en.TryGetProperty("value", out var dv)) rec.Description = dv.GetString() ?? "";
            }
            if (cve.TryGetProperty("metrics", out var metrics))
            {
                foreach (var key in new[] { "cvssMetricV31", "cvssMetricV30" })
                {
                    if (!metrics.TryGetProperty(key, out var arr) || arr.GetArrayLength() == 0) continue;
                    var chosen = arr.EnumerateArray().FirstOrDefault(x => x.TryGetProperty("type", out var t) && t.GetString() == "Primary");
                    if (chosen.ValueKind == JsonValueKind.Undefined) chosen = arr[0];
                    var data = chosen.GetProperty("cvssData");
                    rec.Cvss = data.GetProperty("baseScore").GetDouble();
                    rec.CvssVector = data.TryGetProperty("vectorString", out var vs) ? vs.GetString() : null;
                    rec.Severity = data.TryGetProperty("baseSeverity", out var bs) ? bs.GetString() : null;
                    break;
                }
            }
            if (cve.TryGetProperty("references", out var refs))
                rec.References.AddRange(refs.EnumerateArray().Select(r => r.GetProperty("url").GetString() ?? "").Where(u => u.Length > 0).Take(20));
            if (cve.TryGetProperty("configurations", out var configs))
            {
                foreach (var config in configs.EnumerateArray())
                foreach (var node in config.GetProperty("nodes").EnumerateArray())
                foreach (var match in node.GetProperty("cpeMatch").EnumerateArray())
                {
                    if (!match.TryGetProperty("vulnerable", out var vul) || !vul.GetBoolean()) continue;
                    var criteria = match.GetProperty("criteria").GetString() ?? "";
                    var parts = CpeMapper.Parse(criteria);
                    if (parts == null || parts.Part != "a" && parts.Part != "o" && parts.Part != "h") continue;
                    rec.Rules.Add(new CveMatchRule(id, parts.Vendor, parts.Product, criteria,
                        Opt(match, "versionStartIncluding"), Opt(match, "versionStartExcluding"),
                        Opt(match, "versionEndIncluding"), Opt(match, "versionEndExcluding")));
                }
            }
            items.Add(rec);
        }
        return new Page(total, items);
    }

    private static string? Opt(JsonElement e, string name) => e.TryGetProperty(name, out var v) ? v.GetString() : null;
}

/// <summary>Downloads the CISA Known Exploited Vulnerabilities catalog.</summary>
public sealed class KevClient
{
    public const string FeedUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private readonly HttpClient _http;

    public KevClient(HttpClient? http = null) => _http = http ?? FeedHttp.Create();

    public async Task<int> SyncAsync(CveDatabase db, IProgress<FeedProgress>? progress, CancellationToken ct)
    {
        var uri = new Uri(FeedUrl);
        FeedHttp.RequireHttps(uri);
        progress?.Report(new FeedProgress("KEV", 0, 1, "Downloading CISA KEV catalog…"));
        using var resp = await _http.GetAsync(uri, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode) throw new FeedException($"CISA KEV returned HTTP {(int)resp.StatusCode}.");
        await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var records = await ParseAsync(stream, ct).ConfigureAwait(false);
        db.ApplyKev(records);
        db.SetMeta("last_kev_sync", DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture));
        progress?.Report(new FeedProgress("KEV", 1, 1, $"KEV catalog: {records.Count:N0} actively exploited CVEs"));
        return records.Count;
    }

    public static async Task<List<KevImportRecord>> ParseAsync(Stream json, CancellationToken ct)
    {
        using var doc = await JsonDocument.ParseAsync(json, default, ct).ConfigureAwait(false);
        var root = doc.RootElement;
        if (!root.TryGetProperty("vulnerabilities", out var vulns) || !root.TryGetProperty("catalogVersion", out _))
            throw new FeedException("Unexpected KEV catalog format (integrity check failed).");
        var list = new List<KevImportRecord>();
        foreach (var v in vulns.EnumerateArray())
        {
            var id = v.GetProperty("cveID").GetString() ?? "";
            if (!Regex.IsMatch(id, @"^CVE-\d{4}-\d{4,}$")) continue;
            list.Add(new KevImportRecord(id,
                Get(v, "vulnerabilityName"),
                ParseDate(Get(v, "dateAdded")),
                ParseDate(Get(v, "dueDate")),
                Get(v, "requiredAction"),
                Get(v, "knownRansomwareCampaignUse")));
        }
        if (list.Count < 100) throw new FeedException("KEV catalog looks truncated (fewer than 100 entries); not applied.");
        return list;
    }

    private static string? Get(JsonElement e, string name) => e.TryGetProperty(name, out var v) ? v.GetString() : null;

    private static DateTimeOffset? ParseDate(string? s)
        => DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var d) ? d : null;
}

/// <summary>
/// Offline update bundle: a zip with cve.db and manifest.json holding its SHA-256.
/// Export on an internet-connected PC, import on air-gapped ones.
/// </summary>
public static class OfflineBundle
{
    public sealed record Manifest(string Format, string Created, string Sha256, long Size, long CveCount);

    public static void Export(string cveDbPath, string zipPath, long cveCount)
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"nw-cve-{Guid.NewGuid():N}.db");
        File.Copy(cveDbPath, tmp, overwrite: true);
        try
        {
            var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(tmp)));
            var manifest = new Manifest("netwarden-cve-bundle-1", DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture), hash, new FileInfo(tmp).Length, cveCount);
            if (File.Exists(zipPath)) File.Delete(zipPath);
            using var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create);
            zip.CreateEntryFromFile(tmp, "cve.db", CompressionLevel.Optimal);
            var entry = zip.CreateEntry("manifest.json");
            using var w = new StreamWriter(entry.Open());
            w.Write(JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }));
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    /// <summary>Verifies the bundle and writes the database to a temporary file. Returns its path.</summary>
    public static string VerifyAndExtract(string zipPath)
    {
        using var zip = ZipFile.OpenRead(zipPath);
        var manifestEntry = zip.GetEntry("manifest.json") ?? throw new FeedException("Bundle has no manifest.json.");
        var dbEntry = zip.GetEntry("cve.db") ?? throw new FeedException("Bundle has no cve.db.");
        Manifest manifest;
        using (var s = manifestEntry.Open())
            manifest = JsonSerializer.Deserialize<Manifest>(s) ?? throw new FeedException("Bundle manifest is empty.");
        if (manifest.Format != "netwarden-cve-bundle-1") throw new FeedException($"Unknown bundle format '{manifest.Format}'.");
        var tmp = Path.Combine(Path.GetTempPath(), $"nw-cve-import-{Guid.NewGuid():N}.db");
        dbEntry.ExtractToFile(tmp, overwrite: true);
        var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(tmp)));
        if (!string.Equals(hash, manifest.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            File.Delete(tmp);
            throw new FeedException("Integrity check failed: cve.db does not match the SHA-256 in the manifest. The bundle may be damaged or tampered with.");
        }
        return tmp;
    }
}
