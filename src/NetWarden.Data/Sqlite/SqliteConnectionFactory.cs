using System.Data.Common;
using Microsoft.Data.Sqlite;
using NetWarden.Data.Storage;

namespace NetWarden.Data.Sqlite;

public sealed class SqliteConnectionFactory : IDbConnectionFactory
{
    public static readonly SqliteConnectionFactory Instance = new();

    public DbConnection Open(string path, bool readOnly = false)
    {
        var cs = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = readOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = true
        }.ToString();
        var conn = new SqliteConnection(cs);
        conn.Open();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = readOnly ? "PRAGMA busy_timeout=5000;" : "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;";
            cmd.ExecuteNonQuery();
        }
        return conn;
    }

    /// <summary>Releases pooled handles so a database file can be replaced (offline CVE bundle import).</summary>
    public void ReleaseAll() => SqliteConnection.ClearAllPools();
}
