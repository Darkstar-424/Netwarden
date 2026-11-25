using System.Data;
using System.Data.Common;

namespace NetWarden.Data.Storage;

/// <summary>Creates open connections to a database file. The production implementation uses SQLite.</summary>
public interface IDbConnectionFactory
{
    DbConnection Open(string path, bool readOnly = false);
    /// <summary>Closes pooled connections so a database file can be replaced.</summary>
    void ReleaseAll();
}

/// <summary>Tiny parameterised-SQL helpers over ADO.NET (no ORM, trim- and single-file-friendly).</summary>
public static class Db
{
    public static DbCommand Command(DbConnection conn, string sql, object? args = null, DbTransaction? tx = null)
    {
        var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.Transaction = tx;
        if (args != null)
        {
            foreach (var prop in args.GetType().GetProperties())
            {
                var p = cmd.CreateParameter();
                p.ParameterName = "@" + prop.Name;
                p.Value = prop.GetValue(args) ?? DBNull.Value;
                cmd.Parameters.Add(p);
            }
        }
        return cmd;
    }

    public static int Execute(DbConnection conn, string sql, object? args = null, DbTransaction? tx = null)
    {
        using var cmd = Command(conn, sql, args, tx);
        return cmd.ExecuteNonQuery();
    }

    public static T? Scalar<T>(DbConnection conn, string sql, object? args = null)
    {
        using var cmd = Command(conn, sql, args);
        var v = cmd.ExecuteScalar();
        if (v == null || v is DBNull) return default;
        return (T)Convert.ChangeType(v, Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T), System.Globalization.CultureInfo.InvariantCulture);
    }

    public static List<T> Query<T>(DbConnection conn, string sql, Func<IDataRecord, T> map, object? args = null)
    {
        using var cmd = Command(conn, sql, args);
        using var r = cmd.ExecuteReader();
        var list = new List<T>();
        while (r.Read()) list.Add(map(r));
        return list;
    }

    public static string? Str(this IDataRecord r, string col)
    {
        var i = r.GetOrdinal(col);
        return r.IsDBNull(i) ? null : r.GetValue(i).ToString();
    }

    public static long Long(this IDataRecord r, string col)
    {
        var i = r.GetOrdinal(col);
        return r.IsDBNull(i) ? 0 : Convert.ToInt64(r.GetValue(i), System.Globalization.CultureInfo.InvariantCulture);
    }

    public static double? Dbl(this IDataRecord r, string col)
    {
        var i = r.GetOrdinal(col);
        return r.IsDBNull(i) ? null : Convert.ToDouble(r.GetValue(i), System.Globalization.CultureInfo.InvariantCulture);
    }

    public static DateTimeOffset? Date(this IDataRecord r, string col)
        => DateTimeOffset.TryParse(r.Str(col), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var d) ? d : null;

    public static string Iso(DateTimeOffset d) => d.ToUniversalTime().ToString("o", System.Globalization.CultureInfo.InvariantCulture);
}
