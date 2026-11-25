using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using NetWarden.Core.Util;
using NetWarden.UI.Services;
using Serilog;

namespace NetWarden.App.Services;

/// <summary>Structured logging to the data folder's logs directory (rolling daily, 30 days).</summary>
public sealed class SerilogLog : INwLog
{
    public SerilogLog(string folder)
    {
        Directory.CreateDirectory(folder);
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .Enrich.WithProperty("App", "NetWarden")
            .WriteTo.File(Path.Combine(folder, "netwarden-.log"), rollingInterval: RollingInterval.Day, retainedFileCountLimit: 30, shared: true,
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
            .CreateLogger();
        Log.Information("NetWarden {Version} started by {User} on {Machine}", typeof(SerilogLog).Assembly.GetName().Version, Environment.UserName, Environment.MachineName);
    }

    public void Debug(string message) => Log.Debug(message);
    public void Info(string message) => Log.Information(message);
    public void Warn(string message, Exception? ex = null) => Log.Warning(ex, message);
    public void Error(string message, Exception? ex = null) => Log.Error(ex, message);
}

/// <summary>Secrets in Windows Credential Manager (per user, encrypted by Windows).</summary>
public sealed class CredentialStore : ISecretStore
{
    private const uint CredTypeGeneric = 1;
    private const uint CredPersistLocalMachine = 2;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Credential
    {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string? Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string? TargetAlias;
        public string? UserName;
    }

    [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWrite(ref Credential credential, uint flags);

    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, uint type, uint reservedFlag, out IntPtr credential);

    [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredDelete(string target, uint type, uint flags);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);

    public string? Get(string name)
    {
        if (!CredRead(name, CredTypeGeneric, 0, out var ptr)) return null;
        try
        {
            var cred = Marshal.PtrToStructure<Credential>(ptr);
            if (cred.CredentialBlob == IntPtr.Zero || cred.CredentialBlobSize == 0) return "";
            var bytes = new byte[cred.CredentialBlobSize];
            Marshal.Copy(cred.CredentialBlob, bytes, 0, bytes.Length);
            return Encoding.Unicode.GetString(bytes);
        }
        finally
        {
            CredFree(ptr);
        }
    }

    public void Set(string name, string? value)
    {
        if (value == null)
        {
            CredDelete(name, CredTypeGeneric, 0);
            return;
        }
        var bytes = Encoding.Unicode.GetBytes(value);
        var blob = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, blob, bytes.Length);
            var cred = new Credential
            {
                Type = CredTypeGeneric,
                TargetName = name,
                CredentialBlobSize = (uint)bytes.Length,
                CredentialBlob = blob,
                Persist = CredPersistLocalMachine,
                UserName = Environment.UserName
            };
            if (!CredWrite(ref cred, 0)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not save to Windows Credential Manager.");
        }
        finally
        {
            Marshal.FreeHGlobal(blob);
        }
    }
}

/// <summary>Per-user scheduled scans through the built-in schtasks.exe (no admin rights needed).</summary>
public sealed class SchtasksScheduler : IScanScheduler
{
    private const string Folder = "NetWarden";
    private readonly INwLog _log;

    public SchtasksScheduler(INwLog log) => _log = log;

    public IReadOnlyList<ScheduledScan> List()
    {
        var (code, output) = Run(new[] { "/Query", "/FO", "CSV", "/V" });
        if (code != 0) return Array.Empty<ScheduledScan>();
        var list = new List<ScheduledScan>();
        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            var cols = SplitCsv(line.TrimEnd('\r'));
            if (cols.Count < 9) continue;
            var taskName = cols[1];
            if (!taskName.StartsWith($"\\{Folder}\\", StringComparison.OrdinalIgnoreCase)) continue;
            var name = taskName[(Folder.Length + 2)..];
            if (list.Any(s => s.Name == name)) continue; // /V prints one line per trigger
            var command = cols.FirstOrDefault(c => c.Contains(" scan ", StringComparison.OrdinalIgnoreCase) && c.Contains("--scope", StringComparison.OrdinalIgnoreCase)) ?? cols[8];
            var scope = Regex.Match(command, "--scope \"(?<v>[^\"]+)\"").Groups["v"].Value;
            var profile = Regex.Match(command, "--profile \"(?<v>[^\"]+)\"").Groups["v"].Value;
            list.Add(new ScheduledScan(name, scope, profile, ScheduleFrequency.Weekly, DayOfWeek.Sunday, TimeSpan.Zero, cols[2], cols[3]));
        }
        return list;
    }

    public void Create(ScheduledScan scan, string executablePath, bool notify)
    {
        var action = $"\"{executablePath}\" scan --scope \"{scan.Scope}\" --profile \"{scan.Profile}\"" + (notify ? " --notify" : "");
        if (action.Length > 261) throw new InvalidOperationException("The command line is too long for Task Scheduler. Move NetWarden.exe to a shorter path or use shorter scope/profile names.");
        var args = new List<string> { "/Create", "/TN", $"{Folder}\\{scan.Name}", "/TR", action, "/ST", scan.Time.ToString("hh\\:mm", CultureInfo.InvariantCulture), "/F" };
        switch (scan.Frequency)
        {
            case ScheduleFrequency.Daily:
                args.AddRange(new[] { "/SC", "DAILY" });
                break;
            case ScheduleFrequency.Weekly:
                args.AddRange(new[] { "/SC", "WEEKLY", "/D", scan.Day.ToString()[..3].ToUpperInvariant() });
                break;
            case ScheduleFrequency.Monthly:
                args.AddRange(new[] { "/SC", "MONTHLY", "/D", "1" });
                break;
        }
        var (code, output) = Run(args);
        if (code != 0) throw new InvalidOperationException(output.Trim());
        _log.Info($"Scheduled task created: {scan.Name}");
    }

    public void Delete(string name)
    {
        var (code, output) = Run(new[] { "/Delete", "/TN", $"{Folder}\\{name}", "/F" });
        if (code != 0) throw new InvalidOperationException(output.Trim());
    }

    private static (int Code, string Output) Run(IEnumerable<string> args)
    {
        var psi = new ProcessStartInfo("schtasks.exe")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage),
            StandardErrorEncoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage)
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Could not start schtasks.exe.");
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(30000)) { p.Kill(); throw new InvalidOperationException("schtasks.exe did not respond."); }
        return (p.ExitCode, stdout.Result + stderr.Result);
    }

    private static List<string> SplitCsv(string line)
    {
        var result = new List<string>();
        var sb = new StringBuilder();
        bool q = false;
        for (int i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (c == '"') { if (q && i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; } else q = !q; }
            else if (c == ',' && !q) { result.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }
        result.Add(sb.ToString());
        return result;
    }
}
