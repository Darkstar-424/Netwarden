using System.Runtime.InteropServices;
using System.Text;
using NetWarden.App.Services;
using NetWarden.Data.Sqlite;
using NetWarden.Data.Storage;
using NetWarden.Reporting.Pdf;
using NetWarden.UI.Services;

namespace NetWarden.App;

/// <summary>
/// Entry point. With command-line arguments NetWarden runs headless (used by Task Scheduler);
/// without arguments it opens the window. Both modes live in the same portable exe.
/// </summary>
public static class Program
{
    [DllImport("kernel32.dll")]
    private static extern bool AttachConsole(int processId);

    [STAThread]
    public static int Main(string[] args)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        if (CliRunner.IsCliInvocation(args)) return RunCli(args);

        var app = new App();
        app.InitializeComponent();
        return app.Run();
    }

    /// <summary>Creates the shared services (used by both modes).</summary>
    public static AppServices CreateServices()
    {
        var paths = AppPaths.Resolve();
        var log = new SerilogLog(paths.Logs);
        PdfReportWriter.Register();
        return new AppServices(paths, SqliteConnectionFactory.Instance, log, new CredentialStore(), new SchtasksScheduler(log));
    }

    private static int RunCli(string[] args)
    {
        AttachConsole(-1); // print to the calling console when started from cmd/PowerShell
        var console = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
        AppServices services;
        try
        {
            services = CreateServices();
        }
        catch (Exception ex)
        {
            console.WriteLine("NetWarden could not start: " + ex.Message);
            return 2;
        }
        var logFile = Path.Combine(services.Paths.Logs, $"cli-{DateTime.Now:yyyyMMdd-HHmmss}.log");
        using var file = new StreamWriter(logFile) { AutoFlush = true };
        using var tee = new TeeWriter(console, file);
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
        try
        {
            return new CliRunner(services, tee).RunAsync(args, cts.Token).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            tee.WriteLine("Unexpected error: " + ex);
            services.Log.Error("CLI crashed", ex);
            return 3;
        }
        finally
        {
            Serilog.Log.CloseAndFlush();
        }
    }

    private sealed class TeeWriter : TextWriter
    {
        private readonly TextWriter _a, _b;
        public TeeWriter(TextWriter a, TextWriter b) { _a = a; _b = b; }
        public override Encoding Encoding => Encoding.UTF8;
        public override void Write(char value) { _a.Write(value); _b.Write(value); }
        public override void Write(string? value) { _a.Write(value); _b.Write(value); }
        public override void WriteLine(string? value) { _a.WriteLine(value); _b.WriteLine(value); }
        public override void Flush() { _a.Flush(); _b.Flush(); }
    }
}
