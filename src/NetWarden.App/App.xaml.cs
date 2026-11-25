using System.Windows;
using System.Windows.Threading;
using NetWarden.App.Services;
using NetWarden.UI.Mvvm;
using NetWarden.UI.Services;
using NetWarden.UI.ViewModels;

namespace NetWarden.App;

public partial class App : Application
{
    private AppServices? _services;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        UiThread.Context = new DispatcherSynchronizationContext(Dispatcher);
        DispatcherUnhandledException += OnUnhandled;
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            _services?.Log.Error("Unobserved task exception", args.Exception);
            args.SetObserved();
        };

        try
        {
            _services = Program.CreateServices();
        }
        catch (Exception ex)
        {
            MessageBox.Show("NetWarden could not start:\n\n" + ex.Message, "NetWarden", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(2);
            return;
        }

        ThemeManager.Apply(_services.Settings.Theme);
        var platform = new WpfPlatform();
        var vm = new MainViewModel(_services, platform) { EffectiveDark = ThemeManager.IsDark };
        ThemeManager.Changed += () => vm.EffectiveDark = ThemeManager.IsDark;
        var window = new MainWindow { DataContext = vm };
        MainWindow = window;
        window.Show();
        foreach (var warning in _services.StartupWarnings)
            _services.Log.Warn(warning);
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        _services?.Log.Error("Unhandled UI exception", e.Exception);
        MessageBox.Show("Something went wrong:\n\n" + e.Exception.Message + "\n\nDetails were written to the log file.", "NetWarden", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        Serilog.Log.CloseAndFlush();
        base.OnExit(e);
    }
}
