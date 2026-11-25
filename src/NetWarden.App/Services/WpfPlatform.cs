using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using Microsoft.Win32;
using NetWarden.Data.Storage;
using NetWarden.UI.Services;

namespace NetWarden.App.Services;

/// <summary>Switches the light/dark resource dictionary at runtime and tints the window title bar to match.</summary>
public static class ThemeManager
{
    private static readonly Uri LightUri = new("pack://application:,,,/Themes/Light.xaml", UriKind.Absolute);
    private static readonly Uri DarkUri = new("pack://application:,,,/Themes/Dark.xaml", UriKind.Absolute);

    public static bool IsDark { get; private set; }
    public static event Action? Changed;

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    public static bool SystemPrefersDark()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static void Apply(ThemeChoice choice)
    {
        var dark = choice == ThemeChoice.Dark || (choice == ThemeChoice.System && SystemPrefersDark());
        IsDark = dark;
        var dictionaries = Application.Current.Resources.MergedDictionaries;
        var replacement = new ResourceDictionary { Source = dark ? DarkUri : LightUri };
        if (dictionaries.Count > 0) dictionaries[0] = replacement; else dictionaries.Insert(0, replacement);
        foreach (Window w in Application.Current.Windows) ApplyTitleBar(w);
        Changed?.Invoke();
    }

    public static void ApplyTitleBar(Window window)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == IntPtr.Zero) return;
        int on = IsDark ? 1 : 0;
        // DWMWA_USE_IMMERSIVE_DARK_MODE = 20 (Windows 10 2004+ / Windows 11); 19 on older Windows 10 builds.
        if (DwmSetWindowAttribute(hwnd, 20, ref on, sizeof(int)) != 0)
            DwmSetWindowAttribute(hwnd, 19, ref on, sizeof(int));
    }
}

public sealed class WpfPlatform : IPlatform
{
    private static Window? Owner => Application.Current?.MainWindow is { IsVisible: true } w ? w : null;

    public void ShowMessage(string title, string message, bool isError = false)
    {
        if (Owner != null) MessageBox.Show(Owner, message, title, MessageBoxButton.OK, isError ? MessageBoxImage.Warning : MessageBoxImage.Information);
        else MessageBox.Show(message, title, MessageBoxButton.OK, isError ? MessageBoxImage.Warning : MessageBoxImage.Information);
    }

    public bool Confirm(string title, string message)
        => (Owner != null ? MessageBox.Show(Owner, message, title, MessageBoxButton.YesNo, MessageBoxImage.Question)
                          : MessageBox.Show(message, title, MessageBoxButton.YesNo, MessageBoxImage.Question)) == MessageBoxResult.Yes;

    public string? PromptText(string title, string label, string initial = "")
    {
        var dlg = new PromptWindow(title, label, initial) { Owner = Owner };
        return dlg.ShowDialog() == true ? dlg.Value : null;
    }

    public string? PickSaveFile(string title, string filter, string defaultName)
    {
        var dlg = new SaveFileDialog { Title = title, Filter = filter, AddExtension = true, OverwritePrompt = true };
        var dir = Path.GetDirectoryName(defaultName);
        if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir)) dlg.InitialDirectory = dir;
        dlg.FileName = Path.GetFileName(defaultName);
        return (Owner != null ? dlg.ShowDialog(Owner) : dlg.ShowDialog()) == true ? dlg.FileName : null;
    }

    public string? PickOpenFile(string title, string filter)
    {
        var dlg = new OpenFileDialog { Title = title, Filter = filter, CheckFileExists = true };
        return (Owner != null ? dlg.ShowDialog(Owner) : dlg.ShowDialog()) == true ? dlg.FileName : null;
    }

    public void ApplyTheme(ThemeChoice theme) => ThemeManager.Apply(theme);

    public void OpenPath(string path)
    {
        try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { ShowMessage("Can't open", ex.Message, true); }
    }

    public void OpenUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)) return;
        OpenPath(uri.AbsoluteUri);
    }

    public void CopyText(string text)
    {
        try { Clipboard.SetText(text); }
        catch (COMException) { /* clipboard busy; ignore */ }
    }
}

/// <summary>Small themed text-input dialog.</summary>
public sealed class PromptWindow : Window
{
    private readonly TextBox _box;
    public string Value => _box.Text;

    public PromptWindow(string title, string label, string initial)
    {
        Title = title;
        Width = 440;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        SetResourceReference(BackgroundProperty, "Brush.Window");
        SetResourceReference(ForegroundProperty, "Brush.Text");
        FontFamily = new System.Windows.Media.FontFamily("Segoe UI Variable Text, Segoe UI");
        FontSize = 14;

        var panel = new StackPanel { Margin = new Thickness(20) };
        panel.Children.Add(new TextBlock { Text = label, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) });
        _box = new TextBox { Text = initial };
        panel.Children.Add(_box);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) };
        var ok = new Button { Content = "OK", IsDefault = true, MinWidth = 90, Margin = new Thickness(0, 0, 8, 0) };
        ok.SetResourceReference(StyleProperty, "PrimaryButton");
        ok.Click += (_, _) => DialogResult = true;
        var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 90 };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        panel.Children.Add(buttons);
        Content = panel;
        Loaded += (_, _) => { ThemeManager.ApplyTitleBar(this); _box.Focus(); _box.SelectAll(); };
    }
}
