using System.Windows;
using System.Windows.Controls;
using NetWarden.UI.ViewModels;

namespace NetWarden.App.Views;

public partial class SettingsView : UserControl
{
    private bool _loading;

    public SettingsView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => LoadSecrets();
        Loaded += (_, _) => LoadSecrets();
    }

    private SettingsViewModel? Vm => DataContext as SettingsViewModel;

    // PasswordBox.Password can't be data-bound (by design), so it is synced here.
    private void LoadSecrets()
    {
        if (Vm == null) return;
        _loading = true;
        SmtpPasswordBox.Password = Vm.SmtpPassword;
        TeamsWebhookBox.Password = Vm.TeamsWebhook;
        _loading = false;
    }

    private void SmtpPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (!_loading && Vm != null) Vm.SmtpPassword = SmtpPasswordBox.Password;
    }

    private void TeamsWebhookBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (!_loading && Vm != null) Vm.TeamsWebhook = TeamsWebhookBox.Password;
    }
}
