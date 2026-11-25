using System.Windows.Controls;
using System.Windows.Input;
using NetWarden.UI.ViewModels;

namespace NetWarden.App.Views;

public partial class DashboardView : UserControl
{
    public DashboardView() => InitializeComponent();

    private void History_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is DashboardViewModel vm && History.SelectedItem != null)
            vm.OpenScanCommand.Execute(History.SelectedItem);
    }
}
