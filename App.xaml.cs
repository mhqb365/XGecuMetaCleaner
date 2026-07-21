using System.Windows;

namespace XGecuMetaCleaner
{
public partial class App : Application
{
    private void App_Startup(object sender, StartupEventArgs e)
    {
        if (e.Args.Length == 0)
        {
            new MainWindow().Show();
            return;
        }

        var ok = 0;
        var failed = 0;
        foreach (var path in e.Args)
        {
            var result = XGecuMetaCleaner.MainWindow.CleanFile(path, createBackup: true);
            if (result.Success)
            {
                ok++;
                continue;
            }

            failed++;
        }

        MessageBox.Show(
            "Clean completed\r\nOK: " + ok + "\r\nFailed/skipped: " + failed,
            "XGecu Meta Cleaner",
            MessageBoxButton.OK,
            failed == 0 ? MessageBoxImage.Information : MessageBoxImage.Warning);
        Shutdown(failed == 0 ? 0 : 1);
    }
}
}
