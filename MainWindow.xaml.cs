using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Windows;

namespace XGecuMetaCleaner
{
public partial class MainWindow : Window
{
    private const int TailScanBytes = 1024 * 1024;
    private static readonly byte[] MetadataMarker =
    {
        0x2D, 0x43, 0x6F, 0x6E, 0x66, 0x69, 0x67, 0x75,
        0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2D, 0x00
    };
    private string[] _selectedFiles = new string[0];

    public MainWindow()
    {
        InitializeComponent();
        Title = "XGecu Meta Cleaner v" + GitHubUpdateChecker.CurrentVersion.ToString(3);
        AppendLog("Ready");
        Loaded += MainWindow_Loaded;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        await GitHubUpdateChecker.CheckForUpdatesAsync(this);
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Binary files|*.bin;*.rom;*.fd;*.cap;*.dat|All files|*.*",
            Multiselect = true
        };

        if (dialog.ShowDialog(this) == true)
        {
            _selectedFiles = dialog.FileNames;
            FilePathBox.Text = string.Join(Environment.NewLine, _selectedFiles);
            AppendLog("Selected " + _selectedFiles.Length + " file(s)");
        }
    }

    private void ClearSelection_Click(object sender, RoutedEventArgs e)
    {
        _selectedFiles = new string[0];
        FilePathBox.Clear();
        AppendLog("Selection cleared");
    }

    private void About_Click(object sender, RoutedEventArgs e)
    {
        GitHubUpdateChecker.OpenRepository();
    }

    private void Clean_Click(object sender, RoutedEventArgs e)
    {
        var files = GetSelectedFiles();
        if (files.Length == 0)
        {
            MessageBox.Show(this, "Please select file(s) first", "Clean", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var ok = 0;
        var failed = 0;
        foreach (var path in files)
        {
            AppendLog("Cleaning " + path);
            var result = CleanFile(path, BackupCheckBox.IsChecked == true);
            foreach (var line in result.LogLines)
            {
                AppendLog(line);
            }

            if (result.Success)
            {
                ok++;
            }
            else
            {
                failed++;
            }
        }

        MessageBox.Show(this, "Clean completed\r\nOK: " + ok + "\r\nFailed/skipped: " + failed, "Clean", MessageBoxButton.OK, failed == 0 ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    private async void FindWinKey_Click(object sender, RoutedEventArgs e)
    {
        var files = GetSelectedFiles();
        if (files.Length == 0)
        {
            MessageBox.Show(this, "Please select file(s) first", "Find WinKey", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        FindWinKeyButton.IsEnabled = false;
        AppendLog("Find WinKey started");
        try
        {
            var result = await Task.Run(() => FindWinKeys(files));
            foreach (var line in result.LogLines)
            {
                AppendLog(line);
            }

            MessageBox.Show(this, "Find completed\r\nCandidates: " + result.Total + "\r\nFailed: " + result.Failed, "Find WinKey", MessageBoxButton.OK, result.Total > 0 && result.Failed == 0 ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        finally
        {
            FindWinKeyButton.IsEnabled = true;
        }
    }

    private static WinKeyFindResult FindWinKeys(string[] files)
    {
        var result = new WinKeyFindResult();
        foreach (var path in files)
        {
            result.LogLines.Add("Finding WinKey in " + path);
            try
            {
                if (!File.Exists(path))
                {
                    result.LogLines.Add("File does not exist: " + path);
                    result.Failed++;
                    continue;
                }

                var candidates = WinKeyFinder.Find(File.ReadAllBytes(path));
                if (candidates.Count == 0)
                {
                    result.LogLines.Add("No plaintext Windows product key candidate found");
                    continue;
                }

                result.Total += candidates.Count;
                foreach (var candidate in candidates)
                {
                    result.LogLines.Add(candidate.Key
                        + " | offset 0x" + candidate.Offset.ToString("X")
                        + " | " + candidate.Method
                        + " | " + candidate.Classification);
                }
            }
            catch (Exception ex)
            {
                result.Failed++;
                result.LogLines.Add("Find WinKey failed: " + ex.Message);
            }
        }

        return result;
    }

    private string[] GetSelectedFiles()
    {
        return _selectedFiles.Length > 0
            ? _selectedFiles
            : string.IsNullOrWhiteSpace(FilePathBox.Text) ? new string[0] : new[] { FilePathBox.Text.Trim() };
    }

    public static CleanResult CleanFile(string path, bool createBackup)
    {
        var log = new List<string>();
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return CleanResult.Fail("File does not exist: " + path, log);
        }

        try
        {
            var buffer = File.ReadAllBytes(path);
            var cutOffset = FindMetadataOffset(buffer);
            if (cutOffset < 0)
            {
                log.Add("No metadata marker found in the last " + FormatBytes(Math.Min(TailScanBytes, buffer.Length)));
                return CleanResult.Fail("No metadata marker found", log);
            }

            if (cutOffset == 0)
            {
                log.Add("Refusing to cut at offset 0");
                return CleanResult.Fail("Refusing to cut at offset 0", log);
            }

            if (createBackup)
            {
                var backupPath = NextBackupPath(path);
                File.Copy(path, backupPath);
                log.Add("Backup saved " + backupPath);
            }

            using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                stream.Write(buffer, 0, cutOffset);
            }

            log.Add("Removed " + FormatBytes(buffer.Length - cutOffset) + " from 0x" + cutOffset.ToString("X") + " to EOF");
            log.Add("Cleaned file size: " + FormatBytes(cutOffset));
            return CleanResult.Ok("metadata removed successfully", log);
        }
        catch (Exception ex)
        {
            log.Add("Clean failed: " + ex.Message);
            return CleanResult.Fail(ex.Message, log);
        }
    }

    private static int FindMetadataOffset(byte[] buffer)
    {
        var start = Math.Max(0, buffer.Length - TailScanBytes);
        return LastIndexOf(buffer, MetadataMarker, start);
    }

    private static int LastIndexOf(byte[] buffer, byte[] pattern, int start)
    {
        if (pattern.Length == 0 || pattern.Length > buffer.Length)
        {
            return -1;
        }

        for (var i = buffer.Length - pattern.Length; i >= start; i--)
        {
            var match = true;
            for (var j = 0; j < pattern.Length; j++)
            {
                if (buffer[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                return i;
            }
        }

        return -1;
    }

    private static string NextBackupPath(string path)
    {
        for (var index = 1; index < int.MaxValue; index++)
        {
            var backupPath = path + ".bak" + index;
            if (!File.Exists(backupPath))
            {
                return backupPath;
            }
        }

        throw new IOException("Too many backup files");
    }

    private void AppendLog(string message)
    {
        LogBox.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + message + Environment.NewLine);
        LogBox.ScrollToEnd();
    }

    private static string FormatBytes(int bytes)
    {
        if (bytes >= 1024 * 1024)
        {
            return (bytes / 1024d / 1024d).ToString("0.##") + " MB";
        }

        if (bytes >= 1024)
        {
            return (bytes / 1024d).ToString("0.##") + " KB";
        }

        return bytes + " bytes";
    }
}

public sealed class CleanResult
{
    private CleanResult(bool success, string message, List<string> logLines)
    {
        Success = success;
        Message = message;
        LogLines = logLines;
    }

    public bool Success { get; }
    public string Message { get; }
    public List<string> LogLines { get; }

    public static CleanResult Ok(string message, List<string> logLines)
    {
        return new CleanResult(true, message, logLines);
    }

    public static CleanResult Fail(string message, List<string> logLines)
    {
        return new CleanResult(false, message, logLines);
    }
}

public sealed class WinKeyFindResult
{
    public int Total { get; set; }
    public int Failed { get; set; }
    public List<string> LogLines { get; } = new List<string>();
}
}
