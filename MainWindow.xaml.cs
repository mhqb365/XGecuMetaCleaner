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
    private const int MinRomSizeBytes = 512 * 1024;
    private static readonly byte[] MetadataMarker =
    {
        0x2D, 0x43, 0x6F, 0x6E, 0x66, 0x69, 0x67, 0x75,
        0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2D, 0x00
    };
    private string _selectedFile;

    public MainWindow()
    {
        InitializeComponent();
        Title = "XGecu Meta Cleaner v" + GitHubUpdateChecker.CurrentDisplayVersion;
        AppendLog("Ready");
        Loaded += MainWindow_Loaded;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            var release = await GitHubUpdateChecker.GetLatestReleaseAsync();
            if (GitHubUpdateChecker.IsNewerThanCurrent(release))
            {
                AppendLog("New version available: " + GitHubUpdateChecker.FormatVersion(release.Version) + " | " + release.Url);
                if (string.IsNullOrWhiteSpace(release.AssetUrl))
                {
                    AppendLog("Update skipped: no .zip release asset found");
                    return;
                }

                if (GitHubUpdateChecker.WasUpdateAlreadyAttempted(release))
                {
                    AppendLog("Update skipped: already attempted this release. Check the release package version.");
                    return;
                }

                GitHubUpdateChecker.MarkUpdateAttempt(release);
                AppendLog(await GitHubUpdateChecker.DownloadInstallAndRestartAsync(release));
                Application.Current.Shutdown();
            }
        }
        catch
        {
            AppendLog("Update check skipped: GitHub is unavailable");
        }
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Binary files|*.bin;*.rom;*.fd;*.cap;*.dat|All files|*.*",
            Multiselect = false
        };

        if (dialog.ShowDialog(this) == true)
        {
            _selectedFile = dialog.FileName;
            FilePathBox.Text = _selectedFile;
            AppendLog("Selected " + _selectedFile);
        }
    }

    private void ClearSelection_Click(object sender, RoutedEventArgs e)
    {
        _selectedFile = null;
        FilePathBox.Clear();
        AppendLog("Selection cleared");
    }

    private void About_Click(object sender, RoutedEventArgs e)
    {
        GitHubUpdateChecker.OpenRepository();
    }

    private void ClearLog_Click(object sender, RoutedEventArgs e)
    {
        LogBox.Clear();
    }

    private void SaveLog_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(LogBox.Text))
        {
            AppendLog("Save log skipped: log is empty");
            return;
        }

        var dialog = new SaveFileDialog
        {
            FileName = "XGecuMetaCleaner-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".log",
            Filter = "Log files|*.log|Text files|*.txt|All files|*.*"
        };

        if (dialog.ShowDialog(this) != true)
        {
            AppendLog("Save log canceled");
            return;
        }

        try
        {
            File.WriteAllText(dialog.FileName, LogBox.Text);
            AppendLog("Log saved " + dialog.FileName);
        }
        catch (Exception ex)
        {
            AppendLog("Save log failed: " + ex.Message);
        }
    }

    private void Clean_Click(object sender, RoutedEventArgs e)
    {
        var files = GetSelectedFiles();
        if (files.Length == 0)
        {
            AppendLog("Clean skipped: please select file(s) first");
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

        AppendLog("Clean completed | OK: " + ok + " | Failed/skipped: " + failed);
    }

    private async void FindWinKey_Click(object sender, RoutedEventArgs e)
    {
        var files = GetSelectedFiles();
        if (files.Length == 0)
        {
            AppendLog("Find WinKey skipped: please select file(s) first");
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

            AppendLog("Find completed | Candidates: " + result.Total + " | Failed: " + result.Failed);
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
                    result.LogLines.Add(FormatWinKeyCandidate(candidate));
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

    private static string FormatWinKeyCandidate(WinKeyCandidate candidate)
    {
        return "Found at offset 0x" + candidate.Offset.ToString("X")
            + " | " + candidate.Key
            + " | " + candidate.Classification;
    }

    private string[] GetSelectedFiles()
    {
        return !string.IsNullOrWhiteSpace(_selectedFile)
            ? new[] { _selectedFile }
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
            var cleanOffset = FindCleanOffset(buffer);
            var cutOffset = cleanOffset.Offset;
            if (cutOffset < 0)
            {
                log.Add("No size overflow or metadata marker found");
                return CleanResult.Fail("No metadata found", log);
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
            log.Add("Clean method: " + cleanOffset.Method);
            log.Add("Cleaned file size: " + FormatBytes(cutOffset));
            return CleanResult.Ok("metadata removed successfully", log);
        }
        catch (Exception ex)
        {
            log.Add("Clean failed: " + ex.Message);
            return CleanResult.Fail(ex.Message, log);
        }
    }

    private static CleanOffset FindCleanOffset(byte[] buffer)
    {
        var sizeOffset = FindSizeOverflowOffset(buffer.Length);
        if (sizeOffset > 0)
        {
            return new CleanOffset(sizeOffset, "size overflow");
        }

        var markerOffset = FindMetadataOffset(buffer);
        return markerOffset < 0
            ? CleanOffset.NotFound()
            : new CleanOffset(markerOffset, "metadata marker");
    }

    private static int FindSizeOverflowOffset(int fileSize)
    {
        var size = MinRomSizeBytes;
        while (size <= fileSize / 2)
        {
            size *= 2;
        }

        return fileSize > size ? size : -1;
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

public sealed class CleanOffset
{
    public CleanOffset(int offset, string method)
    {
        Offset = offset;
        Method = method;
    }

    public int Offset { get; }
    public string Method { get; }

    public static CleanOffset NotFound()
    {
        return new CleanOffset(-1, null);
    }
}

public sealed class WinKeyFindResult
{
    public int Total { get; set; }
    public int Failed { get; set; }
    public List<string> LogLines { get; } = new List<string>();
}
}
