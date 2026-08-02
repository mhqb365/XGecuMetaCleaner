using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace XGecuMetaCleaner
{
public sealed class GitHubReleaseInfo
{
    public Version Version { get; set; }
    public string TagName { get; set; }
    public string Url { get; set; }
    public string AssetName { get; set; }
    public string AssetUrl { get; set; }
}

public static class GitHubUpdateChecker
{
    public const string RepositoryUrl = "https://github.com/mhqb365/XGecuMetaCleaner";
    public const string AppExeName = "XGecuMetaCleaner.exe";
    private const string LatestReleaseApiUrl = "https://api.github.com/repos/mhqb365/XGecuMetaCleaner/releases/latest";

    public static Version CurrentVersion
    {
        get { return Assembly.GetExecutingAssembly().GetName().Version; }
    }

    public static string CurrentDisplayVersion
    {
        get { return FormatVersion(CurrentVersion); }
    }

    public static async Task<GitHubReleaseInfo> GetLatestReleaseAsync()
    {
        using (var client = new HttpClient())
        {
            client.Timeout = TimeSpan.FromSeconds(8);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("XGecuMetaCleaner/" + CurrentVersion);
            var json = await client.GetStringAsync(LatestReleaseApiUrl);
            var tagName = MatchJsonString(json, "tag_name");
            var url = MatchJsonString(json, "html_url");
            var asset = MatchZipAsset(json);
            var version = ParseVersion(tagName);
            if (version == null || string.IsNullOrWhiteSpace(url))
            {
                return null;
            }

            return new GitHubReleaseInfo
            {
                Version = version,
                TagName = tagName,
                Url = url,
                AssetName = asset.Name,
                AssetUrl = asset.Url
            };
        }
    }

    public static bool IsNewerThanCurrent(GitHubReleaseInfo release)
    {
        return release != null && release.Version > NormalizeVersion3(CurrentVersion);
    }

    public static void OpenRepository()
    {
        OpenUrl(RepositoryUrl);
    }

    public static async Task<string> DownloadInstallAndRestartAsync(GitHubReleaseInfo release)
    {
        if (release == null || string.IsNullOrWhiteSpace(release.AssetUrl))
        {
            return "No .zip release asset found";
        }

        var updateRoot = Path.Combine(Path.GetTempPath(), "XGecuMetaCleanerUpdate-" + Guid.NewGuid().ToString("N"));
        var zipPath = Path.Combine(updateRoot, release.AssetName);
        var extractPath = Path.Combine(updateRoot, "extracted");
        Directory.CreateDirectory(updateRoot);
        Directory.CreateDirectory(extractPath);

        using (var client = new HttpClient())
        {
            client.Timeout = TimeSpan.FromMinutes(3);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("XGecuMetaCleaner/" + CurrentVersion);
            var bytes = await client.GetByteArrayAsync(release.AssetUrl);
            File.WriteAllBytes(zipPath, bytes);
        }

        ZipFile.ExtractToDirectory(zipPath, extractPath);
        var sourcePath = FindUpdateSourcePath(extractPath);
        var exePath = Assembly.GetExecutingAssembly().Location;
        var appPath = Path.GetDirectoryName(exePath);
        var launchPath = Path.Combine(appPath, AppExeName);
        var scriptPath = Path.Combine(updateRoot, "finish-update.cmd");
        File.WriteAllText(scriptPath, CreateUpdateScript(Process.GetCurrentProcess().Id, sourcePath, appPath, launchPath, exePath, updateRoot));

        Process.Start(new ProcessStartInfo
        {
            FileName = scriptPath,
            UseShellExecute = true,
            WindowStyle = ProcessWindowStyle.Hidden
        });

        return "Update downloaded. Restarting with " + AppExeName;
    }

    private static void OpenUrl(string url)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = url,
            UseShellExecute = true
        });
    }

    private static string MatchJsonString(string json, string propertyName)
    {
        var match = Regex.Match(json, "\"" + Regex.Escape(propertyName) + "\"\\s*:\\s*\"(?<value>(?:\\\\.|[^\"])*)\"");
        return match.Success ? Regex.Unescape(match.Groups["value"].Value) : null;
    }

    private static ReleaseAsset MatchZipAsset(string json)
    {
        var assets = new List<ReleaseAsset>();
        foreach (Match match in Regex.Matches(json, "\"browser_download_url\"\\s*:\\s*\"(?<url>(?:\\\\.|[^\"])*)\"", RegexOptions.Singleline))
        {
            var url = Regex.Unescape(match.Groups["url"].Value);
            var name = Path.GetFileName(new Uri(url).AbsolutePath);
            if (name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)
                && url.IndexOf("/zipball/", StringComparison.OrdinalIgnoreCase) < 0)
            {
                assets.Add(new ReleaseAsset
                {
                    Name = name,
                    Url = url
                });
            }
        }

        return assets
            .OrderByDescending(asset => asset.Name.IndexOf("XGecuMetaCleaner", StringComparison.OrdinalIgnoreCase) >= 0)
            .FirstOrDefault() ?? new ReleaseAsset();
    }

    private static Version ParseVersion(string tagName)
    {
        if (string.IsNullOrWhiteSpace(tagName))
        {
            return null;
        }

        var value = tagName.Trim();
        if (value.StartsWith("v", StringComparison.OrdinalIgnoreCase))
        {
            value = value.Substring(1);
        }

        var match = Regex.Match(value, "\\d+(?:\\.\\d+){0,3}");
        return match.Success && Version.TryParse(match.Value, out var version)
            ? NormalizeVersion3(version)
            : null;
    }

    private static Version NormalizeVersion3(Version version)
    {
        return new Version(
            Math.Max(0, version.Major),
            Math.Max(0, version.Minor),
            Math.Max(0, version.Build));
    }

    public static string FormatVersion(Version version)
    {
        var normalized = NormalizeVersion3(version);
        return normalized.Major + "." + normalized.Minor + "." + normalized.Build;
    }

    private static string FindUpdateSourcePath(string extractPath)
    {
        if (File.Exists(Path.Combine(extractPath, AppExeName)))
        {
            return extractPath;
        }

        foreach (var directory in Directory.GetDirectories(extractPath, "*", SearchOption.AllDirectories))
        {
            if (File.Exists(Path.Combine(directory, AppExeName)))
            {
                return directory;
            }
        }

        var currentExeName = Path.GetFileName(Assembly.GetExecutingAssembly().Location);
        if (File.Exists(Path.Combine(extractPath, currentExeName)))
        {
            return extractPath;
        }

        foreach (var directory in Directory.GetDirectories(extractPath, "*", SearchOption.AllDirectories))
        {
            if (File.Exists(Path.Combine(directory, currentExeName)))
            {
                return directory;
            }
        }

        return extractPath;
    }

    private static string CreateUpdateScript(int processId, string sourcePath, string appPath, string launchPath, string oldExePath, string updateRoot)
    {
        return "@echo off\r\n"
            + "setlocal\r\n"
            + "set \"PID=" + processId + "\"\r\n"
            + ":wait\r\n"
            + "tasklist /FI \"PID eq %PID%\" | find \"%PID%\" >nul\r\n"
            + "if not errorlevel 1 (\r\n"
            + "  timeout /t 1 /nobreak >nul\r\n"
            + "  goto wait\r\n"
            + ")\r\n"
            + "robocopy \"" + sourcePath + "\" \"" + appPath + "\" /E /NFL /NDL /NJH /NJS /NC /NS >nul\r\n"
            + "if exist \"" + launchPath + "\" (\r\n"
            + "  start \"\" \"" + launchPath + "\"\r\n"
            + ") else (\r\n"
            + "  start \"\" \"" + oldExePath + "\"\r\n"
            + ")\r\n"
            + "rmdir /s /q \"" + updateRoot + "\"\r\n"
            + "del \"%~f0\"\r\n";
    }

    private sealed class ReleaseAsset
    {
        public string Name { get; set; }
        public string Url { get; set; }
    }
}
}
