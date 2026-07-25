using System;
using System.Diagnostics;
using System.Net.Http;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;

namespace XGecuMetaCleaner
{
public sealed class GitHubReleaseInfo
{
    public Version Version { get; set; }
    public string TagName { get; set; }
    public string Url { get; set; }
}

public static class GitHubUpdateChecker
{
    public const string RepositoryUrl = "https://github.com/mhqb365/XGecuMetaCleaner";
    private const string LatestReleaseApiUrl = "https://api.github.com/repos/mhqb365/XGecuMetaCleaner/releases/latest";

    public static Version CurrentVersion
    {
        get { return Assembly.GetExecutingAssembly().GetName().Version; }
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
            var version = ParseVersion(tagName);
            if (version == null || string.IsNullOrWhiteSpace(url))
            {
                return null;
            }

            return new GitHubReleaseInfo
            {
                Version = version,
                TagName = tagName,
                Url = url
            };
        }
    }

    public static bool IsNewerThanCurrent(GitHubReleaseInfo release)
    {
        return release != null && release.Version > NormalizeVersion(CurrentVersion);
    }

    public static async Task CheckForUpdatesAsync(Window owner)
    {
        try
        {
            var release = await GetLatestReleaseAsync();
            if (!IsNewerThanCurrent(release))
            {
                return;
            }

            var choice = MessageBox.Show(
                owner,
                "New version available: " + release.TagName + "\r\nCurrent version: " + NormalizeVersion(CurrentVersion) + "\r\n\r\nOpen GitHub release page?",
                "XGecu Meta Cleaner Update",
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);
            if (choice == MessageBoxResult.Yes)
            {
                OpenUrl(release.Url);
            }
        }
        catch
        {
            // Update check is best-effort; never block the app when offline or GitHub is unavailable.
        }
    }

    public static void OpenRepository()
    {
        OpenUrl(RepositoryUrl);
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
            ? NormalizeVersion(version)
            : null;
    }

    private static Version NormalizeVersion(Version version)
    {
        return new Version(
            Math.Max(0, version.Major),
            Math.Max(0, version.Minor),
            Math.Max(0, version.Build),
            Math.Max(0, version.Revision));
    }
}
}
