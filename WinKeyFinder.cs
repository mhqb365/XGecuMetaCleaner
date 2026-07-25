using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace XGecuMetaCleaner
{
public sealed class WinKeyCandidate
{
    public string Method { get; set; }
    public int Offset { get; set; }
    public string Key { get; set; }
    public int Length { get; set; }
    public string Classification { get; set; }
}

public static class WinKeyFinder
{
    private const int KeyLength = 29;
    private static readonly byte[] OemMarker =
    {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1D, 0x00, 0x00, 0x00
    };
    private static readonly string[] Anchors =
    {
        "Windows",
        "Product",
        "ProductKey",
        "DigitalProductId"
    };
    private static readonly Dictionary<string, string> KnownKeys =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "7H3HT-N36VD-XK866-8RV8Y-39M6M", "Win 10 RTM Core OEM:DM, EULA OEM" },
            { "TX9XD-98N7V-6WMQ6-BX7FG-H8Q99", "Windows 10/11 Home generic install key, Retail channel" },
            { "VK7JG-NPHTM-C97JM-9MPGT-3V66T", "Windows 10/11 Pro generic install key, Retail channel" },
            { "W269N-WFGWX-YVC9B-4J6C9-T83GX", "Windows 10/11 Pro generic install key, Volume KMS client" },
            { "NPPR9-FWDCX-D2C8J-H872K-2YT43", "Windows 10/11 Enterprise generic install key, Volume KMS client" },
            { "MH37W-N47XK-V7XM9-C7227-GCQG9", "Windows 10/11 Pro N generic install key, Retail channel" },
            { "NW6C2-QMPVW-D7KKK-3GKT6-VCFB2", "Windows 10/11 Education generic install key, Volume KMS client" },
            { "2WH4N-8QGBV-H22JP-CT43Q-MDWWJ", "Windows 10/11 Education N generic install key, Volume KMS client" }
        };

    public static List<WinKeyCandidate> Find(byte[] buffer)
    {
        var byOffset = new Dictionary<int, WinKeyCandidate>();
        if (buffer == null || buffer.Length < KeyLength)
        {
            return new List<WinKeyCandidate>();
        }

        AddBinaryMarkerMatches(buffer, byOffset);
        AddAsciiMarkerMatches(buffer, "MSDM", 512, "ACPI MSDM", byOffset);
        foreach (var anchor in Anchors)
        {
            AddAsciiMarkerMatches(buffer, anchor, 768, "Near " + anchor, byOffset);
        }

        AddRangeMatches(buffer, 0, buffer.Length, "Direct pattern", byOffset);

        var found = byOffset.Values.ToList();
        foreach (var candidate in found)
        {
            candidate.Classification = Classify(candidate.Key, candidate.Method);
        }

        return found
            .OrderBy(candidate => MethodPriority(candidate.Method))
            .ThenBy(candidate => candidate.Offset)
            .ToList();
    }

    private static void AddBinaryMarkerMatches(byte[] buffer, Dictionary<int, WinKeyCandidate> byOffset)
    {
        foreach (var markerOffset in FindAll(buffer, OemMarker, 0))
        {
            AddRangeMatches(buffer, markerOffset + OemMarker.Length, 256, "Hex marker", byOffset);
        }
    }

    private static void AddAsciiMarkerMatches(byte[] buffer, string marker, int windowLength, string method, Dictionary<int, WinKeyCandidate> byOffset)
    {
        var markerBytes = Encoding.ASCII.GetBytes(marker);
        foreach (var markerOffset in FindAll(buffer, markerBytes, 0))
        {
            AddRangeMatches(buffer, markerOffset, windowLength, method, byOffset);
        }
    }

    private static void AddRangeMatches(byte[] buffer, int start, int length, string method, Dictionary<int, WinKeyCandidate> byOffset)
    {
        if (start < 0 || start >= buffer.Length || length <= 0)
        {
            return;
        }

        var end = Math.Min(buffer.Length, start + length);
        for (var offset = start; offset <= end - KeyLength; offset++)
        {
            var key = TryReadKey(buffer, offset);
            if (key == null)
            {
                continue;
            }

            if (!byOffset.TryGetValue(offset, out var existing) || MethodPriority(method) < MethodPriority(existing.Method))
            {
                byOffset[offset] = new WinKeyCandidate
                {
                    Method = method,
                    Offset = offset,
                    Key = key,
                    Length = KeyLength
                };
            }
        }
    }

    private static string TryReadKey(byte[] buffer, int offset)
    {
        var chars = new char[KeyLength];
        for (var index = 0; index < KeyLength; index++)
        {
            var value = buffer[offset + index];
            if (index == 5 || index == 11 || index == 17 || index == 23)
            {
                if (value != (byte)'-')
                {
                    return null;
                }

                chars[index] = '-';
                continue;
            }

            if (!IsAsciiLetterOrDigit(value))
            {
                return null;
            }

            chars[index] = char.ToUpperInvariant((char)value);
        }

        var key = new string(chars);
        return IsValidCandidate(key) ? key : null;
    }

    private static bool IsValidCandidate(string key)
    {
        var compact = key.Replace("-", string.Empty);
        if (!compact.Any(char.IsLetter) || !compact.Any(char.IsDigit))
        {
            return false;
        }

        var groups = key.Split('-');
        if (groups.All(group => string.Equals(group, groups[0], StringComparison.Ordinal)))
        {
            return false;
        }

        return compact.Distinct().Count() >= 6;
    }

    private static bool IsAsciiLetterOrDigit(byte value)
    {
        return value >= (byte)'0' && value <= (byte)'9'
            || value >= (byte)'A' && value <= (byte)'Z'
            || value >= (byte)'a' && value <= (byte)'z';
    }

    private static IEnumerable<int> FindAll(byte[] buffer, byte[] pattern, int start)
    {
        if (pattern.Length == 0 || pattern.Length > buffer.Length)
        {
            yield break;
        }

        for (var offset = Math.Max(0, start); offset <= buffer.Length - pattern.Length; offset++)
        {
            var match = true;
            for (var index = 0; index < pattern.Length; index++)
            {
                if (buffer[offset + index] != pattern[index])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                yield return offset;
            }
        }
    }

    private static string Classify(string key, string method)
    {
        var pidGen = TryClassifyWithPidGenX(key);
        if (!string.IsNullOrWhiteSpace(pidGen))
        {
            return pidGen;
        }

        if (KnownKeys.TryGetValue(key, out var known))
        {
            return known;
        }

        if (string.Equals(method, "Hex marker", StringComparison.Ordinal)
            || string.Equals(method, "ACPI MSDM", StringComparison.Ordinal))
        {
            return "likely OEM:DM embedded key";
        }

        if (method.IndexOf("DigitalProductId", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            return "likely installed Windows product key";
        }

        if (method.StartsWith("Near ", StringComparison.Ordinal))
        {
            return "possible Windows product key";
        }

        return "product key candidate";
    }

    private static string TryClassifyWithPidGenX(string key)
    {
        try
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var pkeyConfigPath = Path.Combine(windows, "System32", "spp", "tokens", "pkeyconfig", "pkeyconfig.xrm-ms");
            if (!File.Exists(pkeyConfigPath))
            {
                return null;
            }

            var digitalProductId4 = new byte[0x04F8];
            digitalProductId4[0] = 0xF8;
            digitalProductId4[1] = 0x04;

            var result = PidGenX(key, pkeyConfigPath, "00000", 0, IntPtr.Zero, IntPtr.Zero, digitalProductId4);
            if (result != 0)
            {
                return null;
            }

            var strings = ReadPrintableUtf16Strings(digitalProductId4);
            var edition = strings.FirstOrDefault(IsEditionString);
            var eula = strings.FirstOrDefault(value =>
                string.Equals(value, "OEM", StringComparison.OrdinalIgnoreCase)
                || string.Equals(value, "Retail", StringComparison.OrdinalIgnoreCase)
                || string.Equals(value, "Volume", StringComparison.OrdinalIgnoreCase));
            var channel = ReadUtf16String(digitalProductId4, 1016, 128);

            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(edition))
            {
                parts.Add(edition);
            }

            if (!string.IsNullOrWhiteSpace(eula))
            {
                parts.Add(eula);
            }

            if (!string.IsNullOrWhiteSpace(channel))
            {
                parts.Add("EULA " + channel);
            }

            return parts.Count == 0 ? null : string.Join(", ", parts);
        }
        catch
        {
            return null;
        }
    }

    private static List<string> ReadPrintableUtf16Strings(byte[] buffer)
    {
        var values = new List<string>();
        var current = new StringBuilder();
        for (var offset = 0; offset + 1 < buffer.Length; offset += 2)
        {
            var value = BitConverter.ToUInt16(buffer, offset);
            if (value >= 0x20 && value <= 0x7E)
            {
                current.Append((char)value);
                continue;
            }

            AddPrintableString(values, current);
        }

        AddPrintableString(values, current);
        return values.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static void AddPrintableString(List<string> values, StringBuilder current)
    {
        if (current.Length >= 3)
        {
            values.Add(current.ToString().Trim());
        }

        current.Clear();
    }

    private static string ReadUtf16String(byte[] buffer, int offset, int length)
    {
        if (offset < 0 || length <= 0 || offset >= buffer.Length)
        {
            return null;
        }

        var count = Math.Min(length, buffer.Length - offset);
        var value = Encoding.Unicode.GetString(buffer, offset, count);
        var terminator = value.IndexOf('\0');
        if (terminator >= 0)
        {
            value = value.Substring(0, terminator);
        }

        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    private static bool IsEditionString(string value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.IndexOf("-", StringComparison.Ordinal) >= 0
            || value.IndexOf(".", StringComparison.Ordinal) >= 0
            || Guid.TryParse(value, out _))
        {
            return false;
        }

        return value.IndexOf("Core", StringComparison.OrdinalIgnoreCase) >= 0
            || value.IndexOf("Professional", StringComparison.OrdinalIgnoreCase) >= 0
            || value.IndexOf("Enterprise", StringComparison.OrdinalIgnoreCase) >= 0
            || value.IndexOf("Education", StringComparison.OrdinalIgnoreCase) >= 0
            || value.IndexOf("Server", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static int MethodPriority(string method)
    {
        if (string.Equals(method, "Hex marker", StringComparison.Ordinal))
        {
            return 0;
        }

        if (string.Equals(method, "ACPI MSDM", StringComparison.Ordinal))
        {
            return 1;
        }

        if (method != null && method.StartsWith("Near ", StringComparison.Ordinal))
        {
            return 2;
        }

        return 3;
    }

    [DllImport("pidgenx.dll", CharSet = CharSet.Unicode, EntryPoint = "PidGenX")]
    private static extern int PidGenX(
        string productKey,
        string pkeyConfigPath,
        string mpc,
        int unknownUsage,
        IntPtr activationId,
        IntPtr productId,
        [Out] byte[] digitalProductId4);
}
}
