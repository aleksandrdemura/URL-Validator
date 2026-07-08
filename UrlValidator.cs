// UrlValidator.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;

class URLValidator
{
    private readonly HashSet<string> _allowedSchemes = new HashSet<string>
        { "http", "https", "ftp", "ftps", "ws", "wss", "mailto", "tel", "ssh" };
    private readonly HashSet<string> _dangerousSchemes = new HashSet<string>
        { "javascript", "data", "file", "vbscript" };
    private const int MaxUrlLength = 2048;
    private readonly Regex _hostnameRegex = new Regex(
        @"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.?[A-Za-z]{2,63}$",
        RegexOptions.Compiled
    );
    private readonly Regex _ipv4Regex = new Regex(
        @"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
        RegexOptions.Compiled
    );
    private readonly Regex _ipv6Regex = new Regex(
        @"^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})$",
        RegexOptions.Compiled
    );

    public bool CheckDNS { get; set; }
    public bool CheckHTTP { get; set; }
    public int Timeout { get; set; } = 5;
    public (int Total, int Valid, int Invalid) Stats { get; private set; }

    public URLValidator(bool checkDNS = false, bool checkHTTP = false, int timeout = 5)
    {
        CheckDNS = checkDNS;
        CheckHTTP = checkHTTP;
        Timeout = timeout;
        Stats = (0, 0, 0);
    }

    private (bool valid, string reason) ValidateScheme(string scheme)
    {
        if (string.IsNullOrEmpty(scheme))
            return (false, "Missing scheme");
        string lower = scheme.ToLowerInvariant();
        if (_dangerousSchemes.Contains(lower))
            return (false, $"Dangerous scheme blocked: {scheme}");
        if (!_allowedSchemes.Contains(lower))
            return (false, $"Unsupported scheme: {scheme}");
        return (true, "OK");
    }

    private (bool valid, string reason) ValidateHost(string host)
    {
        if (string.IsNullOrEmpty(host))
            return (false, "Missing host");
        if (host.Length > 253)
            return (false, "Host too long (>253)");
        if (host.Contains(':'))
        {
            if (_ipv6Regex.IsMatch(host))
                return (true, "OK (IPv6)");
            return (false, "Invalid IPv6 address");
        }
        if (_ipv4Regex.IsMatch(host))
            return (true, "OK (IPv4)");
        if (_hostnameRegex.IsMatch(host))
        {
            string[] parts = host.Split('.');
            if (parts.Length > 1)
            {
                string tld = parts[parts.Length - 1];
                if (tld.Length < 2 || tld.Length > 63)
                    return (false, $"Invalid TLD length: {tld.Length}");
            }
            return (true, "OK (domain)");
        }
        return (false, "Invalid host format");
    }

    private (bool valid, string reason) ValidatePort(string portStr)
    {
        if (string.IsNullOrEmpty(portStr))
            return (true, "OK (default port)");
        if (!int.TryParse(portStr, out int port) || port < 1 || port > 65535)
            return (false, $"Invalid port: {portStr}");
        return (true, $"OK (port {port})");
    }

    private (bool valid, string reason) ValidatePath(string path)
    {
        if (string.IsNullOrEmpty(path))
            return (true, "OK (empty path)");
        foreach (char ch in path)
        {
            if (ch < 32 || "\"<>|\\^`{}".Contains(ch))
                return (false, $"Illegal character in path: {ch}");
        }
        for (int i = 0; i < path.Length; i++)
        {
            if (path[i] == '%')
            {
                if (i + 2 >= path.Length)
                    return (false, "Incomplete percent-encoding");
                string hex = path.Substring(i + 1, 2);
                if (!System.Text.RegularExpressions.Regex.IsMatch(hex, @"^[0-9a-fA-F]{2}$"))
                    return (false, "Invalid percent-encoding");
            }
        }
        return (true, "OK");
    }

    private (bool valid, string reason) ValidateQuery(string query)
    {
        if (string.IsNullOrEmpty(query))
            return (true, "OK (empty query)");
        foreach (char ch in query)
        {
            if (ch < 32)
                return (false, $"Illegal character in query: {ch}");
        }
        for (int i = 0; i < query.Length; i++)
        {
            if (query[i] == '%')
            {
                if (i + 2 >= query.Length)
                    return (false, "Incomplete percent-encoding in query");
                string hex = query.Substring(i + 1, 2);
                if (!System.Text.RegularExpressions.Regex.IsMatch(hex, @"^[0-9a-fA-F]{2}$"))
                    return (false, "Invalid percent-encoding in query");
            }
        }
        return (true, "OK");
    }

    private (bool valid, string reason) ValidateFragment(string fragment)
    {
        if (string.IsNullOrEmpty(fragment))
            return (true, "OK (empty fragment)");
        foreach (char ch in fragment)
        {
            if (ch < 32 || "\"<>|\\^`{}".Contains(ch))
                return (false, $"Illegal character in fragment: {ch}");
        }
        return (true, "OK");
    }

    private bool CheckDNS(string host)
    {
        if (!CheckDNS) return true;
        try
        {
            Dns.GetHostEntry(host);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private bool CheckHTTPAvailability(string rawURL)
    {
        if (!CheckHTTP) return true;
        if (!rawURL.StartsWith("http://") && !rawURL.StartsWith("https://"))
            return true;
        try
        {
            var request = WebRequest.Create(rawURL);
            request.Method = "HEAD";
            request.Timeout = Timeout * 1000;
            using (var response = (HttpWebResponse)request.GetResponse())
            {
                return (int)response.StatusCode < 400;
            }
        }
        catch
        {
            return false;
        }
    }

    private string Normalize(string rawURL)
    {
        if (!Uri.TryCreate(rawURL, UriKind.Absolute, out Uri uri))
            return rawURL;
        // Lowercase scheme and host
        string scheme = uri.Scheme.ToLowerInvariant();
        string host = uri.Host.ToLowerInvariant();
        string path = uri.AbsolutePath;
        if (string.IsNullOrEmpty(path) && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment))
            path = "/";
        string query = uri.Query;
        string fragment = uri.Fragment;
        return $"{scheme}://{host}{(uri.Port != 80 && uri.Port != 443 ? ":" + uri.Port : "")}{path}{query}{fragment}";
    }

    public (bool valid, string reason, string normalized) Validate(string rawURL)
    {
        Stats.Total++;
        if (rawURL.Length > MaxUrlLength)
        {
            Stats.Invalid++;
            return (false, $"URL too long ({rawURL.Length} > {MaxUrlLength})", null);
        }
        if (!Uri.TryCreate(rawURL, UriKind.Absolute, out Uri parsed))
        {
            Stats.Invalid++;
            return (false, "Parse error", null);
        }
        // Scheme
        var schemeResult = ValidateScheme(parsed.Scheme);
        if (!schemeResult.valid)
        {
            Stats.Invalid++;
            return (false, "Scheme error: " + schemeResult.reason, null);
        }
        // Host
        var hostResult = ValidateHost(parsed.Host);
        if (!hostResult.valid)
        {
            Stats.Invalid++;
            return (false, "Host error: " + hostResult.reason, null);
        }
        // Port
        var portResult = ValidatePort(parsed.Port.ToString());
        if (!portResult.valid)
        {
            Stats.Invalid++;
            return (false, "Port error: " + portResult.reason, null);
        }
        // Path
        var pathResult = ValidatePath(parsed.AbsolutePath);
        if (!pathResult.valid)
        {
            Stats.Invalid++;
            return (false, "Path error: " + pathResult.reason, null);
        }
        // Query
        var queryResult = ValidateQuery(parsed.Query.TrimStart('?'));
        if (!queryResult.valid)
        {
            Stats.Invalid++;
            return (false, "Query error: " + queryResult.reason, null);
        }
        // Fragment
        var fragmentResult = ValidateFragment(parsed.Fragment.TrimStart('#'));
        if (!fragmentResult.valid)
        {
            Stats.Invalid++;
            return (false, "Fragment error: " + fragmentResult.reason, null);
        }
        // DNS
        if (CheckDNS && !CheckDNS(parsed.Host))
        {
            Stats.Invalid++;
            return (false, "Host does not resolve (DNS)", null);
        }
        // HTTP
        if (CheckHTTP && !CheckHTTPAvailability(rawURL))
        {
            Stats.Invalid++;
            return (false, "URL is not reachable (HTTP error)", null);
        }
        Stats.Valid++;
        string normalized = Normalize(rawURL);
        return (true, "All checks passed", normalized);
    }

    public List<(string url, bool valid, string reason, string normalized)> BatchValidate(string[] urls)
    {
        var results = new List<(string, bool, string, string)>();
        foreach (var u in urls)
        {
            string url = u.Trim();
            if (string.IsNullOrEmpty(url)) continue;
            var (valid, reason, normalized) = Validate(url);
            results.Add((url, valid, reason, normalized));
        }
        return results;
    }

    public void ShowStats()
    {
        Console.WriteLine($"\nStatistics: Total: {Stats.Total}, Valid: {Stats.Valid}, Invalid: {Stats.Invalid}");
    }

    static void Main()
    {
        var validator = new URLValidator(false, false, 5);
        Console.WriteLine("=== URL Validator ===");
        while (true)
        {
            Console.WriteLine("\n1. Validate single URL");
            Console.WriteLine("2. Validate from file");
            Console.WriteLine("3. Show statistics");
            Console.WriteLine($"4. Toggle DNS check (currently {(validator.CheckDNS ? "ON" : "OFF")})");
            Console.WriteLine($"5. Toggle HTTP check (currently {(validator.CheckHTTP ? "ON" : "OFF")})");
            Console.WriteLine("6. Exit");
            Console.Write("Choose: ");
            string choice = Console.ReadLine()?.Trim() ?? "";
            switch (choice)
            {
                case "1":
                    Console.Write("Enter URL: ");
                    string url = Console.ReadLine()?.Trim() ?? "";
                    var (valid, reason, normalized) = validator.Validate(url);
                    Console.WriteLine($"Valid: {valid}");
                    Console.WriteLine($"Details: {reason}");
                    if (normalized != null)
                        Console.WriteLine($"Normalized: {normalized}");
                    break;
                case "2":
                    Console.Write("Enter file path: ");
                    string fname = Console.ReadLine()?.Trim() ?? "";
                    if (!File.Exists(fname))
                    {
                        Console.WriteLine("File not found.");
                        break;
                    }
                    string[] lines = File.ReadAllLines(fname);
                    var results = validator.BatchValidate(lines);
                    Console.WriteLine("\nBatch results:");
                    foreach (var r in results)
                    {
                        string status = r.valid ? "✓" : "✗";
                        Console.WriteLine($"{status} {r.url}: {r.reason}");
                        if (r.normalized != null)
                            Console.WriteLine($"   Normalized: {r.normalized}");
                    }
                    break;
                case "3":
                    validator.ShowStats();
                    break;
                case "4":
                    validator.CheckDNS = !validator.CheckDNS;
                    Console.WriteLine("DNS check toggled.");
                    break;
                case "5":
                    validator.CheckHTTP = !validator.CheckHTTP;
                    Console.WriteLine("HTTP check toggled.");
                    break;
                case "6":
                    Console.WriteLine("Goodbye!");
                    return;
                default:
                    Console.WriteLine("Invalid choice.");
                    break;
            }
        }
    }
}
