// UrlValidator.java
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.regex.*;

public class UrlValidator {
    private static final Set<String> ALLOWED_SCHEMES = new HashSet<>(Arrays.asList(
        "http", "https", "ftp", "ftps", "ws", "wss", "mailto", "tel", "ssh"
    ));
    private static final Set<String> DANGEROUS_SCHEMES = new HashSet<>(Arrays.asList(
        "javascript", "data", "file", "vbscript"
    ));
    private static final int MAX_URL_LENGTH = 2048;
    private static final Pattern HOSTNAME_PATTERN = Pattern.compile(
        "^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\\.[A-Za-z0-9-]{1,63}(?<!-))*\\.?[A-Za-z]{2,63}$"
    );
    private static final Pattern IPV4_PATTERN = Pattern.compile(
        "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    );
    private static final Pattern IPV6_PATTERN = Pattern.compile(
        "^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})$"
    );

    private boolean checkDNS;
    private boolean checkHTTP;
    private int timeout;
    private int total, valid, invalid;

    public UrlValidator(boolean checkDNS, boolean checkHTTP, int timeout) {
        this.checkDNS = checkDNS;
        this.checkHTTP = checkHTTP;
        this.timeout = timeout;
        this.total = 0;
        this.valid = 0;
        this.invalid = 0;
    }

    private Result validateScheme(String scheme) {
        if (scheme == null || scheme.isEmpty())
            return new Result(false, "Missing scheme");
        String lower = scheme.toLowerCase();
        if (DANGEROUS_SCHEMES.contains(lower))
            return new Result(false, "Dangerous scheme blocked: " + scheme);
        if (!ALLOWED_SCHEMES.contains(lower))
            return new Result(false, "Unsupported scheme: " + scheme);
        return new Result(true, "OK");
    }

    private Result validateHost(String host) {
        if (host == null || host.isEmpty())
            return new Result(false, "Missing host");
        if (host.length() > 253)
            return new Result(false, "Host too long (>253)");
        if (host.contains(":")) {
            if (IPV6_PATTERN.matcher(host).matches())
                return new Result(true, "OK (IPv6)");
            return new Result(false, "Invalid IPv6 address");
        }
        if (IPV4_PATTERN.matcher(host).matches())
            return new Result(true, "OK (IPv4)");
        if (HOSTNAME_PATTERN.matcher(host).matches()) {
            String[] parts = host.split("\\.");
            if (parts.length > 1) {
                String tld = parts[parts.length - 1];
                if (tld.length() < 2 || tld.length() > 63)
                    return new Result(false, "Invalid TLD length: " + tld.length());
            }
            return new Result(true, "OK (domain)");
        }
        return new Result(false, "Invalid host format");
    }

    private Result validatePort(String portStr) {
        if (portStr == null || portStr.isEmpty())
            return new Result(true, "OK (default port)");
        try {
            int port = Integer.parseInt(portStr);
            if (port < 1 || port > 65535)
                return new Result(false, "Invalid port: " + portStr);
            return new Result(true, "OK (port " + port + ")");
        } catch (NumberFormatException e) {
            return new Result(false, "Invalid port: " + portStr);
        }
    }

    private Result validatePath(String path) {
        if (path == null || path.isEmpty())
            return new Result(true, "OK (empty path)");
        for (char ch : path.toCharArray()) {
            if (ch < 32 || "\"<>|\\^`{}".indexOf(ch) != -1)
                return new Result(false, "Illegal character in path: " + ch);
        }
        for (int i = 0; i < path.length(); i++) {
            if (path.charAt(i) == '%') {
                if (i + 2 >= path.length())
                    return new Result(false, "Incomplete percent-encoding");
                String hex = path.substring(i + 1, i + 3);
                if (!hex.matches("[0-9a-fA-F]{2}"))
                    return new Result(false, "Invalid percent-encoding");
            }
        }
        return new Result(true, "OK");
    }

    private Result validateQuery(String query) {
        if (query == null || query.isEmpty())
            return new Result(true, "OK (empty query)");
        for (char ch : query.toCharArray()) {
            if (ch < 32)
                return new Result(false, "Illegal character in query: " + ch);
        }
        for (int i = 0; i < query.length(); i++) {
            if (query.charAt(i) == '%') {
                if (i + 2 >= query.length())
                    return new Result(false, "Incomplete percent-encoding in query");
                String hex = query.substring(i + 1, i + 3);
                if (!hex.matches("[0-9a-fA-F]{2}"))
                    return new Result(false, "Invalid percent-encoding in query");
            }
        }
        return new Result(true, "OK");
    }

    private Result validateFragment(String fragment) {
        if (fragment == null || fragment.isEmpty())
            return new Result(true, "OK (empty fragment)");
        for (char ch : fragment.toCharArray()) {
            if (ch < 32 || "\"<>|\\^`{}".indexOf(ch) != -1)
                return new Result(false, "Illegal character in fragment: " + ch);
        }
        return new Result(true, "OK");
    }

    private boolean checkDNS(String host) {
        if (!checkDNS) return true;
        try {
            InetAddress.getByName(host);
            return true;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private boolean checkHTTPAvailability(String rawURL) {
        if (!checkHTTP) return true;
        if (!rawURL.startsWith("http://") && !rawURL.startsWith("https://"))
            return true;
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(rawURL).openConnection();
            conn.setRequestMethod("HEAD");
            conn.setConnectTimeout(timeout * 1000);
            conn.setReadTimeout(timeout * 1000);
            int code = conn.getResponseCode();
            conn.disconnect();
            return code < 400;
        } catch (Exception e) {
            return false;
        }
    }

    private String normalize(String rawURL) throws URISyntaxException {
        URI uri = new URI(rawURL);
        String scheme = uri.getScheme().toLowerCase();
        String host = uri.getHost().toLowerCase();
        int port = uri.getPort();
        String path = uri.getPath();
        if ((path == null || path.isEmpty()) && uri.getQuery() == null && uri.getFragment() == null)
            path = "/";
        String query = uri.getQuery();
        String fragment = uri.getFragment();
        String portStr = (port != -1 && port != 80 && port != 443) ? ":" + port : "";
        String queryStr = (query != null) ? "?" + query : "";
        String fragmentStr = (fragment != null) ? "#" + fragment : "";
        return scheme + "://" + host + portStr + (path != null ? path : "") + queryStr + fragmentStr;
    }

    public Result validate(String rawURL) {
        total++;
        if (rawURL.length() > MAX_URL_LENGTH) {
            invalid++;
            return new Result(false, "URL too long (" + rawURL.length() + " > " + MAX_URL_LENGTH + ")", null);
        }
        URL parsed;
        try {
            parsed = new URL(rawURL);
        } catch (MalformedURLException e) {
            invalid++;
            return new Result(false, "Parse error: " + e.getMessage(), null);
        }
        // Scheme
        Result schemeResult = validateScheme(parsed.getProtocol());
        if (!schemeResult.valid) {
            invalid++;
            return new Result(false, "Scheme error: " + schemeResult.reason, null);
        }
        // Host
        if (parsed.getHost() == null) {
            invalid++;
            return new Result(false, "Missing host", null);
        }
        Result hostResult = validateHost(parsed.getHost());
        if (!hostResult.valid) {
            invalid++;
            return new Result(false, "Host error: " + hostResult.reason, null);
        }
        // Port
        int port = parsed.getPort();
        Result portResult = validatePort(port == -1 ? "" : String.valueOf(port));
        if (!portResult.valid) {
            invalid++;
            return new Result(false, "Port error: " + portResult.reason, null);
        }
        // Path
        Result pathResult = validatePath(parsed.getPath());
        if (!pathResult.valid) {
            invalid++;
            return new Result(false, "Path error: " + pathResult.reason, null);
        }
        // Query
        Result queryResult = validateQuery(parsed.getQuery());
        if (!queryResult.valid) {
            invalid++;
            return new Result(false, "Query error: " + queryResult.reason, null);
        }
        // Fragment
        Result fragmentResult = validateFragment(parsed.getRef());
        if (!fragmentResult.valid) {
            invalid++;
            return new Result(false, "Fragment error: " + fragmentResult.reason, null);
        }
        // DNS
        if (checkDNS && !checkDNS(parsed.getHost())) {
            invalid++;
            return new Result(false, "Host does not resolve (DNS)", null);
        }
        // HTTP
        if (checkHTTP && !checkHTTPAvailability(rawURL)) {
            invalid++;
            return new Result(false, "URL is not reachable (HTTP error)", null);
        }
        valid++;
        try {
            String normalized = normalize(rawURL);
            return new Result(true, "All checks passed", normalized);
        } catch (Exception e) {
            return new Result(true, "All checks passed (but normalization failed)", rawURL);
        }
    }

    public List<Result> batchValidate(String[] urls) {
        List<Result> results = new ArrayList<>();
        for (String u : urls) {
            String url = u.trim();
            if (url.isEmpty()) continue;
            Result r = validate(url);
            r.setUrl(url);
            results.add(r);
        }
        return results;
    }

    public void showStats() {
        System.out.printf("\nStatistics: Total: %d, Valid: %d, Invalid: %d\n", total, valid, invalid);
    }

    static class Result {
        boolean valid;
        String reason;
        String normalized;
        String url;
        Result(boolean v, String r) { valid = v; reason = r; }
        Result(boolean v, String r, String n) { valid = v; reason = r; normalized = n; }
        void setUrl(String u) { url = u; }
    }

    public static void main(String[] args) throws IOException {
        UrlValidator validator = new UrlValidator(false, false, 5);
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("=== URL Validator ===");
        while (true) {
            System.out.println("\n1. Validate single URL");
            System.out.println("2. Validate from file");
            System.out.println("3. Show statistics");
            System.out.printf("4. Toggle DNS check (currently %s)\n", validator.checkDNS ? "ON" : "OFF");
            System.out.printf("5. Toggle HTTP check (currently %s)\n", validator.checkHTTP ? "ON" : "OFF");
            System.out.println("6. Exit");
            System.out.print("Choose: ");
            String choice = reader.readLine().trim();
            switch (choice) {
                case "1":
                    System.out.print("Enter URL: ");
                    String url = reader.readLine().trim();
                    Result res = validator.validate(url);
                    System.out.println("Valid: " + res.valid);
                    System.out.println("Details: " + res.reason);
                    if (res.normalized != null)
                        System.out.println("Normalized: " + res.normalized);
                    break;
                case "2":
                    System.out.print("Enter file path: ");
                    String fname = reader.readLine().trim();
                    File file = new File(fname);
                    if (!file.exists()) {
                        System.out.println("File not found.");
                        break;
                    }
                    List<String> lines = new ArrayList<>();
                    try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                        String line;
                        while ((line = br.readLine()) != null) {
                            lines.add(line);
                        }
                    }
                    String[] arr = lines.toArray(new String[0]);
                    List<Result> results = validator.batchValidate(arr);
                    System.out.println("\nBatch results:");
                    for (Result r : results) {
                        String status = r.valid ? "✓" : "✗";
                        System.out.printf("%s %s: %s\n", status, r.url, r.reason);
                        if (r.normalized != null)
                            System.out.printf("   Normalized: %s\n", r.normalized);
                    }
                    break;
                case "3":
                    validator.showStats();
                    break;
                case "4":
                    validator.checkDNS = !validator.checkDNS;
                    System.out.println("DNS check toggled.");
                    break;
                case "5":
                    validator.checkHTTP = !validator.checkHTTP;
                    System.out.println("HTTP check toggled.");
                    break;
                case "6":
                    System.out.println("Goodbye!");
                    return;
                default:
                    System.out.println("Invalid choice.");
            }
        }
    }
}
