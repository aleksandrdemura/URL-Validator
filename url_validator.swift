// url_validator.swift
import Foundation
import Network

class URLValidator {
    private let allowedSchemes: Set<String> = ["http", "https", "ftp", "ftps", "ws", "wss", "mailto", "tel", "ssh"]
    private let dangerousSchemes: Set<String> = ["javascript", "data", "file", "vbscript"]
    private let maxURLLength = 2048
    private let hostnameRegex = try! NSRegularExpression(
        pattern: #"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.?[A-Za-z]{2,63}$"#
    )
    private let ipv4Regex = try! NSRegularExpression(
        pattern: #"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"#
    )
    private let ipv6Regex = try! NSRegularExpression(
        pattern: #"^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})$"#
    )

    var checkDNS: Bool
    var checkHTTP: Bool
    var timeout: Int
    private(set) var stats: (total: Int, valid: Int, invalid: Int) = (0, 0, 0)

    init(checkDNS: Bool = false, checkHTTP: Bool = false, timeout: Int = 5) {
        self.checkDNS = checkDNS
        self.checkHTTP = checkHTTP
        self.timeout = timeout
    }

    func validateScheme(_ scheme: String) -> (valid: Bool, reason: String) {
        if scheme.isEmpty { return (false, "Missing scheme") }
        let lower = scheme.lowercased()
        if dangerousSchemes.contains(lower) {
            return (false, "Dangerous scheme blocked: \(scheme)")
        }
        if !allowedSchemes.contains(lower) {
            return (false, "Unsupported scheme: \(scheme)")
        }
        return (true, "OK")
    }

    func validateHost(_ host: String) -> (valid: Bool, reason: String) {
        if host.isEmpty { return (false, "Missing host") }
        if host.count > 253 { return (false, "Host too long (>253)") }
        if host.contains(":") {
            let range = NSRange(host.startIndex..., in: host)
            if ipv6Regex.firstMatch(in: host, range: range) != nil {
                return (true, "OK (IPv6)")
            }
            return (false, "Invalid IPv6 address")
        }
        let range = NSRange(host.startIndex..., in: host)
        if ipv4Regex.firstMatch(in: host, range: range) != nil {
            return (true, "OK (IPv4)")
        }
        if hostnameRegex.firstMatch(in: host, range: range) != nil {
            let parts = host.split(separator: ".")
            if parts.count > 1 {
                let tld = String(parts.last!)
                if tld.count < 2 || tld.count > 63 {
                    return (false, "Invalid TLD length: \(tld.count)")
                }
            }
            return (true, "OK (domain)")
        }
        return (false, "Invalid host format")
    }

    func validatePort(_ portStr: String?) -> (valid: Bool, reason: String) {
        guard let portStr = portStr, !portStr.isEmpty else {
            return (true, "OK (default port)")
        }
        guard let port = Int(portStr), port >= 1 && port <= 65535 else {
            return (false, "Invalid port: \(portStr ?? "nil")")
        }
        return (true, "OK (port \(port))")
    }

    func validatePath(_ path: String) -> (valid: Bool, reason: String) {
        if path.isEmpty { return (true, "OK (empty path)") }
        for ch in path {
            if ch.unicodeScalars.first!.value < 32 || "\"<>|\\^`{}".contains(ch) {
                return (false, "Illegal character in path: \(ch)")
            }
        }
        var i = path.startIndex
        while i < path.endIndex {
            if path[i] == "%" {
                let nextIndex = path.index(i, offsetBy: 1)
                let nextNextIndex = path.index(i, offsetBy: 2)
                guard nextNextIndex < path.endIndex else {
                    return (false, "Incomplete percent-encoding")
                }
                let hex = String(path[nextIndex..<path.index(i, offsetBy: 3)])
                if !hex.range(of: "^[0-9a-fA-F]{2}$", options: .regularExpression)!.isEmpty {
                    return (false, "Invalid percent-encoding")
                }
            }
            i = path.index(after: i)
        }
        return (true, "OK")
    }

    func validateQuery(_ query: String) -> (valid: Bool, reason: String) {
        if query.isEmpty { return (true, "OK (empty query)") }
        for ch in query {
            if ch.unicodeScalars.first!.value < 32 {
                return (false, "Illegal character in query: \(ch)")
            }
        }
        var i = query.startIndex
        while i < query.endIndex {
            if query[i] == "%" {
                let nextIndex = query.index(i, offsetBy: 1)
                let nextNextIndex = query.index(i, offsetBy: 2)
                guard nextNextIndex < query.endIndex else {
                    return (false, "Incomplete percent-encoding in query")
                }
                let hex = String(query[nextIndex..<query.index(i, offsetBy: 3)])
                if !hex.range(of: "^[0-9a-fA-F]{2}$", options: .regularExpression)!.isEmpty {
                    return (false, "Invalid percent-encoding in query")
                }
            }
            i = query.index(after: i)
        }
        return (true, "OK")
    }

    func validateFragment(_ fragment: String) -> (valid: Bool, reason: String) {
        if fragment.isEmpty { return (true, "OK (empty fragment)") }
        for ch in fragment {
            if ch.unicodeScalars.first!.value < 32 || "\"<>|\\^`{}".contains(ch) {
                return (false, "Illegal character in fragment: \(ch)")
            }
        }
        return (true, "OK")
    }

    func checkDNS(_ host: String) -> Bool {
        guard checkDNS else { return true }
        let host = NWEndpoint.Host(host)
        let semaphore = DispatchSemaphore(value: 0)
        var resolved = false
        // Use DNSService or CFHost? Since Network framework doesn't provide direct DNS lookup, we use a workaround: try to get IP via CFHost.
        let cfHost = CFHostCreateWithName(kCFAllocatorDefault, host as CFString).takeRetainedValue()
        if CFHostStartInfoResolution(cfHost, .addresses, nil) {
            resolved = true
        }
        return resolved
    }

    func checkHTTPAvailability(_ rawURL: String) -> Bool {
        guard checkHTTP else { return true }
        guard rawURL.hasPrefix("http://") || rawURL.hasPrefix("https://") else { return true }
        guard let url = URL(string: rawURL) else { return false }
        let semaphore = DispatchSemaphore(value: 0)
        var available = false
        let task = URLSession.shared.dataTask(with: url) { _, response, error in
            if let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode < 400 {
                available = true
            }
            semaphore.signal()
        }
        task.resume()
        _ = semaphore.wait(timeout: .now() + .seconds(timeout))
        task.cancel()
        return available
    }

    func normalize(_ rawURL: String) -> String? {
        guard let url = URL(string: rawURL) else { return nil }
        var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        components?.scheme = components?.scheme?.lowercased()
        components?.host = components?.host?.lowercased()
        if components?.path == nil || components?.path == "" {
            if components?.query == nil && components?.fragment == nil {
                components?.path = "/"
            }
        }
        return components?.string
    }

    func validate(_ rawURL: String) -> (valid: Bool, reason: String, normalized: String?) {
        stats.total += 1
        if rawURL.count > maxURLLength {
            stats.invalid += 1
            return (false, "URL too long (\(rawURL.count) > \(maxURLLength))", nil)
        }
        guard let url = URL(string: rawURL) else {
            stats.invalid += 1
            return (false, "Parse error", nil)
        }
        // Scheme
        let schemeResult = validateScheme(url.scheme ?? "")
        if !schemeResult.valid {
            stats.invalid += 1
            return (false, "Scheme error: \(schemeResult.reason)", nil)
        }
        // Host
        guard let host = url.host else {
            stats.invalid += 1
            return (false, "Missing host", nil)
        }
        let hostResult = validateHost(host)
        if !hostResult.valid {
            stats.invalid += 1
            return (false, "Host error: \(hostResult.reason)", nil)
        }
        // Port
        let portResult = validatePort(url.port.map(String.init))
        if !portResult.valid {
            stats.invalid += 1
            return (false, "Port error: \(portResult.reason)", nil)
        }
        // Path
        let pathResult = validatePath(url.path)
        if !pathResult.valid {
            stats.invalid += 1
            return (false, "Path error: \(pathResult.reason)", nil)
        }
        // Query
        let queryResult = validateQuery(url.query ?? "")
        if !queryResult.valid {
            stats.invalid += 1
            return (false, "Query error: \(queryResult.reason)", nil)
        }
        // Fragment
        let fragmentResult = validateFragment(url.fragment ?? "")
        if !fragmentResult.valid {
            stats.invalid += 1
            return (false, "Fragment error: \(fragmentResult.reason)", nil)
        }
        // DNS
        if checkDNS && !checkDNS(host) {
            stats.invalid += 1
            return (false, "Host does not resolve (DNS)", nil)
        }
        // HTTP
        if checkHTTP && !checkHTTPAvailability(rawURL) {
            stats.invalid += 1
            return (false, "URL is not reachable (HTTP error)", nil)
        }
        stats.valid += 1
        let normalized = normalize(rawURL)
        return (true, "All checks passed", normalized)
    }

    func batchValidate(_ urls: [String]) -> [(url: String, valid: Bool, reason: String, normalized: String?)] {
        var results: [(String, Bool, String, String?)] = []
        for u in urls {
            let url = u.trimmingCharacters(in: .whitespaces)
            if url.isEmpty { continue }
            let (valid, reason, normalized) = validate(url)
            results.append((url, valid, reason, normalized))
        }
        return results
    }

    func showStats() {
        print("\nStatistics: Total: \(stats.total), Valid: \(stats.valid), Invalid: \(stats.invalid)")
    }
}

func main() {
    let validator = URLValidator(checkDNS: false, checkHTTP: false)
    print("=== URL Validator ===")
    while true {
        print("\n1. Validate single URL")
        print("2. Validate from file")
        print("3. Show statistics")
        print("4. Toggle DNS check (currently \(validator.checkDNS ? "ON" : "OFF"))")
        print("5. Toggle HTTP check (currently \(validator.checkHTTP ? "ON" : "OFF"))")
        print("6. Exit")
        print("Choose: ", terminator: "")
        guard let choice = readLine()?.trimmingCharacters(in: .whitespaces) else { continue }
        switch choice {
        case "1":
            print("Enter URL: ", terminator: "")
            guard let url = readLine()?.trimmingCharacters(in: .whitespaces) else { break }
            let (valid, reason, normalized) = validator.validate(url)
            print("Valid: \(valid)")
            print("Details: \(reason)")
            if let norm = normalized { print("Normalized: \(norm)") }
        case "2":
            print("Enter file path: ", terminator: "")
            guard let fname = readLine()?.trimmingCharacters(in: .whitespaces) else { break }
            let fileURL = URL(fileURLWithPath: fname)
            guard let content = try? String(contentsOf: fileURL, encoding: .utf8) else {
                print("File not found or unreadable.")
                break
            }
            let urls = content.components(separatedBy: .newlines)
            let results = validator.batchValidate(urls)
            print("\nBatch results:")
            for r in results {
                let status = r.valid ? "✓" : "✗"
                print("\(status) \(r.url): \(r.reason)")
                if let norm = r.normalized { print("   Normalized: \(norm)") }
            }
        case "3":
            validator.showStats()
        case "4":
            validator.checkDNS.toggle()
            print("DNS check toggled.")
        case "5":
            validator.checkHTTP.toggle()
            print("HTTP check toggled.")
        case "6":
            print("Goodbye!")
            return
        default:
            print("Invalid choice.")
        }
    }
}

main()
