// url_validator.go
package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type URLValidator struct {
	CheckDNS  bool
	CheckHTTP bool
	Timeout   time.Duration
	Stats     struct{ Total, Valid, Invalid int }
}

func NewURLValidator(checkDNS, checkHTTP bool, timeout int) *URLValidator {
	return &URLValidator{
		CheckDNS:  checkDNS,
		CheckHTTP: checkHTTP,
		Timeout:   time.Duration(timeout) * time.Second,
	}
}

func (v *URLValidator) validateScheme(scheme string) (bool, string) {
	if scheme == "" {
		return false, "Missing scheme"
	}
	// Allowed schemes
	allowed := map[string]bool{
		"http": true, "https": true, "ftp": true, "ftps": true,
		"ws": true, "wss": true, "mailto": true, "tel": true, "ssh": true,
	}
	dangerous := map[string]bool{
		"javascript": true, "data": true, "file": true, "vbscript": true,
	}
	lower := strings.ToLower(scheme)
	if dangerous[lower] {
		return false, fmt.Sprintf("Dangerous scheme blocked: %s", scheme)
	}
	if !allowed[lower] {
		return false, fmt.Sprintf("Unsupported scheme: %s", scheme)
	}
	return true, "OK"
}

func (v *URLValidator) validateHost(host string) (bool, string) {
	if host == "" {
		return false, "Missing host"
	}
	if len(host) > 253 {
		return false, "Host too long (>253)"
	}
	// IPv6
	if strings.Contains(host, ":") {
		ip := net.ParseIP(host)
		if ip != nil && ip.To16() != nil {
			return true, "OK (IPv6)"
		}
		return false, "Invalid IPv6 address"
	}
	// IPv4
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() != nil {
		return true, "OK (IPv4)"
	}
	// Domain name - simple regex check
	hostnameRegex := regexp.MustCompile(`^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.?[A-Za-z]{2,63}$`)
	if hostnameRegex.MatchString(host) {
		// Check TLD length
		parts := strings.Split(host, ".")
		if len(parts) > 1 {
			tld := parts[len(parts)-1]
			if len(tld) < 2 || len(tld) > 63 {
				return false, fmt.Sprintf("Invalid TLD length: %d", len(tld))
			}
		}
		return true, "OK (domain)"
	}
	return false, "Invalid host format"
}

func (v *URLValidator) validatePort(portStr string) (bool, string) {
	if portStr == "" {
		return true, "OK (default port)"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return false, fmt.Sprintf("Invalid port: %s", portStr)
	}
	return true, fmt.Sprintf("OK (port %d)", port)
}

func (v *URLValidator) validatePath(path string) (bool, string) {
	if path == "" {
		return true, "OK (empty path)"
	}
	for _, ch := range path {
		if ch < 32 || strings.ContainsRune("\"<>|\\^`{}", ch) {
			return false, fmt.Sprintf("Illegal character in path: %c", ch)
		}
	}
	// Percent-encoding
	for i, r := range path {
		if r == '%' {
			if i+2 >= len(path) {
				return false, "Incomplete percent-encoding"
			}
			hex := path[i+1 : i+3]
			if _, err := strconv.ParseInt(hex, 16, 64); err != nil {
				return false, "Invalid percent-encoding"
			}
		}
	}
	return true, "OK"
}

func (v *URLValidator) validateQuery(query string) (bool, string) {
	if query == "" {
		return true, "OK (empty query)"
	}
	for _, ch := range query {
		if ch < 32 {
			return false, fmt.Sprintf("Illegal character in query: %c", ch)
		}
	}
	for i, r := range query {
		if r == '%' {
			if i+2 >= len(query) {
				return false, "Incomplete percent-encoding in query"
			}
			hex := query[i+1 : i+3]
			if _, err := strconv.ParseInt(hex, 16, 64); err != nil {
				return false, "Invalid percent-encoding in query"
			}
		}
	}
	return true, "OK"
}

func (v *URLValidator) validateFragment(fragment string) (bool, string) {
	if fragment == "" {
		return true, "OK (empty fragment)"
	}
	for _, ch := range fragment {
		if ch < 32 || strings.ContainsRune("\"<>|\\^`{}", ch) {
			return false, fmt.Sprintf("Illegal character in fragment: %c", ch)
		}
	}
	return true, "OK"
}

func (v *URLValidator) checkDNS(host string) bool {
	_, err := net.LookupHost(host)
	return err == nil
}

func (v *URLValidator) checkHTTPAvailability(rawURL string) bool {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return true
	}
	client := http.Client{Timeout: v.Timeout}
	resp, err := client.Head(rawURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode < 400
}

func (v *URLValidator) normalize(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	// Lowercase scheme and host
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Host != "" {
		hostParts := strings.Split(parsed.Host, ":")
		hostParts[0] = strings.ToLower(hostParts[0])
		if len(hostParts) > 1 {
			parsed.Host = hostParts[0] + ":" + hostParts[1]
		} else {
			parsed.Host = hostParts[0]
		}
	}
	// Add trailing slash if path is empty
	if parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" {
		parsed.Path = "/"
	}
	return parsed.String()
}

func (v *URLValidator) Validate(rawURL string) (bool, string, string) {
	v.Stats.Total++
	if len(rawURL) > 2048 {
		v.Stats.Invalid++
		return false, fmt.Sprintf("URL too long (%d > 2048)", len(rawURL)), ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		v.Stats.Invalid++
		return false, fmt.Sprintf("Parse error: %v", err), ""
	}
	// Scheme
	if ok, msg := v.validateScheme(parsed.Scheme); !ok {
		v.Stats.Invalid++
		return false, "Scheme error: " + msg, ""
	}
	// Host
	if parsed.Host == "" {
		v.Stats.Invalid++
		return false, "Missing host", ""
	}
	host := parsed.Hostname()
	if ok, msg := v.validateHost(host); !ok {
		v.Stats.Invalid++
		return false, "Host error: " + msg, ""
	}
	// Port
	if ok, msg := v.validatePort(parsed.Port()); !ok {
		v.Stats.Invalid++
		return false, "Port error: " + msg, ""
	}
	// Path
	if ok, msg := v.validatePath(parsed.Path); !ok {
		v.Stats.Invalid++
		return false, "Path error: " + msg, ""
	}
	// Query
	if ok, msg := v.validateQuery(parsed.RawQuery); !ok {
		v.Stats.Invalid++
		return false, "Query error: " + msg, ""
	}
	// Fragment
	if ok, msg := v.validateFragment(parsed.Fragment); !ok {
		v.Stats.Invalid++
		return false, "Fragment error: " + msg, ""
	}
	// DNS
	if v.CheckDNS && !v.checkDNS(host) {
		v.Stats.Invalid++
		return false, "Host does not resolve (DNS)", ""
	}
	// HTTP
	if v.CheckHTTP && !v.checkHTTPAvailability(rawURL) {
		v.Stats.Invalid++
		return false, "URL is not reachable (HTTP error)", ""
	}
	v.Stats.Valid++
	normalized := v.normalize(rawURL)
	return true, "All checks passed", normalized
}

func (v *URLValidator) BatchValidate(urls []string) []struct {
	URL        string
	Valid      bool
	Reason     string
	Normalized string
} {
	results := []struct {
		URL        string
		Valid      bool
		Reason     string
		Normalized string
	}{}
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		valid, reason, normalized := v.Validate(u)
		results = append(results, struct {
			URL        string
			Valid      bool
			Reason     string
			Normalized string
		}{u, valid, reason, normalized})
	}
	return results
}

func (v *URLValidator) ShowStats() {
	fmt.Printf("\nStatistics: Total: %d, Valid: %d, Invalid: %d\n", v.Stats.Total, v.Stats.Valid, v.Stats.Invalid)
}

func main() {
	validator := NewURLValidator(false, false, 5)
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("=== URL Validator ===")
	for {
		fmt.Println("\n1. Validate single URL")
		fmt.Println("2. Validate from file")
		fmt.Println("3. Show statistics")
		fmt.Printf("4. Toggle DNS check (currently %s)\n", map[bool]string{true: "ON", false: "OFF"}[validator.CheckDNS])
		fmt.Printf("5. Toggle HTTP check (currently %s)\n", map[bool]string{true: "ON", false: "OFF"}[validator.CheckHTTP])
		fmt.Println("6. Exit")
		fmt.Print("Choose: ")
		scanner.Scan()
		choice := strings.TrimSpace(scanner.Text())
		switch choice {
		case "1":
			fmt.Print("Enter URL: ")
			scanner.Scan()
			url := strings.TrimSpace(scanner.Text())
			valid, reason, normalized := validator.Validate(url)
			fmt.Printf("Valid: %v\n", valid)
			fmt.Printf("Details: %s\n", reason)
			if normalized != "" {
				fmt.Printf("Normalized: %s\n", normalized)
			}
		case "2":
			fmt.Print("Enter file path: ")
			scanner.Scan()
			fname := strings.TrimSpace(scanner.Text())
			file, err := os.Open(fname)
			if err != nil {
				fmt.Println("File not found.")
				break
			}
			defer file.Close()
			var urls []string
			fileScanner := bufio.NewScanner(file)
			for fileScanner.Scan() {
				urls = append(urls, fileScanner.Text())
			}
			results := validator.BatchValidate(urls)
			fmt.Println("\nBatch results:")
			for _, r := range results {
				status := "✓"
				if !r.Valid {
					status = "✗"
				}
				fmt.Printf("%s %s: %s\n", status, r.URL, r.Reason)
				if r.Normalized != "" {
					fmt.Printf("   Normalized: %s\n", r.Normalized)
				}
			}
		case "3":
			validator.ShowStats()
		case "4":
			validator.CheckDNS = !validator.CheckDNS
			fmt.Println("DNS check toggled.")
		case "5":
			validator.CheckHTTP = !validator.CheckHTTP
			fmt.Println("HTTP check toggled.")
		case "6":
			fmt.Println("Goodbye!")
			return
		default:
			fmt.Println("Invalid choice.")
		}
	}
}
