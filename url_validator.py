# url_validator.py
import re
import socket
import urllib.parse
from typing import Tuple, Optional, List, Dict, Any
from urllib.request import urlopen, Request
from urllib.error import URLError
import ssl

class URLValidator:
    """Comprehensive URL validator with syntax, host, and online checks."""
    
    # Allowed schemes (whitelist)
    ALLOWED_SCHEMES = {'http', 'https', 'ftp', 'ftps', 'ws', 'wss', 'mailto', 'tel', 'ssh'}
    # Dangerous schemes (blacklist)
    DANGEROUS_SCHEMES = {'javascript', 'data', 'file', 'vbscript'}
    # Maximum URL length (RFC 2616 recommends 2048, but some browsers support more)
    MAX_URL_LENGTH = 2048
    # TLD length limits
    MIN_TLD_LENGTH = 2
    MAX_TLD_LENGTH = 63
    
    def __init__(self, check_dns: bool = False, check_http: bool = False, timeout: int = 5):
        self.check_dns = check_dns
        self.check_http = check_http
        self.timeout = timeout
        self.stats = {'total': 0, 'valid': 0, 'invalid': 0}
        # IPv6 pattern (full + compressed)
        self.ipv6_pattern = re.compile(
            r'^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
            r'(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})$'
        )
        self.ipv4_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        self.scheme_pattern = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*$')
        self.hostname_pattern = re.compile(
            r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.?[A-Za-z]{2,63}$'
        )
    
    def validate_scheme(self, scheme: str) -> Tuple[bool, str]:
        """Validate the URL scheme."""
        if not scheme:
            return False, "Missing scheme"
        if not self.scheme_pattern.match(scheme):
            return False, f"Invalid scheme: {scheme}"
        if scheme.lower() in self.DANGEROUS_SCHEMES:
            return False, f"Dangerous scheme blocked: {scheme}"
        if scheme.lower() not in self.ALLOWED_SCHEMES:
            return False, f"Unsupported scheme: {scheme}"
        return True, "OK"
    
    def validate_host(self, host: str) -> Tuple[bool, str]:
        """Validate host (domain name or IP address)."""
        if not host:
            return False, "Missing host"
        # Check length
        if len(host) > 253:
            return False, "Host too long (>253)"
        # Check if it's an IPv6 address
        if ':' in host:
            if self.ipv6_pattern.match(host):
                return True, "OK (IPv6)"
            return False, "Invalid IPv6 address"
        # Check if it's an IPv4 address
        if self.ipv4_pattern.match(host):
            return True, "OK (IPv4)"
        # Check domain name
        if self.hostname_pattern.match(host):
            # Additional TLD check
            tld = host.split('.')[-1]
            if len(tld) < self.MIN_TLD_LENGTH or len(tld) > self.MAX_TLD_LENGTH:
                return False, f"Invalid TLD length: {len(tld)}"
            return True, "OK (domain)"
        return False, "Invalid host format"
    
    def validate_port(self, port_str: Optional[str]) -> Tuple[bool, str]:
        """Validate port number."""
        if port_str is None or port_str == '':
            return True, "OK (default port)"
        try:
            port = int(port_str)
            if 1 <= port <= 65535:
                return True, f"OK (port {port})"
            return False, f"Port out of range: {port}"
        except ValueError:
            return False, f"Invalid port: {port_str}"
    
    def validate_path(self, path: str) -> Tuple[bool, str]:
        """Validate URL path (allow standard chars and percent-encoding)."""
        # Path can be empty
        if not path:
            return True, "OK (empty path)"
        # Check for illegal characters (control chars, space, etc.)
        for ch in path:
            if ord(ch) < 32 or ch in '"<>|\\^`{}':
                return False, f"Illegal character in path: {ch}"
        # Allow percent-encoding but ensure it's valid
        if '%' in path:
            # Basic check: % must be followed by two hex digits
            for i, ch in enumerate(path):
                if ch == '%':
                    if i + 2 >= len(path):
                        return False, "Incomplete percent-encoding"
                    if not re.match(r'[0-9a-fA-F]{2}', path[i+1:i+3]):
                        return False, "Invalid percent-encoding"
        return True, "OK"
    
    def validate_query(self, query: str) -> Tuple[bool, str]:
        """Validate query string."""
        if not query:
            return True, "OK (empty query)"
        # Basic: allow key=value pairs separated by &
        # Simple check: no control characters
        for ch in query:
            if ord(ch) < 32:
                return False, f"Illegal character in query: {ch}"
        # Check for valid percent-encoding
        if '%' in query:
            for i, ch in enumerate(query):
                if ch == '%':
                    if i + 2 >= len(query):
                        return False, "Incomplete percent-encoding in query"
                    if not re.match(r'[0-9a-fA-F]{2}', query[i+1:i+3]):
                        return False, "Invalid percent-encoding in query"
        return True, "OK"
    
    def validate_fragment(self, fragment: str) -> Tuple[bool, str]:
        """Validate fragment (anchor)."""
        if not fragment:
            return True, "OK (empty fragment)"
        # Same rules as path
        for ch in fragment:
            if ord(ch) < 32 or ch in '"<>|\\^`{}':
                return False, f"Illegal character in fragment: {ch}"
        return True, "OK"
    
    def check_dns(self, host: str) -> bool:
        """Check if host resolves (A or AAAA record)."""
        try:
            socket.gethostbyname(host)
            return True
        except socket.error:
            return False
    
    def check_http_availability(self, url: str) -> bool:
        """Perform HTTP HEAD request to check availability."""
        if not url.startswith(('http://', 'https://')):
            return True  # only for HTTP/HTTPS
        try:
            req = Request(url, method='HEAD')
            # Create SSL context that doesn't verify (for simplicity)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with urlopen(req, timeout=self.timeout, context=context) as resp:
                return resp.status < 400
        except Exception:
            return False
    
    def normalize(self, url: str) -> str:
        """Normalize URL: lowercase scheme/host, add trailing slash if missing."""
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname.lower() if parsed.hostname else ''
        # Rebuild with lowercase
        normalized = urllib.parse.urlunparse((
            scheme,
            host + (':' + str(parsed.port) if parsed.port else ''),
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        # Add trailing slash if path is empty and no query/fragment
        if parsed.path == '' and not parsed.query and not parsed.fragment:
            normalized += '/'
        return normalized
    
    def validate(self, url: str) -> Tuple[bool, str, Optional[str]]:
        """Full validation. Returns (valid, reason, normalized_url)."""
        self.stats['total'] += 1
        
        # Check length
        if len(url) > self.MAX_URL_LENGTH:
            self.stats['invalid'] += 1
            return False, f"URL too long ({len(url)} > {self.MAX_URL_LENGTH})", None
        
        # Parse URL
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception as e:
            self.stats['invalid'] += 1
            return False, f"Parse error: {e}", None
        
        # Scheme
        valid, msg = self.validate_scheme(parsed.scheme)
        if not valid:
            self.stats['invalid'] += 1
            return False, f"Scheme error: {msg}", None
        
        # Host
        if not parsed.hostname:
            self.stats['invalid'] += 1
            return False, "Missing hostname", None
        valid, msg = self.validate_host(parsed.hostname)
        if not valid:
            self.stats['invalid'] += 1
            return False, f"Host error: {msg}", None
        
        # Port
        valid, msg = self.validate_port(parsed.port)
        if not valid:
            self.stats['invalid'] += 1
            return False, f"Port error: {msg}", None
        
        # Path
        valid, msg = self.validate_path(parsed.path)
        if not valid:
            self.stats['invalid'] += 1
            return False, f"Path error: {msg}", None
        
        # Query
        valid, msg = self.validate_query(parsed.query)
        if not valid:
            self.stats['invalid'] += 1
            return False, f"Query error: {msg}", None
        
        # Fragment
        valid, msg = self.validate_fragment(parsed.fragment)
        if not valid:
            self.stats['invalid'] += 1
            return False, f"Fragment error: {msg}", None
        
        # DNS check
        if self.check_dns:
            if not self.check_dns(parsed.hostname):
                self.stats['invalid'] += 1
                return False, "Host does not resolve (DNS)", None
        
        # HTTP availability
        if self.check_http:
            if not self.check_http_availability(url):
                self.stats['invalid'] += 1
                return False, "URL is not reachable (HTTP error)", None
        
        self.stats['valid'] += 1
        normalized = self.normalize(url)
        return True, "All checks passed", normalized
    
    def batch_validate(self, urls: List[str]) -> List[Dict[str, Any]]:
        results = []
        for u in urls:
            url = u.strip()
            if not url:
                continue
            valid, reason, normalized = self.validate(url)
            results.append({
                'url': url,
                'valid': valid,
                'reason': reason,
                'normalized': normalized
            })
        return results
    
    def show_stats(self):
        print(f"\nStatistics: Total: {self.stats['total']}, Valid: {self.stats['valid']}, Invalid: {self.stats['invalid']}")

def main():
    validator = URLValidator(check_dns=False, check_http=False)
    print("=== URL Validator ===")
    while True:
        print("\n1. Validate single URL")
        print("2. Validate from file")
        print("3. Show statistics")
        print("4. Toggle DNS check (currently {})".format("ON" if validator.check_dns else "OFF"))
        print("5. Toggle HTTP check (currently {})".format("ON" if validator.check_http else "OFF"))
        print("6. Exit")
        choice = input("Choose: ").strip()
        if choice == '1':
            url = input("Enter URL: ").strip()
            valid, reason, normalized = validator.validate(url)
            print(f"Valid: {valid}")
            print(f"Details: {reason}")
            if normalized:
                print(f"Normalized: {normalized}")
        elif choice == '2':
            fname = input("Enter file path: ").strip()
            try:
                with open(fname, 'r') as f:
                    urls = f.readlines()
                results = validator.batch_validate(urls)
                print("\nBatch results:")
                for r in results:
                    status = "✓" if r['valid'] else "✗"
                    print(f"{status} {r['url']}: {r['reason']}")
                    if r['normalized']:
                        print(f"   Normalized: {r['normalized']}")
            except FileNotFoundError:
                print("File not found.")
            except Exception as e:
                print(f"Error: {e}")
        elif choice == '3':
            validator.show_stats()
        elif choice == '4':
            validator.check_dns = not validator.check_dns
            print("DNS check toggled.")
        elif choice == '5':
            validator.check_http = not validator.check_http
            print("HTTP check toggled.")
        elif choice == '6':
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
