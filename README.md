🔗 URL Validator – Multi‑Language Edition

A comprehensive **URL validator** that performs deep syntax checks, host validation (domain/IP), port verification, and optional online availability testing.  
Built in **7 programming languages** – perfect for learning or production use.

## ✨ Features
- **Strict syntax validation** – follows RFC 3986 rules:
  - Scheme (must start with a letter, only alphanumeric, `+`, `-`, `.`)
  - Host (domain name or IPv4/IPv6 address)
  - Port (1‑65535)
  - Path (allowed characters, percent‑encoding)
  - Query parameters (key=value pairs, proper encoding)
  - Fragment (anchor)
- **Advanced host checks** – validates domain labels, TLD length, and IP address formats.
- **Optional online checks**:
  - DNS resolution (verify host exists)
  - HTTP HEAD request (check if URL is reachable)
- **Blacklist** – rejects dangerous schemes like `javascript:`, `data:`, `file:` (configurable).
- **Normalization** – converts URL to canonical form (lowercase scheme/host, add trailing slash if needed).
- **Batch processing** – validate multiple URLs from a text file.
- **Statistics** – total, valid, invalid counts.

## 🗂 Languages & Files
| Language          | File                  |
|-------------------|-----------------------|
| Python            | `url_validator.py`    |
| Go                | `url_validator.go`    |
| JavaScript        | `url_validator.js`    |
| C#                | `UrlValidator.cs`     |
| Java              | `UrlValidator.java`   |
| Ruby              | `url_validator.rb`    |
| Swift             | `url_validator.swift` |

## 🚀 How to Run
Each file is standalone – run it with the appropriate interpreter/compiler:

| Language | Command |
|----------|---------|
| Python   | `python url_validator.py` |
| Go       | `go run url_validator.go` |
| JavaScript | `node url_validator.js` |
| C#       | `dotnet run` (or `csc UrlValidator.cs`) |
| Java     | `javac UrlValidator.java && java UrlValidator` |
| Ruby     | `ruby url_validator.rb` |
| Swift    | `swift url_validator.swift` |

## 📊 Example Session
=== URL Validator ===

Validate single URL

Validate from file

Show statistics

Toggle online checks (currently OFF)

Exit
Choose: 1

Enter URL: https://example.com:8080/path?key=value#section
Valid: true
Normalized: https://example.com:8080/path?key=value#section
Details: All checks passed

Enter URL: ftp://user:pass@invalid.domain/path
Valid: false
Details: Host does not exist (DNS)

text

## 📁 Batch File Format
A plain text file with one URL per line:
https://google.com
http://localhost:3000
ftp://example.com

text
The validator processes each line and outputs results.

## 🔧 Technical Details
- **Scheme validation** – only `http`, `https`, `ftp`, `ftps`, `ws`, `wss`, `mailto`, `tel`, `ssh` allowed by default (customizable).
- **Domain** – supports internationalized domain names (IDN) via punycode (optional).
- **IPv6** – supports full and compressed formats.
- **Online checks** – uses system DNS resolution and HTTP client with timeout (5 seconds).

## 🤝 Contributing
Add more schemes, enhance IDN support, or improve performance – PRs welcome!

## 📜 License
MIT – use freely.
