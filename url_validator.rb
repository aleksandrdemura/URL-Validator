# url_validator.rb
require 'uri'
require 'resolv'
require 'net/http'

class URLValidator
  ALLOWED_SCHEMES = %w[http https ftp ftps ws wss mailto tel ssh].to_set
  DANGEROUS_SCHEMES = %w[javascript data file vbscript].to_set
  MAX_URL_LENGTH = 2048

  attr_accessor :check_dns, :check_http, :timeout
  attr_reader :stats

  def initialize(check_dns: false, check_http: false, timeout: 5)
    @check_dns = check_dns
    @check_http = check_http
    @timeout = timeout
    @stats = { total: 0, valid: 0, invalid: 0 }
    @hostname_regex = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.?[A-Za-z]{2,63}$/
    @ipv4_regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
    @ipv6_regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})$/
  end

  def validate_scheme(scheme)
    return [false, "Missing scheme"] if scheme.nil? || scheme.empty?
    lower = scheme.downcase
    return [false, "Dangerous scheme blocked: #{scheme}"] if DANGEROUS_SCHEMES.include?(lower)
    return [false, "Unsupported scheme: #{scheme}"] unless ALLOWED_SCHEMES.include?(lower)
    [true, "OK"]
  end

  def validate_host(host)
    return [false, "Missing host"] if host.nil? || host.empty?
    return [false, "Host too long (>253)"] if host.length > 253
    if host.include?(':')
      return [true, "OK (IPv6)"] if @ipv6_regex.match?(host)
      return [false, "Invalid IPv6 address"]
    end
    if @ipv4_regex.match?(host)
      return [true, "OK (IPv4)"]
    end
    if @hostname_regex.match?(host)
      parts = host.split('.')
      if parts.length > 1
        tld = parts.last
        return [false, "Invalid TLD length: #{tld.length}"] if tld.length < 2 || tld.length > 63
      end
      return [true, "OK (domain)"]
    end
    [false, "Invalid host format"]
  end

  def validate_port(port_str)
    return [true, "OK (default port)"] if port_str.nil? || port_str.empty?
    port = Integer(port_str) rescue nil
    return [false, "Invalid port: #{port_str}"] if port.nil?
    return [false, "Port out of range: #{port}"] if port < 1 || port > 65535
    [true, "OK (port #{port})"]
  end

  def validate_path(path)
    return [true, "OK (empty path)"] if path.nil? || path.empty?
    path.each_char do |ch|
      return [false, "Illegal character in path: #{ch}"] if ch.ord < 32 || "\"<>|\\^`{}".include?(ch)
    end
    i = 0
    while i < path.length
      if path[i] == '%'
        return [false, "Incomplete percent-encoding"] if i + 2 >= path.length
        hex = path[i+1, 2]
        return [false, "Invalid percent-encoding"] unless hex.match?(/^[0-9a-fA-F]{2}$/)
      end
      i += 1
    end
    [true, "OK"]
  end

  def validate_query(query)
    return [true, "OK (empty query)"] if query.nil? || query.empty?
    query.each_char do |ch|
      return [false, "Illegal character in query: #{ch}"] if ch.ord < 32
    end
    i = 0
    while i < query.length
      if query[i] == '%'
        return [false, "Incomplete percent-encoding in query"] if i + 2 >= query.length
        hex = query[i+1, 2]
        return [false, "Invalid percent-encoding in query"] unless hex.match?(/^[0-9a-fA-F]{2}$/)
      end
      i += 1
    end
    [true, "OK"]
  end

  def validate_fragment(fragment)
    return [true, "OK (empty fragment)"] if fragment.nil? || fragment.empty?
    fragment.each_char do |ch|
      return [false, "Illegal character in fragment: #{ch}"] if ch.ord < 32 || "\"<>|\\^`{}".include?(ch)
    end
    [true, "OK"]
  end

  def check_dns?(host)
    return true unless @check_dns
    Resolv.getaddress(host) rescue nil ? true : false
  end

  def check_http_availability?(raw_url)
    return true unless @check_http
    return true unless raw_url.start_with?('http://', 'https://')
    uri = URI.parse(raw_url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.open_timeout = @timeout
    http.read_timeout = @timeout
    begin
      response = http.head(uri.path.empty? ? '/' : uri.path)
      response.code.to_i < 400
    rescue
      false
    end
  end

  def normalize(raw_url)
    uri = URI.parse(raw_url)
    scheme = uri.scheme.downcase
    host = uri.host.downcase
    port = uri.port
    path = uri.path
    path = '/' if (path.nil? || path.empty?) && uri.query.nil? && uri.fragment.nil?
    query = uri.query
    fragment = uri.fragment
    port_str = (port && port != 80 && port != 443) ? ":#{port}" : ''
    query_str = query ? "?#{query}" : ''
    fragment_str = fragment ? "##{fragment}" : ''
    "#{scheme}://#{host}#{port_str}#{path}#{query_str}#{fragment_str}"
  rescue
    raw_url
  end

  def validate(raw_url)
    @stats[:total] += 1
    if raw_url.length > MAX_URL_LENGTH
      @stats[:invalid] += 1
      return [false, "URL too long (#{raw_url.length} > #{MAX_URL_LENGTH})", nil]
    end
    begin
      parsed = URI.parse(raw_url)
    rescue => e
      @stats[:invalid] += 1
      return [false, "Parse error: #{e.message}", nil]
    end
    # Scheme
    valid, reason = validate_scheme(parsed.scheme)
    unless valid
      @stats[:invalid] += 1
      return [false, "Scheme error: #{reason}", nil]
    end
    # Host
    if parsed.host.nil?
      @stats[:invalid] += 1
      return [false, "Missing host", nil]
    end
    valid, reason = validate_host(parsed.host)
    unless valid
      @stats[:invalid] += 1
      return [false, "Host error: #{reason}", nil]
    end
    # Port
    valid, reason = validate_port(parsed.port.to_s)
    unless valid
      @stats[:invalid] += 1
      return [false, "Port error: #{reason}", nil]
    end
    # Path
    valid, reason = validate_path(parsed.path)
    unless valid
      @stats[:invalid] += 1
      return [false, "Path error: #{reason}", nil]
    end
    # Query
    valid, reason = validate_query(parsed.query)
    unless valid
      @stats[:invalid] += 1
      return [false, "Query error: #{reason}", nil]
    end
    # Fragment
    valid, reason = validate_fragment(parsed.fragment)
    unless valid
      @stats[:invalid] += 1
      return [false, "Fragment error: #{reason}", nil]
    end
    # DNS
    if @check_dns && !check_dns?(parsed.host)
      @stats[:invalid] += 1
      return [false, "Host does not resolve (DNS)", nil]
    end
    # HTTP
    if @check_http && !check_http_availability?(raw_url)
      @stats[:invalid] += 1
      return [false, "URL is not reachable (HTTP error)", nil]
    end
    @stats[:valid] += 1
    normalized = normalize(raw_url)
    [true, "All checks passed", normalized]
  end

  def batch_validate(urls)
    results = []
    urls.each do |u|
      url = u.strip
      next if url.empty?
      valid, reason, normalized = validate(url)
      results << { url: url, valid: valid, reason: reason, normalized: normalized }
    end
    results
  end

  def show_stats
    puts "\nStatistics: Total: #{@stats[:total]}, Valid: #{@stats[:valid]}, Invalid: #{@stats[:invalid]}"
  end
end

def main
  validator = URLValidator.new(check_dns: false, check_http: false)
  puts "=== URL Validator ==="
  loop do
    puts "\n1. Validate single URL"
    puts "2. Validate from file"
    puts "3. Show statistics"
    puts "4. Toggle DNS check (currently #{validator.check_dns ? 'ON' : 'OFF'})"
    puts "5. Toggle HTTP check (currently #{validator.check_http ? 'ON' : 'OFF'})"
    puts "6. Exit"
    print "Choose: "
    choice = gets.chomp.strip
    case choice
    when '1'
      print "Enter URL: "
      url = gets.chomp.strip
      valid, reason, normalized = validator.validate(url)
      puts "Valid: #{valid}"
      puts "Details: #{reason}"
      puts "Normalized: #{normalized}" if normalized
    when '2'
      print "Enter file path: "
      fname = gets.chomp.strip
      unless File.exist?(fname)
        puts "File not found."
        next
      end
      urls = File.readlines(fname).map(&:chomp)
      results = validator.batch_validate(urls)
      puts "\nBatch results:"
      results.each do |r|
        status = r[:valid] ? '✓' : '✗'
        puts "#{status} #{r[:url]}: #{r[:reason]}"
        puts "   Normalized: #{r[:normalized]}" if r[:normalized]
      end
    when '3'
      validator.show_stats
    when '4'
      validator.check_dns = !validator.check_dns
      puts "DNS check toggled."
    when '5'
      validator.check_http = !validator.check_http
      puts "HTTP check toggled."
    when '6'
      puts "Goodbye!"
      break
    else
      puts "Invalid choice."
    end
  end
end

main if __FILE__ == $0
