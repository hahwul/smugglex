# Real socket-level HTTP request smuggling lab, in Crystal.
#
# A single process that runs two cooperating servers (in fibers):
#
#   frontend (CL-first proxy)  ->  backend (TE-priority)
#
# The frontend frames request bodies strictly by the first Content-Length
# (ignoring Transfer-Encoding) and forwards every request over ONE shared,
# persistent backend connection. The backend (FRAMING=te) honours
# Transfer-Encoding: chunked. Because the two disagree on where a request ends
# and the backend connection is reused, bytes the CL frontend forwards past the
# chunked body the TE backend stops at become the prefix of the next request —
# a genuine CL.TE desync.
#
# Like the basic PortSwigger lab, the frontend rejects non GET/POST methods
# (403) while the backend answers 405 for them; so a smuggled `GPOST` is blocked
# at the front door but reaches the backend via the desync, where it surfaces as
# a 405 among 200s — exactly what smugglex keys on.
#
# Vulnerable:  FRAMING=te  (frontend CL  vs backend TE -> desync)
# Patched:     FRAMING=cl  (both frame by first Content-Length -> no desync)
#
# Run:   crystal run lab/desync/desync_lab.cr
# Scan:  smugglex http://127.0.0.1:9000/
#        smugglex --exploit smuggle http://127.0.0.1:9000/

require "socket"

BIND_HOST           = ENV.fetch("BIND_HOST", "127.0.0.1")
FRONTEND_PORT       = ENV.fetch("FRONTEND_PORT", "9000").to_i
BACKEND_PORT        = ENV.fetch("BACKEND_PORT", "9001").to_i
FRAMING             = ENV.fetch("FRAMING", "te").downcase
UPSTREAM_TIMEOUT    = ENV.fetch("UPSTREAM_TIMEOUT", "6").to_f
CLIENT_BODY_TIMEOUT = ENV.fetch("CLIENT_BODY_TIMEOUT", "0.7").to_f

CRLF     = "\r\n".to_slice
CRLFCRLF = "\r\n\r\n".to_slice

# Index of `needle` in `hay`, or nil.
def index_of(hay : Array(UInt8), needle : Bytes) : Int32?
  n = needle.size
  return nil if n == 0 || hay.size < n
  i = 0
  max = hay.size - n
  while i <= max
    j = 0
    while j < n && hay[i + j] == needle[j]
      j += 1
    end
    return i if j == n
    i += 1
  end
  nil
end

# Append bytes read from `sock` into `buf` until it contains `needle`; return the
# index just past `needle`, or nil on EOF.
def read_until(sock, buf : Array(UInt8), needle : Bytes) : Int32?
  tmp = Bytes.new(4096)
  loop do
    if idx = index_of(buf, needle)
      return idx + needle.size
    end
    n = sock.read(tmp)
    return nil if n == 0
    i = 0
    while i < n
      buf << tmp[i]
      i += 1
    end
  end
end

# Ensure `buf` holds at least `count` bytes, reading more from `sock`.
def ensure_bytes(sock, buf : Array(UInt8), count : Int32) : Bool
  tmp = Bytes.new(4096)
  while buf.size < count
    n = sock.read(tmp)
    return false if n == 0
    i = 0
    while i < n
      buf << tmp[i]
      i += 1
    end
  end
  true
end

def to_str(buf : Array(UInt8), len : Int32) : String
  String.new(Bytes.new(len) { |i| buf[i] })
end

def request_method(head : String) : String
  head.split(' ', 2).first? || ""
end

def first_content_length(head : String) : Int32?
  head.each_line do |line|
    if line.lstrip.downcase.starts_with?("content-length:")
      return line.split(':', 2)[1].strip.to_i?
    end
  end
  nil
end

def has_chunked_te(head : String) : Bool
  head.each_line do |line|
    l = line.downcase
    return true if l.lstrip.starts_with?("transfer-encoding:") && l.includes?("chunked")
  end
  false
end

def http_response(status : String, body : String) : String
  "HTTP/1.1 #{status}\r\nContent-Length: #{body.bytesize}\r\nServer: lab-crystal\r\nConnection: keep-alive\r\n\r\n#{body}"
end

# ----------------------------- backend -------------------------------------

# Consume a chunked body sitting at the front of `buf` (reading more from
# `sock`). Returns the leftover buffer, or nil on EOF/malformed (the backend
# then dies — the desync hang that yields the frontend's 504).
def consume_chunked(sock, buf : Array(UInt8)) : Array(UInt8)?
  loop do
    eol = read_until(sock, buf, CRLF)
    return nil unless eol
    size = to_str(buf, eol - 2).split(';').first.strip.to_i?(16)
    return nil unless size
    buf = buf[eol..]
    if size == 0
      fin = read_until(sock, buf, CRLF) # trailing CRLF of the chunked terminator
      return nil unless fin
      return buf[fin..]
    end
    need = size + 2 # data + trailing CRLF
    return nil unless ensure_bytes(sock, buf, need)
    buf = buf[need..]
  end
end

def backend_handle(sock)
  buf = [] of UInt8
  loop do
    he = read_until(sock, buf, CRLFCRLF)
    break unless he
    head = to_str(buf, he)
    buf = buf[he..]

    if FRAMING == "te" && has_chunked_te(head)
      rest = consume_chunked(sock, buf)
      break unless rest
      buf = rest
    elsif cl = first_content_length(head)
      break unless ensure_bytes(sock, buf, cl)
      buf = buf[cl..]
    end

    method = request_method(head)
    if method == "GET" || method == "POST"
      sock.write(http_response("200 OK", "BACKEND ok: #{head.lines.first?}").to_slice)
    else
      sock.write(http_response("405 Method Not Allowed", "method #{method} not allowed").to_slice)
    end
    sock.flush
    # Any leftover bytes in `buf` are the prefix of the next request (the desync).
  end
rescue
  # broken pipe / reset — just drop the connection
ensure
  sock.close rescue nil
end

def run_backend
  server = TCPServer.new("127.0.0.1", BACKEND_PORT)
  policy = FRAMING == "te" ? "TE-priority (vulnerable)" : "CL-first (patched)"
  STDERR.puts "[backend:#{FRAMING}] #{policy} on 127.0.0.1:#{BACKEND_PORT}"
  loop do
    client = server.accept
    spawn backend_handle(client)
  end
end

# ----------------------------- frontend ------------------------------------

class Frontend
  @backend : TCPSocket?
  @carry : Array(UInt8)

  def initialize
    @backend = nil
    @carry = [] of UInt8
    @mutex = Mutex.new
  end

  private def connect_backend
    sock = TCPSocket.new("127.0.0.1", BACKEND_PORT)
    sock.read_timeout = UPSTREAM_TIMEOUT.seconds
    @backend = sock
    @carry = [] of UInt8
  end

  private def close_backend
    if b = @backend
      b.close rescue nil
    end
    @backend = nil
  end

  # Read one Content-Length-framed response from the shared backend connection,
  # carrying surplus bytes (a queued/smuggled response) for the next read.
  private def read_one_backend_response(sock) : Array(UInt8)?
    loop do
      if he = index_of(@carry, CRLFCRLF)
        header_end = he + CRLFCRLF.size
        cl = first_content_length(to_str(@carry, header_end)) || 0
        total = header_end + cl
        return nil unless ensure_bytes(sock, @carry, total)
        resp = @carry[0, total]
        @carry = @carry[total..]
        return resp
      end
      tmp = Bytes.new(4096)
      n = sock.read(tmp)
      return nil if n == 0
      i = 0
      while i < n
        @carry << tmp[i]
        i += 1
      end
    end
  end

  # Forward one already-framed request to the backend over the shared connection.
  def forward(raw : Array(UInt8)) : Array(UInt8)
    @mutex.synchronize do
      2.times do |attempt|
        begin
          connect_backend if @backend.nil?
          sock = @backend.not_nil!
          sock.write(Slice.new(raw.to_unsafe, raw.size))
          sock.flush
          if resp = read_one_backend_response(sock)
            return resp
          end
          raise IO::Error.new("backend closed")
        rescue IO::TimeoutError
          close_backend # backend hung on a truncated body
          return http_response("504 Gateway Timeout", "upstream timeout").to_bytes_arr
        rescue
          close_backend
          return http_response("502 Bad Gateway", "bad gateway").to_bytes_arr if attempt == 1
        end
      end
      http_response("502 Bad Gateway", "bad gateway").to_bytes_arr
    end
  end

  def handle(sock)
    sock.read_timeout = CLIENT_BODY_TIMEOUT.seconds
    buf = [] of UInt8
    loop do
      he = begin
        read_until(sock, buf, CRLFCRLF)
      rescue IO::TimeoutError
        break # idle keep-alive
      end
      break unless he
      head = to_str(buf, he)
      buf = buf[he..]

      method = request_method(head)
      # Front-end security control: only GET/POST are allowed through.
      unless method == "GET" || method == "POST"
        sock.write(http_response("403 Forbidden", "method blocked by front-end").to_slice)
        sock.flush
        next
      end

      cl = first_content_length(head) || 0
      ok = begin
        ensure_bytes(sock, buf, cl)
      rescue IO::TimeoutError
        false
      end
      unless ok
        sock.write(http_response("400 Bad Request", "bad request").to_slice)
        sock.flush
        break
      end
      raw = [] of UInt8
      head.to_slice.each { |b| raw << b }
      cl.times { |i| raw << buf[i] }
      buf = buf[cl..]

      resp = forward(raw)
      sock.write(Slice.new(resp.to_unsafe, resp.size))
      sock.flush
    end
  rescue
  ensure
    sock.close rescue nil
  end

  def run
    server = TCPServer.new(BIND_HOST, FRONTEND_PORT)
    STDERR.puts "[frontend] CL-first proxy on 127.0.0.1:#{FRONTEND_PORT} -> backend :#{BACKEND_PORT} " \
                "(client-body timeout #{CLIENT_BODY_TIMEOUT}s, upstream timeout #{UPSTREAM_TIMEOUT}s)"
    loop do
      client = server.accept
      spawn handle(client)
    end
  end
end

class String
  # Convenience: this String's bytes as an Array(UInt8).
  def to_bytes_arr : Array(UInt8)
    arr = [] of UInt8
    to_slice.each { |b| arr << b }
    arr
  end
end

# ----------------------------- main ----------------------------------------

spawn run_backend
puts "smuggling desync lab ready:"
puts "  vulnerable scan:  smugglex http://127.0.0.1:#{FRONTEND_PORT}/"
puts "  solve:            smugglex --exploit smuggle http://127.0.0.1:#{FRONTEND_PORT}/"
puts "  (FRAMING=cl for a patched, non-vulnerable chain)"
Frontend.new.run
