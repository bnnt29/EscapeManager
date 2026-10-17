#include "Http.hpp"

#include "Compat.hpp"
#include "Json.hpp"

#include <cstdio>
#include <cstring>

namespace Escape {

namespace {

bool iequals(const std::string &a, const char *b) {
  const size_t n = strlen(b);
  if (a.size() != n) return false;
  for (size_t i = 0; i < n; i++) {
    char x = a[i], y = b[i];
    if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
    if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
    if (x != y) return false;
  }
  return true;
}

std::string trim(const std::string &s) {
  size_t b = 0, e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t')) b++;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t')) e--;
  return s.substr(b, e - b);
}

bool validTarget(const std::string &t) {
  if (t.empty() || t[0] != '/' || t.size() > 512) return false;
  for (size_t i = 0; i < t.size(); i++) {
    const unsigned char c = (unsigned char)t[i];
    if (c <= 0x20 || c == 0x7f) return false;
  }
  return true;
}

int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

} // namespace

void HttpRequestParser::reset() {
  state_ = State::Headers;
  errorStatus_ = 0;
  head_.clear();
  req_ = HttpRequest();
}

void HttpRequestParser::fail(int status) {
  state_ = State::Error;
  errorStatus_ = status;
}

void HttpRequestParser::beginBody(size_t maxBody) {
  if (state_ != State::HeadersComplete) return;
  if (req_.contentLength == 0) {
    state_ = State::Done;
    return;
  }
  if (req_.method != Method::Post || req_.contentLength > maxBody) {
    fail(req_.method != Method::Post ? 400 : 413);
    return;
  }
  Escape::guardAlloc([&]() -> bool { req_.body.reserve(req_.contentLength); return true; }, false);
  state_ = State::Body;
}

size_t HttpRequestParser::feed(const uint8_t *data, size_t length) {
  size_t used = 0;
  while (used < length) {
    if (state_ == State::Headers) {
      while (used < length && state_ == State::Headers) {
        head_.push_back((char)data[used++]);
        const size_t n = head_.size();
        if (n > EscapeConfig::MAX_HEADER_BYTES) {
          fail(431);
        } else if (n >= 4 && head_[n - 1] == '\n' && head_[n - 2] == '\r' && head_[n - 3] == '\n' && head_[n - 4] == '\r') {
          parseHead();
        }
      }
    } else if (state_ == State::Body) {
      const size_t need = req_.contentLength - req_.body.size();
      const size_t take = (length - used < need) ? length - used : need;
      req_.body.append((const char *)data + used, take);
      used += take;
      if (req_.body.size() == req_.contentLength) state_ = State::Done;
    } else {
      break; // HeadersComplete / Done / Error: the caller must act first
    }
  }
  return used;
}

void HttpRequestParser::parseHead() {
  req_ = HttpRequest();
  const size_t lineEnd = head_.find("\r\n");
  if (lineEnd == std::string::npos) return fail(400);
  const std::string line = head_.substr(0, lineEnd);
  const size_t sp1 = line.find(' ');
  const size_t sp2 = sp1 == std::string::npos ? std::string::npos : line.find(' ', sp1 + 1);
  if (sp1 == std::string::npos || sp2 == std::string::npos) return fail(400);
  const std::string method = line.substr(0, sp1);
  const std::string target = line.substr(sp1 + 1, sp2 - sp1 - 1);
  const std::string version = line.substr(sp2 + 1);

  if (method == "GET") req_.method = Method::Get;
  else if (method == "HEAD") req_.method = Method::Head;
  else if (method == "POST") req_.method = Method::Post;
  else if (method == "OPTIONS") req_.method = Method::Options;
  else return fail(405);
  if (version.find(' ') != std::string::npos) return fail(400); // extra token in the request line
  if (version != "HTTP/1.1" && version != "HTTP/1.0") return fail(505);
  if (target.size() > 512) return fail(414);
  if (!validTarget(target)) return fail(400);
  const size_t q = target.find('?');
  req_.path = q == std::string::npos ? target : target.substr(0, q);
  if (q != std::string::npos) req_.query = target.substr(q + 1);

  bool haveLength = false;
  size_t pos = lineEnd + 2;
  while (pos < head_.size()) {
    const size_t e = head_.find("\r\n", pos);
    if (e == std::string::npos) return fail(400);
    if (e == pos) break; // blank line: end of headers
    const std::string header = head_.substr(pos, e - pos);
    pos = e + 2;
    if (header[0] == ' ' || header[0] == '\t') return fail(400); // obsolete line folding
    const size_t colon = header.find(':');
    if (colon == std::string::npos || colon == 0) return fail(400);
    const std::string name = header.substr(0, colon);
    const std::string value = trim(header.substr(colon + 1));
    if (iequals(name, "content-length")) {
      if (value.empty() || value.size() > 10) return fail(400);
      unsigned long long v = 0;
      for (size_t i = 0; i < value.size(); i++) {
        if (value[i] < '0' || value[i] > '9') return fail(400);
        v = v * 10 + (unsigned)(value[i] - '0');
      }
      if (haveLength && v != req_.contentLength) return fail(400);
      if (v > 0x7FFFFFFFULL) return fail(413);
      req_.contentLength = (size_t)v;
      haveLength = true;
    } else if (iequals(name, "transfer-encoding")) {
      return fail(501);
    } else if (iequals(name, "origin")) {
      if (value.size() <= 128) req_.origin = value;
    } else if (iequals(name, "if-none-match")) {
      if (value.size() <= 128) req_.ifNoneMatch = value;
    } else if (iequals(name, "expect")) {
      req_.expectContinue = iequals(value, "100-continue");
    }
  }
  state_ = State::HeadersComplete;
}

bool percentDecode(const std::string &in, std::string &out) {
  out.clear();
  for (size_t i = 0; i < in.size(); i++) {
    if (in[i] == '%') {
      if (i + 2 >= in.size()) return false; // needs two hex digits after '%'
      const int hi = hexVal(in[i + 1]);
      const int lo = hexVal(in[i + 2]);
      if (hi < 0 || lo < 0) return false;
      out.push_back((char)(hi * 16 + lo));
      i += 2;
    } else {
      out.push_back(in[i]);
    }
  }
  return true;
}

bool queryParam(const std::string &query, const char *name, std::string &out) {
  size_t pos = 0;
  while (pos <= query.size()) {
    size_t amp = query.find('&', pos);
    if (amp == std::string::npos) amp = query.size();
    const std::string pair = query.substr(pos, amp - pos);
    const size_t eq = pair.find('=');
    const std::string key = pair.substr(0, eq);
    std::string decodedKey;
    if (percentDecode(key, decodedKey) && decodedKey == name) {
      if (eq == std::string::npos) { out.clear(); return true; }
      return percentDecode(pair.substr(eq + 1), out);
    }
    pos = amp + 1;
  }
  return false;
}

bool originAllowed(const std::string &origin) {
  if (origin == "null") return true;
  std::string rest;
  if (origin.compare(0, 7, "http://") == 0) rest = origin.substr(7);
  else if (origin.compare(0, 8, "https://") == 0) rest = origin.substr(8);
  else return false;
  std::string host = rest;
  if (!host.empty() && host[0] == '[') { // IPv6 literal: only loopback
    return host.compare(0, 5, "[::1]") == 0 && (host.size() == 5 || host[5] == ':');
  }
  const size_t colon = host.find(':');
  if (colon != std::string::npos) {
    const std::string port = host.substr(colon + 1);
    for (size_t i = 0; i < port.size(); i++) if (port[i] < '0' || port[i] > '9') return false;
    host = host.substr(0, colon);
  }
  if (host.empty() || host.size() > 100) return false;
  for (size_t i = 0; i < host.size(); i++) {
    const char c = host[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-')) return false;
  }
  std::string lower = host;
  for (size_t i = 0; i < lower.size(); i++) if (lower[i] >= 'A' && lower[i] <= 'Z') lower[i] = (char)(lower[i] + 32);
  if (lower == "localhost") return true;
  if (lower.size() > 6 && lower.compare(lower.size() - 6, 6, ".local") == 0) return true;
  // IPv4 literal in a private/loopback range
  unsigned a = 0, b = 0, c = 0, d = 0;
  int consumed = 0;
  bool numeric = true;
  for (size_t i = 0; i < lower.size(); i++) if (!((lower[i] >= '0' && lower[i] <= '9') || lower[i] == '.')) numeric = false;
  if (!numeric) return false;
  if (sscanf(lower.c_str(), "%u.%u.%u.%u%n", &a, &b, &c, &d, &consumed) != 4 || (size_t)consumed != lower.size()) return false;
  if (a > 255 || b > 255 || c > 255 || d > 255) return false;
  return a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 169 && b == 254);
}

const char *statusText(int status) {
  switch (status) {
    case 200: return "OK";
    case 204: return "No Content";
    case 304: return "Not Modified";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 413: return "Payload Too Large";
    case 414: return "URI Too Long";
    case 422: return "Unprocessable Entity";
    case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    case 505: return "HTTP Version Not Supported";
    default: return "Status";
  }
}

std::string formatResponseHead(const HttpResponse &r, const std::string &origin, bool preflight) {
  std::string h;
  h.reserve(256);
  h += "HTTP/1.1 ";
  EscapeJson::appendUInt(h, (uint32_t)r.status);
  h += ' ';
  h += statusText(r.status);
  h += "\r\n";
  if (!r.contentType.empty()) h += "Content-Type: " + r.contentType + "\r\n";
  h += "Content-Length: ";
  EscapeJson::appendUInt(h, (uint32_t)r.bodyLength());
  h += "\r\nConnection: close\r\n";
  if (r.gzip) h += "Content-Encoding: gzip\r\n";
  if (!r.etag.empty()) h += "ETag: \"" + r.etag + "\"\r\nCache-Control: no-cache\r\n";
  else if (r.noStore) h += "Cache-Control: no-store\r\n";
  if (!origin.empty() && originAllowed(origin)) {
    h += "Access-Control-Allow-Origin: " + origin + "\r\nVary: Origin\r\n";
    if (preflight) h += "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nAccess-Control-Max-Age: 600\r\n";
  }
  h += "\r\n";
  return h;
}

} // namespace Escape
