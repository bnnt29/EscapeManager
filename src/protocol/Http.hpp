#pragma once

// Portable HTTP/1.1 building blocks: an incremental request parser with hard limits,
// response head formatting, query decoding and the CORS origin policy. No sockets
// here - the same code runs behind lwIP on the ESP32 and behind POSIX sockets in the
// simulator (src/net). The parser never allocates more than the header limit plus
// the body limit the router grants for the requested path.

#include "EscapeConfig.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace Escape {

enum class Method : uint8_t { Get, Head, Post, Options };

struct HttpRequest {
  Method method;
  std::string path;          // without query
  std::string query;         // raw text after '?'
  std::string origin;        // Origin header ("" if absent)
  std::string ifNoneMatch;   // If-None-Match header
  size_t contentLength;
  bool expectContinue;
  std::string body;
  HttpRequest() : method(Method::Get), contentLength(0), expectContinue(false) {}
};

class HttpRequestParser {
public:
  enum class State { Headers, HeadersComplete, Body, Done, Error };

  HttpRequestParser() { reset(); }
  void reset();

  // Consumes bytes and returns how many were used. It stops (possibly before the end
  // of the buffer) when the headers are complete, the request is complete, or an
  // error occurred; call state() to see which. After HeadersComplete the caller
  // decides the body limit for the path via beginBody() and feeds the rest.
  size_t feed(const uint8_t *data, size_t length);

  State state() const { return state_; }
  // HTTP status describing the failure when state() == Error (400/405/413/414/431/501/505).
  int errorStatus() const { return errorStatus_; }
  const HttpRequest &request() const { return req_; }
  HttpRequest &mutableRequest() { return req_; }

  // Call when state() == HeadersComplete. A body longer than maxBody is rejected
  // with 413 before any body byte is buffered; maxBody == 0 means "no body allowed".
  void beginBody(size_t maxBody);
  // Marks the request failed (e.g. route not found) - the caller answers with `status`.
  void fail(int status);

private:
  void parseHead();

  State state_;
  int errorStatus_;
  std::string head_;
  HttpRequest req_;
};

// Value of `name` in a raw query string (percent-decoded, '+' stays '+').
bool queryParam(const std::string &query, const char *name, std::string &out);
bool percentDecode(const std::string &in, std::string &out);

// CORS policy of PROTOCOL.md section 4: "null", localhost/loopback, *.local and
// private IPv4 ranges may call the API from a browser.
bool originAllowed(const std::string &origin);

struct HttpResponse {
  int status;
  std::string contentType;
  std::string body;               // owned body (small responses)
  const uint8_t *staticBody;      // or a body in flash (the gzipped UI)
  size_t staticLength;
  bool gzip;
  std::string etag;               // without quotes; sent as ETag: "<etag>"
  bool noStore;                   // Cache-Control: no-store
  std::string location;           // Location header (3xx), empty = none
  HttpResponse() : status(200), staticBody(nullptr), staticLength(0), gzip(false), noStore(true) {}
  size_t bodyLength() const { return staticBody ? staticLength : body.size(); }
};

const char *statusText(int status);

// Status line and headers (ending with the blank line). `origin` is the request's
// Origin header; CORS headers are added only if originAllowed(). `preflight` adds the
// OPTIONS answer headers. Always `Connection: close`.
std::string formatResponseHead(const HttpResponse &response, const std::string &origin, bool preflight);

} // namespace Escape
