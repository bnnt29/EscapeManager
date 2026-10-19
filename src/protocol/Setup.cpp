// Implementation of Setup.hpp.

#include "Setup.hpp"

#include "Compat.hpp"
#include "Json.hpp"
#include "Peers.hpp"

#include <cstring>

namespace Escape {

namespace {

bool printable(const std::string &s, unsigned char lo, unsigned char hi) {
  for (size_t i = 0; i < s.size(); i++) {
    const unsigned char c = (unsigned char)s[i];
    if (c < lo || c > hi) return false;
  }
  return true;
}

// Escapes text for HTML (element content and double-quoted attributes).
void appendHtml(std::string &out, const std::string &s) {
  for (size_t i = 0; i < s.size(); i++) {
    switch (s[i]) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      case '\'': out += "&#39;"; break;
      default: out += s[i];
    }
  }
}

// form-urlencoded value of `name` ('+' is a space, unlike in URL queries).
bool formValue(const std::string &body, const char *name, std::string &out) {
  size_t pos = 0;
  while (pos <= body.size()) {
    size_t amp = body.find('&', pos);
    if (amp == std::string::npos) amp = body.size();
    const std::string pair = body.substr(pos, amp - pos);
    const size_t eq = pair.find('=');
    std::string key = pair.substr(0, eq);
    for (size_t i = 0; i < key.size(); i++) if (key[i] == '+') key[i] = ' ';
    std::string decodedKey;
    if (percentDecode(key, decodedKey) && decodedKey == name) {
      std::string value = eq == std::string::npos ? std::string() : pair.substr(eq + 1);
      for (size_t i = 0; i < value.size(); i++) if (value[i] == '+') value[i] = ' ';
      return percentDecode(value, out);
    }
    pos = amp + 1;
  }
  out.clear();
  return false;
}

const char kPageHead[] =
    "<!doctype html><html lang=de><meta charset=utf-8>"
    "<meta name=viewport content=\"width=device-width,initial-scale=1\"><title>EscapeManager Setup</title>"
    "<style>body{font:16px system-ui,sans-serif;max-width:30em;margin:1em auto;padding:0 1em}"
    "label{display:block;margin:.8em 0 .2em}input{width:100%;box-sizing:border-box;padding:.5em;font-size:1em}"
    "button,a.b{display:inline-block;margin-top:1.2em;padding:.7em 1.2em;font-size:1em}"
    ".e{color:#b00}.o{color:#060}.n{color:#555;font-size:.9em}</style>";

std::string redirectTarget() {
  char ip[16];
  u32ToIpv4Text(EscapeConfig::SETUP_AP_IP, ip);
  return std::string("http://") + ip + "/setup";
}

const char *phaseText(WifiPhase p) {
  switch (p) {
    case WifiPhase::Connecting: return "verbindet ...";
    case WifiPhase::Connected: return "verbunden";
    case WifiPhase::Failed: return "nicht verbunden";
    case WifiPhase::Idle:
    default: return "kein WLAN konfiguriert";
  }
}

void page(HttpResponse &r, int status, const std::string &body, bool refreshStatus) {
  r.status = status;
  r.contentType = "text/html; charset=utf-8";
  r.body = kPageHead;
  if (refreshStatus) r.body += "<meta http-equiv=refresh content=\"3;url=/setup/status\">";
  r.body += body;
}

void formPage(HttpResponse &r, int status, SetupSink &sink, const std::string &did, const std::string &label,
              const std::string &error) {
  std::string b;
  b.reserve(2048);
  b += "<h1>EscapeManager Setup</h1><p>Ger&auml;t <b>";
  appendHtml(b, label.empty() ? std::string("-") : label);
  b += "</b> (";
  appendHtml(b, did);
  b += ")<br>Setup-WLAN <b>";
  appendHtml(b, sink.setupNetworkName());
  b += "</b> (";
  b += sink.setupNetworkOpen() ? "offen" : "WPA2";
  b += ")</p>";
  if (!error.empty()) {
    b += "<p class=e>";
    appendHtml(b, error);
    b += "</p>";
  }
  const std::string current = sink.configuredSsid();
  b += "<p class=n>Aktuelles WLAN: ";
  if (current.empty()) b += "&ndash;";
  else appendHtml(b, current);
  b += " &middot; Status: ";
  b += phaseText(sink.wifiPhase());
  b += "</p><form method=post action=/setup/save>"
       "<label>WLAN-Name (SSID)<input name=ssid maxlength=32 autocapitalize=off autocomplete=off></label>"
       "<label>WLAN-Passwort<input name=pass maxlength=63 autocapitalize=off autocomplete=off></label>"
       "<label>Token (leer = unver&auml;ndert)<input name=token maxlength=128 autocapitalize=off autocomplete=off></label>"
       "<label>Bearbeiten-Token (leer = unver&auml;ndert)<input name=edit maxlength=128 autocapitalize=off autocomplete=off></label>"
       "<button>Speichern</button></form>"
       "<p class=n>Das Ger&auml;t versucht weiter, sich mit dem konfigurierten WLAN zu verbinden. "
       "Ist die SSID leer, bleibt das WLAN unver&auml;ndert; ein leeres Passwort bedeutet ein offenes WLAN.</p>";
  if (sink.setupNetworkOpen()) {
    b += "<p class=n>Dieses Setup-WLAN ist offen: Jeder in Reichweite kann diese Einstellungen &auml;ndern, "
         "solange das Ger&auml;t kein WLAN hat.</p>";
  }
  page(r, status, b, false);
}

void statusPage(HttpResponse &r, SetupSink &sink) {
  const WifiPhase phase = sink.wifiPhase();
  std::string b = "<h1>EscapeManager Setup</h1><p>WLAN <b>";
  appendHtml(b, sink.configuredSsid());
  b += "</b>: ";
  if (phase == WifiPhase::Connected) {
    b += "<span class=o>verbunden</span>, Adresse ";
    appendHtml(b, sink.wifiAddress());
    b += "</p><p>Das Setup-WLAN schaltet sich gleich ab. Verbinde dein Ger&auml;t wieder mit dem normalen WLAN "
         "und &ouml;ffne <b>http://escapemanager.local</b>.</p>";
  } else if (phase == WifiPhase::Failed) {
    b += "<span class=e>nicht verbunden</span> (";
    appendHtml(b, sink.wifiFailReason());
    b += ")</p><p>Das Ger&auml;t versucht es weiter.</p><a class=b href=/setup>Zur&uuml;ck zum Formular</a>";
  } else {
    b += std::string(phaseText(phase)) + "</p><p class=n>Diese Seite aktualisiert sich selbst.</p>";
  }
  page(r, 200, b, phase == WifiPhase::Connecting || phase == WifiPhase::Idle);
}

} // namespace

// ---- Names and validation --------------------------------------------------------------------------

std::string setupNetworkName(const std::string &did, const std::string &routerSsid) {
  std::string name = std::string(EscapeConfig::SETUP_AP_PREFIX) + did;
  if (name == routerSsid) name += "-S";
  return name;
}

bool isSetupNetworkName(const std::string &ssid) {
  const size_t n = strlen(EscapeConfig::SETUP_AP_PREFIX);
  return ssid.size() >= n && ssid.compare(0, n, EscapeConfig::SETUP_AP_PREFIX) == 0;
}

bool validWifiSsid(const std::string &ssid) {
  if (ssid.empty() || ssid.size() > EscapeConfig::WIFI_SSID_MAX_LEN) return false;
  for (size_t i = 0; i < ssid.size(); i++) {
    const unsigned char c = (unsigned char)ssid[i];
    if (c < 0x20 || c == 0x7f) return false;
  }
  return true;
}

bool validWifiPassword(const std::string &pass) {
  if (pass.empty()) return true; // open network
  return pass.size() >= 8 && pass.size() <= EscapeConfig::WIFI_PASSWORD_MAX_LEN && printable(pass, 0x20, 0x7e);
}

bool validSetupToken(const std::string &token) {
  return token.size() >= EscapeConfig::MIN_AUTH_TOKEN_LEN && token.size() <= EscapeConfig::MAX_AUTH_TOKEN_LEN &&
         printable(token, 0x21, 0x7e);
}

bool validateSetupChange(const SetupChange &c, std::string &error) {
  if (c.hasWifi) {
    if (!validWifiSsid(c.ssid)) { error = "invalid Wi-Fi name (1..32 characters)"; return false; }
    if (isSetupNetworkName(c.ssid)) { error = "a setup network cannot be used as the Wi-Fi to join"; return false; }
    if (!validWifiPassword(c.pass)) { error = "Wi-Fi password must be empty or 8..63 characters"; return false; }
  }
  if (c.hasToken && !c.token.empty() && !validSetupToken(c.token)) {
    error = "token must be 8..128 printable characters";
    return false;
  }
  if (c.hasEditToken && !c.editToken.empty() && !validSetupToken(c.editToken)) {
    error = "edit token must be 8..128 printable characters";
    return false;
  }
  return true;
}

bool parseSetupJson(const std::string &body, SetupChange &out, std::string &error) {
  out = SetupChange();
  EscapeJson::Value doc;
  if (body.empty() || body.size() > 1024 || !EscapeJson::parse(body, doc) || doc.type != EscapeJson::Type::Object) {
    error = "invalid json";
    return false;
  }
  const EscapeJson::Value *ssid = doc.find("ssid"), *pass = doc.find("pass");
  const EscapeJson::Value *token = doc.find("token"), *edit = doc.find("editToken");
  if (ssid || pass) {
    if (!ssid || !pass || ssid->type != EscapeJson::Type::String || pass->type != EscapeJson::Type::String) {
      error = "ssid and pass must be given together as strings";
      return false;
    }
    out.hasWifi = true;
    out.ssid = ssid->stringValue;
    out.pass = pass->stringValue;
  }
  if (token) {
    if (token->type != EscapeJson::Type::String) { error = "token must be a string"; return false; }
    out.hasToken = true;
    out.token = token->stringValue;
  }
  if (edit) {
    if (edit->type != EscapeJson::Type::String) { error = "editToken must be a string"; return false; }
    out.hasEditToken = true;
    out.editToken = edit->stringValue;
  }
  if (out.empty()) { error = "nothing to change"; return false; }
  return validateSetupChange(out, error);
}

bool parseSetupForm(const std::string &body, SetupChange &out, std::string &error) {
  out = SetupChange();
  if (body.size() > 2048) { error = "Eingabe zu lang"; return false; }
  std::string ssid, pass, token, edit;
  formValue(body, "ssid", ssid);
  formValue(body, "pass", pass);
  formValue(body, "token", token);
  formValue(body, "edit", edit);
  if (!ssid.empty()) {
    out.hasWifi = true;
    out.ssid = ssid;
    out.pass = pass;
  } else if (!pass.empty()) {
    error = "WLAN-Name fehlt";
    return false;
  }
  if (!token.empty()) { out.hasToken = true; out.token = token; }
  if (!edit.empty()) { out.hasEditToken = true; out.editToken = edit; }
  if (out.empty()) { error = "Nichts zu speichern"; return false; }
  std::string detail;
  if (!validateSetupChange(out, detail)) {
    if (out.hasWifi && !validWifiSsid(out.ssid)) error = "WLAN-Name ung\xc3\xbc" "ltig (1 bis 32 Zeichen)";
    else if (out.hasWifi && isSetupNetworkName(out.ssid)) error = "Ein Setup-WLAN kann nicht als WLAN eingetragen werden";
    else if (out.hasWifi && !validWifiPassword(out.pass)) error = "WLAN-Passwort: leer (offenes WLAN) oder 8 bis 63 Zeichen";
    else error = "Token: 8 bis 128 Zeichen ohne Leerzeichen";
    return false;
  }
  return true;
}

// ---- DNS -------------------------------------------------------------------------------------------------

size_t buildDnsAnswer(const uint8_t *q, size_t length, uint32_t address, uint8_t *out, size_t capacity) {
  if (length < 17 || length > 512) return 0;
  const uint16_t flags = (uint16_t)((q[2] << 8) | q[3]);
  if (flags & 0x8000) return 0;                 // a response, not a query
  if (((flags >> 11) & 0xF) != 0) return 0;     // only standard queries
  if (q[4] != 0 || q[5] != 1) return 0;         // exactly one question
  size_t pos = 12;
  while (pos < length && q[pos] != 0) {
    if (q[pos] & 0xC0) return 0;                // no compression in the question
    pos += (size_t)q[pos] + 1;
  }
  if (pos + 5 > length) return 0;               // terminator + type + class
  const size_t questionEnd = pos + 5;
  const uint16_t qtype = (uint16_t)((q[pos + 1] << 8) | q[pos + 2]);
  const bool wantA = qtype == 1 || qtype == 255; // A or ANY
  const size_t answerLength = wantA ? 16 : 0;
  if (questionEnd + answerLength > capacity) return 0;

  memcpy(out, q, questionEnd);
  out[2] = 0x81;                                 // QR, recursion desired
  out[3] = 0x80;                                 // recursion available, NOERROR
  out[6] = 0; out[7] = wantA ? 1 : 0;            // answers
  out[8] = out[9] = out[10] = out[11] = 0;       // no authority/additional records
  if (wantA) {
    uint8_t *a = out + questionEnd;
    a[0] = 0xC0; a[1] = 0x0C;                    // name: pointer to the question
    a[2] = 0; a[3] = 1;                          // A
    a[4] = 0; a[5] = 1;                          // IN
    a[6] = 0; a[7] = 0; a[8] = 0; a[9] = 30;     // TTL 30 s
    a[10] = 0; a[11] = 4;
    a[12] = (uint8_t)(address >> 24); a[13] = (uint8_t)(address >> 16);
    a[14] = (uint8_t)(address >> 8);  a[15] = (uint8_t)address;
  }
  return questionEnd + answerLength;
}

// ---- Portal ------------------------------------------------------------------------------------------------

void handleSetupPortal(const HttpRequest &request, SetupSink &sink, const std::string &did, const std::string &label,
                       HttpResponse &response, bool &tokensChanged) {
  tokensChanged = false;
  const bool post = request.method == Method::Post;
  if (post && request.path == "/setup/save") {
    SetupChange change;
    std::string error;
    if (!parseSetupForm(request.body, change, error)) return formPage(response, 400, sink, did, label, error);
    if (sink.applySetup(change, false) != SetupResult::Ok) {
      return formPage(response, 500, sink, did, label, "Speichern fehlgeschlagen");
    }
    tokensChanged = change.hasToken || change.hasEditToken;
    std::string b = "<h1>EscapeManager Setup</h1><p class=o>Gespeichert.</p><p>";
    if (change.hasWifi) b += "Das Ger&auml;t verbindet sich jetzt mit dem neuen WLAN. ";
    if (tokensChanged) b += "Die Token gelten ab sofort. ";
    b += "</p><p class=n>Diese Seite zeigt gleich das Ergebnis.</p>";
    return page(response, 200, b, true);
  }
  if (!post && request.path == "/setup") return formPage(response, 200, sink, did, label, std::string());
  if (!post && request.path == "/setup/status") return statusPage(response, sink);
  if (post) {
    response.status = 404;
    response.contentType = "text/plain";
    response.body = "not found";
    return;
  }
  // Captive-portal probes (generate_204, hotspot-detect.html, connecttest.txt, ...) and anything else.
  response.status = 302;
  response.contentType = "text/plain";
  response.location = redirectTarget();
  response.body = "setup";
}

} // namespace Escape
