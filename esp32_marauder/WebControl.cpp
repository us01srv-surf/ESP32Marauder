#include "WebControl.h"

#include <WiFi.h>

#include <stdarg.h>  // P4: vsnprintf() arena formatter
#include <string.h>  // P4: memcpy()/strlen() arena appends

#include "WiFiScan.h"
#include "settings.h"
#include "utils.h"
// P3 pulls in the CLI/recon/list externs (cli_obj is declared right below):
//   extern ReconMission recon_obj;   CommandLine.h:36
//   extern LinkedList<ssid>* ssids;  CommandLine.h:45
// CommandLine.h includes WebControl.h, but this file already included it, so
// the include guard stops the cycle.
#include "CommandLine.h"

extern WiFiScan wifi_scan_obj;
extern CommandLine cli_obj;

// Chip name reported by GET /api/v1/info. On the ESP32-S3 targets this is the
// "ESP32-S3" of the P1 API contract; the other branches keep the field truthful
// for the rest of the build matrix instead of lying about the silicon.
#if defined(CONFIG_IDF_TARGET_ESP32S3)
  #define WEBUI_CHIP "ESP32-S3"
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
  #define WEBUI_CHIP "ESP32-S2"
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
  #define WEBUI_CHIP "ESP32-C3"
#elif defined(CONFIG_IDF_TARGET_ESP32C5)
  #define WEBUI_CHIP "ESP32-C5"
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
  #define WEBUI_CHIP "ESP32-C6"
#elif defined(CONFIG_IDF_TARGET_ESP32H2)
  #define WEBUI_CHIP "ESP32-H2"
#else
  #define WEBUI_CHIP "ESP32"
#endif

static uint8_t hexNib(char c) {
  if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
  if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
  if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
  return 0;
}

// True only for characters that can appear in a %XX escape (hexNib() maps
// anything else to 0, so callers must gate on this first).
static bool hexOk(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// ---------------------------------------------------------------------------
// P4 list-snapshot helpers — loop task only (parseListQuery() runs in the
// async_tcp task but only touches its own request). Every writer here is
// bounds-checked against the PSRAM arena, so a build either produces a
// complete, valid JSON document or reports failure and publishes nothing.
// ---------------------------------------------------------------------------

// Strict decimal parse: digits only, no sign, no whitespace, no empty string.
// Rejecting rather than defaulting matters for `limit=abc` (spec: 400) while
// an absent parameter never reaches this function at all.
static bool parseU16(const String& s, uint16_t& out) {
  if (s.length() == 0 || s.length() > 5)  // >5 digits can never fit uint16
    return false;
  uint32_t value = 0;
  for (unsigned i = 0; i < s.length(); i++) {
    const char c = s[i];
    if (c < '0' || c > '9')
      return false;
    value = value * 10u + (uint32_t)(c - '0');
    if (value > 65535UL)
      return false;
  }
  out = (uint16_t)value;
  return true;
}

// Bounded formatted append into the arena. Returns false when the text would
// not fit, which also catches vsnprintf() truncation: the caller then stops
// the build instead of publishing a document that was cut mid-field.
static bool snapFmt(char* dst, size_t cap, size_t* len, const char* fmt, ...) {
  if (*len >= cap)
    return false;
  va_list ap;
  va_start(ap, fmt);
  const int written = vsnprintf(dst + *len, cap - *len, fmt, ap);
  va_end(ap);
  if (written < 0 || (size_t)written >= cap - *len)
    return false;
  *len += (size_t)written;
  return true;
}

// Bounded raw append (separator commas, quotes, the envelope tail). The
// comparison leaves room for the terminating NUL at dst[*len].
static bool snapRaw(char* dst, size_t cap, size_t* len, const char* text) {
  const size_t n = strlen(text);
  if (n == 0)
    return true;
  if (*len + n >= cap)
    return false;
  memcpy(dst + *len, text, n);
  *len += n;
  return true;
}

// Length of the UTF-8 sequence starting at s (avail bytes remain), or 0 when
// the bytes are not a well-formed sequence (truncated, overlong, surrogate).
// SSIDs are arbitrary bytes on the air, and a JSON document must be valid
// UTF-8 or browsers refuse to JSON.parse() it at all.
static size_t utf8Unit(const uint8_t* s, size_t avail) {
  if (avail < 1)
    return 0;
  const uint8_t lead = s[0];
  size_t n;
  if ((lead & 0xE0) == 0xC0) {
    n = 2;
    if (lead < 0xC2) return 0;  // overlong
  } else if ((lead & 0xF0) == 0xE0) {
    n = 3;
  } else if ((lead & 0xF8) == 0xF0) {
    n = 4;
    if (lead > 0xF4) return 0;  // > U+10FFFF
  } else {
    return 0;  // continuation byte without a lead, or 5/6-byte lead
  }
  if (n > avail)
    return 0;
  if (n == 3 && lead == 0xE0 && s[1] < 0xA0) return 0;        // overlong
  if (n == 3 && lead == 0xED && s[1] >= 0xA0) return 0;       // UTF-16 surrogate
  if (n == 4 && lead == 0xF0 && s[1] < 0x90) return 0;        // overlong
  for (size_t i = 1; i < n; i++)
    if ((s[i] & 0xC0) != 0x80)
      return 0;
  return n;
}

// Appends the *body* of a JSON string (the caller writes the quotes) into the
// arena. SSIDs are arbitrary bytes, so:
//   " and \   -> \" \\   (the two characters JSON requires escaped)
//   < 0x20    -> '?'     (control characters are not representable)
//   bad UTF-8 -> '?'     (one byte at a time, so one bad byte costs one '?')
//   >= 0x80   -> copied through when it is a well-formed multi-byte sequence,
//                so UTF-8 SSIDs survive unchanged
// out_max caps the emitted length: a corrupt/over-long essid can never blow
// the arena budget. Returns false only on arena overflow.
static bool snapEsc(char* dst, size_t cap, size_t* len,
                    const char* src, size_t src_len, size_t out_max) {
  const size_t start = *len;
  size_t i = 0;
  while (i < src_len) {
    char unit[4];
    size_t unit_len = 1;
    size_t consumed = 1;
    const uint8_t c = (uint8_t)src[i];

    if (c == '"' || c == '\\') {
      unit[0] = '\\';
      unit[1] = (char)c;
      unit_len = 2;
    }
    else if (c < 0x20) {
      unit[0] = '?';
    }
    else if (c < 0x80) {
      unit[0] = (char)c;
    }
    else {
      const size_t n = utf8Unit((const uint8_t*)src + i, src_len - i);
      if (n == 0) {
        unit[0] = '?';
      }
      else {
        for (size_t k = 0; k < n; k++)
          unit[k] = src[i + k];
        unit_len = n;
        consumed = n;
      }
    }

    // Bound both ways before emitting: never run past the arena and never
    // past out_max (a unit is never written partially, so truncation is
    // always at a character boundary).
    if (*len + unit_len >= cap)
      return false;
    if (*len - start + unit_len > out_max)
      break;
    memcpy(dst + *len, unit, unit_len);
    *len += unit_len;
    i += consumed;
  }
  return true;
}

// ---------------------------------------------------------------------------
// setup() — called once from the Arduino setup() after cli_obj.RunSetup() and
// the boot StartScan(WIFI_SCAN_OFF). Never blocks boot: the heap guard below
// simply skips the service when DRAM is tight.
// ---------------------------------------------------------------------------
void WebControl::setup() {
  if (!settings_obj.loadSetting<bool>(WEBUI_SETTING_KEY)) {
    Serial.println(F("webui disabled (settings WebUI)"));
    return;
  }

  if (ESP.getFreeHeap() < (uint32_t)MEM_LOWER_LIM + WEBUI_START_HEAP_MARGIN) {
    Serial.print(F("webui skipped: low heap "));
    Serial.println(ESP.getFreeHeap());
    return;
  }

  // Basic SoftAP by default; start() itself downgrades to "server only" when
  // the Evil Portal owns WiFi.
  start(WEBUI_MODE_AP);
}

// ---------------------------------------------------------------------------
// start(mode) — lazily builds the server (once per server object), registers
// the P1 routes, opens the listen socket and optionally brings up the SoftAP.
// ---------------------------------------------------------------------------
bool WebControl::start(uint8_t mode) {
  // Routes are registered lazily on first start() and never twice for the same
  // server object (re-registering would stack handlers). Same once-only guard
  // EvilPortal.cpp uses in startAP(); it is cleared whenever a new server
  // object is allocated below.
  static bool s_routes_registered = false;

  start_mode = mode;

  if (running) {
    Serial.println(F("webui already running"));
    return true;
  }

  const bool portal = portalOwnsWifi();

  if (portal) {
    // Evil Portal owns the radio + its own server on :80 — begin only, no
    // WiFi changes at all.
    Serial.println(F("webui: evil portal owns WiFi, starting server only"));
  }
  else if (mode == WEBUI_MODE_AP) {
    refreshNetCache();

    // Open SoftAP named Marauder-<last 2 MAC bytes>, fixed 192.168.4.1, no DNS.
    // Shared with the P3 interface-recovery monitor.
    initSoftAP();
    owns_ap = true;
  }
  else {
    // STA mode: serve on whatever interface exists / shows up later.
    if (WiFi.getMode() == WIFI_MODE_NULL)
      WiFi.mode(WIFI_MODE_STA);
  }

  if (server == nullptr) {
    server = new AsyncWebServer(WEBUI_PORT);
    if (server == nullptr) {
      Serial.println(F("webui start failed: out of memory"));
      return false;
    }
    // Fresh server object => its routes must be (re)registered.
    s_routes_registered = false;
  }

  // P4: the two snapshot arenas follow the server's lifetime — allocated on
  // the first start(), freed only by the stage-2 teardown in main(). PSRAM
  // first; targets without a PSRAM chip (most of the build matrix) fall back
  // to DRAM so the list endpoints still work there. On any failure the pair
  // is released together and the endpoints answer 503 LOW_HEAP instead of
  // building into a null arena.
  if (snap_buf[0] == nullptr || snap_buf[1] == nullptr) {
    free(snap_buf[0]);
    free(snap_buf[1]);
    snap_buf[0] = nullptr;
    snap_buf[1] = nullptr;
    snap_buf[0] = (char*)ps_malloc(WEBUI_SNAP_BUF_SIZE);
    snap_buf[1] = (char*)ps_malloc(WEBUI_SNAP_BUF_SIZE);
    if (snap_buf[0] == nullptr)
      snap_buf[0] = (char*)malloc(WEBUI_SNAP_BUF_SIZE);
    if (snap_buf[1] == nullptr)
      snap_buf[1] = (char*)malloc(WEBUI_SNAP_BUF_SIZE);
    if (snap_buf[0] == nullptr || snap_buf[1] == nullptr) {
      free(snap_buf[0]);
      free(snap_buf[1]);
      snap_buf[0] = nullptr;
      snap_buf[1] = nullptr;
      Serial.println(F("webui: snapshot arena alloc failed"));
    }
    // Nothing can be published into a freshly (re)built arena pair.
    publish_idx = -1;
    snap_want = false;
  }

  if (!s_routes_registered) {
    server->on("/api/v1/info", HTTP_GET, [this](AsyncWebServerRequest* request) {
      this->handleInfo(request);
    });

    // P3 read endpoint: everything the loop task publishes to volatile fields.
    server->on("/api/v1/status", HTTP_GET, [this](AsyncWebServerRequest* request) {
      this->handleStatus(request);
    });

    // P3 control endpoints: these only publish into the pending-action slot;
    // main() performs the actual scan/recon/CLI calls in the loop task.
    server->on("/api/v1/scan", HTTP_POST, [this](AsyncWebServerRequest* request) {
      this->handleScan(request);
    });
    server->on("/api/v1/recon", HTTP_POST, [this](AsyncWebServerRequest* request) {
      this->handleRecon(request);
    });
    server->on("/api/v1/cli", HTTP_POST, [this](AsyncWebServerRequest* request) {
      this->handleCli(request);
    });

    // P4 list endpoints: registered before the catch-all. The handlers never
    // iterate a list — they replay a loop-task snapshot arena or queue the
    // query and answer 503 SNAPSHOT_PENDING for the UI to retry.
    server->on("/api/v1/aps", HTTP_GET, [this](AsyncWebServerRequest* request) {
      this->handleList(request, LIST_APS, "aps");
    });
    server->on("/api/v1/stations", HTTP_GET, [this](AsyncWebServerRequest* request) {
      this->handleList(request, LIST_STATIONS, "stations");
    });
    server->on("/api/v1/ssids", HTTP_GET, [this](AsyncWebServerRequest* request) {
      this->handleList(request, LIST_SSIDS, "ssids");
    });

    // P4 reconciliation alias: same 128-byte CLI slot and marshaling as
    // /api/v1/cli (see handleCmd for the body-format contract).
    server->on("/api/v1/cmd", HTTP_POST, [this](AsyncWebServerRequest* request) {
      this->handleCmd(request);
    });

    // Catch-all, registered LAST: 404 JSON for everything P1 does not expose.
    // onNotFound() backs it up in case a library build does not honour the
    // trailing-"*" wildcard.
    server->on("/*", HTTP_ANY, [this](AsyncWebServerRequest* request) {
      this->handleNotFound(request);
    });
    server->onNotFound([this](AsyncWebServerRequest* request) {
      this->handleNotFound(request);
    });

    s_routes_registered = true;
  }

  server->begin();

  running = true;
  stopping = false;
  end_time = 0;
  last_cache_refresh = millis();
  // Interface-recovery monitor baseline: no edge is pending at start, and the
  // 2 s throttle window opens now.
  last_scanning = wifi_scan_obj.scanning();
  iface_edge = false;
  last_iface_check = millis();
  refreshNetCache();

  persistSetting(true);

  if (ip_addr == 0) {
    Serial.println(F("webui started (no IP yet: start -ap or join a network)"));
  }
  else {
    Serial.print(F("webui started: http://"));
    Serial.printf("%u.%u.%u.%u:%u\n",
                  (unsigned)((ip_addr >> 24) & 0xFF),
                  (unsigned)((ip_addr >> 16) & 0xFF),
                  (unsigned)((ip_addr >> 8) & 0xFF),
                  (unsigned)(ip_addr & 0xFF),
                  (unsigned)WEBUI_PORT);
  }

  return true;
}

// ---------------------------------------------------------------------------
// stop() — STAGE 1 only, immediate and safe at any time: close the listen
// socket (established connections keep draining) and drop the SoftAP we own.
// The server object is freed later, from main() (STAGE 2). There is no
// force-delete: deletion without a drain would pull handlers out from under
// the async_tcp task.
// ---------------------------------------------------------------------------
void WebControl::stop() {
  // Single source of truth: stop persists "WebUI = disabled".
  persistSetting(false);

  if (stopping) {
    Serial.println(F("webui already stopping"));
    return;
  }

  if (server == nullptr) {
    running = false;
    Serial.println(F("webui not running"));
    return;
  }

  server->end();  // closes the listen socket only; clients survive

  if (owns_ap && WiFi.status() != WL_CONNECTED) {
    WiFi.softAPdisconnect(true);
    owns_ap = false;
  }

  running = false;
  stopping = true;
  end_time = millis();

  Serial.print(F("stopping (draining "));
  Serial.print(in_flight);
  Serial.println(F(")"));
}

// ---------------------------------------------------------------------------
// status()
// ---------------------------------------------------------------------------
void WebControl::status() {
  Serial.println(F("--- webui status ---"));

  Serial.print(F("state: "));
  if (stopping)
    Serial.println(F("stopping"));
  else
    Serial.println(running ? F("running") : F("stopped"));

  Serial.print(F("mode: "));
  Serial.print(modeName());
  Serial.print(F(" (start: "));
  Serial.print(start_mode == WEBUI_MODE_STA ? "sta" : "ap");
  Serial.println(F(")"));

  Serial.print(F("ip: "));
  Serial.printf("%u.%u.%u.%u\n",
                (unsigned)((ip_addr >> 24) & 0xFF),
                (unsigned)((ip_addr >> 16) & 0xFF),
                (unsigned)((ip_addr >> 8) & 0xFF),
                (unsigned)(ip_addr & 0xFF));

  Serial.print(F("in_flight: "));
  Serial.println(in_flight);

  Serial.print(F("dram free: "));
  Serial.print(ESP.getFreeHeap());
  Serial.print(F(" ("));
  Serial.print(getDRAMUsagePercent());
  Serial.println(F("% used)"));

  #ifdef HAS_PSRAM
    Serial.print(F("psram free: "));
    Serial.print(ESP.getFreePsram());
    Serial.print(F(" ("));
    Serial.print(getPSRAMUsagePercent());
    Serial.println(F("% used)"));
  #endif

  Serial.print(F("WebUI setting: "));
  Serial.println(settings_obj.loadSetting<bool>(WEBUI_SETTING_KEY) ? F("enabled") : F("disabled"));
}

// ---------------------------------------------------------------------------
// main() — runs in the loop task. STAGE 2 lives here: the server object is
// deleted only once every request that was in flight at stop() time has
// finished and the drain grace period has elapsed.
// ---------------------------------------------------------------------------
void WebControl::main() {
  // P3 marshaling: run any action a route handler published first, and run it
  // unconditionally — a request can be accepted and immediately followed by a
  // `webui stop`, and the slot must never be left stuck (a stuck slot would
  // answer 503 BUSY to every later control request).
  consumePending();

  if (stopping) {
    if (in_flight == 0 && (millis() - end_time) >= WEBUI_DRAIN_MS) {
      // P4: the snapshot arenas belong to the same lifecycle as the server.
      // in_flight == 0 means no handler is inside tryServeSnapshot(), and a
      // request that arrives from here on is shed by stop()'s STOPPING check
      // before it ever reaches an arena — so no reader can still hold one.
      publish_idx = -1;  // drop the published reference before freeing
      snap_want = false;
      free(snap_buf[0]);
      snap_buf[0] = nullptr;
      free(snap_buf[1]);
      snap_buf[1] = nullptr;
      delete server;
      server = nullptr;
      stopping = false;
      Serial.println(F("webui freed"));
    }
    return;
  }

  if (!running)
    return;

  // P4: build a queued list snapshot here, in the loop task. All list
  // iteration (and any risk of the lists shrinking under us) stays in this
  // task; the async_tcp task only ever reads a finished arena.
  buildSnapshot();

  // P3 interface-recovery monitor (§5 v1): a scan/recon that ends can leave
  // the WiFi interface off (WiFiScan::shutdownWiFi() calls WiFi.mode(WIFI_OFF)).
  monitorIface();

  if ((millis() - last_cache_refresh) >= 2000) {
    last_cache_refresh = millis();
    refreshNetCache();
  }
}

// ---------------------------------------------------------------------------
// Handlers — these run in the async_tcp task, so they only read the
// volatile flags/counters and the cached network facts (no WiFi calls, no
// list iteration) and build one small fixed response.
// ---------------------------------------------------------------------------

void WebControl::trackReq(AsyncWebServerRequest* request) {
  in_flight++;
  request->onDisconnect([this]() { in_flight--; });
}

// One error envelope for every failure path (P1 shed + P3 BAD_PARAM/BUSY):
// {"protocol":1,"command":"...","status":"error","code":"..."}.
void WebControl::sendError(AsyncWebServerRequest* request, const char* command,
                           const char* code, int http_code) {
  char body[192];
  snprintf(body, sizeof(body),
           "{\"protocol\":1,\"command\":\"%s\",\"status\":\"error\",\"code\":\"%s\"}",
           command, code);
  request->send(http_code, "application/json", body);
}

// 202-style acceptance: the action only *entered* the pending slot here; the
// loop task performs it.
void WebControl::sendAccepted(AsyncWebServerRequest* request, const char* command) {
  char body[128];
  snprintf(body, sizeof(body),
           "{\"protocol\":1,\"command\":\"%s\",\"status\":\"accepted\"}",
           command);
  request->send(200, "application/json", body);
}

bool WebControl::shedRequest(AsyncWebServerRequest* request, const char* command) {
  if (stopping) {
    sendError(request, command, "STOPPING", 503);
    return true;
  }

  if (ESP.getFreeHeap() < (uint32_t)MEM_LOWER_LIM + WEBUI_LOW_HEAP_MARGIN) {
    sendError(request, command, "LOW_HEAP", 503);
    return true;
  }

  return false;
}

void WebControl::handleInfo(AsyncWebServerRequest* request) {
  trackReq(request);
  if (shedRequest(request, "info"))
    return;

  // Fixed buffer on the handler stack: the formatted body is well under 1KB.
  // (For gzip HTML later: request->beginResponse_P(200, "text/html", buf, len)
  //  then r->addHeader("Content-Encoding", "gzip"); request->send(r);
  //  — request->addHeader() does not exist on the request object.)
  const uint32_t ip = ip_addr;
  char body[256];
  snprintf(body, sizeof(body),
           "{\"chip\":\"" WEBUI_CHIP "\","
           "\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
           "\"fw\":\"%s\","
           "\"heap_free\":%u,"
           "\"psram_free\":%u,"
           "\"mode\":\"%s\","
           "\"ip\":\"%u.%u.%u.%u\","
           "\"webui\":\"%s\"}",
           (unsigned)mac6[0], (unsigned)mac6[1], (unsigned)mac6[2],
           (unsigned)mac6[3], (unsigned)mac6[4], (unsigned)mac6[5],
           MARAUDER_VERSION,
           (unsigned)ESP.getFreeHeap(),
           (unsigned)ESP.getFreePsram(),
           modeName(),
           (unsigned)((ip >> 24) & 0xFF),
           (unsigned)((ip >> 16) & 0xFF),
           (unsigned)((ip >> 8) & 0xFF),
           (unsigned)(ip & 0xFF),
           running ? "running" : "stopped");

  request->send(200, "application/json", body);
}

// GET /api/v1/status — read-only snapshot of the loop-task state. Every value
// is either a volatile this class owns or a one-word read of a public helper;
// no list is iterated, so the body stays well under 1 KB and the handler
// never blocks the async_tcp task.
void WebControl::handleStatus(AsyncWebServerRequest* request) {
  trackReq(request);
  if (shedRequest(request, "status"))
    return;

  // ssids is the same list `list -s` walks (CommandLine.cpp); it is only ever
  // dereferenced here, never iterated, and it is null until WiFiScan builds it.
  const unsigned long ssid_count =
      (ssids == nullptr) ? 0UL : (unsigned long)ssids->size();

  const uint32_t ip = ip_addr;
  char body[512];
  snprintf(body, sizeof(body),
           "{\"protocol\":1,\"command\":\"status\",\"status\":\"ok\","
           "\"scanning\":%s,"
           "\"recon\":%s,"
           "\"ap_count\":%u,"
           "\"st_count\":%u,"
           "\"ssid_count\":%u,"
           "\"scan_mode\":%u,"
           "\"uptime_ms\":%u,"
           "\"webui\":{\"state\":\"%s\",\"mode\":\"%s\",\"in_flight\":%d},"
           "\"ip\":\"%u.%u.%u.%u\","
           "\"heap_free\":%u}",
           wifi_scan_obj.scanning() ? "true" : "false",
           recon_obj.active() ? "true" : "false",
           (unsigned)wifi_scan_obj.retainedAccessPointCount(),
           (unsigned)wifi_scan_obj.retainedStationCount(),
           (unsigned)ssid_count,
           (unsigned)wifi_scan_obj.currentScanMode,
           (unsigned)millis(),
           stopping ? "stopping" : (running ? "running" : "stopped"),
           modeName(),
           (int)in_flight,
           (unsigned)((ip >> 24) & 0xFF),
           (unsigned)((ip >> 16) & 0xFF),
           (unsigned)((ip >> 8) & 0xFF),
           (unsigned)(ip & 0xFF),
           (unsigned)ESP.getFreeHeap());

  request->send(200, "application/json", body);
}

// POST /api/v1/scan?mode=ap_sta|off — marshaled. StartScan() is loop-task
// state (it reconfigures the radio), so the handler only claims the pending
// slot and answers "accepted"; main() runs the scan.
void WebControl::handleScan(AsyncWebServerRequest* request) {
  trackReq(request);
  if (shedRequest(request, "scan"))
    return;

  const AsyncWebParameter* mode_param = request->getParam("mode");
  if (mode_param == nullptr) {
    sendError(request, "scan", "BAD_PARAM", 400);
    return;
  }

  const String& mode = mode_param->value();
  uint8_t kind;
  if (mode == "ap_sta")
    kind = PendingAction::PEND_SCAN_ON;
  else if (mode == "off")
    kind = PendingAction::PEND_SCAN_OFF;
  else {
    sendError(request, "scan", "BAD_PARAM", 400);
    return;
  }

  if (pending_set) {  // one slot only — never overwrite an unrun action
    sendError(request, "scan", "BUSY", 503);
    return;
  }

  pending.arg = 0;
  pending.kind = kind;
  pending_set = true;  // publish after the payload is filled
  sendAccepted(request, "scan");
}

// POST /api/v1/recon?mode=wifi|ble|stop — exact mirror of the CLI dispatch
// (CommandLine.cpp RECON_CMD): stop/status run unconditionally, starting recon
// is refused while a scan runs, and `ble` only exists on HAS_BT builds.
void WebControl::handleRecon(AsyncWebServerRequest* request) {
  trackReq(request);
  if (shedRequest(request, "recon"))
    return;

  const AsyncWebParameter* mode_param = request->getParam("mode");
  if (mode_param == nullptr) {
    sendError(request, "recon", "BAD_PARAM", 400);
    return;
  }

  const String& mode = mode_param->value();
  uint8_t kind;
  if (mode == "stop")
    kind = PendingAction::PEND_RECON_STOP;
  else if (mode == "wifi")
    kind = PendingAction::PEND_RECON_WIFI;
  else if (mode == "ble") {
    #ifdef HAS_BT
      kind = PendingAction::PEND_RECON_BLE;
    #else
      sendError(request, "recon", "BAD_PARAM", 400);
      return;
    #endif
  }
  else {
    sendError(request, "recon", "BAD_PARAM", 400);
    return;
  }

  // Mirror of the CLI guard: "Stop the current scan before starting Recon".
  // reading scanning() is a one-word read of a public helper, safe here.
  if (kind != PendingAction::PEND_RECON_STOP && wifi_scan_obj.scanning()) {
    sendError(request, "recon", "BUSY", 503);
    return;
  }

  if (pending_set) {
    sendError(request, "recon", "BUSY", 503);
    return;
  }

  pending.arg = 0;
  pending.kind = kind;
  pending_set = true;
  sendAccepted(request, "recon");
}

// POST /api/v1/cli?cmd=<urlencoded> — P3-lite. The command string is copied
// into the fixed 128-byte slot and run by the loop task; its output stays on
// serial (capturing it is out of scope). Commands longer than 127 bytes are
// rejected, never truncated. Decoding/claiming lives in claimCliSlot(), which
// the P4 /api/v1/cmd alias shares verbatim.
void WebControl::handleCli(AsyncWebServerRequest* request) {
  trackReq(request);
  if (shedRequest(request, "cli"))
    return;

  const AsyncWebParameter* cmd_param = request->getParam("cmd");
  if (cmd_param == nullptr) {
    sendError(request, "cli", "BAD_PARAM", 400);
    return;
  }

  claimCliSlot(request, "cli", cmd_param->value());
}

// POST /api/v1/cmd — P4 reconciliation alias for the cross-lane contract: any
// client that expects a `cmd` endpoint reaches the exact same 128-byte slot,
// marshaling and error codes as /api/v1/cli (only the envelope's command
// field differs: "cmd" instead of "cli").
//
// Body format: form-encoded, i.e. Content-Type:
// application/x-www-form-urlencoded with a `cmd=...` field (or ?cmd=... on
// the query string, which /api/v1/cli already accepts). A raw JSON body is
// deliberately NOT supported: the vendored ESPAsyncWebServer v2.10.4 exposes
// no public body reader on AsyncWebServerRequest (only the private _onData),
// so a JSON body would have to go through a route-level body handler whose
// on(uri, method, onRequest, onUpload, onBody) signature could not be
// verified against CI's v3.8.1 — the least risky path is the parser the
// library already runs for urlencoded bodies (WebRequest.cpp
// _parsePlainPostChar), which is identical in both versions. UI: send the
// command form-encoded.
void WebControl::handleCmd(AsyncWebServerRequest* request) {
  trackReq(request);
  if (shedRequest(request, "cmd"))
    return;

  // Body parameter first (post=true), then the query string as a fallback.
  const AsyncWebParameter* cmd_param = request->getParam("cmd", true);
  if (cmd_param == nullptr)
    cmd_param = request->getParam("cmd");
  if (cmd_param == nullptr) {
    sendError(request, "cmd", "BAD_PARAM", 400);
    return;
  }

  claimCliSlot(request, "cmd", cmd_param->value());
}

// Shared P3 CLI-slot claim (called by handleCli and handleCmd): decodes %XX
// escapes, enforces the 127-byte limit and publishes PEND_CLI for main().
// Always sends exactly one response, using `command` ("cli"/"cmd") in the
// envelope and the same codes as before: 400 BAD_PARAM, 503 BUSY.
void WebControl::claimCliSlot(AsyncWebServerRequest* request,
                              const char* command, const String& raw) {
  // Minimal %XX decode. ESPAsyncWebServer already decodes query and
  // form-body parameters (WebRequest.cpp: _addGetParams / _parsePlainPostChar),
  // so this is normally a no-op; it only fires for values that still carry a
  // valid escape. Invalid escapes are copied through untouched, and a %XX
  // that would not fit is an overflow.
  char decoded[WEBUI_CLI_MAX];
  size_t out = 0;
  for (size_t i = 0; i < raw.length(); i++) {
    const char c = raw[i];
    char value;
    if (c == '%' && (i + 2) < raw.length() &&
        hexOk(raw[i + 1]) && hexOk(raw[i + 2])) {
      value = (char)((hexNib(raw[i + 1]) << 4) | hexNib(raw[i + 2]));
      i += 2;
    }
    else {
      value = c;
    }
    if (out + 1 >= sizeof(decoded)) {  // >127 decoded bytes
      sendError(request, command, "BAD_PARAM", 400);
      return;
    }
    decoded[out++] = value;
  }
  decoded[out] = '\0';

  if (out == 0) {
    sendError(request, command, "BAD_PARAM", 400);
    return;
  }

  if (pending_set) {
    sendError(request, command, "BUSY", 503);
    return;
  }

  for (size_t i = 0; i <= out; i++)  // include the NUL
    pending.cmd[i] = decoded[i];
  pending.arg = 0;
  pending.kind = PendingAction::PEND_CLI;
  pending_set = true;
  sendAccepted(request, command);
}

// ---------------------------------------------------------------------------
// P4 list endpoints — GET /api/v1/{aps,stations,ssids}?offset=<n>&limit=<n>
//
// The handler does zero list iteration: it either replays the arena the loop
// task already published for this exact query (and a copy is made inside this
// call, so the arena is free again before send() returns), or it queues the
// query and answers 503 SNAPSHOT_PENDING. P1 pollers already retry on that
// code, so the client sees at most one extra round trip per rebuild.
// ---------------------------------------------------------------------------

void WebControl::handleList(AsyncWebServerRequest* request, ListKind kind,
                            const char* command) {
  trackReq(request);
  if (shedRequest(request, command))
    return;

  // Both arenas are needed (the builder must not reuse the published one).
  if (snap_buf[0] == nullptr || snap_buf[1] == nullptr) {
    sendError(request, command, "LOW_HEAP", 503);
    return;
  }

  uint16_t offset = 0;
  uint16_t limit = WEBUI_LIST_LIMIT_DEFAULT;
  if (!parseListQuery(request, command, offset, limit))
    return;  // 400 BAD_PARAM already sent

  if (tryServeSnapshot(request, command, kind, offset, limit))
    return;  // 200 (or 503 LOW_HEAP) already sent

  queueSnapshot(kind, offset, limit);
  sendError(request, command, "SNAPSHOT_PENDING", 503);
}

// offset/limit parsing: absent -> default (200-bound, never an error);
// present but empty, signed, non-decimal or > 65535 -> 400 BAD_PARAM;
// limit > WEBUI_LIST_LIMIT_MAX -> 400 BAD_PARAM.
bool WebControl::parseListQuery(AsyncWebServerRequest* request,
                                const char* command,
                                uint16_t& offset, uint16_t& limit) {
  const AsyncWebParameter* p = request->getParam("offset");
  if (p != nullptr && !parseU16(p->value(), offset)) {
    sendError(request, command, "BAD_PARAM", 400);
    return false;
  }

  p = request->getParam("limit");
  if (p != nullptr) {
    uint16_t parsed = 0;
    if (!parseU16(p->value(), parsed) || parsed > WEBUI_LIST_LIMIT_MAX) {
      sendError(request, command, "BAD_PARAM", 400);
      return false;
    }
    limit = parsed;
  }
  return true;
}

// Reads the published arena for this query, if it is a match, fresh and
// covered by every build requested so far. Returns true once a response has
// been sent (200 on success, 503 LOW_HEAP if the DRAM copy would not fit).
//
// snap_reading is raised BEFORE publish_idx is read — buildSnapshot() relies
// on exactly that order (its L1/L3 pair), which is what keeps a build from
// choosing the very arena this handler is copying out of.
bool WebControl::tryServeSnapshot(AsyncWebServerRequest* request,
                                  const char* command, ListKind kind,
                                  uint16_t offset, uint16_t limit) {
  const uint32_t need = snap_req_seq;

  snap_reading = true;                 // H0: flag first...
  __sync_synchronize();                // release: flag globally visible before H1
  const int idx = publish_idx;         // H1: ...then the index
  __sync_synchronize();                // acquire: metadata/arena precede the index
  const bool match =
      (idx >= 0 && idx <= 1) &&
      (snap_buf[idx] != nullptr) &&
      (pub_kind == kind) &&
      (pub_offset == offset) &&
      (pub_limit == limit) &&
      (pub_len > 0) &&
      (pub_len <= WEBUI_SNAP_BUF_SIZE) &&
      (pub_seq >= need) &&
      ((uint32_t)(millis() - snap_built_ms) < WEBUI_SNAP_FRESH_MS);

  if (!match) {
    snap_reading = false;
    return false;
  }

  const uint16_t len = pub_len;
  String body(snap_buf[idx]);  // copy out of PSRAM into DRAM
  snap_reading = false;        // the arena is no longer referenced

  if (body.length() != len) {  // allocation failed (or a torn length)
    sendError(request, command, "LOW_HEAP", 503);
    return true;
  }

  request->send(200, "application/json", body);
  return true;
}

// Handler -> loop task hand-off: write the query only while snap_want is
// down (buildSnapshot() only reads it while the flag is up), then raise the
// flag. A second request that arrives while a build is already queued leaves
// both the fields and the flag alone — its own retry queues it afterwards,
// and until then it gets SNAPSHOT_PENDING, which is exactly what is true.
void WebControl::queueSnapshot(ListKind kind, uint16_t offset, uint16_t limit) {
  if (snap_want)
    return;
  snap_kind = kind;
  snap_offset = offset;
  snap_limit = limit;
  snap_req_seq++;
  __sync_synchronize();  // release: the whole query is visible before the flag
  snap_want = true;  // publish the request after the payload is complete
}

void WebControl::handleNotFound(AsyncWebServerRequest* request) {
  trackReq(request);
  if (shedRequest(request, ""))
    return;

  request->send(404, "application/json",
                "{\"protocol\":1,\"command\":\"\",\"status\":\"error\",\"code\":\"NOT_FOUND\"}");
}

// ---------------------------------------------------------------------------
// Loop-task helpers
// ---------------------------------------------------------------------------

// Refreshes everything route handlers read: WiFi mode, the address that is
// serving us, and the MAC used for the SoftAP name / info endpoint. Handlers
// must never call WiFi themselves (they run in the async_tcp task).
void WebControl::refreshNetCache() {
  wifi_mode = (uint8_t)WiFi.getMode();

  if (WiFi.status() == WL_CONNECTED)
    ip_addr = ipAddressToUint32(WiFi.localIP());
  else
    ip_addr = ipAddressToUint32(WiFi.softAPIP());

  // Parse the station MAC only once — it does not change during a boot, and
  // mac6 is read by handlers in the async_tcp task, so it must not be
  // rewritten underneath them every refresh.
  if ((mac6[0] | mac6[1] | mac6[2] | mac6[3] | mac6[4] | mac6[5]) == 0) {
    const String mac = WiFi.macAddress();
    for (int i = 0; i < 6; i++) {
      const int pos = i * 3;
      if (pos + 1 >= (int)mac.length())
        break;
      mac6[i] = (uint8_t)((hexNib(mac[pos]) << 4) | hexNib(mac[pos + 1]));
    }
  }
}

// ---------------------------------------------------------------------------
// P3 marshaling — loop-task half. The route handlers only fill `pending` and
// raise `pending_set`; everything that touches wifi_scan_obj/recon_obj/cli_obj
// runs here, in the same task that owns their state.
// ---------------------------------------------------------------------------

void WebControl::consumePending() {
  if (!pending_set)
    return;

  // Copy everything out first, then lower the flag: the producer only writes
  // while the flag is down, so the payload cannot change under this read.
  const uint8_t kind = pending.kind;
  char cmd[WEBUI_CLI_MAX] = {0};
  if (kind == PendingAction::PEND_CLI) {
    for (size_t i = 0; i < WEBUI_CLI_MAX; i++)
      cmd[i] = pending.cmd[i];
    cmd[WEBUI_CLI_MAX - 1] = '\0';
  }
  pending.kind = PendingAction::PEND_NONE;
  pending_set = false;  // slot free again before the (possibly slow) call

  switch (kind) {
    case PendingAction::PEND_SCAN_ON:
      // cf. `scanall` (CommandLine.cpp): color defaults to 0, no TFT needed.
      wifi_scan_obj.StartScan(WIFI_SCAN_AP_STA);
      break;

    case PendingAction::PEND_SCAN_OFF:
      wifi_scan_obj.StartScan(WIFI_SCAN_OFF);
      break;

    case PendingAction::PEND_RECON_WIFI:
      // Mirrors the CLI dispatch guard so a scan started between the HTTP
      // request and this loop pass still gets refused the same way.
      if (wifi_scan_obj.scanning())
        Serial.println(F("Stop the current scan before starting Recon"));
      else
        recon_obj.start(ReconMode::WIFI_RECON);
      break;

    case PendingAction::PEND_RECON_BLE:
      #ifdef HAS_BT
        if (wifi_scan_obj.scanning())
          Serial.println(F("Stop the current scan before starting Recon"));
        else
          recon_obj.start(ReconMode::BLE_RECON);
      #endif
      break;

    case PendingAction::PEND_RECON_STOP:
      recon_obj.stop();
      wifi_scan_obj.StartScan(WIFI_SCAN_OFF);
      break;

    case PendingAction::PEND_CLI:
      // Output stays on serial (capturing it is out of scope for P3).
      cli_obj.runCommand(String(cmd));
      break;

    default:
      break;
  }
}

// ---------------------------------------------------------------------------
// P4 snapshot builder — loop task only (called from main()). One builder,
// serialized by main(), so two builds can never overlap. The arena pair
// makes the cross-task invariant cheap: publish_idx names the arena the
// async_tcp task may read, and this function only ever writes the other one.
// ---------------------------------------------------------------------------

// Builds the query queueSnapshot() left behind. Returns true when a new
// snapshot was published.
//
// The L1/L3 ordering below is the whole safety argument, so it must not be
// reordering-friendly:
//   L1 read publish_idx and derive the arena to write (1 - publish_idx);
//   L3 then test snap_reading, and bail out if a handler is reading.
// A handler raises snap_reading (H0) *before* it reads publish_idx (H1), so
// for any handler we either abort here (flag still up), or it observed
// publish_idx before we changed it — in which case it reads `pub` while we
// write 1-pub — or it observed the index only after our publish, by which
// time this build is finished and its next build hits L3 with the flag up.
// In every interleaving the arena being written stays unread.
bool WebControl::buildSnapshot() {
  if (!snap_want)
    return false;  // fast path: no request pending (most loop passes)

  // L1: read publish_idx FIRST...
  const int pub = publish_idx;
  const int target = (pub == 0) ? 1 : 0;  // the non-published arena
  __sync_synchronize();  // order L1 strictly before L3 (two cores, two loads)

  // L3: ...check the reader flag SECOND (see the ordering note above).
  if (snap_reading)
    return false;  // a handler is copying: keep snap_want, retry next pass

  if (snap_buf[0] == nullptr || snap_buf[1] == nullptr)
    return false;

  __sync_synchronize();  // acquire: the query the handler wrote before the flag
  // Copy the query out first, then lower the flag (same hand-off as `pending`).
  const ListKind kind = snap_kind;
  const uint16_t offset = snap_offset;
  const uint16_t limit = snap_limit;
  const uint32_t req = snap_req_seq;
  snap_want = false;

  // Build guard: never spend DRAM the boot path needs. Skipping here is
  // deliberate — nothing is published, so the client's next poll re-queues.
  if (ESP.getFreeHeap() < (uint32_t)MEM_LOWER_LIM + WEBUI_LOW_HEAP_MARGIN)
    return false;

  char* dst = snap_buf[target];
  size_t len = 0;
  bool ok = false;
  switch (kind) {
    case LIST_APS:
      ok = buildAps(dst, WEBUI_SNAP_BUF_SIZE, &len, offset, limit);
      break;
    case LIST_STATIONS:
      ok = buildStations(dst, WEBUI_SNAP_BUF_SIZE, &len, offset, limit);
      break;
    case LIST_SSIDS:
      ok = buildSsids(dst, WEBUI_SNAP_BUF_SIZE, &len, offset, limit);
      break;
    default:
      break;
  }
  if (!ok)
    return false;  // overflow/empty build: nothing published, keep the old one
  dst[len] = '\0'; // builders reserve 16 B + WEBUI_SNAP_ENTRY_ROOM, so len < cap

  // Metadata first, index last: publish_idx is the release flag for readers.
  pub_kind = kind;
  pub_offset = offset;
  pub_limit = limit;
  pub_len = (uint16_t)len;
  pub_seq = req;
  snap_seq++;
  snap_built_ms = millis();
  __sync_synchronize();  // payload + metadata visible before the index
  publish_idx = target;
  return true;
}

// GET /api/v1/aps payload. Fields come from the same LinkedList<AccessPoint>
// walk the CLI's `list -a` does (CommandLine.cpp:1657): value-copy per entry,
// size re-checked every iteration because the WiFi-task sniffer callback and
// `clearlist` can append/trim the list while we walk it. `total` comes from
// the public accessor (WiFiScan.h:846), which is literally access_points->
// size() (WiFiScan.cpp:46), so a list that grows between the two reads only
// makes the walk conservative.
bool WebControl::buildAps(char* dst, size_t cap, size_t* len,
                          uint16_t offset, uint16_t limit) {
  *len = 0;
  // Every write below targets `lim`, which reserves the last 16 bytes for the
  // closing "]}}" — so a build can never fail on its own tail, and a document
  // that cannot be closed is impossible by construction.
  const size_t lim = (cap > 16) ? cap - 16 : cap;
  const unsigned total =
      (unsigned)wifi_scan_obj.retainedAccessPointCount();

  if (!snapFmt(dst, lim, len,
               "{\"protocol\":1,\"command\":\"aps\",\"status\":\"ok\","
               "\"data\":{\"total\":%u,\"offset\":%u,\"limit\":%u,\"aps\":[",
               total, (unsigned)offset, (unsigned)limit))
    return false;

  unsigned emitted = 0;
  for (unsigned i = offset; i < total && emitted < limit; i++) {
    if (access_points == nullptr || i >= (unsigned)access_points->size())
      break;  // list shrank under us (clearlist) — stop at a real boundary
    if (lim - *len < WEBUI_SNAP_ENTRY_ROOM)
      break;  // no room for a whole entry: close the array instead
            // (the arena is sized for a full page, so this is belt-and-braces)

    const AccessPoint ap = access_points->get((int)i);
    char bssid[18];
    // Uppercase AA:BB:.. — the same helper macToString()/`info -a` use, so
    // the BSSID matches GET /api/v1/info's "mac" formatting.
    marauder::formatMacAddress(ap.bssid, bssid);

    if (emitted != 0 && !snapRaw(dst, lim, len, ","))
      return false;
    if (!snapFmt(dst, lim, len, "{\"ssid\":\""))
      return false;
    // Arbitrary bytes, 64-byte output budget (= a 32-char SSID that is all
    // quotes) so one corrupt essid cannot eat the page.
    if (!snapEsc(dst, lim, len, ap.essid.c_str(), ap.essid.length(), 64))
      return false;
    if (!snapFmt(dst, lim, len,
                 "\",\"bssid\":\"%s\",\"ch\":%u,\"rssi\":%d,\"sec\":%u,"
                 "\"stas\":%u,\"pkts\":%u}",
                 bssid, (unsigned)ap.channel, (int)ap.rssi, (unsigned)ap.sec,
                 (unsigned)(ap.stations == nullptr ? 0 : ap.stations->size()),
                 (unsigned)ap.packets))
      return false;
    emitted++;
  }

  return snapRaw(dst, cap, len, "]}}");  // real cap: the 16-byte reserve
}

// GET /api/v1/stations payload. Only two fields of struct Station (utils.h:20)
// are actually readable: "mac" and "pkts". Omitted on purpose — "vendor"
// (no public OUI->vendor lookup exists; WiFiScan::suspicious_vendors[] is
// private at WiFiScan.h:557) and "probed" (Station carries no probe data;
// probe_req_ssids is keyed by SSID, not by station).
bool WebControl::buildStations(char* dst, size_t cap, size_t* len,
                               uint16_t offset, uint16_t limit) {
  *len = 0;
  const size_t lim = (cap > 16) ? cap - 16 : cap;  // reserve the "]}}" tail
  const unsigned total =
      (unsigned)wifi_scan_obj.retainedStationCount();  // WiFiScan.h:847

  if (!snapFmt(dst, lim, len,
               "{\"protocol\":1,\"command\":\"stations\",\"status\":\"ok\","
               "\"data\":{\"total\":%u,\"offset\":%u,\"limit\":%u,\"stations\":[",
               total, (unsigned)offset, (unsigned)limit))
    return false;

  unsigned emitted = 0;
  for (unsigned i = offset; i < total && emitted < limit; i++) {
    if (stations == nullptr || i >= (unsigned)stations->size())
      break;
    if (lim - *len < WEBUI_SNAP_ENTRY_ROOM)
      break;

    const Station st = stations->get((int)i);
    char mac[18];
    marauder::formatMacAddress(st.mac, mac);

    if (emitted != 0 && !snapRaw(dst, lim, len, ","))
      return false;
    if (!snapFmt(dst, lim, len, "{\"mac\":\"%s\",\"pkts\":%u}",
                 mac, (unsigned)st.packets))
      return false;
    emitted++;
  }

  return snapRaw(dst, cap, len, "]}}");  // real cap: the 16-byte reserve
}

// GET /api/v1/ssids payload: the retained SSID list `list -s` prints
// (CommandLine.cpp:1701, extern at CommandLine.h:45) — strings only, exactly
// the shape the contract asks for: data = {total, ssids}. total is the whole
// list size so the client can page with offset/limit.
bool WebControl::buildSsids(char* dst, size_t cap, size_t* len,
                            uint16_t offset, uint16_t limit) {
  *len = 0;
  const size_t lim = (cap > 16) ? cap - 16 : cap;  // reserve the "]}}" tail
  const unsigned total = (ssids == nullptr) ? 0U : (unsigned)ssids->size();

  if (!snapFmt(dst, lim, len,
               "{\"protocol\":1,\"command\":\"ssids\",\"status\":\"ok\","
               "\"data\":{\"total\":%u,\"ssids\":[",
               total))
    return false;

  unsigned emitted = 0;
  for (unsigned i = offset; i < total && emitted < limit; i++) {
    if (ssids == nullptr || i >= (unsigned)ssids->size())
      break;
    if (lim - *len < WEBUI_SNAP_ENTRY_ROOM)
      break;

    const ssid entry = ssids->get((int)i);
    if (emitted != 0 && !snapRaw(dst, lim, len, ","))
      return false;
    if (!snapRaw(dst, lim, len, "\""))
      return false;
    if (!snapEsc(dst, lim, len, entry.essid.c_str(), entry.essid.length(), 64))
      return false;
    if (!snapRaw(dst, lim, len, "\""))
      return false;
    emitted++;
  }

  return snapRaw(dst, cap, len, "]}}");  // real cap: the 16-byte reserve
}

// ---------------------------------------------------------------------------
// P3 interface-recovery monitor (§5 v1) — loop task, throttled to one check
// per WEBUI_IFACE_CHECK_MS.
// ---------------------------------------------------------------------------

// Watches the scanning() edge; a true->false transition means a scan/recon
// just tore the radio down (WiFiScan::shutdownWiFi() ends in WiFi.mode(WIFI_OFF))
// and the webui interface may need to come back.
void WebControl::monitorIface() {
  const bool scanning_now = wifi_scan_obj.scanning();
  if (last_scanning && !scanning_now)
    iface_edge = true;  // scan ended — queue one recovery check
  last_scanning = scanning_now;

  if (!iface_edge)
    return;
  if ((millis() - last_iface_check) < WEBUI_IFACE_CHECK_MS)
    return;  // throttle: never check more than once every 2 s

  last_iface_check = millis();
  iface_edge = false;
  recoverIface();
}

// Runs one recovery attempt after a scan/recon ended. Only acts when the webui
// is up and the Evil Portal does not own the radio, and only touches an
// interface that is actually down (no unconditional re-init, so a healthy
// link is never bounced).
void WebControl::recoverIface() {
  if (!running || stopping || portalOwnsWifi())
    return;

  if (start_mode == WEBUI_MODE_AP) {
    if (!owns_ap)
      return;

    // Only re-init when the AP interface really is gone. The scan path may
    // have called WiFi.mode(WIFI_OFF) (WIFI_MODE_NULL), or dropped the AP bit
    // and left STA behind; an intact AP/APSTA mode needs nothing.
    const wifi_mode_t mode = WiFi.getMode();
    if (mode == WIFI_MODE_AP || mode == WIFI_MODE_APSTA)
      return;  // still up — don't thrash

    if (initSoftAP()) {
      Serial.println(F("webui iface recovered"));
    }
    else {
      Serial.println(F("webui iface down"));
    }
  }
  else {
    // STA mode: an intact station link is already the desired state.
    if (WiFi.status() == WL_CONNECTED)
      return;

    // Same public entry the CLI `join -s` uses (gui=false skips the display).
    // It blocks for the duration of an OS scan — acceptable here: this runs
    // only on the 2 s-throttled edge path, in the loop task.
    if (wifi_scan_obj.joinSavedWiFi(false))
      Serial.println(F("webui iface recovered"));
    else
      Serial.println(F("webui iface down"));
  }
}

// Brings the webui SoftAP up: mode first (keeping a live station link), then
// the fixed 192.168.4.1 config, then the AP itself. Shared by start() and the
// recovery monitor; owns_ap is left for the caller to decide.
bool WebControl::initSoftAP() {
  char ssid[16];
  snprintf(ssid, sizeof(ssid), "Marauder-%02X%02X",
           (unsigned)mac6[4], (unsigned)mac6[5]);

  // Keep an existing station link alive instead of dropping it.
  if (WiFi.status() == WL_CONNECTED)
    WiFi.mode(WIFI_MODE_APSTA);
  else
    WiFi.mode(WIFI_MODE_AP);

  const IPAddress ap_ip(192, 168, 4, 1);
  WiFi.softAPConfig(ap_ip, ap_ip, IPAddress(255, 255, 255, 0));
  return WiFi.softAP(ssid);
}

const char* WebControl::modeName() const {
  switch (wifi_mode) {
    case WIFI_MODE_AP:    return "ap";
    case WIFI_MODE_STA:   return "sta";
    case WIFI_MODE_APSTA: return "apsta";
    default:              return "off";
  }
}

// Persist "WebUI" only when the value actually changes. loadSetting() also
// auto-creates the key on settings files written before it existed.
void WebControl::persistSetting(bool enabled) {
  if (settings_obj.loadSetting<bool>(WEBUI_SETTING_KEY) != enabled)
    settings_obj.saveSetting<bool>(WEBUI_SETTING_KEY, enabled);
}

// True while the Evil Portal is actually serving its AP/catch-all on :80.
// runServer is only cleared by EvilPortal::setup() at boot (cleanup() leaves it
// set), so it is paired with the live scan-mode check: at boot this reduces to
// `evil_portal_obj.isActive()` exactly, while a portal session that was stopped
// earlier in this boot does not block `webui start -ap`.
bool WebControl::portalOwnsWifi() {
  return evil_portal_obj.isActive() &&
         wifi_scan_obj.currentScanMode == WIFI_SCAN_EVIL_PORTAL;
}
