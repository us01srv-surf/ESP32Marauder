#include "WebControl.h"

#include <WiFi.h>

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
      delete server;
      server = nullptr;
      stopping = false;
      Serial.println(F("webui freed"));
    }
    return;
  }

  if (!running)
    return;

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
// rejected, never truncated.
void WebControl::handleCli(AsyncWebServerRequest* request) {
  trackReq(request);
  if (shedRequest(request, "cli"))
    return;

  const AsyncWebParameter* cmd_param = request->getParam("cmd");
  if (cmd_param == nullptr) {
    sendError(request, "cli", "BAD_PARAM", 400);
    return;
  }

  // Minimal %XX decode. ESPAsyncWebServer already decodes query parameters
  // (WebRequest.cpp _addGetParams), so this is normally a no-op; it only
  // fires for values that still carry a valid escape. Invalid escapes are
  // copied through untouched, and a %XX that would not fit is an overflow.
  const String& raw = cmd_param->value();
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
      sendError(request, "cli", "BAD_PARAM", 400);
      return;
    }
    decoded[out++] = value;
  }
  decoded[out] = '\0';

  if (out == 0) {
    sendError(request, "cli", "BAD_PARAM", 400);
    return;
  }

  if (pending_set) {
    sendError(request, "cli", "BUSY", 503);
    return;
  }

  for (size_t i = 0; i <= out; i++)  // include the NUL
    pending.cmd[i] = decoded[i];
  pending.arg = 0;
  pending.kind = PendingAction::PEND_CLI;
  pending_set = true;
  sendAccepted(request, "cli");
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
