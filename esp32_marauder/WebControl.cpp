#include "WebControl.h"

#include <WiFi.h>

#include "WiFiScan.h"
#include "settings.h"
#include "utils.h"

extern WiFiScan wifi_scan_obj;

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
    WiFi.softAP(ssid);
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

bool WebControl::shedRequest(AsyncWebServerRequest* request) {
  if (stopping) {
    request->send(503, "application/json", "{\"code\":\"STOPPING\"}");
    return true;
  }

  if (ESP.getFreeHeap() < (uint32_t)MEM_LOWER_LIM + WEBUI_LOW_HEAP_MARGIN) {
    request->send(503, "application/json", "{\"code\":\"LOW_HEAP\"}");
    return true;
  }

  return false;
}

void WebControl::handleInfo(AsyncWebServerRequest* request) {
  trackReq(request);
  if (shedRequest(request))
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

void WebControl::handleNotFound(AsyncWebServerRequest* request) {
  trackReq(request);
  if (shedRequest(request))
    return;

  request->send(404, "application/json", "{\"code\":\"NOT_FOUND\"}");
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
