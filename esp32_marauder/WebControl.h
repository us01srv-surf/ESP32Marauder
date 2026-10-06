#pragma once

#ifndef WebControl_h
#define WebControl_h

#include "configs.h"

#include "ESPAsyncWebServer.h"

// P1 of the web-control architecture. The server is deliberately bound to
// 8080: the Evil Portal owns the global `AsyncWebServer server(80)` and its
// catch-all handler must never be touched by this module.
#define WEBUI_PORT 8080

// Persisted bool setting ("WebUI") — single source of truth for auto-start.
#define WEBUI_SETTING_KEY "WebUI"

// start() modes
#define WEBUI_MODE_AP  0  // bring up an open SoftAP (Marauder-XXXX), then serve
#define WEBUI_MODE_STA 1  // serve on the WiFi interface that already exists

// Heap guards. MEM_LOWER_LIM comes from configs.h; webui must never prevent a
// clean boot, and handlers must shed load instead of OOMing the async_tcp task.
#define WEBUI_START_HEAP_MARGIN (64UL * 1024UL)
#define WEBUI_LOW_HEAP_MARGIN   (16UL * 1024UL)

// Stage 2 (deferred free) waits for in-flight requests to drain first.
#define WEBUI_DRAIN_MS 3000

class WebControl {
  public:
    void setup();
    bool start(uint8_t mode);
    void stop();
    void status();
    void main();

  private:
    // In-flight tracking: called on the first line of every route handler so
    // stage 2 can wait until no handler is executing before deleting the server.
    void trackReq(AsyncWebServerRequest* request);
    // Sends 503 {"code":"STOPPING"}/{"code":"LOW_HEAP"} and returns true when
    // the caller must not continue handling the request.
    bool shedRequest(AsyncWebServerRequest* request);
    void handleInfo(AsyncWebServerRequest* request);
    void handleNotFound(AsyncWebServerRequest* request);
    // Loop-task only: caches IP/mode/mac so route handlers never call WiFi.
    void refreshNetCache();
    const char* modeName() const;
    void persistSetting(bool enabled);
    bool portalOwnsWifi();

    AsyncWebServer* server = nullptr;

    // Read by handlers from the async_tcp task.
    volatile int in_flight = 0;
    volatile bool running = false;
    volatile bool stopping = false;

    // Loop-task state.
    bool owns_ap = false;
    uint8_t start_mode = WEBUI_MODE_AP;
    uint32_t end_time = 0;
    uint32_t last_cache_refresh = 0;

    // Cached network facts (written in the loop task, read by handlers).
    volatile uint32_t ip_addr = 0;   // host-order IPv4: a<<24 | b<<16 | c<<8 | d
    volatile uint8_t wifi_mode = 0;  // wifi_mode_t
    uint8_t mac6[6] = {0, 0, 0, 0, 0, 0};
};

#endif
