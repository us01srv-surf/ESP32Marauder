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

// P3: fixed-size marshaled CLI command slot (127 chars + NUL). Commands longer
// than this are rejected with 400 BAD_PARAM instead of being truncated.
#define WEBUI_CLI_MAX 128

// P3: interface-recovery monitor throttle — at most one WiFi recovery check
// every 2 s, so a scan/recon that toggles the radio cannot cause a thrash.
#define WEBUI_IFACE_CHECK_MS 2000

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
    // Sends 503 {"code":"STOPPING"}/{"code":"LOW_HEAP"} (full error envelope)
    // and returns true when the caller must not continue handling the request.
    bool shedRequest(AsyncWebServerRequest* request, const char* command);
    // Shared JSON error/success envelopes: {"protocol":1,"command":...,...}.
    void sendError(AsyncWebServerRequest* request, const char* command,
                   const char* code, int http_code);
    void sendAccepted(AsyncWebServerRequest* request, const char* command);

    void handleInfo(AsyncWebServerRequest* request);
    void handleStatus(AsyncWebServerRequest* request);
    void handleScan(AsyncWebServerRequest* request);
    void handleRecon(AsyncWebServerRequest* request);
    void handleCli(AsyncWebServerRequest* request);
    void handleNotFound(AsyncWebServerRequest* request);

    // P3 marshaling: route handlers (async_tcp task) publish exactly one
    // pending action into this slot; main() (loop task) consumes it. The
    // pending_set flag is the hand-off: the producer fills the fields first
    // and only then raises the flag, the consumer copies the fields out and
    // only then lowers it, so the two tasks never touch the payload at the
    // same time. A second request while the slot is full gets 503 BUSY.
    struct PendingAction {
      enum Kind : uint8_t {
        PEND_NONE = 0,
        PEND_SCAN_ON,     // StartScan(WIFI_SCAN_AP_STA)
        PEND_SCAN_OFF,    // StartScan(WIFI_SCAN_OFF)
        PEND_RECON_WIFI,  // recon_obj.start(ReconMode::WIFI_RECON)
        PEND_RECON_BLE,   // recon_obj.start(ReconMode::BLE_RECON)
        PEND_RECON_STOP,  // recon_obj.stop() + StartScan(WIFI_SCAN_OFF)
        PEND_CLI          // cli_obj.runCommand(String(cmd))
      };
      volatile uint8_t kind = PEND_NONE;
      volatile uint8_t arg = 0;
      // Loop-task-only read, and only while pending_set is raised; volatile
      // keeps the fill ordered against the flag store below.
      volatile char cmd[WEBUI_CLI_MAX] = {0};
    };

    // Loop-task side of P3: consumes the slot and the recovery monitor.
    void consumePending();
    void monitorIface();
    void recoverIface();

    // Loop-task only: caches IP/mode/mac so route handlers never call WiFi.
    void refreshNetCache();
    // Brings the SoftAP up (mode -> softAPConfig -> softAP). Does not touch
    // owns_ap — the caller decides whether it now owns the interface.
    bool initSoftAP();
    const char* modeName() const;
    void persistSetting(bool enabled);
    bool portalOwnsWifi();

    AsyncWebServer* server = nullptr;

    // Read by handlers from the async_tcp task.
    volatile int in_flight = 0;
    volatile bool running = false;
    volatile bool stopping = false;

    // P3 pending-action slot (written by handlers, consumed by main()).
    PendingAction pending;
    volatile bool pending_set = false;

    // Loop-task state.
    bool owns_ap = false;
    uint8_t start_mode = WEBUI_MODE_AP;
    uint32_t end_time = 0;
    uint32_t last_cache_refresh = 0;

    // P3 interface-recovery monitor state (loop task only).
    bool last_scanning = false;
    bool iface_edge = false;
    uint32_t last_iface_check = 0;

    // Cached network facts (written in the loop task, read by handlers).
    volatile uint32_t ip_addr = 0;   // host-order IPv4: a<<24 | b<<16 | c<<8 | d
    volatile uint8_t wifi_mode = 0;  // wifi_mode_t
    uint8_t mac6[6] = {0, 0, 0, 0, 0, 0};
};

#endif
