/*
 * fluxo_plugin.h — The Fluxo external plugin C ABI contract.
 *
 * This header defines the interface between Fluxo and external plugins
 * loaded as shared libraries (.so / .dylib) at startup.
 *
 * Plugins implement the lifecycle and hook functions they need.
 * Fluxo provides host functions via function pointers passed during init.
 *
 * STATUS: Draft — this ABI is not yet stable (v0.6 target).
 */

#ifndef FLUXO_PLUGIN_H
#define FLUXO_PLUGIN_H

#define FLUXO_CONTINUE  0   /* proceed to next phase */
#define FLUXO_STOP      1   /* request handled, stop pipeline */

/* Opaque types — Fluxo owns these, plugins receive pointers */
typedef struct fluxo_request_t fluxo_request_t;
typedef struct fluxo_response_t fluxo_response_t;

/*
 * === Functions the plugin implements (Fluxo calls these) ===
 */

/* Lifecycle */
int  fluxo_plugin_init(const char *config_json);
void fluxo_plugin_deinit(void);

/* Request phase hooks (implement the ones you need) */
int  on_request(fluxo_request_t *req);
int  on_upstream_request(fluxo_request_t *req);
int  on_response(fluxo_request_t *req, fluxo_response_t *resp);
void on_log(fluxo_request_t *req, fluxo_response_t *resp);

#endif /* FLUXO_PLUGIN_H */
