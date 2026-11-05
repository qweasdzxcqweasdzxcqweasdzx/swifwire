/* SwifWire C ABI — link swifwire.dll / libswifwire.a
 * Free every non-NULL char* from *_alloc / err_out with swif_string_free.
 */
#ifndef SWIFWIRE_H
#define SWIFWIRE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#  ifdef SWIFWIRE_BUILD
#    define SWIF_API __declspec(dllexport)
#  else
#    define SWIF_API __declspec(dllimport)
#  endif
#else
#  define SWIF_API
#endif

SWIF_API int swif_abi_version(void);
SWIF_API char *swif_version(void);
SWIF_API void swif_string_free(char *s);

SWIF_API int swif_core_start(const char *config_json, char **err_out);
SWIF_API void swif_core_stop(void);
SWIF_API int swif_core_set_route_mode(const char *mode, char **err_out);
SWIF_API int swif_core_import_subscription(const char *url_or_blob, char **err_out);
SWIF_API int swif_core_apply_mask_pack(const uint8_t *data, size_t len, char **err_out);
SWIF_API char *swif_core_status_alloc(char **err_out);
SWIF_API char *swif_core_outbound_alloc(char **err_out);

/* 3x-ui / panel helpers */
SWIF_API char *swif_panel_edge_argv_alloc(const char *inbound_json, char **err_out);
SWIF_API char *swif_panel_share_uri_alloc(
    const char *inbound_json,
    const char *public_host,
    const char *server_pub_hex,
    const char *remark,
    char **err_out);

#ifdef __cplusplus
}
#endif
#endif
