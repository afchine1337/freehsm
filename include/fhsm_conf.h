/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm_conf.h --- Minimal reader for /etc/freehsm/freehsm.conf.
 *
 *  Deliberately minimal. Before #128 the shipped config file carried nine
 *  keys and no code read any of them, while the one key a parser did look
 *  for (`mode`) was absent from the file. A configuration file that promises
 *  controls nothing enforces is the same shape as a module advertising a
 *  mechanism it refuses to run -- so the rule here is that a key exists in
 *  the shipped file if and only if something reads it.
 *
 *  Everything else about this module is compile-time (FHSM_PIN_MAX_FAILED,
 *  the PBKDF2 iteration count, the throttle curve) or environment-driven
 *  (FHSM_TOKENS_DIR). That is a legitimate design; it just must not be
 *  dressed up as runtime configuration.
 *
 *  Path override: FHSM_CONF, for tests. Absent file is not an error --
 *  every caller has a documented default.
 * ========================================================================= */
#ifndef FHSM_CONF_H
#define FHSM_CONF_H

#include "fhsm_common.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Look up `key` in the config file. On success copies the value into `out`
 * (NUL-terminated, truncated to outlen-1) and returns 1. Returns 0 when the
 * file or the key is absent, or on any malformed input.
 *
 * Key matching is exact: `mode` does not match `mode_extra`. The previous
 * ad-hoc reader in fhsm_mode.c used strncmp on a 4-byte prefix, so a stray
 * `modem = x` would have been read as the mode. */
int fhsm_conf_lookup(const char *key, char *out, size_t outlen);

/* Size of the mlock'd secure-heap arena, in bytes.
 *
 * Reads `secure_heap_kb`; falls back to FHSM_SECURE_HEAP_BYTES when the key
 * is absent, unparseable, or outside [FHSM_CONF_HEAP_MIN_KB,
 * FHSM_CONF_HEAP_MAX_KB]. The bounds exist because this value is handed to
 * mlock(): too small bricks the module, too large fails against RLIMIT_MEMLOCK
 * and silently drops the swap guarantee. */
#define FHSM_CONF_HEAP_MIN_KB   64u
#define FHSM_CONF_HEAP_MAX_KB   (64u * 1024u)   /* 64 MiB */
size_t fhsm_conf_secure_heap_bytes(void);

#ifdef __cplusplus
}
#endif

#endif /* FHSM_CONF_H */
