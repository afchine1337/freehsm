/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm_conf.c --- Minimal config reader. See fhsm_conf.h for the rule this
 * module exists to enforce: a key ships in the file only if code reads it.
 * ========================================================================= */

#include "fhsm_conf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#define FHSM_CONF_PATH_DEFAULT "/etc/freehsm/freehsm.conf"
#define FHSM_CONF_LINE_MAX     512

static const char *conf_path(void) {
    const char *p = getenv("FHSM_CONF");
    return (p && *p) ? p : FHSM_CONF_PATH_DEFAULT;
}

int fhsm_conf_lookup(const char *key, char *out, size_t outlen) {
    if (!key || !*key || !out || outlen == 0) return 0;
    size_t klen = strlen(key);

    FILE *f = fopen(conf_path(), "r");
    if (!f) return 0;                 /* absent file : callers have defaults */

    char line[FHSM_CONF_LINE_MAX];
    int found = 0;
    while (!found && fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == ';' || *p == '[' || *p == '\0') continue;

        /* Exact key match, then optional space, then '='. Prefix matching is
         * what let the old reader treat `modem = x` as `mode`. */
        if (strncmp(p, key, klen) != 0) continue;
        char *q = p + klen;
        while (*q == ' ' || *q == '\t') q++;
        if (*q != '=') continue;
        q++;
        while (*q == ' ' || *q == '\t') q++;

        /* Copy the value, stopping at end-of-line or an inline comment. */
        size_t i = 0;
        while (*q && *q != '\n' && *q != '\r' && *q != '#' && *q != ';'
               && i + 1 < outlen) {
            out[i++] = *q++;
        }
        while (i > 0 && isspace((unsigned char)out[i - 1])) i--;  /* rtrim */
        out[i] = '\0';
        found = (i > 0);
    }
    fclose(f);
    return found;
}

size_t fhsm_conf_secure_heap_bytes(void) {
    char v[32];
    if (!fhsm_conf_lookup("secure_heap_kb", v, sizeof(v)))
        return (size_t)FHSM_SECURE_HEAP_BYTES;

    errno = 0;
    char *end = NULL;
    unsigned long kb = strtoul(v, &end, 10);
    /* Reject trailing garbage, overflow, and out-of-range values rather than
     * clamping: a silently clamped value is a setting the operator believes
     * took effect. Falling back to the compiled default at least matches what
     * an unconfigured module does. */
    if (errno != 0 || end == v || (end && *end != '\0')) 
        return (size_t)FHSM_SECURE_HEAP_BYTES;
    if (kb < FHSM_CONF_HEAP_MIN_KB || kb > FHSM_CONF_HEAP_MAX_KB)
        return (size_t)FHSM_SECURE_HEAP_BYTES;

    /* OpenSSL's secure arena requires a power-of-two size and asserts on
     * anything else -- `secure_heap_kb = 100` aborted the process inside
     * CRYPTO_secure_malloc_init. A config typo must not crash an HSM, so round
     * UP to the next power of two.
     *
     * Rounding up rather than rejecting: the operator asked for at least this
     * much arena and gets at least that much. That is not the silent clamping
     * refused above -- clamping down would hand back less than was asked for
     * while reporting success. */
    size_t bytes = (size_t)kb * 1024u;
    size_t pow2  = 1;
    while (pow2 < bytes) pow2 <<= 1;
    return pow2;
}
