/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm_mode.c --- Runtime mode selector implementation.
 *
 *  Reads FHSM_MODE from the environment, then falls back to
 *  /etc/freehsm/freehsm.conf "mode = strict|permissive".
 *
 *  The former spellings (fips, legacy, default) are still accepted and warn.
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_mode.h"
#include "fhsm_conf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>

static pthread_mutex_t g_mtx     = PTHREAD_MUTEX_INITIALIZER;
static int             g_cached  = 0;
static int             g_is_fips = 0;

/* The spellings this axis accepts, and what each one is.
 *
 * Canonical since 2026-09-26: strict and permissive. They say what the module
 * does with the thirteen mechanisms NIST has not approved -- refuse them, or
 * run them -- without naming a standard the module does not claim. FHSM_MODE
 * was `fips`, which asserted in an environment variable the same thing the
 * `-FIPS` version suffix asserted before v2.0.0 removed it.
 *
 * `legacy` was wrong for a second reason. The thirteen are not old: eleven
 * are (MD5, SHA-1, 3DES, RC4, DSA, DH, RSA v1.5 and its SHA-1 pairing), and
 * two are newer than anything else in the module -- X25519/X448 key
 * generation, and the composite ML-DSA signature. One bucket holding RC4 and
 * a post-quantum composite has no name based on age.
 *
 * `fips-strict` and `interop` are the BUILD profile's names, and this
 * function took them for the runtime mode. That is issue #11's third defect
 * written into the parser: two axes, one vocabulary, and nothing to tell a
 * reader they are different questions. Still accepted -- someone has them in
 * a script -- and now warned about by name.
 *
 * `deprecated` is out-only: it lets the caller warn once rather than on every
 * lookup, since the answer is cached. */
static int parse_mode_word(const char *v, int *deprecated) {
    static const struct { const char *word; int fips; int old; } tbl[] = {
        { "strict",      1, 0 },
        { "permissive",  0, 0 },
        { "fips",        1, 1 },
        { "legacy",      0, 1 },
        { "default",     0, 1 },
        /* the build profile's vocabulary, taken here by mistake */
        { "fips-strict", 1, 2 },
        { "interop",     0, 2 },
    };
    for (size_t i = 0; i < sizeof tbl / sizeof tbl[0]; ++i) {
        if (strcasecmp(v, tbl[i].word) == 0) {
            if (deprecated) *deprecated = tbl[i].old;
            return tbl[i].fips;
        }
    }
    return -1;
}

static void warn_old_spelling(const char *where, const char *v, int kind) {
    if (kind == 0) return;
    if (kind == 2) {
        fprintf(stderr,
            "[freehsm-c] NOTE : %s is \"%s\", which is a BUILD PROFILE name,\n"
            "  not a runtime mode. They are different questions: the profile\n"
            "  decides which mechanisms are compiled in, this decides whether\n"
            "  the unapproved ones may run. Taken as \"%s\"; say that instead.\n",
            where, v, parse_mode_word(v, NULL) ? "strict" : "permissive");
        return;
    }
    fprintf(stderr,
        "[freehsm-c] NOTE : %s is \"%s\". The accepted spellings are now\n"
        "  \"strict\" and \"permissive\", which say what happens to the\n"
        "  mechanisms NIST has not approved rather than naming a standard\n"
        "  this module does not claim. \"%s\" still works and means \"%s\".\n",
        where, v, v, parse_mode_word(v, NULL) ? "strict" : "permissive");
}

static int env_says_fips(void) {
    const char *v = getenv("FHSM_MODE");
    if (!v) return -1;
    int old = 0;
    int r = parse_mode_word(v, &old);
    if (r >= 0) warn_old_spelling("FHSM_MODE", v, old);
    return r;
}

/* Reads `mode` through the shared reader (#128). The previous inline version
 * matched the key with strncmp on a 4-byte prefix, so a line such as
 * `modem = x` would have been accepted as the mode; fhsm_conf_lookup matches
 * the whole key. */
static int conf_says_fips(void) {
    char v[32];
    if (!fhsm_conf_lookup("mode", v, sizeof(v))) return -1;
    int old = 0;
    int r = parse_mode_word(v, &old);
    if (r >= 0) warn_old_spelling("the `mode` key in freehsm.conf", v, old);
    return r;
}

static void compute_mode_locked(void) {
    int e = env_says_fips();
    if (e == 1) { g_is_fips = 1; g_cached = 1; return; }
    if (e == 0) { g_is_fips = 0; g_cached = 1; return; }
    int c = conf_says_fips();
    if (c == 1) { g_is_fips = 1; g_cached = 1; return; }
    /* Default : permissive -- the unapproved mechanisms run. Unchanged; only
     * the name for it is new. */
    g_is_fips = 0;
    g_cached  = 1;
}

int fhsm_mode_is_fips(void) {
    pthread_mutex_lock(&g_mtx);
    if (!g_cached) compute_mode_locked();
    int v = g_is_fips;
    pthread_mutex_unlock(&g_mtx);
    return v;
}

void fhsm_mode_reset_cache(void) {
    pthread_mutex_lock(&g_mtx);
    g_cached = 0;
    pthread_mutex_unlock(&g_mtx);
}

/* The canonical spellings, so anything that prints the mode prints the words
 * the documentation uses.
 *
 * Nothing in the tree calls this -- it is declared in include/fhsm_mode.h and
 * has no caller in src, tests, tools or service. Left in place because the
 * header is public and removing an exported symbol is an ABI change for
 * somebody, but worth recording: an accessor nobody reads is also an accessor
 * nobody would notice returning the wrong thing. */
const char *fhsm_mode_string(void) {
    return fhsm_mode_is_fips() ? "strict" : "permissive";
}
