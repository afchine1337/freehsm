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
 *  /etc/freehsm/freehsm.conf "mode = fips|legacy".
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_mode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>

static pthread_mutex_t g_mtx     = PTHREAD_MUTEX_INITIALIZER;
static int             g_cached  = 0;
static int             g_is_fips = 0;

static int env_says_fips(void) {
    const char *v = getenv("FHSM_MODE");
    if (!v) return -1;
    if (strcasecmp(v, "fips") == 0 ||
        strcasecmp(v, "strict") == 0 ||
        strcasecmp(v, "fips-strict") == 0) return 1;
    if (strcasecmp(v, "legacy") == 0 ||
        strcasecmp(v, "interop") == 0 ||
        strcasecmp(v, "default") == 0) return 0;
    return -1;
}

static int conf_says_fips(void) {
    FILE *f = fopen("/etc/freehsm/freehsm.conf", "r");
    if (!f) return -1;
    char line[256];
    int verdict = -1;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        if (strncmp(p, "mode", 4) != 0) continue;
        p += 4;
        while (*p && (*p == ' ' || *p == '\t' || *p == '=')) p++;
        if (strncasecmp(p, "fips", 4) == 0)   { verdict = 1; break; }
        if (strncasecmp(p, "strict", 6) == 0) { verdict = 1; break; }
        if (strncasecmp(p, "legacy", 6) == 0) { verdict = 0; break; }
        if (strncasecmp(p, "interop", 7) == 0) { verdict = 0; break; }
    }
    fclose(f);
    return verdict;
}

static void compute_mode_locked(void) {
    int e = env_says_fips();
    if (e == 1) { g_is_fips = 1; g_cached = 1; return; }
    if (e == 0) { g_is_fips = 0; g_cached = 1; return; }
    int c = conf_says_fips();
    if (c == 1) { g_is_fips = 1; g_cached = 1; return; }
    /* Default : legacy mode. */
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

const char *fhsm_mode_string(void) {
    return fhsm_mode_is_fips() ? "fips" : "legacy";
}
