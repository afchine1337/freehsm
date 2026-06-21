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
 * fhsm_integrity.c --- Boot-time integrity self-test.
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_integrity.h"
#include "fhsm_crypto.h"

#include <fcntl.h>
#include <link.h>           /* dl_iterate_phdr */
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

/* ---------------------------------------------------------------------------
 * The expected digest. Defined in its own ELF section so :
 *   1. scripts/sign_module.sh can locate it precisely
 *   2. the runtime verifier knows exactly which file bytes to zero
 *      before hashing.
 *
 * `aligned(16)` makes the offset reliably found via readelf and gives
 * us a stable 32-byte slot. The volatile prevents the compiler from
 * constant-folding the digest into the code generator.
 * ----------------------------------------------------------------------- */
__attribute__((used, section(FHSM_INTEGRITY_SECTION), aligned(16)))
const uint8_t fhsm_module_integrity_digest[FHSM_INTEGRITY_DIGEST_LEN] = { 0 };

/* ---------------------------------------------------------------------------
 * Internal state
 * ----------------------------------------------------------------------- */
static pthread_once_t  g_once         = PTHREAD_ONCE_INIT;
static fhsm_rv_t       g_result       = FHSM_RV_FUNCTION_FAILED;
static uint8_t         g_last_digest[FHSM_INTEGRITY_DIGEST_LEN];
static char            g_so_path[1024];

/* The mismatched-digest detection : a known all-zero placeholder means
 * the .so has not been signed yet. In a shipping (production) build
 * this counts as INTEGRITY_FAILED. In a dev build (the env var
 * FHSM_INTEGRITY_ALLOW_UNSIGNED is set), it is downgraded to a
 * warning. */
static int is_all_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; ++i) if (p[i] != 0) return 0;
    return 1;
}

/* ---------------------------------------------------------------------------
 * dl_iterate_phdr callback : locate the loaded path of our own .so.
 * We match by checking whether the address of an internal symbol
 * (fhsm_module_integrity_digest) falls within the segment range
 * advertised by the phdr table.
 * ----------------------------------------------------------------------- */
struct find_ctx_s {
    const void *needle;
    char        out[1024];
    int         found;
};

static int find_self_cb(struct dl_phdr_info *info, size_t sz, void *vdata) {
    (void)sz;
    struct find_ctx_s *c = (struct find_ctx_s *)vdata;
    ElfW(Addr) addr = (ElfW(Addr))(uintptr_t)c->needle;
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];
        if (p->p_type != PT_LOAD) continue;
        ElfW(Addr) start = info->dlpi_addr + p->p_vaddr;
        ElfW(Addr) end   = start + p->p_memsz;
        if (addr >= start && addr < end) {
            if (info->dlpi_name && info->dlpi_name[0]) {
                /* snprintf for gcc 14 -Wstringop-truncation compliance. */
                (void)snprintf(c->out, sizeof(c->out), "%s", info->dlpi_name);
                c->found = 1;
            } else {
                /* Main executable case : per Linux convention, dlpi_name
                 * is the empty string for the program's own image (rather
                 * than a path). This happens for any binary that
                 * statically links fhsm_integrity.o instead of
                 * dynamically loading libfreehsm-fips.so : the test
                 * harness `tests/test_smoke`, the CAVS harness, etc.
                 *
                 * Recover the binary's path via /proc/self/exe so the
                 * integrity self-test can read its own image and
                 * compare against the embedded digest. On systems
                 * without /proc (some chroot/jail environments), the
                 * readlink fails and ctx.found stays 0 ; the caller
                 * then returns the usual setup error and the rest of
                 * the bypass logic applies. */
                ssize_t n = readlink("/proc/self/exe", c->out,
                                     sizeof(c->out) - 1);
                if (n > 0) {
                    c->out[n] = '\0';
                    c->found = 1;
                }
            }
            return 1;   /* stop iteration */
        }
    }
    return 0;
}

static int locate_self(char *path, size_t cap) {
    struct find_ctx_s ctx = {
        .needle = (const void *)fhsm_module_integrity_digest,
        .found  = 0,
    };
    dl_iterate_phdr(find_self_cb, &ctx);
    if (!ctx.found) return -1;
    /* snprintf instead of strncpy : gcc 14's -Wstringop-truncation
     * refuses strncpy(dst, src, cap-1) even when followed by a manual
     * NUL-terminator. snprintf is unambiguous : always NUL-terminates
     * within the destination capacity. */
    int n = snprintf(path, cap, "%s", ctx.out);
    return (n < 0) ? -1 : 0;
}

/* ---------------------------------------------------------------------------
 * The actual digest computation. mmap the .so read-only, zeroize the
 * FHSM_INTEGRITY_SECTION bytes in the IN-MEMORY copy (private mapping
 * means the on-disk file is untouched), then hash.
 *
 * Finding the section offset : we use `readelf -S` semantics in C by
 * parsing the ELF header / section table. This is portable across
 * little-endian x86_64 / aarch64 builds. The implementation here
 * supports ELF64 only (the production build target).
 * ----------------------------------------------------------------------- */
#include <elf.h>

static int find_section_offset(const uint8_t *map, size_t map_len,
                                 const char *name,
                                 size_t *out_off, size_t *out_len)
{
    if (map_len < sizeof(Elf64_Ehdr)) return -1;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)map;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return -1;
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) return -1;
    if (eh->e_shoff == 0 || eh->e_shnum == 0)  return -1;
    if (eh->e_shoff + (size_t)eh->e_shnum * eh->e_shentsize > map_len) return -1;

    const Elf64_Shdr *sh = (const Elf64_Shdr *)(map + eh->e_shoff);
    if (eh->e_shstrndx >= eh->e_shnum) return -1;
    const Elf64_Shdr *shstr = &sh[eh->e_shstrndx];
    if (shstr->sh_offset + shstr->sh_size > map_len) return -1;
    const char *strtab = (const char *)(map + shstr->sh_offset);

    for (uint16_t i = 0; i < eh->e_shnum; ++i) {
        const char *n = strtab + sh[i].sh_name;
        if (strcmp(n, name) == 0) {
            *out_off = sh[i].sh_offset;
            *out_len = sh[i].sh_size;
            return 0;
        }
    }
    return -1;
}

static fhsm_rv_t do_verify(void) {
    if (locate_self(g_so_path, sizeof(g_so_path)) != 0) {
        return FHSM_RV_FUNCTION_FAILED;
    }
    int fd = open(g_so_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return FHSM_RV_FUNCTION_FAILED;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd); return FHSM_RV_FUNCTION_FAILED;
    }
    size_t flen = (size_t)st.st_size;
    void *m = mmap(NULL, flen, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return FHSM_RV_FUNCTION_FAILED;

    /* Copy to a writable buffer so we can zero the digest area without
     * touching the on-disk file. mmap with MAP_PRIVATE would do the
     * trick alone, but writing through it counts as a COW page that
     * persists in the process address space ; copying is simpler and
     * avoids a partial-RSS spike. */
    uint8_t *buf = (uint8_t *)malloc(flen);
    if (!buf) { munmap(m, flen); return FHSM_RV_FUNCTION_FAILED; }
    memcpy(buf, m, flen);
    munmap(m, flen);

    /* Locate and zero the digest area. */
    size_t off = 0, len = 0;
    if (find_section_offset(buf, flen, FHSM_INTEGRITY_SECTION, &off, &len) != 0
        || len < FHSM_INTEGRITY_DIGEST_LEN) {
        /* The .fhsm_digest section is only present in binaries built
         * with the integrity-aware build (libfreehsm-fips.so plus any
         * statically-linked test harness that includes
         * fhsm_integrity.o). If we cannot locate it, the operator is
         * running the wrong artifact. In dev mode (env var set) we
         * downgrade to a permissive return ; in production we MUST
         * return FHSM_RV_INTEGRITY_FAILED so the caller's state
         * machine latches ERROR. The previous version fell through
         * to `memset(buf + off, 0, len)` after free(buf), an
         * exploitable use-after-free that could be triggered by any
         * binary lacking the .fhsm_digest section. */
        fhsm_zeroize(buf, flen);
        free(buf);
        if (getenv("FHSM_INTEGRITY_ALLOW_UNSIGNED")) {
            return FHSM_RV_OK;
        }
        return FHSM_RV_INTEGRITY_FAILED;
    }
    memset(buf + off, 0, len);

    /* Compute SHA-256 over the masked buffer. */
    EVP_MD *md = EVP_MD_fetch(NULL, "SHA2-256", NULL);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    fhsm_rv_t rv = FHSM_RV_FUNCTION_FAILED;
    unsigned int n = 0;
    if (md && ctx &&
        EVP_DigestInit_ex2(ctx, md, NULL) == 1 &&
        EVP_DigestUpdate(ctx, buf, flen) == 1 &&
        EVP_DigestFinal_ex(ctx, g_last_digest, &n) == 1 &&
        n == FHSM_INTEGRITY_DIGEST_LEN) {
        rv = FHSM_RV_OK;
    }
    if (ctx) EVP_MD_CTX_free(ctx);
    if (md)  EVP_MD_free(md);

    fhsm_zeroize(buf, flen);
    free(buf);

    if (rv != FHSM_RV_OK) return rv;

    /* Compare. Two failure modes converge here :
     *   (a) Unsigned build : the .fhsm_digest section is the all-zero
     *       placeholder placed by the compiler. In production this is
     *       INTEGRITY_FAILED (the operator must run a signed binary).
     *       In dev mode (FHSM_INTEGRITY_ALLOW_UNSIGNED set) the build
     *       is allowed to run unsigned.
     *   (b) Signed build with mismatched digest : the embedded digest
     *       is non-zero but does not match g_last_digest (computed
     *       above). In production this is INTEGRITY_FAILED (the
     *       binary has been tampered with after signing). In dev mode
     *       the mismatch is tolerated for ergonomics (e.g. an
     *       unsigned test harness reusing a stale .fhsm_digest from
     *       a previous build).
     *
     * The env var is REFUSED in production per AGD_PRE §7.5 ; the
     * permissive paths here exist purely for developer ergonomics.
     *
     * Prior to v1.2.1 this function fell through to a final
     * `return FHSM_RV_OK` in both failure modes, silently bypassing
     * the integrity check whenever the env var was unset. That
     * effectively disabled FIPS 140-3 §7.10.2 in all signed
     * production builds. Fixed in v1.2.1 (CVE candidate). */
    if (is_all_zero(fhsm_module_integrity_digest, FHSM_INTEGRITY_DIGEST_LEN)) {
        if (getenv("FHSM_INTEGRITY_ALLOW_UNSIGNED")) {
            return FHSM_RV_OK;   /* unsigned build, allowed by explicit opt-in */
        }
        return FHSM_RV_INTEGRITY_FAILED;
    }

    if (fhsm_ct_memcmp(g_last_digest,
                        fhsm_module_integrity_digest,
                        FHSM_INTEGRITY_DIGEST_LEN) != 0) {
        if (getenv("FHSM_INTEGRITY_ALLOW_UNSIGNED")) {
            return FHSM_RV_OK;   /* dev override, mismatch tolerated */
        }
        return FHSM_RV_INTEGRITY_FAILED;
    }
    return FHSM_RV_OK;
}

static void verify_once(void) {
    g_result = do_verify();
    if (g_result != FHSM_RV_OK) {
        /* FHSM_INTEGRITY_ALLOW_UNSIGNED downgrades integrity failures
         * to a warning : we suppress both the ERROR state latch and the
         * non-OK return so the rest of the module can continue. This
         * matches the existing partial bypass in crypto_init_once,
         * which only filtered the return value but missed the latch
         * happening here. The setup-error paths in do_verify (locate_self
         * / open / fstat / mmap / malloc) have no internal bypass, so
         * without this consolidation the state machine ended up in
         * ERROR before any crypto could run.
         *
         * The flag is REFUSED in production by AGD_PRE §7.5 ; this
         * downgrade is purely a developer ergonomics path. */
        if (getenv("FHSM_INTEGRITY_ALLOW_UNSIGNED")) {
            fprintf(stderr,
                "[freehsm-c] WARNING : FHSM_INTEGRITY_ALLOW_UNSIGNED "
                "active --- integrity verify failed (rv=0x%08x) but the "
                "ERROR latch is suppressed. This is INVALID for any "
                "FIPS 140-3 / CC EAL4+ deployment.\n",
                (unsigned)g_result);
            g_result = FHSM_RV_OK;
            return;
        }
        fhsm_state_latch_error("integrity check failed");
    }
}

fhsm_rv_t fhsm_integrity_verify(void) {
    pthread_once(&g_once, verify_once);
    return g_result;
}

int fhsm_integrity_is_signed(void) {
    return !is_all_zero(fhsm_module_integrity_digest,
                         FHSM_INTEGRITY_DIGEST_LEN);
}

const uint8_t *fhsm_integrity_last_computed(void) {
    return g_last_digest;
}

const char *fhsm_integrity_so_path(void) {
    return g_so_path[0] ? g_so_path : "(unknown)";
}
