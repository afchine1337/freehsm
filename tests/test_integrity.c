/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_integrity.c --- the module integrity self-check must actually gate.
 *
 * Why this test exists (#125)
 * ---------------------------
 * FIPS 140-3 §7.10.2 requires a module integrity self-test. FreeHSM had one:
 * declared, documented, wired into C_Initialize, and inert. Twice.
 *
 *   1. Until v1.2.1, fhsm_integrity_verify() fell through to a final
 *      `return FHSM_RV_OK` in both failure modes, so it passed
 *      unconditionally. Found and fixed (labelled a CVE candidate in-source).
 *
 *   2. That fix turned "always passes" into "always fails": the embedded
 *      digest slot was `const uint8_t ... = { 0 }` with no `volatile`, even
 *      though the comment above it stated that "the volatile prevents the
 *      compiler from constant-folding the digest into the code generator".
 *      GCC folded the explicitly-initialised element [0] to a literal zero,
 *      so byte 0 of every comparison came from the code generator and bytes
 *      1..31 from memory. Every correctly signed build failed on that byte.
 *
 * Neither was noticed, because the whole chain -- unit tests, harness, CI --
 * runs with FHSM_INTEGRITY_ALLOW_UNSIGNED=1, which downgrades the failure to
 * a warning. A security mechanism exercised only from behind its own bypass
 * is not exercised at all.
 *
 * So this test runs WITHOUT the bypass and asserts the three outcomes that
 * matter. It links fhsm_integrity.o directly, so the test binary carries its
 * own .fhsm_digest section and can be signed by scripts/sign_module.sh just
 * like the shipped .so (find_self_cb already resolves the main-executable
 * case via /proc/self/exe). It needs no FIPS provider: it calls
 * fhsm_integrity_verify() directly rather than going through C_Initialize,
 * which legitimately refuses to start without one.
 *
 *   argv[1] = expected outcome: "unsigned" | "signed" | "tampered"
 * ======================================================================== */

#include "fhsm_common.h"
#include "fhsm_integrity.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* A stable, locatable payload in .rodata that the `tampered` case flips a bit
 * in. Flipping a random byte risks corrupting the ELF or the digest slot
 * itself; this gives the test a byte that is unambiguously part of the hashed
 * image and unambiguously not the digest. */
__attribute__((used))
static const char fhsm_tamper_canary[] = "FHSM_TAMPER_CANARY_PAYLOAD";

static int fail(const char *what, const char *detail) {
    fprintf(stderr, "FAIL: %s : %s\n", what, detail);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s unsigned|signed|tampered\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];

    /* The whole point is to run without the bypass. If it leaks in from the
     * environment this test proves nothing, so refuse rather than report a
     * false pass. */
    if (getenv("FHSM_INTEGRITY_ALLOW_UNSIGNED")) {
        return fail("environment",
                    "FHSM_INTEGRITY_ALLOW_UNSIGNED is set; this test must run "
                    "without it or it verifies nothing");
    }

    fhsm_rv_t rv = fhsm_integrity_verify();
    int signed_flag = fhsm_integrity_is_signed();

    if (strcmp(mode, "unsigned") == 0) {
        if (signed_flag)
            return fail("unsigned binary", "fhsm_integrity_is_signed() = 1");
        if (rv != FHSM_RV_INTEGRITY_FAILED)
            return fail("unsigned binary must not verify",
                        "expected FHSM_RV_INTEGRITY_FAILED");
        printf("  unsigned binary  -> INTEGRITY_FAILED : OK\n");
        return 0;
    }

    if (strcmp(mode, "signed") == 0) {
        /* The case that was broken: a correctly signed binary must verify.
         * It failed on byte 0 for as long as the volatile was missing. */
        if (!signed_flag)
            return fail("signed binary", "fhsm_integrity_is_signed() = 0");
        if (rv != FHSM_RV_OK) {
            const uint8_t *got = fhsm_integrity_last_computed();
            char hex[65];
            for (int i = 0; i < 32; ++i) snprintf(hex + i * 2, 3, "%02x", got[i]);
            fprintf(stderr, "  computed digest = %s\n", hex);
            fprintf(stderr, "  image           = %s\n", fhsm_integrity_so_path());
            return fail("signed binary must verify",
                        "expected FHSM_RV_OK -- embedded digest does not match "
                        "the computed one (constant-folded slot?)");
        }
        printf("  signed binary    -> OK : OK\n");
        return 0;
    }

    if (strcmp(mode, "tampered") == 0) {
        /* Signed, then one byte of the image flipped. The check must notice:
         * this is the property the mechanism exists for. */
        if (!signed_flag)
            return fail("tampered binary", "fhsm_integrity_is_signed() = 0");
        if (rv != FHSM_RV_INTEGRITY_FAILED)
            return fail("tampered binary must not verify",
                        "expected FHSM_RV_INTEGRITY_FAILED -- a modified image "
                        "passed its own integrity check");
        printf("  tampered binary  -> INTEGRITY_FAILED : OK\n");
        return 0;
    }

    return fail("usage", "mode must be unsigned|signed|tampered");
}
