/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * C_Login must honour ulPinLen.
 *
 * `pPin` is a byte array of `ulPinLen`. PKCS#11 nowhere says it is
 * NUL-terminated, and an application has no reason to terminate it. C_Login
 * derived the KEK over `strlen(pPin)`, which does two things:
 *
 *   - it reads past the end of the caller's buffer, so a PIN allocated at the
 *     end of a page faults inside the module, on input the caller controls;
 *   - it refuses the correct PIN whenever the byte after it is not zero.
 *
 * Found by trying to log in through `p11-kit server`, whose RPC unmarshals the
 * PIN into a buffer that is not terminated. Our own tools pass a `getenv()`
 * pointer, which is terminated by accident, so everything looked fine.
 *
 * C_InitToken, C_InitPIN and C_SetPIN all copied `ulPinLen` bytes through
 * fhsm_copy_to_cstr and were correct. C_Login was the fourth PIN entry point
 * and the only one that was not -- the same shape as #61 and #49: a rule
 * wired to some of the paths that reach a state, and not the rest.
 *
 * Case 2 is the proof: with the defect back, it does not fail, it segfaults.
 * Case 4 is there so that a pass means something -- with the length honoured,
 * a WRONG pin of the same length must still be refused, or this test would
 * also pass against a module that had stopped checking the PIN at all.
 */
#include "fhsm_common.h"
#include "fhsm_token.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

#define USER_PIN "userpin1234"
#define SO_PIN   "sopin1234"

int main(void)
{
    char path[512];
    const char *dir = getenv("FHSM_TOKENS_DIR");
    snprintf(path, sizeof path, "%s/pinlen.tok", dir ? dir : "/tmp");
    unlink(path);

    printf("C_Login honours ulPinLen\n\n");

    fhsm_token_t *t = NULL;
    if (fhsm_token_init(path, SO_PIN, "pinlen", &t) != FHSM_RV_OK || !t) {
        printf("  cannot create a token at %s\n", path);
        return 2;
    }
    if (fhsm_token_login(t, FHSM_ROLE_SO, SO_PIN, strlen(SO_PIN)) != FHSM_RV_OK
        || fhsm_token_init_user_pin(t, USER_PIN) != FHSM_RV_OK) {
        printf("  cannot set the user PIN\n");
        return 2;
    }
    fhsm_token_logout(t);

    const size_t n = strlen(USER_PIN);

    /* The order below is deliberate. Every failed login bumps the counter and
     * arms the throttle, and the throttle returns BEFORE the derivation --
     * which would hide the very read this test is about. So each case starts
     * from a successful login, which resets the counter to zero. */

    /* 1. The easy case, and the only one that ever ran: a C string. */
    ok(fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, n) == FHSM_RV_OK,
       "a NUL-terminated buffer logs in");
    fhsm_token_logout(t);

    /* 2. The over-read itself. The PIN sits at the very end of a mapped page
     *    with an unmapped guard page after it, so a read past ulPinLen faults
     *    instead of merely returning the wrong answer. Put the defect back and
     *    this test does not fail, it CRASHES -- which is what a daemon does
     *    when a remote client sends a PIN that ends on a page boundary. */
    {
        long ps = sysconf(_SC_PAGESIZE);
        char *region = mmap(NULL, (size_t)ps * 2, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (region == MAP_FAILED) {
            printf("  (mmap unavailable, guard-page case skipped)\n");
        } else {
            mprotect(region + ps, (size_t)ps, PROT_NONE);
            char *pin = region + ps - (long)n;      /* ends exactly at the guard */
            memcpy(pin, USER_PIN, n);
            ok(fhsm_token_login(t, FHSM_ROLE_USER, pin, n) == FHSM_RV_OK,
               "a PIN ending at a guard page logs in, and does not fault");
            fhsm_token_logout(t);
            munmap(region, (size_t)ps * 2);
        }
    }

    /* 3. The same bytes, the same length, followed by something other than a
     *    terminator. A conforming module cannot tell this from case 1. */
    {
        char buf[64];
        memset(buf, 'X', sizeof buf);
        memcpy(buf, USER_PIN, n);
        ok(fhsm_token_login(t, FHSM_ROLE_USER, buf, n) == FHSM_RV_OK,
           "the same bytes, not terminated, log in");
        fhsm_token_logout(t);
    }

    /* 4. The mutation. If the length were ignored again, or the PIN not
     *    checked at all, everything above would still pass -- so this has to
     *    fail. It runs last because it is the one that arms the throttle. */
    {
        char buf[64];
        memset(buf, 'X', sizeof buf);
        memcpy(buf, USER_PIN, n);
        buf[0] = 'Z';                       /* same length, wrong content */
        fhsm_rv_t rv = fhsm_token_login(t, FHSM_ROLE_USER, buf, n);
        ok(rv == FHSM_RV_PIN_INCORRECT || rv == FHSM_RV_PIN_LOCKED,
           "a wrong PIN of the same length is still refused");
        fhsm_token_logout(t);
    }

    fhsm_token_close(t);
    unlink(path);
    printf("\n%s : %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
