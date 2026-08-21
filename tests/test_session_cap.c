/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * A session the module hands out has to be a session that works.
 *
 * FHSM_MAX_SESSIONS used to live inside src/fhsm_session.c, where nothing
 * else could see it, while src/fhsm_pkcs11.c bounded the same handles four
 * other ways: five operation tables of [256], a literal 256 in op_slot(),
 * another in fhsm_session_ops_reset(), and g_finds[FHSM_MAX_SLOTS * 32] --
 * which equals 128 only because there happen to be four slots.
 *
 * All four were >= the 128 the session table could issue, so the module was
 * correct by coincidence. Raising the cap -- the first thing a service (#111)
 * would do -- broke it: measured with -DFHSM_MAX_SESSIONS=512, 511 sessions
 * opened, 511 accepted C_Login, and 255 could perform an operation. The rest
 * answered CKR_SESSION_HANDLE_INVALID for handles the module had just issued.
 *
 * The tables now derive from one constant and _Static_assert says so, which
 * catches a mismatch at compile time. This checks the property that actually
 * matters to a caller, which no assertion about array sizes can: that the
 * LAST handle the module is willing to issue can log in and do work.
 *
 *     make tests/test_session_cap && ./tests/test_session_cap
 *
 * Correct under any cap. It asks the module how far it goes rather than
 * being told, because a test that hard-codes 128 passes for the wrong reason
 * the day someone changes it.
 */
#include "p11_util.h"

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

int main(int argc, char **argv)
{
    p11_progname = "test_session_cap";
    load_module(argc > 1 ? argv[1] : "./libfreehsm-fips.so");
    if (p11.Initialize(NULL) != CKR_OK) {
        fprintf(stderr, "test_session_cap: C_Initialize failed\n"); return 2; }
    const char *pin   = getenv("FHSM_PIN");    if (!pin   || !*pin)   pin   = "userpin1234";
    const char *sopin = getenv("FHSM_SO_PIN"); if (!sopin || !*sopin) sopin = "sopin1234";

    /* Provision its own token if the directory has none, rather than requiring
     * one to exist. A test whose precondition is set up elsewhere reports FAIL
     * for a reason that has nothing to do with what it checks -- which is what
     * this one did on its first run, in a harness that hands every test a
     * fresh empty FHSM_TOKENS_DIR. */
    CK_SLOT_ID slot;
    {
        CK_SLOT_ID with[16]; CK_ULONG nw = 16;
        if (p11.GetSlotList(1, with, &nw) != CKR_OK || nw == 0) {
            CK_SLOT_ID s0 = p11_resolve_slot(-1, P11_SLOT_FOR_INIT);
            unsigned char label[32]; memset(label, ' ', sizeof label);
            memcpy(label, "cap", 3);
            if (p11.InitToken(s0, (CK_BYTE*)(uintptr_t)sopin,
                               (CK_ULONG)strlen(sopin), label) != CKR_OK) {
                fprintf(stderr, "test_session_cap: C_InitToken failed\n"); return 2; }
            CK_SESSION_HANDLE so = 0;
            if (p11.OpenSession(s0, CKF_RW, NULL, NULL, &so) != CKR_OK
                || p11.Login(so, CKU_SO, (CK_BYTE*)(uintptr_t)sopin,
                              (CK_ULONG)strlen(sopin)) != CKR_OK
                || p11.InitPIN(so, (CK_BYTE*)(uintptr_t)pin,
                                (CK_ULONG)strlen(pin)) != CKR_OK) {
                fprintf(stderr, "test_session_cap: could not set the user PIN\n"); return 2; }
            (void)p11.CloseSession(so);
        }
        slot = p11_resolve_slot(-1, P11_SLOT_WITH_TOKEN);
    }

    printf("The session cap\n\n");

    enum { CAP = 8192 };
    static CK_SESSION_HANDLE s[CAP];
    int n = 0;
    CK_RV last = CKR_OK;
    for (; n < CAP; n++) {
        last = p11.OpenSession(slot, CKF_RW, NULL, NULL, &s[n]);
        if (last != CKR_OK) break;
    }
    printf("  the module issued %d handles, then 0x%lx\n\n",
           n, (unsigned long)last);

    ok(n > 0, "the module opens at least one session");
    ok(last == 0x00000002UL /* CKR_HOST_MEMORY */,
       "the refusal past the cap is CKR_HOST_MEMORY, not a crash");
    ok(n < CAP, "the cap is reached rather than exhausting the test");

    /* The last handle, which is the one every off-by-one lands on. */
    CK_SESSION_HANDLE top = n ? s[n-1] : 0;
    CK_RV rv = p11.Login(top, CKU_USER, (CK_BYTE*)(uintptr_t)pin,
                          (CK_ULONG)strlen(pin));
    ok(rv == CKR_OK || rv == 0x00000100UL /* ALREADY_LOGGED_IN */,
       "the last handle issued accepts a login");

    /* And can work. This is the assertion the old arrangement failed: login
     * succeeded on every handle because login state is per token per
     * application and never touches a per-session table, so the mismatch was
     * invisible until an operation asked for the session's own slot. */
    CK_MECHANISM sha256 = { 0x00000250UL /* CKM_SHA256 */, NULL, 0 };
    ok(p11.DigestInit(top, &sha256) == CKR_OK,
       "the last handle issued can start an operation");

    /* Every handle, not just the last: an off-by-one in the middle of a
     * table would leave a hole rather than a short tail. */
    int workable = 0;
    for (int i = 0; i < n; i++)
        if (p11.DigestInit(s[i], &sha256) == CKR_OK
            || i == n - 1 /* already started above */) workable++;
    ok(workable == n, "every handle issued can start an operation");

    for (int i = 0; i < n; i++) (void)p11.CloseSession(s[i]);
    (void)p11.Finalize(NULL);

    printf("\n%s : %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
