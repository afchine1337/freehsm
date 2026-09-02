/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * What a forked child inherits, and what it must not.
 *
 * `fhsm_reset_after_fork()` has existed since #125 and had no test in this
 * repository: the property was checked by an external harness
 * (pkcs11-check TestSessionObjectProcessIsolation), so nothing here ever
 * called fork(). That is how the two omissions below survived.
 *
 *   1. The module state was not reset. A child inherited INITIALIZED, and
 *      INITIALIZED -> INITIALIZING is rightly not a legal transition, so
 *      C_Initialize in the child returned CKR_FUNCTION_FAILED. A listener
 *      that initialised the module and then forked per connection could not
 *      work at all -- which is the model #111 was about to cost out.
 *
 *   2. Three of the five operation tables were not zeroized. g_op_sig,
 *      g_op_dig and g_op_ver, plus both OAEP tables, crossed the fork intact
 *      -- with the parent's IVs, its GCM additional data (4 KiB a slot), its
 *      ML-DSA context strings and its EVP context pointers.
 *
 * The cause of 2 is worth naming: two operation tables were declared above
 * the reset function and three below it, so the reset could only see two --
 * and zeroized exactly those. Declaration order decided which state survived
 * a fork.
 *
 * BUT 2 IS NOT TESTED HERE, AND CANNOT BE. C_OpenSession calls
 * fhsm_session_ops_reset() for the handle it issues, so by the time a child
 * can reach an operation slot through the API, that slot has been cleared
 * anyway -- removing the zeroizing from the fork path breaks no assertion
 * below, which was checked by doing it. What the fork-time zeroizing buys is
 * confidentiality, not correctness: without it the parent's plaintext-adjacent
 * buffers sit in the child's address space until something happens to
 * overwrite them, and a child is a different security domain. That is a real
 * reason and it is not one this test can demonstrate. Written down rather than
 * dressed up as coverage, because an assertion whose name promises more than
 * its mutation delivers is worse than no assertion.
 *
 *     make tests/test_fork_child && ./tests/test_fork_child
 *
 * Not covered here: a child of a parent whose state is latched ERROR. The
 * choice made is that ERROR survives the fork -- a fork is not a restart, and
 * inheriting a refusal is the fail-closed reading -- but putting a parent into
 * ERROR from outside the module is not something this test can do cleanly, so
 * the behaviour is a decision with a comment rather than a decision with a
 * test. Said here rather than left to look like coverage.
 */
#include "p11_util.h"

#include <sys/types.h>
#include <sys/wait.h>

static int g_fail = 0;
static void ok(int cond, const char *what) {
    printf("  %-62s %s\n", what, cond ? "OK" : "FAIL");
    if (!cond) g_fail++;
}

/* Each check runs in its own child so one failure cannot poison the next.
 * Returns the child's exit code, which is 0 for the property holding. */
static int in_child(int (*fn)(void)) {
    pid_t k = fork();
    if (k < 0) return 127;
    if (k == 0) _exit(fn());
    int st = 0;
    if (waitpid(k, &st, 0) < 0) return 127;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 126;
}

static CK_SLOT_ID g_slot;
static const char *g_pin;

static int child_can_initialize(void) {
    return p11.Initialize(NULL) == CKR_OK ? 0 : 1;
}


static int child_must_log_in_again(void) {
    if (p11.Initialize(NULL) != CKR_OK) return 1;
    CK_SESSION_HANDLE s = 0;
    if (p11.OpenSession(g_slot, CKF_RW, NULL, NULL, &s) != CKR_OK) return 2;
    /* If the child inherited the parent's login, this returns
     * CKR_USER_ALREADY_LOGGED_IN instead of doing the work. */
    return p11.Login(s, CKU_USER, (CK_BYTE*)(uintptr_t)g_pin,
                      (CK_ULONG)strlen(g_pin)) == CKR_OK ? 0 : 3;
}

static int child_has_no_active_operation(void) {
    if (p11.Initialize(NULL) != CKR_OK) return 1;
    CK_SESSION_HANDLE s = 0;
    if (p11.OpenSession(g_slot, CKF_RW, NULL, NULL, &s) != CKR_OK) return 2;
    /* The parent started a digest on the handle this child has just been
     * given. An unzeroized g_op_dig answers CKR_OPERATION_ACTIVE. */
    CK_MECHANISM sha256 = { 0x00000250UL, NULL, 0 };
    CK_RV rv = p11.DigestInit(s, &sha256);
    if (rv == 0x00000090UL /* CKR_OPERATION_ACTIVE */) return 3;
    return rv == CKR_OK ? 0 : 4;
}

int main(int argc, char **argv)
{
    p11_progname = "test_fork_child";
    load_module(argc > 1 ? argv[1] : "./libfreehsm.so");

    g_pin = getenv("FHSM_PIN");  if (!g_pin || !*g_pin) g_pin = "userpin1234";
    const char *sopin = getenv("FHSM_SO_PIN");
    if (!sopin || !*sopin) sopin = "sopin1234";

    if (p11.Initialize(NULL) != CKR_OK) {
        fprintf(stderr, "test_fork_child: C_Initialize failed\n"); return 2; }

    {   CK_SLOT_ID with[16]; CK_ULONG nw = 16;
        if (p11.GetSlotList(1, with, &nw) != CKR_OK || nw == 0) {
            CK_SLOT_ID s0 = p11_resolve_slot(-1, P11_SLOT_FOR_INIT);
            unsigned char label[32]; memset(label, ' ', sizeof label);
            memcpy(label, "fork", 4);
            CK_SESSION_HANDLE so = 0;
            if (p11.InitToken(s0, (CK_BYTE*)(uintptr_t)sopin, (CK_ULONG)strlen(sopin), label) != CKR_OK
                || p11.OpenSession(s0, CKF_RW, NULL, NULL, &so) != CKR_OK
                || p11.Login(so, CKU_SO, (CK_BYTE*)(uintptr_t)sopin, (CK_ULONG)strlen(sopin)) != CKR_OK
                || p11.InitPIN(so, (CK_BYTE*)(uintptr_t)g_pin, (CK_ULONG)strlen(g_pin)) != CKR_OK) {
                fprintf(stderr, "test_fork_child: could not provision a token\n"); return 2; }
            (void)p11.CloseSession(so);
        }
        g_slot = p11_resolve_slot(-1, P11_SLOT_WITH_TOKEN);
    }

    printf("What a forked child inherits\n\n");

    /* The parent takes up every kind of state a child might wrongly adopt:
     * an open session, a login, and an operation in progress. */
    CK_SESSION_HANDLE ps = 0;
    if (p11.OpenSession(g_slot, CKF_RW, NULL, NULL, &ps) != CKR_OK) {
        fprintf(stderr, "test_fork_child: parent could not open a session\n"); return 2; }
    if (p11.Login(ps, CKU_USER, (CK_BYTE*)(uintptr_t)g_pin,
                   (CK_ULONG)strlen(g_pin)) != CKR_OK) {
        fprintf(stderr, "test_fork_child: parent could not log in\n"); return 2; }
    CK_MECHANISM sha256 = { 0x00000250UL, NULL, 0 };
    if (p11.DigestInit(ps, &sha256) != CKR_OK) {
        fprintf(stderr, "test_fork_child: parent could not start a digest\n"); return 2; }

    printf("  the parent holds session %lu, a login, and an active digest\n\n",
           (unsigned long)ps);

    ok(in_child(child_can_initialize) == 0,
       "a child of an initialised parent can C_Initialize");
    /* Caught by removing fhsm_token_close() from the fork path: the child
     * then finds the parent's token object, already authenticated. */
    ok(in_child(child_must_log_in_again) == 0,
       "  and has to log in itself, not inherit the parent's login");
    /* True, and worth pinning -- but it holds because C_OpenSession resets
     * the slot it issues, not because of anything the fork path does. Named
     * for what it proves. */
    ok(in_child(child_has_no_active_operation) == 0,
       "  and the handle it is issued starts with no operation active");

    (void)p11.Finalize(NULL);
    printf("\n%s : %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
