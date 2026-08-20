/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * Does `p11-kit server` isolate two clients' login state?
 *
 * 03_login_shared established that inside ONE process, a second session
 * inherits the first one's login: PKCS#11 login state is per token per
 * *application*, and one process is one application. Correct, and locally
 * harmless.
 *
 * p11-kit remoting moves the module into a server process. If that server is
 * one application for every client behind its socket, then the first client to
 * log in logs the token in for all of them, and the PIN stops being a check
 * after the first request of the server's life. That is the difference between
 * "p11-kit is the PKCS#11 answer for #111" and "one server per operator".
 *
 * It cannot be answered from one process, so this probe is two:
 *
 *   06_kit_isolation MODULE hold SECONDS LABEL
 *       logs in and holds the session open.
 *
 *   06_kit_isolation MODULE peek LABEL
 *       opens a session, NEVER logs in, and asks three questions:
 *         - what does C_GetSessionInfo say its state is?
 *         - can it find the private key? (private objects are filtered from
 *           an unauthenticated session -- see #49)
 *         - can it sign with it?
 *
 * Run `peek` against the module DIRECTLY first. Two processes, two
 * applications, so the answer must be "no" to all three. That is the control:
 * a peek that reports isolation against a socket, without having reported the
 * opposite here, has proved nothing about p11-kit.
 */
#include "p11_probe.h"
#include <unistd.h>

static const char *state_name(CK_ULONG s) {
    switch (s) {
    case 0: return "RO_PUBLIC   -- not logged in";
    case 1: return "RO_USER     -- LOGGED IN as user";
    case 2: return "RW_PUBLIC   -- not logged in";
    case 3: return "RW_USER     -- LOGGED IN as user";
    case 4: return "RW_SO       -- logged in as SO";
    default: return "(unknown)";
    }
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr,
          "usage: %s MODULE hold SECONDS LABEL\n"
          "       %s MODULE peek LABEL\n", argv[0], argv[0]);
        return 1;
    }
    probe_load(argv[1]);
    if (p11.Initialize(NULL)) { fprintf(stderr, "C_Initialize failed\n"); return 2; }
    CK_SLOT_ID slot = probe_slot();

    CK_SESSION_HANDLE s = 0;
    CK_RV rv = p11.OpenSession(slot, 6 /* RW|SERIAL */, NULL, NULL, &s);
    if (rv) { fprintf(stderr, "C_OpenSession(slot %lu) -> 0x%lx\n",
                      (unsigned long)slot, (unsigned long)rv); return 2; }

    /* ---------------------------------------------------------------- hold */
    if (!strcmp(argv[2], "hold")) {
        const char *pin = getenv("FHSM_PIN");
        int secs = argc > 3 ? atoi(argv[3]) : 30;
        if (!pin || !*pin) { fprintf(stderr, "FHSM_PIN is not set\n"); return 1; }
        rv = p11.Login(s, 1, (CK_BYTE*)(size_t)pin, (CK_ULONG)strlen(pin));
        printf("  [hold] slot %lu, C_Login -> 0x%lx\n", (unsigned long)slot,
               (unsigned long)rv);
        if (rv) return 2;
        printf("  [hold] logged in, holding the session for %d s\n", secs);
        fflush(stdout);
        sleep((unsigned)secs);
        p11.CloseSession(s);
        p11.Finalize(NULL);
        return 0;
    }

    /* ---------------------------------------------------------------- peek */
    if (strcmp(argv[2], "peek")) { fprintf(stderr, "mode is hold or peek\n"); return 1; }
    const char *label = argc > 3 ? argv[3] : "k1";
    int leaked = 0;

    printf("  [peek] slot %lu, opened a session, did NOT log in\n",
           (unsigned long)slot);

    struct { CK_ULONG slot, state, flags, err; } si;
    memset(&si, 0, sizeof si);
    if (p11.GetSessionInfo && p11.GetSessionInfo(s, &si) == 0) {
        printf("  [peek] C_GetSessionInfo state = %lu  %s\n",
               si.state, state_name(si.state));
        if (si.state == 1 || si.state == 3) leaked++;
    } else {
        printf("  [peek] C_GetSessionInfo unavailable\n");
    }

    CK_ULONG cls = 3;                                   /* CKO_PRIVATE_KEY */
    CK_ATTRIBUTE t[2] = { { 0, &cls, sizeof cls },
                          { 3, (void*)(size_t)label, (CK_ULONG)strlen(label) } };
    CK_OBJECT_HANDLE k = 0; CK_ULONG n = 0;
    if (p11.FindObjectsInit(s, t, 2) == 0) {
        p11.FindObjects(s, &k, 1, &n);
        p11.FindObjectsFinal(s);
    }
    printf("  [peek] private key \"%s\" %s\n", label,
           n ? "IS VISIBLE to this session" : "is not visible (filtered)");
    if (n) leaked++;

    if (n) {
        CK_BYTE d[32]; memset(d, 0x5A, sizeof d);
        static CK_BYTE sig[8192]; CK_ULONG sl = sizeof sig;
        CK_MECHANISM m = { 0x80004202, NULL, 0 };
        CK_RV r1 = p11.SignInit(s, &m, k);
        CK_RV r2 = r1 ? r1 : p11.Sign(s, d, sizeof d, sig, &sl);
        printf("  [peek] signing without a PIN -> 0x%lx  %s\n", (unsigned long)r2,
               r2 ? "refused" : "SUCCEEDED");
        if (!r2) leaked++;
    }

    printf("\n  %s\n", leaked
        ? "  ==> the login LEAKED across processes: this server is one PKCS#11\n"
          "      application for every client behind its socket."
        : "  ==> no leak: this client proved nothing it had not proved itself.");

    p11.CloseSession(s);
    p11.Finalize(NULL);
    return leaked ? 1 : 0;
}
