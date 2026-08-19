/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * What does one signature request cost, opening a session per request versus
 * keeping one warm? That is the number that decides whether a stateless REST
 * API can be stateless all the way down. */
#include "p11_probe.h"
#include <time.h>
#include <pthread.h>

static double ms(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) * 1e3 + (double)(b.tv_nsec - a.tv_nsec) / 1e6;
}
#define NOW(v) struct timespec v; clock_gettime(CLOCK_MONOTONIC, &v)

static const char *PIN;
static CK_ULONG CKM_COMPOSITE = 0x80004202;

static CK_OBJECT_HANDLE find_key(CK_SESSION_HANDLE s, const char *label) {
    CK_ULONG cls = 3;                         /* CKO_PRIVATE_KEY */
    CK_ATTRIBUTE t[2] = {
        { 0x00000000, &cls, sizeof cls },     /* CKA_CLASS */
        { 0x00000003, (void*)(size_t)label, (CK_ULONG)strlen(label) } /* CKA_LABEL */
    };
    CK_OBJECT_HANDLE h = 0; CK_ULONG n = 0;
    if (p11.FindObjectsInit(s, t, 2) != 0) return 0;
    p11.FindObjects(s, &h, 1, &n);
    p11.FindObjectsFinal(s);
    return n ? h : 0;
}

int main(int argc, char **argv) {
    (void)argc;
    const char *mod = argc > 1 ? argv[1] : "./libfreehsm-fips.so";
    const char *label = argc > 2 ? argv[2] : "k";
    PIN = getenv("FHSM_PIN");
    probe_load(mod);

    NOW(t0); if (p11.Initialize(NULL)) { fprintf(stderr,"init\n"); return 2; } NOW(t1);
    printf("  C_Initialize .............. %8.2f ms  (once per process)\n", ms(t0,t1));

    CK_SLOT_ID slot = probe_slot();

    CK_BYTE data[32]; memset(data, 0x5A, sizeof data);
    static CK_BYTE sig[8192];

    /* --- the stateless path: everything per request ------------------- */
    double open_t=0, login_t=0, find_t=0, sign_t=0, close_t=0;
    const int N = 5;
    for (int i = 0; i < N; i++) {
        CK_SESSION_HANDLE s = 0;
        NOW(a); p11.OpenSession(slot, 6, NULL, NULL, &s); NOW(b);
        p11.Logout(s); p11.Login(s, 1, (CK_BYTE*)(size_t)PIN, (CK_ULONG)strlen(PIN)); NOW(c);
        CK_OBJECT_HANDLE k = find_key(s, label); NOW(d);
        CK_MECHANISM m = { CKM_COMPOSITE, NULL, 0 };
        CK_ULONG sl = sizeof sig;
        p11.SignInit(s, &m, k); p11.Sign(s, data, sizeof data, sig, &sl); NOW(e);
        p11.CloseSession(s); NOW(f);
        open_t+=ms(a,b); login_t+=ms(b,c); find_t+=ms(c,d); sign_t+=ms(d,e); close_t+=ms(e,f);
    }
    printf("\n  One request, session opened and closed every time:\n");
    printf("    C_OpenSession ........... %8.2f ms\n", open_t/N);
    printf("    C_Login ................. %8.2f ms   <-- PBKDF2, 200000 iterations\n", login_t/N);
    printf("    key lookup .............. %8.2f ms\n", find_t/N);
    printf("    C_SignInit + C_Sign ..... %8.2f ms\n", sign_t/N);
    printf("    C_CloseSession .......... %8.2f ms\n", close_t/N);
    printf("    -------------------------------------\n");
    printf("    total per request ....... %8.2f ms  -> %6.1f requests/s\n",
           (open_t+login_t+find_t+sign_t+close_t)/N,
           1000.0*N/(open_t+login_t+find_t+sign_t+close_t));

    /* --- the path with a session kept open ---------------------------- */
    {
        CK_SESSION_HANDLE s = 0;
        p11.OpenSession(slot, 6, NULL, NULL, &s);
        p11.Login(s, 1, (CK_BYTE*)(size_t)PIN, (CK_ULONG)strlen(PIN));
        CK_OBJECT_HANDLE k = find_key(s, label);
        CK_MECHANISM m = { CKM_COMPOSITE, NULL, 0 };
        NOW(a);
        const int M = 20;
        for (int i = 0; i < M; i++) {
            CK_ULONG sl = sizeof sig;
            p11.SignInit(s, &m, k);
            p11.Sign(s, data, sizeof data, sig, &sl);
        }
        NOW(b);
        printf("\n  One request, session already open and logged in:\n");
        printf("    C_SignInit + C_Sign ..... %8.2f ms  -> %6.1f requests/s\n",
               ms(a,b)/M, 1000.0*M/ms(a,b));
        p11.CloseSession(s);
    }
    p11.Finalize(NULL);
    return 0;
}
