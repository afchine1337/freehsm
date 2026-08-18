/* Combien coute une requete de signature, selon qu'on ouvre une session par
 * requete ou qu'on en garde une ouverte ? C'est le chiffre qui decide si une
 * API REST sans etat peut l'etre jusqu'au bout. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_FLAGS;
typedef struct { CK_ULONG mechanism; void *p; CK_ULONG len; } CK_MECHANISM;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;

static struct {
    CK_RV (*Initialize)(void*);
    CK_RV (*Finalize)(void*);
    CK_RV (*OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
    CK_RV (*CloseSession)(CK_SESSION_HANDLE);
    CK_RV (*Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
    CK_RV (*Logout)(CK_SESSION_HANDLE);
    CK_RV (*FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
    CK_RV (*FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE*, CK_ULONG, CK_ULONG*);
    CK_RV (*FindObjectsFinal)(CK_SESSION_HANDLE);
    CK_RV (*SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
    CK_RV (*Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
} p11;

#define SYM(n) do { *(void**)(&p11.n) = dlsym(h, "C_" #n); \
                    if (!p11.n) { fprintf(stderr, "C_" #n " absent\n"); exit(2);} } while(0)

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
    const char *mod = argc > 1 ? argv[1] : "./libfreehsm-fips.so";
    const char *label = argc > 2 ? argv[2] : "k";
    PIN = getenv("FHSM_PIN");
    void *h = dlopen(mod, RTLD_NOW);
    if (!h) { fprintf(stderr, "%s\n", dlerror()); return 2; }
    SYM(Initialize); SYM(Finalize); SYM(OpenSession); SYM(CloseSession);
    SYM(Login); SYM(Logout); SYM(FindObjectsInit); SYM(FindObjects);
    SYM(FindObjectsFinal); SYM(SignInit); SYM(Sign);

    NOW(t0); if (p11.Initialize(NULL)) { fprintf(stderr,"init\n"); return 2; } NOW(t1);
    printf("  C_Initialize .............. %8.2f ms  (une fois par processus)\n", ms(t0,t1));

    CK_BYTE data[32]; memset(data, 0x5A, sizeof data);
    static CK_BYTE sig[8192];

    /* --- chemin sans etat : tout par requete -------------------------- */
    double open_t=0, login_t=0, find_t=0, sign_t=0, close_t=0;
    const int N = 5;
    for (int i = 0; i < N; i++) {
        CK_SESSION_HANDLE s = 0;
        NOW(a); p11.OpenSession(0, 6, NULL, NULL, &s); NOW(b);
        p11.Logout(s); p11.Login(s, 1, (CK_BYTE*)(size_t)PIN, (CK_ULONG)strlen(PIN)); NOW(c);
        CK_OBJECT_HANDLE k = find_key(s, label); NOW(d);
        CK_MECHANISM m = { CKM_COMPOSITE, NULL, 0 };
        CK_ULONG sl = sizeof sig;
        p11.SignInit(s, &m, k); p11.Sign(s, data, sizeof data, sig, &sl); NOW(e);
        p11.CloseSession(s); NOW(f);
        open_t+=ms(a,b); login_t+=ms(b,c); find_t+=ms(c,d); sign_t+=ms(d,e); close_t+=ms(e,f);
    }
    printf("\n  Une requete, session ouverte et fermee a chaque fois :\n");
    printf("    C_OpenSession ........... %8.2f ms\n", open_t/N);
    printf("    C_Login ................. %8.2f ms   <-- PBKDF2, 200000 iterations\n", login_t/N);
    printf("    recherche de la cle ..... %8.2f ms\n", find_t/N);
    printf("    C_SignInit + C_Sign ..... %8.2f ms\n", sign_t/N);
    printf("    C_CloseSession .......... %8.2f ms\n", close_t/N);
    printf("    -------------------------------------\n");
    printf("    total par requete ....... %8.2f ms  -> %6.1f requetes/s\n",
           (open_t+login_t+find_t+sign_t+close_t)/N,
           1000.0*N/(open_t+login_t+find_t+sign_t+close_t));

    /* --- chemin avec session gardee ouverte --------------------------- */
    {
        CK_SESSION_HANDLE s = 0;
        p11.OpenSession(0, 6, NULL, NULL, &s);
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
        printf("\n  Une requete, session deja ouverte et connectee :\n");
        printf("    C_SignInit + C_Sign ..... %8.2f ms  -> %6.1f requetes/s\n",
               ms(a,b)/M, 1000.0*M/ms(a,b));
        p11.CloseSession(s);
    }
    p11.Finalize(NULL);
    return 0;
}
