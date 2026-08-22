/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * The probes' module loader.
 *
 * Every probe here used to dlsym C_Initialize and friends by name, and every
 * probe here segfaulted against p11-kit-client.so, which exports exactly one
 * symbol -- the one the standard actually requires. Not a crash in p11-kit: a
 * crash in the probe, calling a null pointer dlsym had already refused to
 * fill. The four tools carried the same defect and it was fixed in
 * tools/p11_util.h; the probes were left behind, and the first attempt to run
 * 03_login_shared through a p11-kit server found it.
 *
 * That matters more here than a fixed bug, because these probes exist to
 * measure the module a REST service would sit on. A probe that can only load
 * OUR module can only measure our module -- and the whole question being
 * measured is what happens when a client and a token are not in the same
 * process.
 *
 * Deliberately standalone: this header links nothing from src/ or tools/. A
 * measurement should come through the same door a client uses, and a client
 * has our headers only by accident.
 *
 * Slot numbers are PKCS#11 v2.40 §C.6 and are the same ones asserted, pointer
 * by pointer, by tests/test_p11_loader.c.
 */
#ifndef FHSM_PROBE_P11_H
#define FHSM_PROBE_P11_H

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_FLAGS;
typedef struct { CK_ULONG mechanism; void *p; CK_ULONG len; } CK_MECHANISM;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;

static struct {
    CK_RV (*Initialize)(void*);
    CK_RV (*Finalize)(void*);
    CK_RV (*GetSlotList)(unsigned char, CK_SLOT_ID*, CK_ULONG*);
    CK_RV (*GetTokenInfo)(CK_SLOT_ID, void*);
    CK_RV (*GetMechanismList)(CK_SLOT_ID, CK_ULONG*, CK_ULONG*);
    CK_RV (*GetMechanismInfo)(CK_SLOT_ID, CK_ULONG, void*);
    CK_RV (*OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
    CK_RV (*CloseSession)(CK_SESSION_HANDLE);
    CK_RV (*GetSessionInfo)(CK_SESSION_HANDLE, void*);
    CK_RV (*Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE*, CK_ULONG);
    CK_RV (*Logout)(CK_SESSION_HANDLE);
    CK_RV (*FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
    CK_RV (*FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE*, CK_ULONG, CK_ULONG*);
    CK_RV (*FindObjectsFinal)(CK_SESSION_HANDLE);
    CK_RV (*SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
    CK_RV (*Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
    CK_RV (*VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
    CK_RV (*Verify)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);
} p11;

struct probe_function_list { unsigned char major, minor; void *pfn[68]; };

/* Not every module implements every entry point, and a probe that does not use
 * one should not refuse to run. Missing entries stay NULL and the probe that
 * needs one says so itself. */
__attribute__((unused))
static void probe_load(const char *path)
{
    void *h = dlopen(path, RTLD_NOW);
    if (!h) { fprintf(stderr, "probe: cannot load %s: %s\n", path, dlerror()); exit(2); }

    CK_RV (*getlist)(struct probe_function_list **) = NULL;
    *(void**)&getlist = dlsym(h, "C_GetFunctionList");

    if (getlist) {
        struct probe_function_list *fl = NULL;
        CK_RV rv = getlist(&fl);
        if (rv != 0 || !fl) {
            fprintf(stderr, "probe: C_GetFunctionList failed (0x%lx)\n", (unsigned long)rv);
            exit(2);
        }
        #define T(f,slot) *(void**)&p11.f = fl->pfn[slot]
        T(Initialize,0);       T(Finalize,1);
        T(GetSlotList,4);      T(GetTokenInfo,6);
        T(GetMechanismList,7); T(GetMechanismInfo,8);
        T(OpenSession,12);     T(CloseSession,13);   T(GetSessionInfo,15);
        T(Login,18);           T(Logout,19);
        T(FindObjectsInit,26); T(FindObjects,27);    T(FindObjectsFinal,28);
        T(SignInit,42);        T(Sign,43);
        T(VerifyInit,48);      T(Verify,49);
        #undef T
    } else {
        #define S(f,n) *(void**)&p11.f = dlsym(h, n)
        S(Initialize,"C_Initialize");     S(Finalize,"C_Finalize");
        S(GetSlotList,"C_GetSlotList");   S(GetTokenInfo,"C_GetTokenInfo");
        S(GetMechanismList,"C_GetMechanismList");
        S(GetMechanismInfo,"C_GetMechanismInfo");
        S(OpenSession,"C_OpenSession");   S(CloseSession,"C_CloseSession");
        S(GetSessionInfo,"C_GetSessionInfo");
        S(Login,"C_Login");               S(Logout,"C_Logout");
        S(FindObjectsInit,"C_FindObjectsInit");
        S(FindObjects,"C_FindObjects");   S(FindObjectsFinal,"C_FindObjectsFinal");
        S(SignInit,"C_SignInit");         S(Sign,"C_Sign");
        S(VerifyInit,"C_VerifyInit");     S(Verify,"C_Verify");
        #undef S
    }

    if (!p11.Initialize || !p11.OpenSession || !p11.GetSlotList) {
        fprintf(stderr, "probe: %s provides neither a usable function list nor "
                        "the C_* symbols\n", path);
        exit(2);
    }
}

/* Slot 0 is not a slot identifier, it is a guess that happens to be right for
 * our module. Through p11-kit the token sits at whatever id the server gave
 * it. So: enumerate, take the one token, refuse if there are several -- a
 * measurement taken against a token nobody chose measures nothing. */
__attribute__((unused))
static CK_SLOT_ID probe_slot(void)
{
    /* An override first, because a probe run against a p11-kit server may well
     * be pointed at one token among several on purpose. */
    const char *env = getenv("FHSM_SLOT");
    if (env && *env) return (CK_SLOT_ID)strtoul(env, NULL, 10);

    CK_ULONG n = 0;
    CK_RV rv = p11.GetSlotList(1, NULL, &n);
    if (rv != 0) { fprintf(stderr, "probe: C_GetSlotList failed (0x%lx)\n",
                           (unsigned long)rv); exit(2); }
    if (n == 0) { fprintf(stderr, "probe: no slot holds a token.\n"); exit(2); }

    CK_SLOT_ID *ids = calloc(n, sizeof *ids);
    if (!ids) { fprintf(stderr, "probe: out of memory\n"); exit(2); }
    if (p11.GetSlotList(1, ids, &n) != 0) { fprintf(stderr, "probe: C_GetSlotList\n"); exit(2); }

    if (n > 1) {
        fprintf(stderr, "probe: %lu slots hold a token; set FHSM_SLOT to one of:\n",
                (unsigned long)n);
        for (CK_ULONG i = 0; i < n; i++)
            fprintf(stderr, "    %lu\n", (unsigned long)ids[i]);
        exit(2);
    }
    CK_SLOT_ID s = ids[0];
    free(ids);
    return s;
}

#endif /* FHSM_PROBE_P11_H */
