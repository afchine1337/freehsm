/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * fhsm-token --- provision a token: initialise it, set the user PIN, and say
 *                what state a slot is in.
 *
 *  Usage :
 *    fhsm-token init [--label TEXT] [--slot N] [--module PATH]
 *    fhsm-token info [--slot N] [--module PATH]
 *
 *  Why this exists. docs/FHSM_CSR.md told operators hitting CKR_TOKEN_NOT_PRESENT
 *  to "initialise it first (C_InitToken, or the module's own provisioning
 *  tool)". There was no such tool. Every path into this project's own tooling
 *  therefore started at a step that could not be taken -- the tests reach
 *  C_InitToken directly from C, which is why it went unnoticed for so long.
 *
 *  Separate from fhsm-csr on the reasoning already settled when fhsm-ca was
 *  split out: a binary named for certification requests should not also be the
 *  thing that wipes and provisions a token. These are different operations,
 *  performed by different people, and one of them destroys data.
 *
 *  Both PINs come from the environment -- FHSM_SO_PIN and FHSM_PIN -- never
 *  from an argument. Same rule as the other tools, and it matters more here
 *  than anywhere else: `init` is the one command that takes the Security
 *  Officer PIN, which is the credential that can re-initialise the token and
 *  reset the user PIN.
 * ========================================================================= */
#include "p11_util.h"

#include <errno.h>

#define CKF_LOGIN_REQUIRED        0x00000004UL
#define CKF_USER_PIN_INITIALIZED  0x00000008UL
#define CKF_TOKEN_INITIALIZED     0x00000400UL
#define CKF_USER_PIN_LOCKED       0x00040000UL
#define CKF_SO_PIN_LOCKED         0x00400000UL

/* CK_TOKEN_INFO, PKCS#11 v3.2 §C.6.3. Declared here rather than pulled from a
 * header so the tool stays usable against any module, not only this one. */
struct tok_info {
    unsigned char label[32], manufacturerID[32], model[16], serialNumber[16];
    CK_ULONG flags;
    CK_ULONG ulMaxSessionCount, ulSessionCount;
    CK_ULONG ulMaxRwSessionCount, ulRwSessionCount;
    CK_ULONG ulMaxPinLen, ulMinPinLen;
    CK_ULONG ulTotalPublicMemory, ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory, ulFreePrivateMemory;
    unsigned char hardwareVersion[2], firmwareVersion[2], utcTime[16];
};

static void usage(void) {
    fprintf(stderr,
      "fhsm-token --- provision a token\n\n"
      "  fhsm-token init [--label TEXT] [--slot N] [--module PATH]\n"
      "  fhsm-token info [--slot N] [--module PATH]\n\n"
      "  --label TEXT    token label, at most 32 characters (default \"freehsm\")\n"
      "  --slot N        slot to address. Default: the lowest empty slot for\n"
      "                  init, the one initialised token for info.\n"
      "  --module PATH   PKCS#11 module (default ./libfreehsm.so)\n\n"
      "  init reads the Security Officer PIN from FHSM_SO_PIN and the user PIN\n"
      "  from FHSM_PIN. Neither can be passed as an argument: arguments are\n"
      "  visible in ps to every user on the machine.\n\n"
      "  WARNING: init on an already-initialised token DESTROYS every key it\n"
      "  holds. That is what C_InitToken means, and this tool refuses to run\n"
      "  it unless --force is given.\n\n"
      "  Exit codes: 0 success. 1 usage, or a PIN not set in the environment.\n"
      "  2 module or PKCS#11 failure. 5 the token is already initialised and\n"
      "  --force was not given.\n");
    exit(1);
}

/* Trim a printed PKCS#11 fixed-width field: they are space-padded, not
 * NUL-terminated, and printing one raw drags 30 spaces across the output. */
static void put_field(const char *name, const unsigned char *f, size_t n) {
    while (n && (f[n-1] == ' ' || f[n-1] == '\0')) n--;
    printf("  %-14s %.*s\n", name, (int)n, (const char *)f);
}

static int cmd_info(const char *module, long slot) {
    load_module(module);
    CK_RV rv = p11.Initialize(NULL);
    if (rv != CKR_OK) die("C_Initialize", rv);
    CK_SLOT_ID sid = p11_resolve_slot(slot, P11_SLOT_ANY);
    struct tok_info ti;
    memset(&ti, 0, sizeof ti);
    rv = p11.GetTokenInfo(sid, &ti);
    if (rv != CKR_OK) die("C_GetTokenInfo", rv);

    printf("slot %lu\n", (unsigned long)sid);
    put_field("label",        ti.label,        sizeof ti.label);
    put_field("manufacturer", ti.manufacturerID, sizeof ti.manufacturerID);
    put_field("model",        ti.model,        sizeof ti.model);
    put_field("serial",       ti.serialNumber, sizeof ti.serialNumber);
    printf("  %-14s %s\n", "initialised",
           (ti.flags & CKF_TOKEN_INITIALIZED) ? "yes" : "no  -- run `fhsm-token init`");
    printf("  %-14s %s\n", "user PIN",
           (ti.flags & CKF_USER_PIN_INITIALIZED) ? "set" : "not set");
    if (ti.flags & CKF_SO_PIN_LOCKED)   printf("  %-14s %s\n", "warning", "SO PIN is LOCKED");
    if (ti.flags & CKF_USER_PIN_LOCKED) printf("  %-14s %s\n", "warning", "user PIN is LOCKED");
    printf("  %-14s %lu..%lu\n", "PIN length",
           (unsigned long)ti.ulMinPinLen, (unsigned long)ti.ulMaxPinLen);

    p11.Finalize(NULL);
    return 0;
}

static int cmd_init(const char *module, long slot, const char *label, int force) {
    CK_SLOT_ID sid = 0;
    const char *so   = getenv("FHSM_SO_PIN");
    const char *user = getenv("FHSM_PIN");
    if (!so || !*so) {
        fprintf(stderr, "fhsm-token: FHSM_SO_PIN is not set.\n"
                        "  The Security Officer PIN initialises the token and can reset the\n"
                        "  user PIN. It is read from the environment, never from an argument.\n");
        return 1;
    }
    if (!user || !*user) {
        fprintf(stderr, "fhsm-token: FHSM_PIN is not set.\n"
                        "  init sets the user PIN as well, so both are needed. Setting only\n"
                        "  the SO PIN would leave a token no application can log into.\n");
        return 1;
    }
    /* Check the length here as well, against the bounds the module itself
     * advertises rather than a copy of them. The module refuses out-of-range
     * PINs with CKR_PIN_LEN_RANGE, but a numeric code at the end of a command
     * is not an explanation -- and the first thing an operator does with a
     * placeholder PIN from a manual is paste it. */
    load_module(module);
    {
        CK_RV irv = p11.Initialize(NULL);
        if (irv != CKR_OK) die("C_Initialize", irv);
    }
    /* Resolved once, before anything is written. A slot the operator did not
     * choose is the one mistake here that cannot be undone. */
    sid = p11_resolve_slot(slot, P11_SLOT_FOR_INIT);

    {
        struct tok_info probe; memset(&probe, 0, sizeof probe);
        unsigned long lo = 4, hi = 64;
        if (p11.GetTokenInfo(sid, &probe) == CKR_OK
            && probe.ulMinPinLen && probe.ulMinPinLen <= probe.ulMaxPinLen) {
            lo = (unsigned long)probe.ulMinPinLen;
            hi = (unsigned long)probe.ulMaxPinLen;
        }
        int bad_so   = strlen(so)   < lo || strlen(so)   > hi;
        int bad_user = strlen(user) < lo || strlen(user) > hi;
        const char *which = bad_so && bad_user ? "FHSM_SO_PIN and FHSM_PIN are"
                          : bad_so             ? "FHSM_SO_PIN is"
                          : bad_user           ? "FHSM_PIN is" : NULL;
        if (which) {
            fprintf(stderr, "fhsm-token: %s outside the token's accepted length "
                            "(%lu..%lu characters).\n"
                            "  Nothing was changed. If you pasted a placeholder from a\n"
                            "  manual, that is the usual cause.\n", which, lo, hi);
            p11.Finalize(NULL);
            return 1;
        }
    }

    if (strlen(label) > 32) {
        fprintf(stderr, "fhsm-token: --label is at most 32 characters "
                        "(PKCS#11 pads it to exactly that).\n");
        p11.Finalize(NULL);
        return 1;
    }

    CK_RV rv = CKR_OK;

    /* Refuse to wipe a live token by accident. C_InitToken destroys every
     * object, and an operator who typed `init` meaning `info` should not lose
     * a CA key to a four-character difference. */
    if (!force) {
        struct tok_info ti; memset(&ti, 0, sizeof ti);
        if (p11.GetTokenInfo(sid, &ti) == CKR_OK
            && (ti.flags & CKF_TOKEN_INITIALIZED)) {
            size_t n = sizeof ti.label;
            while (n && ti.label[n-1] == ' ') n--;
            fprintf(stderr,
              "fhsm-token: slot %lu already holds an initialised token (\"%.*s\").\n"
              "  Re-initialising DESTROYS every key on it. If that is what you\n"
              "  want, pass --force. If you meant to look, use `fhsm-token info`.\n",
              (unsigned long)sid, (int)n, ti.label);
            p11.Finalize(NULL);
            return 5;
        }
    }

    /* PKCS#11 labels are space-padded to exactly 32 bytes, not NUL-terminated.
     * Passing a short C string here made C_InitToken read past the end once
     * already (see tests/test_attributes). */
    CK_BYTE lbl[32];
    memset(lbl, ' ', sizeof lbl);
    memcpy(lbl, label, strlen(label));

    rv = p11.InitToken(sid, (CK_BYTE*)(uintptr_t)so,
                        (CK_ULONG)strlen(so), lbl);
    if (rv != CKR_OK) die("C_InitToken", rv);

    CK_SESSION_HANDLE s = 0;
    rv = p11.OpenSession(sid, CKF_RW, NULL, NULL, &s);
    if (rv != CKR_OK) die("C_OpenSession", rv);
    rv = p11.Login(s, CKU_SO, (CK_BYTE*)(uintptr_t)so, (CK_ULONG)strlen(so));
    if (rv != CKR_OK) die("C_Login (SO)", rv);
    rv = p11.InitPIN(s, (CK_BYTE*)(uintptr_t)user, (CK_ULONG)strlen(user));
    if (rv != CKR_OK) die("C_InitPIN", rv);

    p11.CloseSession(s);
    p11.Finalize(NULL);
    fprintf(stderr, "fhsm-token: slot %lu initialised as \"%s\", user PIN set.\n"
                    "  Next: fhsm-csr keygen --label NAME\n",
            (unsigned long)sid, label);
    return 0;
}

int main(int argc, char **argv) {
    p11_progname = "fhsm-token";
    if (argc < 2) usage();
    const char *module = "./libfreehsm.so", *label = "freehsm";
    int force = 0; long slot = -1;
    for (int i = 2; i < argc; ++i) {
        if      (!strcmp(argv[i],"--module") && i+1<argc) module = argv[++i];
        else if (!strcmp(argv[i],"--label")  && i+1<argc) label  = argv[++i];
        else if (!strcmp(argv[i],"--slot")   && i+1<argc) slot   = p11_slot_arg(argv[++i]);
        else if (!strcmp(argv[i],"--force")) force = 1;
        else if (!strncmp(argv[i],"--pin",5) || !strncmp(argv[i],"--so-pin",8)) {
            fprintf(stderr, "fhsm-token: PINs are not accepted as arguments. Set\n"
                            "  FHSM_SO_PIN and FHSM_PIN instead: an argument is visible in\n"
                            "  ps to every user on this machine.\n");
            return 1;
        }
        else usage();
    }
    if (!strcmp(argv[1], "init")) return cmd_init(module, slot, label, force);
    if (!strcmp(argv[1], "info")) return cmd_info(module, slot);
    usage();
    return 1;
}
