/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * Which mechanisms survive `p11-kit server`?
 *
 * 06_kit_isolation answered whether p11-kit is safe to put between a client
 * and the token. This one answers whether anything useful gets through, and
 * the answer is narrower than §2b of docs/REST_API_DESIGN.md assumed when it
 * said "nothing needs to be written for the transport".
 *
 * Measured on p11-kit 0.24.0: the module advertises 72 mechanisms directly and
 * 20 through the socket. The 52 that vanish include every post-quantum one --
 * ML-DSA (0x1c, 0x1d), the standard SHA-3 family (0x2b0..), and our composite
 * CKM_COMPOSITE_MLDSA65_ED25519 (0x80004202). C_SignInit with the composite
 * answers CKR_MECHANISM_INVALID, and the module never sees the call: the
 * server-side audit log records login_ok and nothing after it.
 *
 * It is not a defect of ours and not a bug of p11-kit's. `rpc-message.c` has
 *
 *     bool p11_rpc_mechanism_is_supported (CK_MECHANISM_TYPE mech)
 *     {
 *         if (mechanism_has_no_parameters (mech) ||
 *             mechanism_has_sane_parameters (mech))
 *
 * -- an allow-list, because a CK_MECHANISM parameter is a void* whose layout
 * depends on the mechanism and cannot be serialised generically. A mechanism
 * absent from both lists cannot cross, even one that takes no parameter at
 * all. On upstream master the list names CKM_IBM_DILITHIUM, CKM_IBM_KYBER and
 * CKM_IBM_SHA3_*, contributed by IBM, and no standard PQ mechanism at all.
 *
 * So this probe exists to be re-run, not to be read once: the number is a
 * property of the p11-kit on the machine, and the day it changes we should
 * find out from a measurement rather than from a bug report.
 *
 *     probes/rest/07_kit_mechanisms MODULE            # what this module offers
 *     probes/rest/07_kit_mechanisms MODULE OTHER      # and what OTHER drops
 *
 * With two arguments it loads both and prints the difference, which is the
 * form that answers the question. Point the first at the module and the
 * second at p11-kit-client.so with P11_KIT_SERVER_ADDRESS set.
 */
#include "p11_probe.h"

/* The ones worth naming in the output. Everything else is printed as a bare
 * value: a table of 72 names would be a second copy of the module's mechanism
 * list, and this file already has enough opinions in it. */
static const struct { unsigned long m; const char *name; } NAMED[] = {
    { 0x80004202UL, "CKM_COMPOSITE_MLDSA65_ED25519 (vendor)" },
    { 0x0000001cUL, "CKM_ML_DSA_KEY_PAIR_GEN" },
    { 0x0000001dUL, "CKM_ML_DSA" },
    { 0x000002b0UL, "CKM_SHA3_256" },
    { 0x00000250UL, "CKM_SHA256" },
    { 0x00001041UL, "CKM_ECDSA" },
    { 0, NULL }
};
static const char *name_of(unsigned long m) {
    for (int i = 0; NAMED[i].name; i++) if (NAMED[i].m == m) return NAMED[i].name;
    return NULL;
}

static size_t list_mechs(const char *path, unsigned long *out, size_t cap)
{
    probe_load(path);
    if (p11.Initialize(NULL) != 0) {
        fprintf(stderr, "07: C_Initialize failed for %s\n", path); exit(2); }
    CK_SLOT_ID s = probe_slot();
    if (!p11.GetMechanismList) {
        fprintf(stderr, "07: %s does not implement C_GetMechanismList\n", path); exit(2); }
    CK_ULONG n = 0;
    if (p11.GetMechanismList(s, NULL, &n) != 0) {
        fprintf(stderr, "07: C_GetMechanismList failed for %s\n", path); exit(2); }
    if ((size_t)n > cap) n = (CK_ULONG)cap;
    static CK_ULONG buf[4096];
    if (p11.GetMechanismList(s, buf, &n) != 0) {
        fprintf(stderr, "07: C_GetMechanismList (2nd call) failed\n"); exit(2); }
    for (CK_ULONG i = 0; i < n; i++) out[i] = (unsigned long)buf[i];
    (void)p11.Finalize(NULL);
    return (size_t)n;
}

static int has(const unsigned long *a, size_t n, unsigned long m) {
    for (size_t i = 0; i < n; i++) if (a[i] == m) return 1;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: 07_kit_mechanisms MODULE [OTHER]\n"
                        "  one argument : list what MODULE advertises\n"
                        "  two          : what OTHER drops relative to MODULE\n");
        return 2;
    }
    static unsigned long a[4096], b[4096];
    size_t na = list_mechs(argv[1], a, 4096);

    if (argc == 2) {
        printf("%s advertises %zu mechanisms\n", argv[1], na);
        for (size_t i = 0; i < na; i++) {
            const char *nm = name_of(a[i]);
            if (nm) printf("  %08lx  %s\n", a[i], nm);
        }
        return 0;
    }

    size_t nb = list_mechs(argv[2], b, 4096);
    printf("Mechanisms across the transport\n\n");
    printf("  %-46s %zu\n", argv[1], na);
    printf("  %-46s %zu\n", argv[2], nb);

    size_t lost = 0;
    for (size_t i = 0; i < na; i++) if (!has(b, nb, a[i])) lost++;
    printf("\n  dropped by the second: %zu\n\n", lost);

    for (int i = 0; NAMED[i].name; i++) {
        int in_a = has(a, na, NAMED[i].m), in_b = has(b, nb, NAMED[i].m);
        printf("  %-42s %s -> %s\n", NAMED[i].name,
               in_a ? "present" : "absent ",
               in_b ? "present" : "DROPPED");
    }

    /* A probe that only ever reports "dropped" proves nothing about the
     * transport: it would say the same if the second module were empty. So
     * the exit status is about the control, not the loss. */
    if (nb == 0) {
        fprintf(stderr, "\n07: the second module advertises nothing at all --"
                        " that is a broken connection, not a filter.\n");
        return 2;
    }
    return 0;
}
